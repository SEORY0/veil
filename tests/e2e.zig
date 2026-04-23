//! End-to-end integration tests.
//!
//! Spawns the built `veil` binary as a child process, wires it up to an
//! in-process TCP echo upstream, and exercises real client traffic against
//! the listen port. All network activity is on 127.0.0.1 and uses ephemeral
//! ports to avoid collisions.

const std = @import("std");
const build_options = @import("build_options");

const VEIL_BIN = build_options.veil_bin;

const UpstreamThread = struct {
    thread: std.Thread,
    listen_fd: std.posix.fd_t,
    port: u16,
    stop_flag: *std.atomic.Value(bool),

    fn start(allocator: std.mem.Allocator) !UpstreamThread {
        const addr = try std.net.Address.parseIp("127.0.0.1", 0);
        var srv = try addr.listen(.{ .reuse_address = true });
        const port = srv.listen_address.getPort();
        const fd = srv.stream.handle;

        const flag = try allocator.create(std.atomic.Value(bool));
        flag.* = .init(false);

        const t = try std.Thread.spawn(.{}, echoLoop, .{ fd, flag });
        return .{
            .thread = t,
            .listen_fd = fd,
            .port = port,
            .stop_flag = flag,
        };
    }

    fn stop(self: *UpstreamThread, allocator: std.mem.Allocator) void {
        self.stop_flag.store(true, .release);
        // shutdown() before close() so the blocked accept() in the other thread wakes up.
        std.posix.shutdown(self.listen_fd, .both) catch {};
        std.posix.close(self.listen_fd);
        self.thread.join();
        allocator.destroy(self.stop_flag);
    }

    fn echoLoop(listen_fd: std.posix.fd_t, stop_flag: *std.atomic.Value(bool)) void {
        while (!stop_flag.load(.acquire)) {
            var client_addr: std.posix.sockaddr = undefined;
            var addr_len: std.posix.socklen_t = @sizeOf(std.posix.sockaddr);
            const c = std.posix.accept(listen_fd, &client_addr, &addr_len, std.posix.SOCK.CLOEXEC) catch |err| switch (err) {
                error.SocketNotListening, error.ConnectionAborted, error.FileDescriptorNotASocket => return,
                else => continue,
            };
            const t = std.Thread.spawn(.{}, echoClient, .{c}) catch {
                std.posix.close(c);
                continue;
            };
            t.detach();
        }
    }

    fn echoClient(fd: std.posix.fd_t) void {
        defer std.posix.close(fd);
        var buf: [8192]u8 = undefined;
        const n = std.posix.read(fd, &buf) catch return;
        if (n == 0) return;
        _ = std.posix.write(fd, buf[0..n]) catch return;
    }
};

fn freePort() !u16 {
    const addr = try std.net.Address.parseIp("127.0.0.1", 0);
    var srv = try addr.listen(.{ .reuse_address = true });
    defer srv.deinit();
    return srv.listen_address.getPort();
}

fn writeConfig(
    allocator: std.mem.Allocator,
    dir: std.fs.Dir,
    listen_port: u16,
    upstream_port: u16,
    burst: u32,
) ![]u8 {
    // rps fixed low for deterministic burst tests. Refill at 10/s means
    // one new token every 100ms — the 20-iter sendAndRead loop (~10ms) can't
    // refill meaningfully, so burst=3 reliably triggers rate_limited.
    const body = try std.fmt.allocPrint(allocator,
        \\{{
        \\  "listen": "127.0.0.1:{d}",
        \\  "upstream": "127.0.0.1:{d}",
        \\  "policy": {{
        \\    "allowed_tools": ["file_read"],
        \\    "blocked_paths": ["/etc/"],
        \\    "blocked_patterns": ["password"],
        \\    "rate_limit": {{ "requests_per_second": 10, "burst": {d} }}
        \\  }},
        \\  "audit": {{ "enabled": false, "path": "./audit.log", "max_size_mb": 10 }}
        \\}}
    , .{ listen_port, upstream_port, burst });
    defer allocator.free(body);
    try dir.writeFile(.{ .sub_path = "config.json", .data = body });
    return try dir.realpathAlloc(allocator, "config.json");
}

fn makeEnvMap(allocator: std.mem.Allocator, runtime_dir: []const u8) !*std.process.EnvMap {
    const env = try allocator.create(std.process.EnvMap);
    env.* = std.process.EnvMap.init(allocator);
    try env.put("XDG_RUNTIME_DIR", runtime_dir);
    if (std.posix.getenv("PATH")) |p| try env.put("PATH", p);
    return env;
}

fn spawnVeil(
    allocator: std.mem.Allocator,
    cfg_path: []const u8,
    env_map: *std.process.EnvMap,
) !std.process.Child {
    var child = std.process.Child.init(
        &.{ VEIL_BIN, "start", "--config", cfg_path },
        allocator,
    );
    child.stdout_behavior = .Ignore;
    child.stderr_behavior = .Ignore;
    child.env_map = env_map;

    try child.spawn();
    return child;
}

/// Wait until the TCP listener is accepting connections, up to ~2s.
fn waitReady(port: u16) !void {
    const addr = try std.net.Address.parseIp("127.0.0.1", port);
    var attempts: u32 = 0;
    while (attempts < 200) : (attempts += 1) {
        if (std.net.tcpConnectToAddress(addr)) |s| {
            s.close();
            return;
        } else |_| {
            std.Thread.sleep(10 * std.time.ns_per_ms);
        }
    }
    return error.VeilNeverListened;
}

fn sendAndRead(allocator: std.mem.Allocator, port: u16, req: []const u8) ![]u8 {
    const addr = try std.net.Address.parseIp("127.0.0.1", port);
    var s = try std.net.tcpConnectToAddress(addr);
    defer s.close();

    var written: usize = 0;
    while (written < req.len) {
        written += try std.posix.write(s.handle, req[written..]);
    }

    var buf: [8192]u8 = undefined;
    const n = try std.posix.read(s.handle, &buf);
    return try allocator.dupe(u8, buf[0..n]);
}

fn sendAndReadUnix(allocator: std.mem.Allocator, path: []const u8, req: []const u8) ![]u8 {
    var s = try std.net.connectUnixSocket(path);
    defer s.close();

    var written: usize = 0;
    while (written < req.len) {
        written += try std.posix.write(s.handle, req[written..]);
    }

    var buf: [8192]u8 = undefined;
    const n = try std.posix.read(s.handle, &buf);
    return try allocator.dupe(u8, buf[0..n]);
}

fn waitReadyUnix(path: []const u8) !void {
    var attempts: u32 = 0;
    while (attempts < 200) : (attempts += 1) {
        if (std.net.connectUnixSocket(path)) |s| {
            s.close();
            return;
        } else |_| {
            std.Thread.sleep(10 * std.time.ns_per_ms);
        }
    }
    return error.VeilNeverListened;
}

const UnixUpstream = struct {
    thread: std.Thread,
    listen_fd: std.posix.fd_t,
    path: []const u8,
    stop_flag: *std.atomic.Value(bool),

    fn start(allocator: std.mem.Allocator, path: []const u8) !UnixUpstream {
        std.posix.unlink(path) catch {};
        const addr = try std.net.Address.initUnix(path);
        const srv = try addr.listen(.{});
        const fd = srv.stream.handle;

        const flag = try allocator.create(std.atomic.Value(bool));
        flag.* = .init(false);

        const t = try std.Thread.spawn(.{}, UpstreamThread.echoLoop, .{ fd, flag });
        return .{
            .thread = t,
            .listen_fd = fd,
            .path = path,
            .stop_flag = flag,
        };
    }

    fn stop(self: *UnixUpstream, allocator: std.mem.Allocator) void {
        self.stop_flag.store(true, .release);
        std.posix.shutdown(self.listen_fd, .both) catch {};
        std.posix.close(self.listen_fd);
        self.thread.join();
        allocator.destroy(self.stop_flag);
        std.posix.unlink(self.path) catch {};
    }
};

fn writeConfigUnix(
    allocator: std.mem.Allocator,
    dir: std.fs.Dir,
    listen_path: []const u8,
    upstream_path: []const u8,
) ![]u8 {
    const body = try std.fmt.allocPrint(allocator,
        \\{{
        \\  "listen": "unix:{s}",
        \\  "upstream": "unix:{s}",
        \\  "policy": {{
        \\    "allowed_tools": ["file_read"],
        \\    "blocked_paths": ["/etc/"],
        \\    "blocked_patterns": ["password"],
        \\    "rate_limit": {{ "requests_per_second": 1000, "burst": 100 }}
        \\  }},
        \\  "audit": {{ "enabled": false, "path": "./audit.log", "max_size_mb": 10 }}
        \\}}
    , .{ listen_path, upstream_path });
    defer allocator.free(body);
    try dir.writeFile(.{ .sub_path = "config.json", .data = body });
    return try dir.realpathAlloc(allocator, "config.json");
}

const TestEnv = struct {
    allocator: std.mem.Allocator,
    tmp: std.testing.TmpDir,
    cfg_path: []u8,
    runtime_dir: []u8,
    env_map: *std.process.EnvMap,
    upstream: UpstreamThread,
    veil: std.process.Child,
    listen_port: u16,

    fn deinit(self: *TestEnv) void {
        _ = self.veil.kill() catch {};
        self.env_map.deinit();
        self.allocator.destroy(self.env_map);
        self.upstream.stop(self.allocator);
        self.allocator.free(self.cfg_path);
        self.allocator.free(self.runtime_dir);
        self.tmp.cleanup();
    }
};

fn setupEnv(allocator: std.mem.Allocator, burst: u32) !TestEnv {
    var tmp = std.testing.tmpDir(.{});
    errdefer tmp.cleanup();

    var upstream = try UpstreamThread.start(allocator);
    errdefer upstream.stop(allocator);

    const listen_port = try freePort();
    const cfg_path = try writeConfig(allocator, tmp.dir, listen_port, upstream.port, burst);
    errdefer allocator.free(cfg_path);

    const runtime_dir = try tmp.dir.realpathAlloc(allocator, ".");
    errdefer allocator.free(runtime_dir);

    const env_map = try makeEnvMap(allocator, runtime_dir);
    errdefer {
        env_map.deinit();
        allocator.destroy(env_map);
    }

    var veil = try spawnVeil(allocator, cfg_path, env_map);
    errdefer _ = veil.kill() catch {};

    try waitReady(listen_port);

    return .{
        .allocator = allocator,
        .tmp = tmp,
        .cfg_path = cfg_path,
        .runtime_dir = runtime_dir,
        .env_map = env_map,
        .upstream = upstream,
        .veil = veil,
        .listen_port = listen_port,
    };
}

// ── Scenarios ──────────────────────────────────────────────

test "e2e: allowed tool_call forwards to upstream" {
    const a = std.testing.allocator;
    var env = try setupEnv(a, 100);
    defer env.deinit();

    const req = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"file_read\",\"arguments\":{\"path\":\"/home/ok.txt\"}}}";
    const resp = try sendAndRead(a, env.listen_port, req);
    defer a.free(resp);

    // Echo upstream returns the request verbatim.
    try std.testing.expectEqualStrings(req, resp);
}

test "e2e: blocked path denies without contacting upstream" {
    const a = std.testing.allocator;
    var env = try setupEnv(a, 100);
    defer env.deinit();

    const req = "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"file_read\",\"arguments\":{\"path\":\"/etc/passwd\"}}}";
    const resp = try sendAndRead(a, env.listen_port, req);
    defer a.free(resp);

    try std.testing.expect(std.mem.indexOf(u8, resp, "\"verdict\":\"deny_path\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, resp, "blocked path detected") != null);
}

test "e2e: unlisted tool denied" {
    const a = std.testing.allocator;
    var env = try setupEnv(a, 100);
    defer env.deinit();

    const req = "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\",\"params\":{\"name\":\"shell_exec\",\"arguments\":{\"cmd\":\"ls\"}}}";
    const resp = try sendAndRead(a, env.listen_port, req);
    defer a.free(resp);

    try std.testing.expect(std.mem.indexOf(u8, resp, "\"verdict\":\"deny_tool\"") != null);
}

test "e2e: sensitive pattern denied" {
    const a = std.testing.allocator;
    var env = try setupEnv(a, 100);
    defer env.deinit();

    const req = "{\"jsonrpc\":\"2.0\",\"id\":4,\"method\":\"tools/call\",\"params\":{\"name\":\"file_read\",\"arguments\":{\"content\":\"password=hunter2\"}}}";
    const resp = try sendAndRead(a, env.listen_port, req);
    defer a.free(resp);

    try std.testing.expect(std.mem.indexOf(u8, resp, "\"verdict\":\"deny_pattern\"") != null);
}

test "e2e: non-tool-call passes through to upstream" {
    const a = std.testing.allocator;
    var env = try setupEnv(a, 100);
    defer env.deinit();

    const req = "{\"jsonrpc\":\"2.0\",\"id\":5,\"method\":\"tools/list\"}";
    const resp = try sendAndRead(a, env.listen_port, req);
    defer a.free(resp);

    // Passthrough → echo upstream returns the request as-is.
    try std.testing.expectEqualStrings(req, resp);
}

test "e2e: burst limit eventually denies" {
    const a = std.testing.allocator;
    // Tight burst so the test is deterministic even under load.
    var env = try setupEnv(a, 3);
    defer env.deinit();

    const req = "{\"jsonrpc\":\"2.0\",\"id\":9,\"method\":\"tools/call\",\"params\":{\"name\":\"file_read\",\"arguments\":{\"path\":\"/home/a.txt\"}}}";

    var saw_rate_limited = false;
    var i: u32 = 0;
    while (i < 20) : (i += 1) {
        const resp = sendAndRead(a, env.listen_port, req) catch {
            continue;
        };
        defer a.free(resp);
        if (std.mem.indexOf(u8, resp, "\"rate_limited\"") != null or
            std.mem.indexOf(u8, resp, "\"deny_rate\"") != null)
        {
            saw_rate_limited = true;
            break;
        }
    }
    try std.testing.expect(saw_rate_limited);
}

// ── Unix-socket scenarios (TD-2.1.2) ──────────────────────────

const UnixEnv = struct {
    allocator: std.mem.Allocator,
    tmp: std.testing.TmpDir,
    cfg_path: []u8,
    listen_path: []u8,
    upstream_path: []u8,
    runtime_dir: []u8,
    env_map: *std.process.EnvMap,
    upstream: UnixUpstream,
    veil: std.process.Child,

    fn deinit(self: *UnixEnv) void {
        _ = self.veil.kill() catch {};
        self.env_map.deinit();
        self.allocator.destroy(self.env_map);
        self.upstream.stop(self.allocator);
        self.allocator.free(self.cfg_path);
        self.allocator.free(self.listen_path);
        self.allocator.free(self.upstream_path);
        self.allocator.free(self.runtime_dir);
        self.tmp.cleanup();
    }
};

fn setupUnixEnv(allocator: std.mem.Allocator) !UnixEnv {
    var tmp = std.testing.tmpDir(.{});
    errdefer tmp.cleanup();

    const tmp_path = try tmp.dir.realpathAlloc(allocator, ".");
    errdefer allocator.free(tmp_path);

    const upstream_path = try std.fmt.allocPrint(allocator, "{s}/upstream.sock", .{tmp_path});
    errdefer allocator.free(upstream_path);

    const listen_path = try std.fmt.allocPrint(allocator, "{s}/veil.sock", .{tmp_path});
    errdefer allocator.free(listen_path);

    var upstream = try UnixUpstream.start(allocator, upstream_path);
    errdefer upstream.stop(allocator);

    const cfg_path = try writeConfigUnix(allocator, tmp.dir, listen_path, upstream_path);
    errdefer allocator.free(cfg_path);

    // tmp_path is reused as runtime dir (pidfile target)
    const env_map = try makeEnvMap(allocator, tmp_path);
    errdefer {
        env_map.deinit();
        allocator.destroy(env_map);
    }

    var veil = try spawnVeil(allocator, cfg_path, env_map);
    errdefer _ = veil.kill() catch {};

    try waitReadyUnix(listen_path);

    return .{
        .allocator = allocator,
        .tmp = tmp,
        .cfg_path = cfg_path,
        .listen_path = listen_path,
        .upstream_path = upstream_path,
        .runtime_dir = tmp_path,
        .env_map = env_map,
        .upstream = upstream,
        .veil = veil,
    };
}

test "e2e(unix): allowed tool_call forwards to unix upstream" {
    const a = std.testing.allocator;
    var env = try setupUnixEnv(a);
    defer env.deinit();

    const req = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"file_read\",\"arguments\":{\"path\":\"/home/ok.txt\"}}}";
    const resp = try sendAndReadUnix(a, env.listen_path, req);
    defer a.free(resp);

    try std.testing.expectEqualStrings(req, resp);
}

// ── TLS upstream scenario (TD-2.1.1) ──────────────────────────
//
// Uses external `openssl` + `python3` to set up a self-signed TLS echo
// server. Skips if either is missing — keeps the suite CI-portable.

fn hasExecutable(name: []const u8) bool {
    const path = std.posix.getenv("PATH") orelse return false;
    var it = std.mem.splitScalar(u8, path, ':');
    while (it.next()) |dir| {
        if (dir.len == 0) continue;
        var buf: [512]u8 = undefined;
        const full = std.fmt.bufPrint(&buf, "{s}/{s}", .{ dir, name }) catch continue;
        std.posix.access(full, std.posix.X_OK) catch continue;
        return true;
    }
    return false;
}

const TlsEnv = struct {
    allocator: std.mem.Allocator,
    tmp: std.testing.TmpDir,
    cfg_path: []u8,
    runtime_dir: []u8,
    env_map: *std.process.EnvMap,
    upstream_proc: std.process.Child,
    veil: std.process.Child,
    listen_port: u16,

    fn deinit(self: *TlsEnv) void {
        _ = self.veil.kill() catch {};
        _ = self.upstream_proc.kill() catch {};
        self.env_map.deinit();
        self.allocator.destroy(self.env_map);
        self.allocator.free(self.cfg_path);
        self.allocator.free(self.runtime_dir);
        self.tmp.cleanup();
    }
};

fn setupTlsEnv(a: std.mem.Allocator) !TlsEnv {
    var tmp = std.testing.tmpDir(.{});
    errdefer tmp.cleanup();

    const tmp_path = try tmp.dir.realpathAlloc(a, ".");
    errdefer a.free(tmp_path);

    // Generate self-signed cert with openssl.
    const key_path = try std.fmt.allocPrint(a, "{s}/key.pem", .{tmp_path});
    defer a.free(key_path);
    const cert_path = try std.fmt.allocPrint(a, "{s}/cert.pem", .{tmp_path});
    defer a.free(cert_path);
    {
        var openssl = std.process.Child.init(&.{
            "openssl",         "req",      "-x509",     "-newkey",
            "rsa:2048",        "-sha256",  "-days",     "1",
            "-nodes",          "-subj",    "/CN=localhost",
            "-keyout",         key_path,   "-out",      cert_path,
        }, a);
        openssl.stdout_behavior = .Ignore;
        openssl.stderr_behavior = .Ignore;
        _ = try openssl.spawnAndWait();
    }

    // Pick a port for upstream TLS.
    const upstream_port = try freePort();

    // Start Python TLS echo server.
    const py_script = try std.fmt.allocPrint(a,
        \\import socket, ssl, threading, sys
        \\ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        \\ctx.load_cert_chain(r"{s}", r"{s}")
        \\def h(c):
        \\    with c:
        \\        try:
        \\            d = c.recv(8192)
        \\            if not d: return
        \\            c.sendall(b"TLS-ECHO:" + d)
        \\        except Exception:
        \\            pass
        \\s = socket.socket()
        \\s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        \\s.bind(("127.0.0.1", {d}))
        \\s.listen(8)
        \\sys.stdout.write("READY\n"); sys.stdout.flush()
        \\while True:
        \\    c,_ = s.accept()
        \\    try: sc = ctx.wrap_socket(c, server_side=True)
        \\    except Exception: continue
        \\    threading.Thread(target=h, args=(sc,), daemon=True).start()
    , .{ cert_path, key_path, upstream_port });
    defer a.free(py_script);

    var upstream_proc = std.process.Child.init(&.{ "python3", "-u", "-c", py_script }, a);
    upstream_proc.stdout_behavior = .Pipe;
    upstream_proc.stderr_behavior = .Ignore;
    try upstream_proc.spawn();
    errdefer _ = upstream_proc.kill() catch {};

    // Wait for Python's "READY\n" token. Single read() — `readAll` would
    // block waiting for the whole buffer (process doesn't exit).
    if (upstream_proc.stdout) |out| {
        var ready_buf: [32]u8 = undefined;
        _ = out.read(&ready_buf) catch {};
    }
    // Give Python a moment to call listen().
    std.Thread.sleep(200 * std.time.ns_per_ms);

    const listen_port = try freePort();
    const body = try std.fmt.allocPrint(a,
        \\{{
        \\  "listen": "127.0.0.1:{d}",
        \\  "upstream": "tls://127.0.0.1:{d}",
        \\  "policy": {{
        \\    "allowed_tools": ["file_read"],
        \\    "blocked_paths": [],
        \\    "blocked_patterns": [],
        \\    "rate_limit": {{ "requests_per_second": 1000, "burst": 100 }}
        \\  }},
        \\  "audit": {{ "enabled": false, "path": "./a.log", "max_size_mb": 10 }}
        \\}}
    , .{ listen_port, upstream_port });
    defer a.free(body);
    try tmp.dir.writeFile(.{ .sub_path = "config.json", .data = body });
    const cfg_path = try tmp.dir.realpathAlloc(a, "config.json");
    errdefer a.free(cfg_path);

    const env_map = try makeEnvMap(a, tmp_path);
    errdefer {
        env_map.deinit();
        a.destroy(env_map);
    }

    var veil = try spawnVeil(a, cfg_path, env_map);
    errdefer _ = veil.kill() catch {};

    try waitReady(listen_port);

    return .{
        .allocator = a,
        .tmp = tmp,
        .cfg_path = cfg_path,
        .runtime_dir = tmp_path,
        .env_map = env_map,
        .upstream_proc = upstream_proc,
        .veil = veil,
        .listen_port = listen_port,
    };
}

test "e2e(tls): allow forwards to TLS upstream" {
    if (!hasExecutable("openssl") or !hasExecutable("python3")) return error.SkipZigTest;

    const a = std.testing.allocator;
    var env = try setupTlsEnv(a);
    defer env.deinit();

    const req = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"file_read\",\"arguments\":{\"path\":\"/home/ok.txt\"}}}";
    const resp = try sendAndRead(a, env.listen_port, req);
    defer a.free(resp);

    try std.testing.expect(std.mem.startsWith(u8, resp, "TLS-ECHO:"));
    try std.testing.expect(std.mem.indexOf(u8, resp, "file_read") != null);
}

test "e2e(unix): blocked path denies without contacting upstream" {
    const a = std.testing.allocator;
    var env = try setupUnixEnv(a);
    defer env.deinit();

    const req = "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"file_read\",\"arguments\":{\"path\":\"/etc/passwd\"}}}";
    const resp = try sendAndReadUnix(a, env.listen_path, req);
    defer a.free(resp);

    try std.testing.expect(std.mem.indexOf(u8, resp, "\"verdict\":\"deny_path\"") != null);
}
