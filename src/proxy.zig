const std = @import("std");
const config = @import("config.zig");
const addr_mod = @import("addr.zig");
const json = @import("json.zig");
const policy = @import("policy.zig");
const audit = @import("audit.zig");
const limiter = @import("limiter.zig");
const frame = @import("frame.zig");
const pool_mod = @import("pool.zig");

const PIPE_BUF_SIZE: usize = 16 * 1024;
const TLS_BUF_SIZE: usize = std.crypto.tls.max_ciphertext_record_len;

// ── Signal-handling state (file-scope; handlers are async-signal-safe) ─────
//
// Only atomic stores and `write(2)` to a preopen pipe are touched from the
// signal handler. Everything else (reload, cleanup) happens on the main
// thread after the handler returns.

var g_sig_pipe: [2]std.posix.fd_t = .{ -1, -1 };
var g_should_exit: std.atomic.Value(bool) = .init(false);
var g_needs_reload: std.atomic.Value(bool) = .init(false);

/// Pointer to the currently-active loaded config. Swapped atomically on
/// SIGHUP. `handleConnection` snapshots the pointer once per request so
/// in-flight traffic sees a consistent config even during reload.
var g_active: std.atomic.Value(?*config.Loaded) = .init(null);

fn signalHandler(sig: i32) callconv(.c) void {
    switch (sig) {
        std.posix.SIG.HUP => g_needs_reload.store(true, .release),
        std.posix.SIG.TERM, std.posix.SIG.INT => g_should_exit.store(true, .release),
        else => {},
    }
    // Wake the main loop: one byte is enough. write() on a pipe is
    // async-signal-safe per POSIX.
    const byte: [1]u8 = .{@intCast(@as(u8, @truncate(@as(u32, @intCast(sig)))))};
    _ = std.posix.write(g_sig_pipe[1], &byte) catch {};
}

fn installSignalHandlers() !void {
    g_sig_pipe = try std.posix.pipe2(.{ .NONBLOCK = true, .CLOEXEC = true });

    const sa: std.posix.Sigaction = .{
        .handler = .{ .handler = signalHandler },
        .mask = std.posix.sigemptyset(),
        .flags = std.posix.SA.RESTART,
    };
    std.posix.sigaction(std.posix.SIG.HUP, &sa, null);
    std.posix.sigaction(std.posix.SIG.TERM, &sa, null);
    std.posix.sigaction(std.posix.SIG.INT, &sa, null);
}

fn drainSigPipe() void {
    var buf: [64]u8 = undefined;
    while (true) {
        const n = std.posix.read(g_sig_pipe[0], &buf) catch return;
        if (n == 0) return;
        if (n < buf.len) return;
    }
}

// ── Server state (per-process, shared across requests) ──────────────────────

const ServerState = struct {
    rate_limiter: *limiter.RateLimiter,
    logger: *audit.AuditLogger,
    allocator: std.mem.Allocator,
    /// Lazily populated the first time a TLS upstream is dialed.
    ca_bundle: ?std.crypto.Certificate.Bundle = null,
    /// Upstream connection pool. Reuse across client connections to avoid
    /// TCP 3-way handshake (and, once TLS streaming is implemented, TLS
    /// handshake) on every request.
    pool: pool_mod.Pool,

    fn deinit(self: *ServerState) void {
        self.pool.deinit();
        if (self.ca_bundle) |*bundle| {
            bundle.deinit(self.allocator);
        }
    }

    fn ensureCaBundle(self: *ServerState) !*const std.crypto.Certificate.Bundle {
        if (self.ca_bundle == null) {
            var bundle: std.crypto.Certificate.Bundle = .{};
            errdefer bundle.deinit(self.allocator);
            try bundle.rescan(self.allocator);
            self.ca_bundle = bundle;
        }
        return &self.ca_bundle.?;
    }
};

// ── Entry point ────────────────────────────────────────────────────────────

/// Takes ownership of `initial` (and all reload-created Loaded instances).
/// Frees everything — including `initial` — on return, regardless of whether
/// exit was triggered by signal or setup error.
pub fn run(
    allocator: std.mem.Allocator,
    initial: *config.Loaded,
    config_path: []const u8,
) !void {
    try installSignalHandlers();
    g_active.store(initial, .release);

    // Retired Loaded instances — we keep them alive until shutdown because
    // in-flight requests may still reference their arena-allocated slices.
    // Free-after-process-exit memory usage grows only with reload count.
    var retired: std.ArrayList(*config.Loaded) = .empty;
    defer {
        // Free the currently-active config (whether initial or a reloaded one).
        if (g_active.swap(null, .acq_rel)) |current| {
            current.deinit();
            allocator.destroy(current);
        }
        // Free all retired (previously-active) configs.
        for (retired.items) |r| {
            r.deinit();
            allocator.destroy(r);
        }
        retired.deinit(allocator);
    }

    var rate_limiter = limiter.RateLimiter.init(
        initial.value.policy.rate_limit.requests_per_second,
        initial.value.policy.rate_limit.burst,
    );

    var logger = audit.AuditLogger.init(initial.value.audit.enabled, initial.value.audit.path);
    defer logger.deinit();

    var state: ServerState = .{
        .rate_limiter = &rate_limiter,
        .logger = &logger,
        .allocator = allocator,
        .pool = pool_mod.Pool.init(allocator),
    };
    defer state.deinit();

    var listener: ListenHandle = try ListenHandle.open(initial.value.listen);
    defer listener.close();

    std.debug.print("veil: listening on {s} → upstream {s}\n", .{ initial.value.listen, initial.value.upstream });

    try acceptLoop(allocator, &listener, config_path, &state, &retired);

    std.debug.print("veil: shutting down\n", .{});
}

/// Bundles a live `std.net.Server` with the spec string and unix path it was
/// bound from, so `acceptLoop` can detect a listen-address change on reload
/// and rebind transparently.
const ListenHandle = struct {
    server: std.net.Server,
    /// Slice into the currently-active config; valid as long as that Loaded
    /// is in `g_active` or `retired`. When listen spec changes on reload we
    /// copy a fresh slice from the new config.
    spec: []const u8,
    unix_path: ?[]const u8,

    fn open(spec: []const u8) !ListenHandle {
        const parsed = try addr_mod.parse(spec);
        if (parsed.unix_path) |path| {
            std.posix.unlink(path) catch |err| switch (err) {
                error.FileNotFound => {},
                else => return err,
            };
        }
        const server = try parsed.address.?.listen(.{
            .reuse_address = !parsed.isUnix(),
            .kernel_backlog = 128,
        });
        return .{
            .server = server,
            .spec = spec,
            .unix_path = parsed.unix_path,
        };
    }

    fn close(self: *ListenHandle) void {
        self.server.deinit();
        if (self.unix_path) |path| {
            std.posix.unlink(path) catch {};
        }
    }

    fn fd(self: *const ListenHandle) std.posix.fd_t {
        return self.server.stream.handle;
    }
};

fn acceptLoop(
    allocator: std.mem.Allocator,
    listener: *ListenHandle,
    config_path: []const u8,
    state: *ServerState,
    retired: *std.ArrayList(*config.Loaded),
) !void {
    var fds = [_]std.posix.pollfd{
        .{ .fd = listener.fd(), .events = std.posix.POLL.IN, .revents = 0 },
        .{ .fd = g_sig_pipe[0], .events = std.posix.POLL.IN, .revents = 0 },
    };

    while (!g_should_exit.load(.acquire)) {
        if (g_needs_reload.swap(false, .acq_rel)) {
            reload(allocator, config_path, retired, state) catch |err| {
                std.debug.print("veil: reload failed: {} (keeping old config)\n", .{err});
                continue;
            };
            // If the listen spec changed, rebind.
            if (g_active.load(.acquire)) |active| {
                if (!std.mem.eql(u8, active.value.listen, listener.spec)) {
                    rebindListener(listener, active.value.listen, &fds) catch |err| {
                        std.debug.print("veil: rebind to {s} failed: {} (keeping old listener)\n", .{ active.value.listen, err });
                    };
                }
            }
        }

        fds[0].revents = 0;
        fds[1].revents = 0;
        _ = std.posix.poll(&fds, -1) catch |err| {
            std.debug.print("veil: poll error: {}\n", .{err});
            continue;
        };

        // Drain any signal-pipe bytes and reprocess flags at top of loop.
        if ((fds[1].revents & std.posix.POLL.IN) != 0) {
            drainSigPipe();
            continue;
        }

        if ((fds[0].revents & std.posix.POLL.IN) == 0) continue;

        const conn = listener.server.accept() catch |err| {
            std.debug.print("veil: accept error: {}\n", .{err});
            continue;
        };
        defer conn.stream.close();

        const snapshot = g_active.load(.acquire) orelse continue;
        handleConnection(conn, snapshot.value, state) catch |err| {
            std.debug.print("veil: connection error: {}\n", .{err});
        };
    }
}

fn rebindListener(listener: *ListenHandle, new_spec: []const u8, fds: []std.posix.pollfd) !void {
    var new_handle = try ListenHandle.open(new_spec);
    errdefer new_handle.close();

    // Close the old one before swapping state.
    listener.close();
    listener.* = new_handle;
    fds[0].fd = listener.fd();
    std.debug.print("veil: re-bound listener to {s}\n", .{new_spec});
}

fn reload(
    allocator: std.mem.Allocator,
    config_path: []const u8,
    retired: *std.ArrayList(*config.Loaded),
    state: *ServerState,
) !void {
    const new_loaded = try allocator.create(config.Loaded);
    errdefer allocator.destroy(new_loaded);
    new_loaded.* = try config.load(allocator, config_path);
    errdefer new_loaded.deinit();

    const old = g_active.swap(new_loaded, .acq_rel);

    // Re-initialize the rate limiter with the new rps/burst. Tokens are
    // reset to the new burst value — fresh allowance after reload.
    state.rate_limiter.* = limiter.RateLimiter.init(
        new_loaded.value.policy.rate_limit.requests_per_second,
        new_loaded.value.policy.rate_limit.burst,
    );

    // Drain prior retired entries. veil is single-threaded — by the time
    // reload() runs (in the accept loop, between accept() calls) no
    // handleConnection is still executing. Every previously-retired config
    // is therefore unreferenced and safe to free immediately, not just at
    // shutdown.
    while (retired.pop()) |r| {
        r.deinit();
        allocator.destroy(r);
    }

    std.debug.print("veil: config reloaded from {s} (rps={d} burst={d})\n", .{
        config_path,
        new_loaded.value.policy.rate_limit.requests_per_second,
        new_loaded.value.policy.rate_limit.burst,
    });
    if (old) |o| {
        try retired.append(allocator, o);
    }
}

// ── Request handling ───────────────────────────────────────────────────────

fn handleConnection(
    conn: std.net.Server.Connection,
    cfg: config.Config,
    state: *ServerState,
) !void {
    var reader: frame.Reader = .{};
    const request = (reader.next(conn.stream.handle) catch |err| {
        std.debug.print("veil: frame error: {}\n", .{err});
        return;
    }) orelse return;

    if (!state.rate_limiter.tryConsume()) {
        try sendDeny(conn.stream.handle, .deny_rate, "rate limit exceeded");
        state.logger.log(.{
            .timestamp = std.time.timestamp(),
            .tool_name = "unknown",
            .verdict = .deny_rate,
            .reason = "rate limit exceeded",
            .client_addr = "client",
        });
        return;
    }

    // Non-tool-call messages pass through unchecked (MCP protocol handshake etc.).
    const tool_call = json.extractToolCall(request) catch {
        return forwardAny(conn.stream.handle, cfg, state, request);
    };

    const result = policy.evaluate(
        tool_call.tool_name,
        tool_call.arguments_raw,
        cfg.policy.allowed_tools,
        cfg.policy.blocked_paths,
        cfg.policy.blocked_patterns,
    );

    state.logger.log(.{
        .timestamp = std.time.timestamp(),
        .tool_name = tool_call.tool_name,
        .verdict = result.verdict,
        .reason = result.reason,
        .client_addr = "client",
    });

    if (result.verdict == .allow) {
        try forwardAny(conn.stream.handle, cfg, state, request);
    } else {
        try sendDeny(conn.stream.handle, result.verdict, result.reason);
    }
}

fn sendDeny(client_fd: std.posix.fd_t, verdict: policy.Verdict, reason: []const u8) !void {
    var deny_buf: [256]u8 = undefined;
    const msg = std.fmt.bufPrint(
        &deny_buf,
        "{{\"error\":\"denied\",\"verdict\":\"{s}\",\"reason\":\"{s}\"}}",
        .{ @tagName(verdict), reason },
    ) catch return;
    _ = try std.posix.write(client_fd, msg);
}

fn forwardAny(
    client_fd: std.posix.fd_t,
    cfg: config.Config,
    state: *ServerState,
    initial: []const u8,
) !void {
    const parsed = try addr_mod.parse(cfg.upstream);
    switch (parsed.scheme) {
        .unix, .tcp => try forwardPlain(client_fd, state, cfg.upstream, parsed, initial),
        .tls => try forwardTls(client_fd, cfg, state, parsed, initial),
    }
}

fn forwardPlain(
    client_fd: std.posix.fd_t,
    state: *ServerState,
    spec: []const u8,
    parsed: addr_mod.Parsed,
    initial: []const u8,
) !void {
    // Try the pool first. If the pooled connection is stale (peer closed),
    // writeAll will error — dial a fresh one and retry once.
    var from_pool = true;
    var upstream: std.net.Stream = state.pool.take(spec) orelse blk: {
        from_pool = false;
        break :blk try dialPlain(state.allocator, parsed);
    };

    writeAll(upstream.handle, initial) catch |err| {
        // Pool hit but connection was half-closed → retry once with fresh dial.
        upstream.close();
        if (from_pool) {
            upstream = try dialPlain(state.allocator, parsed);
            try writeAll(upstream.handle, initial);
        } else {
            return err;
        }
    };

    const exit = pipeBidirectional(client_fd, upstream.handle) catch |err| {
        upstream.close();
        return err;
    };

    // Return to pool only if client closed cleanly and upstream appears idle.
    if (exit == .client_closed and isUpstreamIdle(upstream.handle)) {
        state.pool.put(spec, upstream);
    } else {
        upstream.close();
    }
}

fn dialPlain(allocator: std.mem.Allocator, parsed: addr_mod.Parsed) !std.net.Stream {
    if (parsed.unix_path) |path| return try std.net.connectUnixSocket(path);
    if (parsed.host) |h| return try std.net.tcpConnectToHost(allocator, h, parsed.port);
    return try std.net.tcpConnectToAddress(parsed.address.?);
}

/// Best-effort drain detection: non-blocking poll. If no data/HUP/ERR is
/// immediately pending, the upstream has no in-flight response bytes and
/// is safe to reuse for the next request.
fn isUpstreamIdle(fd: std.posix.fd_t) bool {
    var pfd = [_]std.posix.pollfd{.{ .fd = fd, .events = std.posix.POLL.IN, .revents = 0 }};
    _ = std.posix.poll(&pfd, 0) catch return false;
    const bad = std.posix.POLL.IN | std.posix.POLL.HUP | std.posix.POLL.ERR | std.posix.POLL.NVAL;
    return (pfd[0].revents & bad) == 0;
}

/// Single-shot TLS forward: handshake, send request, drain response back to client.
/// Streaming bidirectional TLS is deferred — MCP tool calls are request/response.
fn forwardTls(
    client_fd: std.posix.fd_t,
    cfg: config.Config,
    state: *ServerState,
    parsed: addr_mod.Parsed,
    initial: []const u8,
) !void {
    var tcp: std.net.Stream = if (parsed.host) |h|
        try std.net.tcpConnectToHost(state.allocator, h, parsed.port)
    else
        try std.net.tcpConnectToAddress(parsed.address.?);
    defer tcp.close();

    var raw_recv: [TLS_BUF_SIZE]u8 = undefined;
    var raw_send: [TLS_BUF_SIZE]u8 = undefined;
    var stream_reader = tcp.reader(&raw_recv);
    var stream_writer = tcp.writer(&raw_send);

    var tls_write_buf: [TLS_BUF_SIZE]u8 = undefined;
    var tls_read_buf: [TLS_BUF_SIZE]u8 = undefined;

    const ca_bundle = try state.ensureCaBundle();

    // SNI precedence: config.upstream_sni > parsed.host > none.
    // CA precedence:  config.upstream_ca_path → mixed (extra CAs added);
    //                 otherwise system bundle if an SNI is available.
    // If no SNI is available at all → no_verification (opt-in via tls://IP).
    const sni: ?[]const u8 = cfg.upstream_sni orelse parsed.host;

    var tls_client = if (sni) |h|
        try std.crypto.tls.Client.init(
            stream_reader.interface(),
            &stream_writer.interface,
            .{
                .host = .{ .explicit = h },
                .ca = .{ .bundle = ca_bundle.* },
                .write_buffer = &tls_write_buf,
                .read_buffer = &tls_read_buf,
                .allow_truncation_attacks = !cfg.upstream_tls_strict,
            },
        )
    else
        try std.crypto.tls.Client.init(
            stream_reader.interface(),
            &stream_writer.interface,
            .{
                .host = .no_verification,
                .ca = .no_verification,
                .write_buffer = &tls_write_buf,
                .read_buffer = &tls_read_buf,
                .allow_truncation_attacks = !cfg.upstream_tls_strict,
            },
        );

    try tls_client.writer.writeAll(initial);
    try tls_client.writer.flush();
    try stream_writer.interface.flush();

    var resp_buf: [8192]u8 = undefined;
    while (true) {
        const n = tls_client.reader.readSliceShort(&resp_buf) catch |err| switch (err) {
            error.ReadFailed => break,
        };
        if (n == 0) break;
        writeAll(client_fd, resp_buf[0..n]) catch break;
        if (n < resp_buf.len and tls_client.received_close_notify) break;
    }
}

const PipeExit = enum { client_closed, upstream_closed, error_exit };

fn pipeBidirectional(a: std.posix.fd_t, b: std.posix.fd_t) !PipeExit {
    var fds = [_]std.posix.pollfd{
        .{ .fd = a, .events = std.posix.POLL.IN, .revents = 0 },
        .{ .fd = b, .events = std.posix.POLL.IN, .revents = 0 },
    };
    var buf: [PIPE_BUF_SIZE]u8 = undefined;
    const hup_err = std.posix.POLL.HUP | std.posix.POLL.ERR | std.posix.POLL.NVAL;

    while (true) {
        _ = try std.posix.poll(&fds, -1);

        if ((fds[0].revents & std.posix.POLL.IN) != 0) {
            const n = std.posix.read(a, &buf) catch |err| switch (err) {
                error.ConnectionResetByPeer => return .client_closed,
                else => return err,
            };
            if (n == 0) return .client_closed;
            writeAll(b, buf[0..n]) catch return .upstream_closed;
        }

        if ((fds[1].revents & std.posix.POLL.IN) != 0) {
            const n = std.posix.read(b, &buf) catch |err| switch (err) {
                error.ConnectionResetByPeer => return .upstream_closed,
                else => return err,
            };
            if (n == 0) return .upstream_closed;
            writeAll(a, buf[0..n]) catch return .client_closed;
        }

        if ((fds[0].revents & hup_err) != 0) return .client_closed;
        if ((fds[1].revents & hup_err) != 0) return .upstream_closed;

        fds[0].revents = 0;
        fds[1].revents = 0;
    }
}

fn writeAll(fd: std.posix.fd_t, bytes: []const u8) !void {
    var written: usize = 0;
    while (written < bytes.len) {
        const n = try std.posix.write(fd, bytes[written..]);
        if (n == 0) return error.BrokenPipe;
        written += n;
    }
}

test "parse upstream specs" {
    try std.testing.expectError(error.InvalidAddress, addr_mod.parse("garbage-no-port"));
    const tls = try addr_mod.parse("tls://example.com:443");
    try std.testing.expect(tls.isTls());
}
