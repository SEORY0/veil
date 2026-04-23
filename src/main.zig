const std = @import("std");
const config = @import("config.zig");
const proxy = @import("proxy.zig");
const policy = @import("policy.zig");
const audit = @import("audit.zig");
const limiter = @import("limiter.zig");
const pidfile = @import("pidfile.zig");
const addr_mod = @import("addr.zig");

fn upstreamIsUnverifiedTls(cfg: config.Config) bool {
    const parsed = addr_mod.parse(cfg.upstream) catch return false;
    if (!parsed.isTls()) return false;
    // If SNI is explicitly set in config, or parsed host is a hostname → verified.
    if (cfg.upstream_sni != null) return false;
    if (parsed.host != null) return false;
    return true;
}

const VERSION = "0.1.0";

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len < 2) {
        printUsage();
        return;
    }

    const command = args[1];

    if (std.mem.eql(u8, command, "start")) {
        try cmdStart(allocator, args);
    } else if (std.mem.eql(u8, command, "status")) {
        try cmdStatus(allocator);
    } else if (std.mem.eql(u8, command, "validate")) {
        try cmdValidate(allocator, args);
    } else if (std.mem.eql(u8, command, "version")) {
        std.debug.print("veil v{s}\n", .{VERSION});
    } else if (std.mem.eql(u8, command, "help")) {
        printUsage();
    } else {
        std.debug.print("unknown command: {s}\n", .{command});
        printUsage();
    }
}

fn cmdStart(allocator: std.mem.Allocator, args: []const []const u8) !void {
    const cfg_path = getConfigPath(args);

    // Heap-allocate and hand off to proxy.run, which takes ownership and
    // handles cleanup (including on reload, where the old Loaded is retired
    // into an internal list and freed at shutdown).
    const loaded = try allocator.create(config.Loaded);
    errdefer allocator.destroy(loaded);
    loaded.* = try config.load(allocator, cfg_path);
    errdefer loaded.deinit();

    const pid_path = try pidfile.defaultPath(allocator);
    defer allocator.free(pid_path);

    // Refuse to start if another instance appears to be running. The
    // authoritative check is flock() below — the kill(pid,0) probe is an
    // informational hint so we can print the running pid.
    const existing: pidfile.CheckResult = pidfile.check(pid_path) catch |err| blk: {
        std.debug.print("veil: warning — cannot read pidfile ({s}): {}\n", .{ pid_path, err });
        break :blk .{ .status = .absent, .pid = null };
    };

    const pid = std.os.linux.getpid();
    const pid_fd = pidfile.acquireAndWrite(pid_path, pid) catch |err| switch (err) {
        error.AlreadyRunning => {
            std.debug.print("veil: already running (pid {?d}) — refusing to start\n", .{existing.pid});
            std.process.exit(1);
        },
        else => return err,
    };
    defer pidfile.release(pid_fd);
    defer pidfile.remove(pid_path) catch {};

    std.debug.print("veil v{s} starting on {s} (pid {d})\n", .{ VERSION, loaded.value.listen, pid });

    if (loaded.value.hasEmptyAllowlist()) {
        std.debug.print("veil: WARNING — policy.allowed_tools is empty; every tool_call will be denied\n", .{});
    }

    if (upstreamIsUnverifiedTls(loaded.value)) {
        std.debug.print(
            \\veil: WARNING — upstream uses TLS without hostname or upstream_sni; certificate
            \\  verification is DISABLED. Set upstream_sni in config for MITM protection.
            \\
        , .{});
    }

    try proxy.run(allocator, loaded, cfg_path);
}

fn cmdValidate(allocator: std.mem.Allocator, args: []const []const u8) !void {
    const cfg_path = getConfigPath(args);

    const loaded = config.load(allocator, cfg_path) catch |err| {
        const msg = describeConfigError(err);
        std.debug.print("veil: config invalid ({s}): {s}\n  path: {s}\n", .{
            @errorName(err),
            msg,
            cfg_path,
        });
        std.process.exit(1);
    };
    defer loaded.deinit();

    const v = loaded.value;
    std.debug.print("veil: config OK\n", .{});
    std.debug.print("  path:              {s}\n", .{cfg_path});
    std.debug.print("  listen:            {s}\n", .{v.listen});
    std.debug.print("  upstream:          {s}\n", .{v.upstream});
    std.debug.print("  policy.mode:       {s}\n", .{v.policy.mode});
    std.debug.print("  allowed_tools:     {d} entries\n", .{v.policy.allowed_tools.len});
    std.debug.print("  blocked_paths:     {d} entries\n", .{v.policy.blocked_paths.len});
    std.debug.print("  blocked_patterns:  {d} entries\n", .{v.policy.blocked_patterns.len});
    std.debug.print("  rate_limit:        {d} rps / burst {d}\n", .{
        v.policy.rate_limit.requests_per_second,
        v.policy.rate_limit.burst,
    });
    std.debug.print("  audit.enabled:     {}\n", .{v.audit.enabled});
    if (v.audit.enabled) {
        std.debug.print("  audit.path:        {s}\n", .{v.audit.path});
    }

    if (v.hasEmptyAllowlist()) {
        std.debug.print(
            \\
            \\veil: WARNING — policy.allowed_tools is empty. Every tool_call
            \\  will be denied. Add tool names to allowed_tools in your config.
            \\
        , .{});
    }

    if (upstreamIsUnverifiedTls(v)) {
        std.debug.print(
            \\
            \\veil: WARNING — upstream uses TLS without hostname or upstream_sni;
            \\  certificate verification is DISABLED (MITM possible on the upstream
            \\  leg). Set upstream_sni in config for strict verification.
            \\
        , .{});
    }
}

fn describeConfigError(err: anyerror) []const u8 {
    return switch (err) {
        error.InvalidListen => "listen field is empty",
        error.InvalidUpstream => "upstream field is empty",
        error.InvalidRps => "policy.rate_limit.requests_per_second must be > 0",
        error.InvalidBurst => "policy.rate_limit.burst must be > 0",
        error.FileNotFound => "config file does not exist",
        error.AccessDenied => "config file unreadable (permissions?)",
        error.SyntaxError => "JSON syntax error (check braces, commas, quotes)",
        error.UnexpectedEndOfInput => "JSON ends before a value closes (missing brace or quote?)",
        error.UnexpectedToken => "JSON structure does not match expected schema (wrong type for a field?)",
        error.MissingField => "required field missing",
        error.UnknownField => "unrecognized field (typo? unknown_fields are ignored — this shouldn't fire)",
        error.InvalidCharacter => "invalid character in JSON",
        error.InvalidNumber => "invalid number literal",
        error.Overflow => "numeric value out of range",
        error.DuplicateField => "same field name appears twice in the same object",
        error.OutOfMemory => "allocator exhausted",
        else => "see error name above",
    };
}

fn cmdStatus(allocator: std.mem.Allocator) !void {
    const pid_path = try pidfile.defaultPath(allocator);
    defer allocator.free(pid_path);

    const r = pidfile.check(pid_path) catch |err| {
        std.debug.print("veil v{s} — status: error reading {s}: {}\n", .{ VERSION, pid_path, err });
        return;
    };

    switch (r.status) {
        .running => std.debug.print("veil v{s} — running (pid {?d})\n", .{ VERSION, r.pid }),
        .stale => std.debug.print("veil v{s} — stale pidfile at {s} (pid {?d} not alive)\n", .{ VERSION, pid_path, r.pid }),
        .absent => std.debug.print("veil v{s} — not running\n", .{VERSION}),
    }
}

fn getConfigPath(args: []const []const u8) []const u8 {
    var i: usize = 2;
    while (i + 1 < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--config")) {
            return args[i + 1];
        }
    }
    return "config.json";
}

fn printUsage() void {
    const usage =
        \\veil — MCP sidecar proxy
        \\
        \\Usage:
        \\  veil start    [--config <path>]   Start the proxy
        \\  veil validate [--config <path>]   Validate config file (exit 1 on error)
        \\  veil status                       Check proxy status
        \\  veil version                      Print version
        \\  veil help                         Show this message
        \\
        \\Signals (while running):
        \\  SIGHUP    reload config from disk (policy updates take effect on next connection)
        \\  SIGTERM   clean shutdown (removes pidfile + unix socket)
        \\  SIGINT    clean shutdown (same as SIGTERM)
        \\
    ;
    std.debug.print("{s}", .{usage});
}

test {
    _ = @import("config.zig");
    _ = @import("addr.zig");
    _ = @import("pidfile.zig");
    _ = @import("policy.zig");
    _ = @import("json.zig");
    _ = @import("limiter.zig");
    _ = @import("audit.zig");
    _ = @import("proxy.zig");
    _ = @import("frame.zig");
    _ = @import("pool.zig");
}
