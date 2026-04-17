const std = @import("std");
const config = @import("config.zig");
const json = @import("json.zig");
const policy = @import("policy.zig");
const audit = @import("audit.zig");
const limiter = @import("limiter.zig");

pub fn run(allocator: std.mem.Allocator, cfg: config.Config) !void {
    _ = allocator;

    // Initialize subsystems
    var rate_limiter = limiter.RateLimiter.init(
        cfg.policy.rate_limit.requests_per_second,
        cfg.policy.rate_limit.burst,
    );

    var logger = audit.AuditLogger.init(cfg.audit.enabled, cfg.audit.path);
    defer logger.deinit();

    // Parse listen address
    const addr = try parseAddress(cfg.listen);

    // Create TCP listener
    const server = try std.posix.socket(std.posix.AF.INET, std.posix.SOCK.STREAM, 0);
    defer std.posix.close(server);

    // Set SO_REUSEADDR
    try std.posix.setsockopt(server, std.posix.SOL.SOCKET, std.posix.SO.REUSEADDR, &std.mem.toBytes(@as(c_int, 1)));

    try std.posix.bind(server, &addr, @sizeOf(std.posix.sockaddr.in));
    try std.posix.listen(server, 128);

    std.debug.print("veil: listening on {s}\n", .{cfg.listen});

    // Accept loop
    while (true) {
        var client_addr: std.posix.sockaddr = undefined;
        var client_addr_len: std.posix.socklen_t = @sizeOf(std.posix.sockaddr);

        const client = std.posix.accept(server, &client_addr, &client_addr_len, 0) catch |err| {
            std.debug.print("veil: accept error: {}\n", .{err});
            continue;
        };
        defer std.posix.close(client);

        handleConnection(client, cfg, &rate_limiter, &logger) catch |err| {
            std.debug.print("veil: connection error: {}\n", .{err});
        };
    }
}

fn handleConnection(
    client: std.posix.socket_t,
    cfg: config.Config,
    rate_limiter: *limiter.RateLimiter,
    logger: *audit.AuditLogger,
) !void {
    var buf: [8192]u8 = undefined;
    const n = try std.posix.read(client, &buf);
    if (n == 0) return;

    const request = buf[0..n];

    // Rate limit check
    if (!rate_limiter.tryConsume()) {
        const deny_msg = "{\"error\":\"rate_limited\",\"message\":\"too many requests\"}";
        _ = try std.posix.write(client, deny_msg);

        logger.log(.{
            .timestamp = std.time.timestamp(),
            .tool_name = "unknown",
            .verdict = .deny_rate,
            .reason = "rate limit exceeded",
            .client_addr = "client",
        });
        return;
    }

    // Parse tool call
    const tool_call = json.extractToolCall(request) catch {
        // Not a tool call, forward as-is
        // TODO: connect to upstream and forward
        _ = try std.posix.write(client, request);
        return;
    };

    // Evaluate policy
    const result = policy.evaluate(
        tool_call.tool_name,
        tool_call.arguments_raw,
        cfg.policy.allowed_tools,
        cfg.policy.blocked_paths,
        cfg.policy.blocked_patterns,
    );

    // Log the decision
    logger.log(.{
        .timestamp = std.time.timestamp(),
        .tool_name = tool_call.tool_name,
        .verdict = result.verdict,
        .reason = result.reason,
        .client_addr = "client",
    });

    if (result.verdict == .allow) {
        // TODO: forward to upstream MCP server
        _ = try std.posix.write(client, request);
    } else {
        var deny_buf: [256]u8 = undefined;
        const deny_msg = std.fmt.bufPrint(&deny_buf, "{{\"error\":\"denied\",\"verdict\":\"{s}\",\"reason\":\"{s}\"}}", .{
            @tagName(result.verdict),
            result.reason,
        }) catch return;
        _ = try std.posix.write(client, deny_msg);
    }
}

fn parseAddress(addr_str: []const u8) !std.posix.sockaddr.in {
    // Parse "host:port" format
    const colon_pos = std.mem.lastIndexOf(u8, addr_str, ":") orelse return error.InvalidAddress;
    const port_str = addr_str[colon_pos + 1 ..];
    const port = std.fmt.parseInt(u16, port_str, 10) catch return error.InvalidAddress;

    return std.posix.sockaddr.in{
        .family = std.posix.AF.INET,
        .port = std.mem.nativeToBig(u16, port),
        .addr = 0, // INADDR_ANY for now
    };
}

test "parse address" {
    const addr = try parseAddress("127.0.0.1:9000");
    try std.testing.expect(std.mem.bigToNative(u16, addr.port) == 9000);
}
