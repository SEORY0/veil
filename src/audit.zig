const std = @import("std");
const policy = @import("policy.zig");

pub const LogEntry = struct {
    timestamp: i64,
    tool_name: []const u8,
    verdict: policy.Verdict,
    reason: []const u8,
    client_addr: []const u8,
};

/// Fixed-size ring buffer for audit log entries.
/// Entries are formatted and written to a file descriptor.
pub const AuditLogger = struct {
    fd: ?std.fs.File,
    enabled: bool,

    pub fn init(enabled: bool, path: []const u8) AuditLogger {
        if (!enabled) return .{ .fd = null, .enabled = false };

        const file = std.fs.cwd().createFile(path, .{ .truncate = false }) catch |err| {
            std.debug.print("veil: audit log open failed ({s}): {}\n", .{ path, err });
            return .{ .fd = null, .enabled = false };
        };

        // Seek to end for append
        file.seekFromEnd(0) catch {};

        return .{ .fd = file, .enabled = true };
    }

    pub fn log(self: *AuditLogger, entry: LogEntry) void {
        if (!self.enabled) return;
        const fd = self.fd orelse return;

        // Format: timestamp|verdict|tool|reason|client
        var buf: [512]u8 = undefined;
        const line = std.fmt.bufPrint(&buf, "{d}|{s}|{s}|{s}|{s}\n", .{
            entry.timestamp,
            @tagName(entry.verdict),
            entry.tool_name,
            entry.reason,
            entry.client_addr,
        }) catch return;

        _ = fd.write(line) catch {};
    }

    pub fn deinit(self: *AuditLogger) void {
        if (self.fd) |fd| fd.close();
    }
};

// ── Tests ──────────────────────────────────────────────────

test "disabled logger does not crash" {
    var logger = AuditLogger.init(false, "");
    defer logger.deinit();

    logger.log(.{
        .timestamp = 1234567890,
        .tool_name = "file_read",
        .verdict = .allow,
        .reason = "passed",
        .client_addr = "127.0.0.1",
    });
}

test "logger init with bad path stays disabled" {
    var logger = AuditLogger.init(true, "/nonexistent/deep/path/audit.log");
    defer logger.deinit();
    try std.testing.expect(!logger.enabled or logger.fd == null);
}
