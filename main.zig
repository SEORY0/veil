const std = @import("std");
const config = @import("config.zig");
const proxy = @import("proxy.zig");
const policy = @import("policy.zig");
const audit = @import("audit.zig");
const limiter = @import("limiter.zig");

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
        const cfg_path = getConfigPath(args);
        const cfg = try config.load(allocator, cfg_path);
        defer cfg.deinit(allocator);

        std.debug.print("veil v{s} starting on {s}\n", .{ VERSION, cfg.listen });

        try proxy.run(allocator, cfg);
    } else if (std.mem.eql(u8, command, "status")) {
        std.debug.print("veil v{s} — status: not running\n", .{VERSION});
    } else if (std.mem.eql(u8, command, "version")) {
        std.debug.print("veil v{s}\n", .{VERSION});
    } else if (std.mem.eql(u8, command, "help")) {
        printUsage();
    } else {
        std.debug.print("unknown command: {s}\n", .{command});
        printUsage();
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
        \\  veil start [--config <path>]   Start the proxy
        \\  veil status                    Check proxy status
        \\  veil version                   Print version
        \\  veil help                      Show this message
        \\
    ;
    std.debug.print("{s}", .{usage});
}

test {
    // Import all modules for testing
    _ = @import("config.zig");
    _ = @import("policy.zig");
    _ = @import("json.zig");
    _ = @import("limiter.zig");
    _ = @import("audit.zig");
    _ = @import("proxy.zig");
}
