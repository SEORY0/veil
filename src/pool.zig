//! Upstream connection pool with idle-timeout eviction.
//!
//! Single-threaded (shared by veil's accept loop only). No mutex needed —
//! all `take`/`put` calls happen sequentially in the accept loop.
//!
//! Entries are keyed by the upstream spec string's hash. Idle connections
//! past `idle_timeout_ns` are closed on the next `take`. Pool capacity is
//! bounded by `max_entries` — on overflow the oldest entry is evicted.

const std = @import("std");

pub const MAX_ENTRIES: usize = 16;
pub const IDLE_TIMEOUT_NS: i128 = 30 * std.time.ns_per_s;

pub const Pool = struct {
    entries: std.ArrayList(Entry) = .empty,
    allocator: std.mem.Allocator,

    const Entry = struct {
        spec_hash: u64,
        stream: std.net.Stream,
        last_used_ns: i128,
    };

    pub fn init(allocator: std.mem.Allocator) Pool {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *Pool) void {
        for (self.entries.items) |*e| e.stream.close();
        self.entries.deinit(self.allocator);
    }

    /// Return a cached stream for `spec`, or null if none is pooled / all
    /// pooled entries for this spec are stale. Caller gets exclusive
    /// ownership — closes or `put`s back.
    pub fn take(self: *Pool, spec: []const u8) ?std.net.Stream {
        const hash = std.hash.Wyhash.hash(0, spec);
        const now = std.time.nanoTimestamp();

        var i: usize = 0;
        while (i < self.entries.items.len) {
            const e = &self.entries.items[i];
            if (now - e.last_used_ns > IDLE_TIMEOUT_NS) {
                e.stream.close();
                _ = self.entries.swapRemove(i);
                continue;
            }
            if (e.spec_hash == hash) {
                const stream = e.stream;
                _ = self.entries.swapRemove(i);
                return stream;
            }
            i += 1;
        }
        return null;
    }

    /// Return a live stream to the pool for reuse. If the pool is full,
    /// the oldest entry is evicted. On allocation failure the stream is
    /// closed instead of pooled.
    pub fn put(self: *Pool, spec: []const u8, stream: std.net.Stream) void {
        if (self.entries.items.len >= MAX_ENTRIES) {
            var oldest_idx: usize = 0;
            var oldest_ts: i128 = std.math.maxInt(i128);
            for (self.entries.items, 0..) |e, idx| {
                if (e.last_used_ns < oldest_ts) {
                    oldest_ts = e.last_used_ns;
                    oldest_idx = idx;
                }
            }
            var evicted = self.entries.swapRemove(oldest_idx);
            evicted.stream.close();
        }

        const hash = std.hash.Wyhash.hash(0, spec);
        self.entries.append(self.allocator, .{
            .spec_hash = hash,
            .stream = stream,
            .last_used_ns = std.time.nanoTimestamp(),
        }) catch {
            stream.close();
        };
    }

    pub fn size(self: *const Pool) usize {
        return self.entries.items.len;
    }
};

// ── Tests ──────────────────────────────────────────────────

test "empty pool returns null" {
    var p = Pool.init(std.testing.allocator);
    defer p.deinit();
    try std.testing.expect(p.take("host:9000") == null);
}

test "put then take same spec" {
    var p = Pool.init(std.testing.allocator);
    defer p.deinit();

    const fds = try std.posix.pipe();
    defer std.posix.close(fds[1]); // write end stays open

    const stream: std.net.Stream = .{ .handle = fds[0] };
    p.put("host:9000", stream);
    try std.testing.expectEqual(@as(usize, 1), p.size());

    const reused = p.take("host:9000");
    try std.testing.expect(reused != null);
    try std.testing.expectEqual(fds[0], reused.?.handle);
    try std.testing.expectEqual(@as(usize, 0), p.size());

    reused.?.close();
}

test "take mismatched spec returns null" {
    var p = Pool.init(std.testing.allocator);
    defer p.deinit();

    const fds = try std.posix.pipe();
    defer std.posix.close(fds[1]);

    p.put("host:9000", .{ .handle = fds[0] });
    try std.testing.expect(p.take("other:3000") == null);
    try std.testing.expectEqual(@as(usize, 1), p.size());

    // Cleanup the still-pooled fd
    var taken = p.take("host:9000");
    if (taken) |*s| s.close();
}

test "pool evicts oldest when full" {
    var p = Pool.init(std.testing.allocator);
    defer p.deinit();

    // Fill to capacity with MAX_ENTRIES different specs.
    var i: usize = 0;
    while (i < MAX_ENTRIES) : (i += 1) {
        const fds = try std.posix.pipe();
        std.posix.close(fds[1]);
        var buf: [32]u8 = undefined;
        const spec = try std.fmt.bufPrint(&buf, "host:{d}", .{i});
        p.put(spec, .{ .handle = fds[0] });
    }
    try std.testing.expectEqual(MAX_ENTRIES, p.size());

    // Adding one more forces eviction.
    const extra_fds = try std.posix.pipe();
    std.posix.close(extra_fds[1]);
    p.put("host:extra", .{ .handle = extra_fds[0] });
    try std.testing.expectEqual(MAX_ENTRIES, p.size());
}
