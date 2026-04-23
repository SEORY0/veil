const std = @import("std");

/// Token bucket rate limiter.
/// Fixed-size, zero-allocation after init.
pub const RateLimiter = struct {
    tokens: f64,
    max_tokens: f64,
    refill_rate: f64, // tokens per nanosecond
    last_refill: i128,

    pub fn init(requests_per_second: u32, burst: u32) RateLimiter {
        const rps_f: f64 = @floatFromInt(requests_per_second);
        return .{
            .tokens = @floatFromInt(burst),
            .max_tokens = @floatFromInt(burst),
            .refill_rate = rps_f / 1_000_000_000.0,
            .last_refill = std.time.nanoTimestamp(),
        };
    }

    /// Try to consume one token. Returns true if allowed.
    pub fn tryConsume(self: *RateLimiter) bool {
        self.refill();

        if (self.tokens >= 1.0) {
            self.tokens -= 1.0;
            return true;
        }
        return false;
    }

    fn refill(self: *RateLimiter) void {
        const now = std.time.nanoTimestamp();
        const elapsed = now - self.last_refill;
        if (elapsed <= 0) return;

        const elapsed_f: f64 = @floatFromInt(elapsed);
        const new_tokens = elapsed_f * self.refill_rate;
        self.tokens = @min(self.tokens + new_tokens, self.max_tokens);
        self.last_refill = now;
    }
};

// ── Tests ──────────────────────────────────────────────────

test "rate limiter allows burst" {
    var rl = RateLimiter.init(100, 5);

    // Should allow burst of 5
    var allowed: u32 = 0;
    for (0..5) |_| {
        if (rl.tryConsume()) allowed += 1;
    }
    try std.testing.expect(allowed == 5);

    // 6th should be denied (no time to refill)
    try std.testing.expect(!rl.tryConsume());
}

test "rate limiter refills over time" {
    var rl = RateLimiter.init(1000, 1);

    // Consume the one token
    try std.testing.expect(rl.tryConsume());
    try std.testing.expect(!rl.tryConsume());

    // Wait a bit for refill
    std.Thread.sleep(2_000_000); // 2ms = should refill ~2 tokens at 1000/s
    try std.testing.expect(rl.tryConsume());
}

test "rate limiter init values" {
    const rl = RateLimiter.init(100, 20);
    try std.testing.expect(rl.max_tokens == 20.0);
    try std.testing.expect(rl.tokens == 20.0);
}
