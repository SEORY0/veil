const std = @import("std");

pub const RateLimit = struct {
    requests_per_second: u32 = 100,
    burst: u32 = 20,
};

pub const Policy = struct {
    mode: []const u8 = "allowlist",
    allowed_tools: []const []const u8 = &.{},
    blocked_paths: []const []const u8 = &.{},
    blocked_patterns: []const []const u8 = &.{},
    rate_limit: RateLimit = .{},
};

pub const Audit = struct {
    enabled: bool = false,
    path: []const u8 = "./veil-audit.log",
    max_size_mb: u32 = 10,
};

pub const Config = struct {
    listen: []const u8 = "127.0.0.1:9000",
    upstream: []const u8 = "127.0.0.1:3000",
    /// Override SNI/hostname for upstream TLS cert verification. Use with
    /// `tls://IP:port` to still get strict verification against the supplied
    /// hostname. Null → SNI taken from `tls://hostname:port`, or none.
    upstream_sni: ?[]const u8 = null,
    /// Path to a PEM bundle to use for upstream TLS CA verification, in
    /// addition to the system bundle. Null → system bundle only.
    upstream_ca_path: ?[]const u8 = null,
    /// Reject TLS connections that close without sending `close_notify`.
    /// Protects against truncation attacks but breaks compat with servers
    /// that close abruptly (Python ssl, many raw TLS servers). Default
    /// permissive for compat.
    upstream_tls_strict: bool = false,
    policy: Policy = .{},
    audit: Audit = .{},

    /// Built-in safe defaults. Equivalent to parsing `{}`. Fields that are
    /// omitted in JSON take these values (zig struct field defaults handle
    /// the omitted-field case automatically).
    ///
    /// Note: `policy.allowed_tools` is empty by default — this is intentional
    /// "deny everything" fail-safe. Callers should set it explicitly.
    pub fn defaults() Config {
        return .{};
    }

    /// True when the policy has no allowed tools. In this state every
    /// `tools/call` is denied and only pass-through traffic (non-tool-call)
    /// reaches upstream. Callers should warn users who hit this.
    pub fn hasEmptyAllowlist(self: Config) bool {
        return self.policy.allowed_tools.len == 0;
    }
};

pub const Loaded = struct {
    value: Config,
    arena: *std.heap.ArenaAllocator,
    parent_allocator: std.mem.Allocator,

    pub fn deinit(self: Loaded) void {
        self.arena.deinit();
        self.parent_allocator.destroy(self.arena);
    }
};

pub const LoadError = error{
    InvalidListen,
    InvalidUpstream,
    InvalidRps,
    InvalidBurst,
};

const MAX_CONFIG_BYTES: usize = 1 * 1024 * 1024;

pub fn load(allocator: std.mem.Allocator, path: []const u8) !Loaded {
    var file = try std.fs.cwd().openFile(path, .{});
    defer file.close();

    const data = try file.readToEndAlloc(allocator, MAX_CONFIG_BYTES);
    defer allocator.free(data);

    return loadFromSlice(allocator, data);
}

pub fn loadFromSlice(allocator: std.mem.Allocator, data: []const u8) !Loaded {
    const arena = try allocator.create(std.heap.ArenaAllocator);
    errdefer allocator.destroy(arena);
    arena.* = std.heap.ArenaAllocator.init(allocator);
    errdefer arena.deinit();

    const cfg = try std.json.parseFromSliceLeaky(
        Config,
        arena.allocator(),
        data,
        .{ .ignore_unknown_fields = true, .allocate = .alloc_always },
    );

    try validate(&cfg);

    return .{
        .value = cfg,
        .arena = arena,
        .parent_allocator = allocator,
    };
}

pub fn validate(cfg: *const Config) LoadError!void {
    if (cfg.listen.len == 0) return error.InvalidListen;
    if (cfg.upstream.len == 0) return error.InvalidUpstream;
    if (cfg.policy.rate_limit.requests_per_second == 0) return error.InvalidRps;
    if (cfg.policy.rate_limit.burst == 0) return error.InvalidBurst;
}

// ── Tests ──────────────────────────────────────────────────

test "loadFromSlice parses full config" {
    const src =
        \\{
        \\  "listen": "127.0.0.1:9000",
        \\  "upstream": "127.0.0.1:3000",
        \\  "policy": {
        \\    "mode": "allowlist",
        \\    "allowed_tools": ["file_read", "shell_exec"],
        \\    "blocked_paths": ["/etc/", "/root/"],
        \\    "blocked_patterns": ["password"],
        \\    "rate_limit": { "requests_per_second": 200, "burst": 50 }
        \\  },
        \\  "audit": { "enabled": true, "path": "/tmp/a.log", "max_size_mb": 5 }
        \\}
    ;
    const loaded = try loadFromSlice(std.testing.allocator, src);
    defer loaded.deinit();
    const cfg = loaded.value;

    try std.testing.expectEqualStrings("127.0.0.1:9000", cfg.listen);
    try std.testing.expectEqualStrings("127.0.0.1:3000", cfg.upstream);
    try std.testing.expectEqual(@as(usize, 2), cfg.policy.allowed_tools.len);
    try std.testing.expectEqualStrings("file_read", cfg.policy.allowed_tools[0]);
    try std.testing.expectEqual(@as(u32, 200), cfg.policy.rate_limit.requests_per_second);
    try std.testing.expectEqual(@as(u32, 50), cfg.policy.rate_limit.burst);
    try std.testing.expect(cfg.audit.enabled);
    try std.testing.expectEqualStrings("/tmp/a.log", cfg.audit.path);
}

test "loadFromSlice applies defaults for missing fields" {
    const src = "{\"listen\":\"127.0.0.1:9000\",\"upstream\":\"127.0.0.1:3000\"}";
    const loaded = try loadFromSlice(std.testing.allocator, src);
    defer loaded.deinit();
    const cfg = loaded.value;

    try std.testing.expectEqual(@as(u32, 100), cfg.policy.rate_limit.requests_per_second);
    try std.testing.expectEqual(@as(u32, 20), cfg.policy.rate_limit.burst);
    try std.testing.expect(!cfg.audit.enabled);
    try std.testing.expectEqual(@as(usize, 0), cfg.policy.allowed_tools.len);
}

test "loadFromSlice ignores unknown fields" {
    const src =
        \\{"listen":"127.0.0.1:9000","upstream":"127.0.0.1:3000","experimental":{"x":1}}
    ;
    const loaded = try loadFromSlice(std.testing.allocator, src);
    defer loaded.deinit();
    try std.testing.expectEqualStrings("127.0.0.1:9000", loaded.value.listen);
}

test "validate rejects empty listen" {
    const src = "{\"listen\":\"\",\"upstream\":\"127.0.0.1:3000\"}";
    try std.testing.expectError(error.InvalidListen, loadFromSlice(std.testing.allocator, src));
}

test "validate rejects zero burst" {
    const src =
        \\{"listen":"127.0.0.1:9000","upstream":"127.0.0.1:3000","policy":{"rate_limit":{"requests_per_second":100,"burst":0}}}
    ;
    try std.testing.expectError(error.InvalidBurst, loadFromSlice(std.testing.allocator, src));
}

test "Config.defaults() matches empty {} parse" {
    const loaded = try loadFromSlice(std.testing.allocator, "{}");
    defer loaded.deinit();

    const d = Config.defaults();
    try std.testing.expectEqualStrings(d.listen, loaded.value.listen);
    try std.testing.expectEqualStrings(d.upstream, loaded.value.upstream);
    try std.testing.expectEqual(d.policy.rate_limit.requests_per_second, loaded.value.policy.rate_limit.requests_per_second);
    try std.testing.expectEqual(d.policy.rate_limit.burst, loaded.value.policy.rate_limit.burst);
    try std.testing.expectEqual(d.audit.enabled, loaded.value.audit.enabled);
}

test "empty {} JSON boots with safe defaults and empty allowlist flag" {
    const loaded = try loadFromSlice(std.testing.allocator, "{}");
    defer loaded.deinit();

    // Safe defaults — validation passes, every field populated.
    try std.testing.expectEqualStrings("127.0.0.1:9000", loaded.value.listen);
    try std.testing.expectEqualStrings("127.0.0.1:3000", loaded.value.upstream);
    try std.testing.expectEqual(@as(u32, 100), loaded.value.policy.rate_limit.requests_per_second);
    try std.testing.expectEqual(@as(u32, 20), loaded.value.policy.rate_limit.burst);

    // Deny-by-default: empty allowlist is detectable so callers can warn.
    try std.testing.expect(loaded.value.hasEmptyAllowlist());
}

test "hasEmptyAllowlist returns false when tools listed" {
    const loaded = try loadFromSlice(std.testing.allocator,
        \\{"policy":{"allowed_tools":["file_read"]}}
    );
    defer loaded.deinit();
    try std.testing.expect(!loaded.value.hasEmptyAllowlist());
}
