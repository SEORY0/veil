const std = @import("std");

pub const ParseError = error{
    InvalidAddress,
    EmptyUnixPath,
    UnixPathTooLong,
};

pub const Scheme = enum { tcp, tls, unix };

pub const Parsed = struct {
    scheme: Scheme,
    /// Set when the spec parsed to a numeric IP or was a Unix socket.
    /// Null when only a hostname was supplied — caller must DNS-resolve.
    address: ?std.net.Address = null,
    /// Set when the spec used a hostname (non-numeric host).
    /// Slice points into the original input buffer.
    host: ?[]const u8 = null,
    /// Present for tcp/tls (mirrors address port when address is set).
    port: u16 = 0,
    /// Present for unix. Slice points into the original input buffer.
    unix_path: ?[]const u8 = null,

    pub fn isUnix(self: Parsed) bool {
        return self.scheme == .unix;
    }

    pub fn isTls(self: Parsed) bool {
        return self.scheme == .tls;
    }
};

/// Parse a listen/upstream spec.
/// Accepted forms:
///   "tcp://127.0.0.1:9000"
///   "tls://mcp.example.com:443"
///   "tls://10.0.0.5:8443"
///   "127.0.0.1:9000"                (legacy; implicit TCP)
///   "unix:/tmp/veil.sock"
pub fn parse(spec: []const u8) ParseError!Parsed {
    if (std.mem.startsWith(u8, spec, "unix:")) {
        const path = spec["unix:".len..];
        if (path.len == 0) return error.EmptyUnixPath;
        const addr = std.net.Address.initUnix(path) catch return error.UnixPathTooLong;
        return .{ .scheme = .unix, .address = addr, .unix_path = path };
    }

    var scheme: Scheme = .tcp;
    var rest = spec;
    if (std.mem.startsWith(u8, spec, "tls://")) {
        scheme = .tls;
        rest = spec["tls://".len..];
    } else if (std.mem.startsWith(u8, spec, "tcp://")) {
        rest = spec["tcp://".len..];
    }

    // Fast path: numeric IP + port (e.g. 127.0.0.1:9000, [::1]:443)
    if (std.net.Address.parseIpAndPort(rest)) |addr| {
        return .{
            .scheme = scheme,
            .address = addr,
            .port = addr.getPort(),
        };
    } else |_| {}

    // Fallback: hostname:port — deferred DNS resolution.
    const colon = std.mem.lastIndexOfScalar(u8, rest, ':') orelse return error.InvalidAddress;
    const host = rest[0..colon];
    const port_str = rest[colon + 1 ..];
    if (host.len == 0 or port_str.len == 0) return error.InvalidAddress;
    const port = std.fmt.parseInt(u16, port_str, 10) catch return error.InvalidAddress;
    return .{
        .scheme = scheme,
        .host = host,
        .port = port,
    };
}

// ── Tests ──────────────────────────────────────────────────

test "parse bare host:port as TCP" {
    const p = try parse("127.0.0.1:9000");
    try std.testing.expect(!p.isUnix());
    try std.testing.expect(!p.isTls());
    try std.testing.expectEqual(@as(u16, 9000), p.address.?.getPort());
}

test "parse tcp:// scheme" {
    const p = try parse("tcp://10.0.0.1:3000");
    try std.testing.expectEqual(Scheme.tcp, p.scheme);
    try std.testing.expectEqual(@as(u16, 3000), p.address.?.getPort());
}

test "parse unix path" {
    const p = try parse("unix:/tmp/veil.sock");
    try std.testing.expect(p.isUnix());
    try std.testing.expectEqualStrings("/tmp/veil.sock", p.unix_path.?);
    try std.testing.expectEqual(std.posix.AF.UNIX, p.address.?.any.family);
}

test "parse tls:// with hostname" {
    const p = try parse("tls://mcp.example.com:443");
    try std.testing.expect(p.isTls());
    try std.testing.expect(p.address == null);
    try std.testing.expectEqualStrings("mcp.example.com", p.host.?);
    try std.testing.expectEqual(@as(u16, 443), p.port);
}

test "parse tls:// with IP" {
    const p = try parse("tls://10.0.0.5:8443");
    try std.testing.expect(p.isTls());
    try std.testing.expect(p.address != null);
    try std.testing.expect(p.host == null);
    try std.testing.expectEqual(@as(u16, 8443), p.address.?.getPort());
}

test "parse invalid tcp" {
    try std.testing.expectError(error.InvalidAddress, parse("garbage-no-port"));
}

test "parse empty unix path" {
    try std.testing.expectError(error.EmptyUnixPath, parse("unix:"));
}

// ── Fuzz ──────────────────────────────────────────────────
//
// Run with: `zig build test --fuzz`

const fuzz_corpus = [_][]const u8{
    "",
    ":",
    "127.0.0.1:9000",
    "tcp://127.0.0.1:9000",
    "tls://example.com:443",
    "unix:/tmp/a",
    "unix:",
    "tls://",
    "tcp://",
    "tls://:",
    ":::",
    "x:y:z",
    "host:99999999", // port overflow
    "host:-1",
    "host:",
    ":9000",
    "a:a",
    "\x00\x00:\x00",
};

fn fuzzParse(_: void, input: []const u8) anyerror!void {
    _ = parse(input) catch {};
}

test "fuzz: addr.parse never crashes on corpus" {
    try std.testing.fuzz({}, fuzzParse, .{ .corpus = &fuzz_corpus });
}

test "fuzz: addr.parse survives 10k random inputs" {
    var prng = std.Random.DefaultPrng.init(0xf00dbabe);
    const r = prng.random();

    var buf: [128]u8 = undefined;
    var i: usize = 0;
    while (i < 10_000) : (i += 1) {
        const len = r.intRangeAtMost(usize, 0, buf.len);
        r.bytes(buf[0..len]);
        try fuzzParse({}, buf[0..len]);
    }
}

test "fuzz: addr.parse survives 5k scheme-seeded inputs" {
    var prng = std.Random.DefaultPrng.init(0x13371337);
    const r = prng.random();

    const schemes = [_][]const u8{ "tcp://", "tls://", "unix:", "", "https://", "tcp:", "unix:/" };
    const alphabet = "0123456789abcdef.:/[]-_";
    var buf: [256]u8 = undefined;
    var i: usize = 0;
    while (i < 5_000) : (i += 1) {
        const scheme = schemes[r.intRangeLessThan(usize, 0, schemes.len)];
        const tail_len = r.intRangeAtMost(usize, 0, buf.len - scheme.len);
        @memcpy(buf[0..scheme.len], scheme);
        for (buf[scheme.len .. scheme.len + tail_len]) |*b| {
            b.* = alphabet[r.intRangeLessThan(usize, 0, alphabet.len)];
        }
        try fuzzParse({}, buf[0 .. scheme.len + tail_len]);
    }
}
