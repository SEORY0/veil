const std = @import("std");

/// Extracted fields from an MCP tool_call JSON request.
/// All slices point into the original input buffer (zero-copy).
pub const ToolCall = struct {
    method: []const u8,
    tool_name: []const u8,
    arguments_raw: []const u8, // raw JSON string of arguments
};

pub const ParseError = error{
    InvalidJson,
    MissingMethod,
    MissingToolName,
    BufferTooSmall,
};

/// Extract tool_name and arguments from an MCP JSON-RPC request.
/// Zero-allocation: all returned slices point into `input`.
///
/// Expected format (MCP tool call):
/// {
///   "jsonrpc": "2.0",
///   "method": "tools/call",
///   "params": {
///     "name": "file_read",
///     "arguments": { "path": "/home/user/file.txt" }
///   }
/// }
pub fn extractToolCall(input: []const u8) ParseError!ToolCall {
    const method = extractStringValue(input, "\"method\"") orelse
        return ParseError.MissingMethod;

    const tool_name = extractStringValue(input, "\"name\"") orelse
        return ParseError.MissingToolName;

    // Extract raw arguments object
    const args_raw = extractObjectValue(input, "\"arguments\"") orelse "{}";

    return .{
        .method = method,
        .tool_name = tool_name,
        .arguments_raw = args_raw,
    };
}

/// Find a JSON string value for a given key.
/// Returns a slice into the original input.
fn extractStringValue(input: []const u8, key: []const u8) ?[]const u8 {
    const key_pos = std.mem.indexOf(u8, input, key) orelse return null;
    const after_key = key_pos + key.len;

    // Skip whitespace and colon
    var i = after_key;
    while (i < input.len and (input[i] == ' ' or input[i] == ':' or input[i] == '\t' or input[i] == '\n' or input[i] == '\r')) : (i += 1) {}

    if (i >= input.len or input[i] != '"') return null;
    i += 1; // skip opening quote

    const start = i;
    while (i < input.len and input[i] != '"') : (i += 1) {
        if (input[i] == '\\') i += 1; // skip escaped chars
    }

    if (i >= input.len) return null;
    return input[start..i];
}

/// Find a JSON object value for a given key.
/// Returns the raw object string including braces.
fn extractObjectValue(input: []const u8, key: []const u8) ?[]const u8 {
    const key_pos = std.mem.indexOf(u8, input, key) orelse return null;
    const after_key = key_pos + key.len;

    // Skip whitespace and colon
    var i = after_key;
    while (i < input.len and (input[i] == ' ' or input[i] == ':' or input[i] == '\t' or input[i] == '\n' or input[i] == '\r')) : (i += 1) {}

    if (i >= input.len or input[i] != '{') return null;

    const start = i;
    var depth: usize = 0;
    var in_string = false;

    while (i < input.len) : (i += 1) {
        if (input[i] == '\\' and in_string) {
            i += 1;
            continue;
        }
        if (input[i] == '"') {
            in_string = !in_string;
            continue;
        }
        if (!in_string) {
            if (input[i] == '{') depth += 1;
            if (input[i] == '}') {
                depth -= 1;
                if (depth == 0) return input[start .. i + 1];
            }
        }
    }

    return null;
}

// ── Tests ──────────────────────────────────────────────────

test "parse valid tool call" {
    const input =
        \\{"jsonrpc":"2.0","method":"tools/call","params":{"name":"file_read","arguments":{"path":"/home/user/main.py"}}}
    ;

    const tc = try extractToolCall(input);
    try std.testing.expectEqualStrings("tools/call", tc.method);
    try std.testing.expectEqualStrings("file_read", tc.tool_name);
    try std.testing.expect(std.mem.indexOf(u8, tc.arguments_raw, "/home/user/main.py") != null);
}

test "missing method returns error" {
    const input =
        \\{"params":{"name":"file_read"}}
    ;
    try std.testing.expectError(ParseError.MissingMethod, extractToolCall(input));
}

test "missing tool name returns error" {
    const input =
        \\{"method":"tools/call","params":{}}
    ;
    try std.testing.expectError(ParseError.MissingToolName, extractToolCall(input));
}

test "extract string value" {
    const input =
        \\{"method": "tools/call", "id": 1}
    ;
    const val = extractStringValue(input, "\"method\"");
    try std.testing.expect(val != null);
    try std.testing.expectEqualStrings("tools/call", val.?);
}

test "extract nested object" {
    const input =
        \\{"arguments": {"path": "/etc/passwd", "mode": "r"}}
    ;
    const val = extractObjectValue(input, "\"arguments\"");
    try std.testing.expect(val != null);
    try std.testing.expect(std.mem.indexOf(u8, val.?, "/etc/passwd") != null);
}

// ── Fuzz tests ────────────────────────────────────────────
//
// Run with: `zig build test --fuzz`
// Without --fuzz these only exercise the corpus (regression anchors).
//
// Guarantee being checked: the parser must not crash, hang, or read
// out of bounds on *any* input. Valid parse results are unchecked —
// we only verify memory-safety and termination.

const fuzz_corpus = [_][]const u8{
    // well-formed
    "{\"method\":\"tools/call\",\"params\":{\"name\":\"x\",\"arguments\":{}}}",
    "{\"method\":\"tools/list\"}",
    // truncated / malformed
    "",
    "{",
    "}",
    "\"",
    "{\"method\":\"",
    "{\"method\":\"x",
    "{\"method\":\"x\\",
    "{\"method\":\"\\\\\\",
    // unmatched braces
    "{{{{{{{",
    "}}}}}}}",
    "{\"a\":{\"b\":{\"c\":{\"d\":{}}}}}",
    // strings with embedded braces
    "{\"name\":\"}}}\",\"method\":\"\"}",
    "{\"name\":\"{{{\",\"method\":\"\"}",
    // escape edge cases
    "{\"name\":\"\\\"\",\"method\":\"\"}",
    "{\"name\":\"a\\\\\\\"b\",\"method\":\"\"}",
    // key substring confusion
    "{\"methodx\":\"not-method\"}",
    "{\"xmethod\":\"not-method\"}",
    // non-JSON bytes
    "\x00\x01\x02\x03",
    "not json at all",
};

fn fuzzExtractToolCall(_: void, input: []const u8) anyerror!void {
    _ = extractToolCall(input) catch {};
    _ = extractStringValue(input, "\"method\"");
    _ = extractStringValue(input, "\"name\"");
    _ = extractObjectValue(input, "\"arguments\"");
}

test "fuzz: json parsers never crash on corpus" {
    try std.testing.fuzz({}, fuzzExtractToolCall, .{ .corpus = &fuzz_corpus });
}

// Deterministic randomized property test. Complements the fixed corpus:
// generates 10,000 random byte strings of varying lengths and feeds them
// to every parser entry point. Any panic, OOB, or infinite loop fails the
// test. Seeded — identical run every time so failures are reproducible.
test "fuzz: json parsers survive 10k random inputs" {
    var prng = std.Random.DefaultPrng.init(0xdeadbeef_cafe_f00d);
    const r = prng.random();

    var buf: [256]u8 = undefined;
    var i: usize = 0;
    while (i < 10_000) : (i += 1) {
        const len = r.intRangeAtMost(usize, 0, buf.len);
        r.bytes(buf[0..len]);
        try fuzzExtractToolCall({}, buf[0..len]);
    }
}

// Seeds randomness around structural landmarks (brace, quote, colon,
// backslash, key strings) rather than uniformly — denser exploration of
// the parse state transitions that matter.
test "fuzz: json parsers survive 5k structured-random inputs" {
    var prng = std.Random.DefaultPrng.init(0x12345678);
    const r = prng.random();

    const alphabet = "{}\"\\:,abc\"method\"\"name\"\"arguments\"\"params\"";
    var buf: [512]u8 = undefined;
    var i: usize = 0;
    while (i < 5_000) : (i += 1) {
        const len = r.intRangeAtMost(usize, 0, buf.len);
        for (buf[0..len]) |*b| {
            b.* = alphabet[r.intRangeLessThan(usize, 0, alphabet.len)];
        }
        try fuzzExtractToolCall({}, buf[0..len]);
    }
}
