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
