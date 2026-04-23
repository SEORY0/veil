const std = @import("std");

pub const Verdict = enum {
    allow,
    deny_tool,
    deny_path,
    deny_pattern,
    deny_rate,
};

pub const PolicyResult = struct {
    verdict: Verdict,
    reason: []const u8,
};

/// Check if a tool call is allowed by policy.
/// This is the security-critical hotpath.
pub fn evaluate(
    tool_name: []const u8,
    arguments: []const u8,
    allowed_tools: []const []const u8,
    blocked_paths: []const []const u8,
    blocked_patterns: []const []const u8,
) PolicyResult {
    // Phase 1: Tool allowlist check
    if (!isToolAllowed(tool_name, allowed_tools)) {
        return .{
            .verdict = .deny_tool,
            .reason = "tool not in allowlist",
        };
    }

    // Phase 2: Path traversal check
    if (containsBlockedPath(arguments, blocked_paths)) {
        return .{
            .verdict = .deny_path,
            .reason = "blocked path detected",
        };
    }

    // Phase 3: Sensitive pattern check
    if (containsBlockedPattern(arguments, blocked_patterns)) {
        return .{
            .verdict = .deny_pattern,
            .reason = "sensitive pattern detected",
        };
    }

    return .{
        .verdict = .allow,
        .reason = "passed all checks",
    };
}

/// Check if tool name is in the allowlist.
/// Empty allowlist = deny all.
fn isToolAllowed(tool_name: []const u8, allowed: []const []const u8) bool {
    if (allowed.len == 0) return false;

    for (allowed) |name| {
        if (std.mem.eql(u8, tool_name, name)) return true;
    }
    return false;
}

/// Check if arguments contain any blocked path prefix.
fn containsBlockedPath(arguments: []const u8, blocked: []const []const u8) bool {
    for (blocked) |path| {
        if (std.mem.indexOf(u8, arguments, path) != null) return true;
    }
    return false;
}

/// Check if arguments contain sensitive patterns (case-insensitive).
fn containsBlockedPattern(arguments: []const u8, patterns: []const []const u8) bool {
    // Simple case-insensitive substring match
    for (patterns) |pattern| {
        if (caseInsensitiveContains(arguments, pattern)) return true;
    }
    return false;
}

fn caseInsensitiveContains(haystack: []const u8, needle: []const u8) bool {
    if (needle.len > haystack.len) return false;
    if (needle.len == 0) return true;

    var i: usize = 0;
    while (i + needle.len <= haystack.len) : (i += 1) {
        var match = true;
        for (needle, 0..) |nc, j| {
            const hc = haystack[i + j];
            if (toLower(hc) != toLower(nc)) {
                match = false;
                break;
            }
        }
        if (match) return true;
    }
    return false;
}

fn toLower(c: u8) u8 {
    return if (c >= 'A' and c <= 'Z') c + 32 else c;
}

// ── Tests ──────────────────────────────────────────────────

test "allow valid tool" {
    const allowed = [_][]const u8{ "file_read", "file_write" };
    const blocked_paths = [_][]const u8{"/etc/"};
    const blocked_patterns = [_][]const u8{"password"};

    const result = evaluate(
        "file_read",
        "{\"path\": \"/home/user/project/main.py\"}",
        &allowed,
        &blocked_paths,
        &blocked_patterns,
    );
    try std.testing.expect(result.verdict == .allow);
}

test "deny unlisted tool" {
    const allowed = [_][]const u8{"file_read"};
    const result = evaluate(
        "shell_exec",
        "{}",
        &allowed,
        &.{},
        &.{},
    );
    try std.testing.expect(result.verdict == .deny_tool);
}

test "deny blocked path" {
    const allowed = [_][]const u8{"file_read"};
    const blocked_paths = [_][]const u8{ "/etc/", "/root/" };

    const result = evaluate(
        "file_read",
        "{\"path\": \"/etc/passwd\"}",
        &allowed,
        &blocked_paths,
        &.{},
    );
    try std.testing.expect(result.verdict == .deny_path);
}

test "deny sensitive pattern" {
    const allowed = [_][]const u8{"file_write"};
    const blocked_patterns = [_][]const u8{ "password", "api_key" };

    const result = evaluate(
        "file_write",
        "{\"content\": \"API_KEY=sk-1234\"}",
        &allowed,
        &.{},
        &blocked_patterns,
    );
    try std.testing.expect(result.verdict == .deny_pattern);
}

test "case insensitive pattern match" {
    try std.testing.expect(caseInsensitiveContains("Hello World", "hello"));
    try std.testing.expect(caseInsensitiveContains("API_KEY=123", "api_key"));
    try std.testing.expect(!caseInsensitiveContains("safe content", "danger"));
}

test "empty allowlist denies all" {
    const result = evaluate("any_tool", "{}", &.{}, &.{}, &.{});
    try std.testing.expect(result.verdict == .deny_tool);
}
