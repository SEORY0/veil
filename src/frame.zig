//! MCP-compatible JSON-RPC message framing.
//!
//! Two wire formats are accepted on the same socket, auto-detected on the
//! first bytes of each frame:
//!
//!   1. LSP-style Content-Length headers (the MCP stdio transport format):
//!        Content-Length: 123\r\n
//!        \r\n
//!        { ... 123 bytes ... }
//!
//!   2. Newline-delimited JSON (NDJSON):
//!        { ... one JSON object per line, \n-terminated ... }
//!
//! Fallback: if neither is detected and the peer has closed the write half,
//! whatever bytes are buffered are returned as a single frame — preserves
//! the pre-framing "read-until-EOF" behavior for naive clients.

const std = @import("std");

pub const MAX_FRAME_BYTES: usize = 1 * 1024 * 1024;
pub const MAX_HEADER_BYTES: usize = 4 * 1024;

pub const Error = error{
    FrameTooLarge,
    HeaderTooLarge,
    MalformedHeader,
    InvalidContentLength,
};

pub const Format = enum { unknown, lsp, ndjson, raw };

pub const Reader = struct {
    buf: [MAX_FRAME_BYTES + MAX_HEADER_BYTES]u8 = undefined,
    start: usize = 0,
    end: usize = 0,
    format: Format = .unknown,

    /// Read the next complete frame. Returns:
    ///   * a slice into `self.buf` valid until the next call,
    ///   * `null` on peer EOF with no more data.
    ///
    /// Auto-detection on the first chunk we receive, then format is latched:
    ///   * Starts with `Content-Length:`  → LSP (multi-frame, persistent)
    ///   * Contains `\n`                  → NDJSON (multi-frame, persistent)
    ///   * Otherwise                      → raw: each `read()` is one frame
    ///
    /// The returned slice never includes framing headers (LSP) or the
    /// trailing `\n` (NDJSON).
    pub fn next(self: *Reader, fd: std.posix.fd_t) !?[]const u8 {
        while (true) {
            switch (self.format) {
                .unknown => {
                    if (self.start == self.end) {
                        if (!try self.fillOnce(fd)) return null;
                    }
                    const avail = self.buf[self.start..self.end];
                    if (std.mem.startsWith(u8, avail, "Content-Length:") or
                        std.mem.startsWith(u8, avail, "content-length:"))
                    {
                        self.format = .lsp;
                        continue;
                    }
                    if (std.mem.indexOfScalar(u8, avail, '\n') != null) {
                        self.format = .ndjson;
                        continue;
                    }
                    // Naive client: return this chunk as the single frame.
                    self.format = .raw;
                    const frame = avail;
                    self.start = self.end;
                    return frame;
                },
                .lsp => return try self.readLspFrame(fd),
                .ndjson => return try self.readNdjsonFrame(fd),
                .raw => {
                    if (self.start == self.end) {
                        if (!try self.fillOnce(fd)) return null;
                    }
                    const frame = self.buf[self.start..self.end];
                    self.start = self.end;
                    return frame;
                },
            }
        }
    }

    fn readNdjsonFrame(self: *Reader, fd: std.posix.fd_t) !?[]const u8 {
        while (true) {
            const slice = self.buf[self.start..self.end];
            if (std.mem.indexOfScalar(u8, slice, '\n')) |off| {
                const abs = self.start + off;
                const frame = self.buf[self.start..abs];
                self.start = abs + 1;
                return frame;
            }
            if (self.end - self.start >= MAX_FRAME_BYTES) return error.FrameTooLarge;
            if (!try self.fillOnce(fd)) {
                if (self.end > self.start) {
                    const frame = self.buf[self.start..self.end];
                    self.start = self.end;
                    return frame;
                }
                return null;
            }
        }
    }

    fn readLspFrame(self: *Reader, fd: std.posix.fd_t) !?[]const u8 {
        var content_length: ?usize = null;

        // Parse headers until a blank line.
        while (true) {
            const line_end = blk: while (true) {
                const slice = self.buf[self.start..self.end];
                if (std.mem.indexOf(u8, slice, "\r\n")) |off| break :blk self.start + off;
                if (self.end - self.start > MAX_HEADER_BYTES) return error.HeaderTooLarge;
                if (!try self.fillOnce(fd)) return error.MalformedHeader;
            };

            const line = self.buf[self.start..line_end];
            self.start = line_end + 2; // consume \r\n

            if (line.len == 0) break; // blank line → end of headers

            if (std.ascii.startsWithIgnoreCase(line, "content-length:")) {
                const val = std.mem.trim(u8, line["content-length:".len..], " \t");
                content_length = std.fmt.parseInt(usize, val, 10) catch return error.InvalidContentLength;
            }
            // Other headers ignored for now (Content-Type, etc.).
        }

        const len = content_length orelse return error.MalformedHeader;
        if (len > MAX_FRAME_BYTES) return error.FrameTooLarge;

        // Ensure we have `len` bytes in [start..].
        while (self.end - self.start < len) {
            if (!try self.fillOnce(fd)) return error.MalformedHeader;
        }

        const body = self.buf[self.start .. self.start + len];
        self.start += len;
        return body;
    }

    /// Compact the buffer and read one chunk. Returns false on EOF.
    fn fillOnce(self: *Reader, fd: std.posix.fd_t) !bool {
        if (self.start > 0) {
            const rem = self.end - self.start;
            std.mem.copyForwards(u8, self.buf[0..rem], self.buf[self.start..self.end]);
            self.start = 0;
            self.end = rem;
        }
        if (self.end == self.buf.len) return error.FrameTooLarge;
        const n = std.posix.read(fd, self.buf[self.end..]) catch |e| switch (e) {
            error.ConnectionResetByPeer => return false,
            else => return e,
        };
        if (n == 0) return false;
        self.end += n;
        return true;
    }
};

// ── Tests ──────────────────────────────────────────────────

fn makePipeWithData(data: []const u8) !std.posix.fd_t {
    const fds = try std.posix.pipe();
    // Write all data then close the write end so reads see EOF.
    var written: usize = 0;
    while (written < data.len) {
        written += try std.posix.write(fds[1], data[written..]);
    }
    std.posix.close(fds[1]);
    return fds[0];
}

test "ndjson: single line" {
    const fd = try makePipeWithData("{\"a\":1}\n");
    defer std.posix.close(fd);

    var r: Reader = .{};
    const frame = (try r.next(fd)) orelse return error.NoFrame;
    try std.testing.expectEqualStrings("{\"a\":1}", frame);
    try std.testing.expect((try r.next(fd)) == null);
}

test "ndjson: two lines back to back" {
    const fd = try makePipeWithData("{\"a\":1}\n{\"b\":2}\n");
    defer std.posix.close(fd);

    var r: Reader = .{};
    try std.testing.expectEqualStrings("{\"a\":1}", (try r.next(fd)).?);
    try std.testing.expectEqualStrings("{\"b\":2}", (try r.next(fd)).?);
    try std.testing.expect((try r.next(fd)) == null);
}

test "lsp framing" {
    const fd = try makePipeWithData("Content-Length: 7\r\n\r\n{\"a\":1}");
    defer std.posix.close(fd);

    var r: Reader = .{};
    const frame = (try r.next(fd)).?;
    try std.testing.expectEqualStrings("{\"a\":1}", frame);
}

test "lsp framing: two frames" {
    const fd = try makePipeWithData(
        "Content-Length: 7\r\n\r\n{\"a\":1}" ++
            "Content-Length: 7\r\n\r\n{\"b\":2}",
    );
    defer std.posix.close(fd);

    var r: Reader = .{};
    try std.testing.expectEqualStrings("{\"a\":1}", (try r.next(fd)).?);
    try std.testing.expectEqualStrings("{\"b\":2}", (try r.next(fd)).?);
}

test "eof without trailing newline returns remainder" {
    // Naive client sends one JSON object then closes. No \n terminator.
    const fd = try makePipeWithData("{\"x\":42}");
    defer std.posix.close(fd);

    var r: Reader = .{};
    try std.testing.expectEqualStrings("{\"x\":42}", (try r.next(fd)).?);
    try std.testing.expect((try r.next(fd)) == null);
}

test "empty stream returns null" {
    const fd = try makePipeWithData("");
    defer std.posix.close(fd);

    var r: Reader = .{};
    try std.testing.expect((try r.next(fd)) == null);
}

test "lsp malformed (no content-length value)" {
    const fd = try makePipeWithData("Content-Length: abc\r\n\r\n{}");
    defer std.posix.close(fd);

    var r: Reader = .{};
    try std.testing.expectError(error.InvalidContentLength, r.next(fd));
}
