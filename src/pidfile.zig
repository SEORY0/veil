const std = @import("std");

pub const Status = enum { running, stale, absent };

pub const CheckResult = struct {
    status: Status,
    pid: ?std.posix.pid_t,
};

pub const Error = error{
    InvalidPidFile,
};

/// Resolve the PID file path. Prefers $XDG_RUNTIME_DIR/veil.pid; falls back to /tmp/veil.pid.
/// Caller owns the returned memory.
pub fn defaultPath(allocator: std.mem.Allocator) ![]u8 {
    if (std.posix.getenv("XDG_RUNTIME_DIR")) |xdg| {
        if (xdg.len > 0) {
            return std.fmt.allocPrint(allocator, "{s}/veil.pid", .{xdg});
        }
    }
    return allocator.dupe(u8, "/tmp/veil.pid");
}

/// Acquire an exclusive advisory lock on `path` and write the current PID.
///
/// Returns an open fd. The lock lives for the lifetime of the fd — the kernel
/// releases it when the process exits or the fd is explicitly closed via
/// `release`. A concurrent start attempt by a second veil process gets
/// `error.AlreadyRunning`.
pub fn acquireAndWrite(path: []const u8, pid: std.posix.pid_t) !std.posix.fd_t {
    const file = try std.fs.cwd().createFile(path, .{ .truncate = false, .read = true });
    errdefer file.close();

    std.posix.flock(file.handle, std.posix.LOCK.EX | std.posix.LOCK.NB) catch |err| switch (err) {
        error.WouldBlock => return error.AlreadyRunning,
        else => return err,
    };

    try file.seekTo(0);
    try file.setEndPos(0);
    var buf: [32]u8 = undefined;
    const line = try std.fmt.bufPrint(&buf, "{d}\n", .{pid});
    try file.writeAll(line);

    return file.handle;
}

/// Release the lock and close the underlying fd. The file is not unlinked;
/// call `remove()` separately if you want to delete it.
pub fn release(fd: std.posix.fd_t) void {
    std.posix.flock(fd, std.posix.LOCK.UN) catch {};
    std.posix.close(fd);
}

/// Legacy unlocked write — kept for tests that just want to deposit a pid.
pub fn write(path: []const u8, pid: std.posix.pid_t) !void {
    const file = try std.fs.cwd().createFile(path, .{ .truncate = true });
    defer file.close();

    var buf: [32]u8 = undefined;
    const line = try std.fmt.bufPrint(&buf, "{d}\n", .{pid});
    try file.writeAll(line);
}

/// Read PID and probe liveness with `kill(pid, 0)`.
pub fn check(path: []const u8) !CheckResult {
    const file = std.fs.cwd().openFile(path, .{}) catch |err| switch (err) {
        error.FileNotFound => return .{ .status = .absent, .pid = null },
        else => return err,
    };
    defer file.close();

    var buf: [32]u8 = undefined;
    const n = try file.readAll(&buf);
    const trimmed = std.mem.trim(u8, buf[0..n], &std.ascii.whitespace);
    if (trimmed.len == 0) return error.InvalidPidFile;

    const pid = std.fmt.parseInt(std.posix.pid_t, trimmed, 10) catch return error.InvalidPidFile;

    std.posix.kill(pid, 0) catch |err| switch (err) {
        error.ProcessNotFound => return .{ .status = .stale, .pid = pid },
        error.PermissionDenied => return .{ .status = .running, .pid = pid }, // exists, just can't signal
        else => return err,
    };

    // Defend against PID reuse: verify /proc/<pid>/comm says "veil".
    // If we can't read /proc (sandboxed?), fall back to trusting kill(pid,0).
    if (procComm(pid)) |comm| {
        if (!std.mem.eql(u8, comm, "veil")) {
            return .{ .status = .stale, .pid = pid };
        }
    } else |_| {}

    return .{ .status = .running, .pid = pid };
}

/// Read /proc/<pid>/comm, returning the trimmed command name.
fn procComm(pid: std.posix.pid_t) ![]const u8 {
    var path_buf: [64]u8 = undefined;
    const path = try std.fmt.bufPrint(&path_buf, "/proc/{d}/comm", .{pid});

    const file = try std.fs.cwd().openFile(path, .{});
    defer file.close();

    var comm_buf: [64]u8 = undefined;
    const n = try file.readAll(&comm_buf);
    const trimmed = std.mem.trimRight(u8, comm_buf[0..n], "\n");
    // Copy into a static area we can return — but we can't return stack
    // memory. Instead, use a thread-local static buffer.
    const holder = struct {
        threadlocal var storage: [64]u8 = undefined;
    };
    @memcpy(holder.storage[0..trimmed.len], trimmed);
    return holder.storage[0..trimmed.len];
}

/// Remove the PID file. Ignores FileNotFound.
pub fn remove(path: []const u8) !void {
    std.posix.unlink(path) catch |err| switch (err) {
        error.FileNotFound => {},
        else => return err,
    };
}

// ── Tests ──────────────────────────────────────────────────

test "write + check reports stale for self when comm mismatches (PID reuse guard)" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const path = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(path);
    const full = try std.fmt.allocPrint(std.testing.allocator, "{s}/veil.pid", .{path});
    defer std.testing.allocator.free(full);

    try write(full, std.os.linux.getpid());
    // The test binary's comm is "test", not "veil" — procComm check kicks
    // in and reports stale even though the pid is alive. This IS the PID
    // reuse guard: a live but non-veil process should not be mistaken for
    // a running veil.
    const r = try check(full);
    try std.testing.expectEqual(Status.stale, r.status);
    try std.testing.expect(r.pid.? == std.os.linux.getpid());
}

test "check reports absent when file missing" {
    const r = try check("/tmp/veil-nonexistent-test-pid-xyzzy");
    try std.testing.expectEqual(Status.absent, r.status);
}

test "check reports stale for long-dead pid" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const path = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(path);
    const full = try std.fmt.allocPrint(std.testing.allocator, "{s}/veil.pid", .{path});
    defer std.testing.allocator.free(full);

    // PID 1 exists (init) — we need a definitely-dead PID. Use a very large one.
    try std.fs.cwd().writeFile(.{ .sub_path = full, .data = "2147483646\n" });
    const r = try check(full);
    try std.testing.expectEqual(Status.stale, r.status);
}

test "acquireAndWrite succeeds and second acquire fails" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const path = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(path);
    const full = try std.fmt.allocPrint(std.testing.allocator, "{s}/veil.pid", .{path});
    defer std.testing.allocator.free(full);

    const fd = try acquireAndWrite(full, std.os.linux.getpid());
    defer release(fd);

    // Second acquire must fail with AlreadyRunning (same process holds the lock
    // on a different fd — flock is per-fd on Linux, so this still collides).
    try std.testing.expectError(error.AlreadyRunning, acquireAndWrite(full, 99999));
}

test "check rejects invalid content" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const path = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(path);
    const full = try std.fmt.allocPrint(std.testing.allocator, "{s}/veil.pid", .{path});
    defer std.testing.allocator.free(full);

    try std.fs.cwd().writeFile(.{ .sub_path = full, .data = "not-a-number" });
    try std.testing.expectError(error.InvalidPidFile, check(full));
}
