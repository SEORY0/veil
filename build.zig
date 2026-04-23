const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const exe_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        .strip = if (optimize != .Debug) true else false,
    });
    exe_mod.link_libc = true;

    const exe = b.addExecutable(.{
        .name = "veil",
        .root_module = exe_mod,
    });

    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }
    const run_step = b.step("run", "Run veil proxy");
    run_step.dependOn(&run_cmd.step);

    const test_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    const unit_tests = b.addTest(.{
        .root_module = test_mod,
    });
    const run_unit_tests = b.addRunArtifact(unit_tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_unit_tests.step);

    // ── End-to-end tests ──
    const veil_bin_path = b.getInstallPath(.bin, exe.out_filename);
    const e2e_options = b.addOptions();
    e2e_options.addOption([]const u8, "veil_bin", veil_bin_path);

    const e2e_mod = b.createModule(.{
        .root_source_file = b.path("tests/e2e.zig"),
        .target = target,
        .optimize = optimize,
    });
    e2e_mod.addOptions("build_options", e2e_options);

    const e2e_tests = b.addTest(.{
        .root_module = e2e_mod,
    });
    const run_e2e = b.addRunArtifact(e2e_tests);
    run_e2e.step.dependOn(b.getInstallStep());
    if (b.option([]const u8, "test-filter", "Only run e2e tests whose name contains this substring")) |f| {
        run_e2e.addArgs(&.{ "--test-filter", f });
    }
    const e2e_step = b.step("e2e", "Run end-to-end integration tests");
    e2e_step.dependOn(&run_e2e.step);

    // ── Static (musl) cross-compile ──
    // Produces zero-dependency binaries under zig-out/static/<arch>/.
    // Invoke: `zig build static`.
    const static_step = b.step("static", "Build statically-linked musl binaries for release");

    const static_targets = [_]std.Target.Query{
        .{ .cpu_arch = .x86_64, .os_tag = .linux, .abi = .musl },
        .{ .cpu_arch = .aarch64, .os_tag = .linux, .abi = .musl },
    };

    for (static_targets) |query| {
        const st = b.resolveTargetQuery(query);

        const st_mod = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = st,
            .optimize = .ReleaseSmall,
            .strip = true,
        });
        st_mod.link_libc = true;

        const st_exe = b.addExecutable(.{
            .name = "veil",
            .root_module = st_mod,
        });

        const arch_name = @tagName(query.cpu_arch.?);
        const subdir = b.fmt("static/{s}-linux-musl", .{arch_name});
        const install = b.addInstallArtifact(st_exe, .{
            .dest_dir = .{ .override = .{ .custom = subdir } },
        });
        static_step.dependOn(&install.step);
    }
}
