const std = @import("std");

pub const Tls = enum {
    // no TLS: `.tls = .prefer` connects in plain text, other modes fail
    none,
    // Zig's std.crypto.tls (src/std_tls.zig)
    std,
    // the application adds the `tls` import itself:
    //   pg_dep.module("pg").addImport("tls", my_tls_module);
    // see TlsHandshake in src/stream.zig for what the module provides
    injected,
};

pub fn build(b: *std.Build) !void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // setup our dependencies
    const dep_opts = .{ .target = target, .optimize = optimize };

    const tls = b.option(Tls, "tls", "TLS implementation: none (default), std or injected");
    const metrics = b.option(bool, "metrics", "Count queries and allocations with metrics.zig (pg.writeMetrics); off by default") orelse false;

    // Expose this as a module that others can import
    const pg_module = b.addModule("pg", .{
        .target = target,
        .optimize = optimize,
        .root_source_file = b.path("src/pg.zig"),
        .imports = &.{
            .{ .name = "buffer", .module = b.dependency("buffer", dep_opts).module("buffer") },
        },
    });
    addTls(b, pg_module, tls orelse .none);
    addMetrics(b, pg_module, metrics, dep_opts);

    var column_names = false;
    const column_names_opt = b.option(bool, "column_names", "");

    if (column_names_opt) |val| {
        column_names = val;
    }

    {
        const options = b.addOptions();
        options.addOption(bool, "column_names", column_names);
        pg_module.addOptions("config", options);
    }

    {
        // The tests need a live server; tests/run.sh starts one in Docker and
        // runs them in each configuration.
        const test_port = b.option(u16, "test_port", "Port of the PostgreSQL server the tests use (default 5432)") orelse 5432;
        // run the tests on a zio runtime (pinned executors) instead of std's Threaded Io
        const test_zio = b.option(bool, "zio", "Run the tests on a zio runtime with pinned executors") orelse false;
        const test_executors = b.option(u6, "test_executors", "Executors of the zio runtime the tests run on (default 4)") orelse 4;

        // test step: with std's TLS unless -Dtls=none (an injected module
        // isn't there to test with)
        const test_tls: Tls = if (tls == .none) .none else .std;

        const test_module = b.createModule(.{
            .target = target,
            .optimize = optimize,
            .root_source_file = b.path("src/pg.zig"),
            .imports = &.{
                .{ .name = "buffer", .module = b.dependency("buffer", dep_opts).module("buffer") },
            },
        });
        addTls(b, test_module, test_tls);
        addMetrics(b, test_module, metrics, dep_opts);
        if (test_zio) {
            if (b.lazyDependency("zio", .{ .target = target, .optimize = optimize, .scheduling = .pinned })) |dep| {
                test_module.addImport("zio", dep.module("zio"));
            }
        }

        const lib_test = b.addTest(.{
            .root_module = test_module,
            .use_llvm = true,
            .test_runner = .{ .path = b.path("test_runner.zig"), .mode = .simple },
        });

        {
            const options = b.addOptions();
            options.addOption(bool, "column_names", false);
            options.addOption(u16, "default_port", test_port);
            options.addOption(bool, "test_zio", test_zio);
            options.addOption(u6, "test_executors", test_executors);
            lib_test.root_module.addOptions("config", options);
        }

        const run_test = b.addRunArtifact(lib_test);
        run_test.has_side_effects = true;

        const test_step = b.step("test", "Run unit tests");
        test_step.dependOn(&run_test.step);
    }
}

fn addMetrics(b: *std.Build, module: *std.Build.Module, enabled: bool, dep_opts: anytype) void {
    if (enabled) {
        if (b.lazyDependency("metrics", dep_opts)) |dep| {
            module.addImport("metrics", dep.module("metrics"));
        }
    } else {
        module.addAnonymousImport("metrics", .{ .root_source_file = b.path("src/metrics_stub.zig") });
    }
}

fn addTls(b: *std.Build, module: *std.Build.Module, tls: Tls) void {
    switch (tls) {
        .none => module.addAnonymousImport("tls", .{ .root_source_file = b.path("src/tls_none.zig") }),
        .std => module.addAnonymousImport("tls", .{ .root_source_file = b.path("src/std_tls.zig") }),
        .injected => {},
    }
}
