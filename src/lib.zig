// Exposed within this library
const std = @import("std");

// The TLS implementation: injected by the application, or a bundled one, or
// none (build option `tls`). See TlsHandshake in stream.zig for what it
// provides.
pub const tls = @import("tls");
pub const has_tls = !@hasDecl(tls, "pg_tls_disabled");
pub const TlsConfig = if (@hasDecl(tls, "Config")) tls.Config else struct {};

const build_config = @import("config");

pub const log = std.log.scoped(.pg);

pub const types = @import("types.zig");
pub const proto = @import("proto.zig");
pub const auth = @import("auth.zig");
pub const Conn = @import("conn.zig").Conn;
pub const Stmt = @import("stmt.zig").Stmt;
pub const StatementCache = @import("statement_cache.zig").StatementCache;
pub const Pool = @import("pool.zig").Pool;
pub const Stream = @import("stream.zig").Stream;
pub const TlsHandshake = @import("stream.zig").TlsHandshake;
pub const TlsMode = @import("stream.zig").TlsMode;
pub const sendTerminate = @import("stream.zig").sendTerminate;
pub const metrics = @import("metrics.zig");
pub const default_column_names = build_config.column_names;

// The tests can run against a server on another port (-Dtest_port).
pub const default_port: u16 = if (@hasDecl(build_config, "default_port")) build_config.default_port else 5432;

const result = @import("result.zig");
pub const Row = result.Row;
pub const RowUnsafe = result.RowUnsafe;
pub const Result = result.Result;
pub const Iterator = result.Iterator;
pub const IteratorUnsafe = result.IteratorUnsafe;
pub const QueryRow = result.QueryRow;
pub const QueryRowUnsafe = result.QueryRowUnsafe;
pub const Mapper = result.Mapper;

const reader = @import("reader.zig");
pub const Reader = reader.Reader;
pub const Message = reader.Message;

pub const testing = @import("t.zig");

const root = @import("root");
const _assert = blk: {
    if (@hasDecl(root, "pg_assert")) {
        break :blk root.pg_assert;
    }
    switch (@import("builtin").mode) {
        .ReleaseFast, .ReleaseSmall => break :blk false,
        else => break :blk true,
    }
};

pub fn assert(ok: bool) void {
    if (comptime _assert) {
        std.debug.assert(ok);
    }
}

pub fn verifyDecodeType(comptime fail_mode: FailMode, comptime T: type, comptime expected_oids: []const i32, actual: i32) !void {
    if (comptime fail_mode == .safe) {
        if (isExpectedId(expected_oids, actual)) {
            return;
        }
        return error.InvalidType;
    }

    if (comptime _assert == false) {
        return;
    }

    if (isExpectedId(expected_oids, actual)) {
        return;
    }

    log.warn("PostgreSQL value of type {s} cannot be read into a " ++ @typeName(T) ++ ". " ++
        "pg.zig has strict type checking when reading value.", .{types.oidToString(actual)});
    unreachable;
}

fn isExpectedId(comptime expected_oids: []const i32, actual: i32) bool {
    inline for (expected_oids) |expected_oid| {
        if (expected_oid == actual) {
            return true;
        }
    }
    return false;
}

pub fn verifyNotNull(comptime fail_mode: FailMode, comptime T: type, is_null: bool) !void {
    if (comptime fail_mode == .safe) {
        if (is_null == false) {
            return;
        }
        return error.UnexpectedNull;
    }

    if (comptime _assert == false) {
        return;
    }

    if (is_null == false) {
        return;
    }

    log.warn("PostgreSQL null column cannot be read into non-optional type (" ++ @typeName(T) ++ "). " ++
        "pg.zig has strict type checking when reading value.", .{});
    unreachable;
}

pub fn verifyColumnName(comptime fail_mode: FailMode, name: []const u8, valid: bool) !void {
    if (comptime fail_mode == .safe) {
        if (valid) {
            return;
        }
        return error.UnknownColumnName;
    }

    if (comptime _assert == false) {
        return;
    }

    if (valid) {
        return;
    }

    log.warn("Unknown column name '{s}'", .{name});
    unreachable;
}

pub const ParsedOpts = struct {
    opts: Pool.Opts,
    arena: std.heap.ArenaAllocator,

    pub fn deinit(self: *ParsedOpts) void {
        self.arena.deinit();
    }
};

pub fn parseOpts(uri: std.Uri, allocator: std.mem.Allocator) !ParsedOpts {
    if (!std.mem.eql(u8, uri.scheme, "postgresql") and !std.mem.eql(u8, uri.scheme, "postgres")) {
        return error.InvalidUriScheme;
    }

    var arena = std.heap.ArenaAllocator.init(allocator);
    errdefer arena.deinit();
    const aa = arena.allocator();

    var tls_mode: enum { disable, prefer, require, verify_ca, verify_full } = .disable;
    var root_cert: ?[]const u8 = null;
    var tls_direct = false;
    var application_name: ?[]const u8 = null;
    var tcp_user_timeout: ?u32 = null;
    if (uri.query) |qry| {
        const query_string = try qry.toRawMaybeAlloc(aa);
        var it = std.mem.splitScalar(u8, query_string, '&');
        while (it.next()) |param| {
            var it2 = std.mem.splitScalar(u8, param, '=');
            const key = it2.first();
            const val = std.Uri.percentDecodeInPlace(try aa.dupe(u8, it2.rest()));
            if (std.mem.eql(u8, key, "tcp_user_timeout")) {
                tcp_user_timeout = try std.fmt.parseInt(u32, val, 10);
            } else if (std.mem.eql(u8, key, "sslmode")) {
                tls_mode = std.meta.stringToEnum(@TypeOf(tls_mode), val) orelse blk: {
                    if (std.mem.eql(u8, val, "verify-ca")) break :blk .verify_ca;
                    if (std.mem.eql(u8, val, "verify-full")) break :blk .verify_full;
                    return error.UnsupportedSSLModeValue;
                };
            } else if (std.mem.eql(u8, key, "sslrootcert")) {
                root_cert = val;
            } else if (std.mem.eql(u8, key, "sslnegotiation")) {
                if (std.mem.eql(u8, val, "direct")) {
                    tls_direct = true;
                } else if (std.mem.eql(u8, val, "postgres") == false) {
                    return error.UnsupportedSSLNegotiationValue;
                }
            } else if (std.mem.eql(u8, key, "application_name")) {
                application_name = val;
            } else {
                return error.UnsupportedConnectionParam;
            }
        }
    }

    // As libpq: sslrootcert=system means the system's trust store and
    // implies verify-full; with any other root certificate, require means
    // verify-ca.
    if (root_cert) |rc| {
        if (std.mem.eql(u8, rc, "system")) {
            root_cert = null;
            tls_mode = .verify_full;
        } else if (tls_mode == .require) {
            tls_mode = .verify_ca;
        }
    }
    const tls_opt: Conn.Opts.TLS = switch (tls_mode) {
        .disable => .off,
        .prefer => .prefer,
        .require => .require,
        .verify_ca => .{ .verify_ca = root_cert },
        .verify_full => .{ .verify_full = root_cert },
    };

    const path = std.mem.trimStart(u8, try uri.path.toRawMaybeAlloc(aa), "/");
    const host = if (uri.host) |host| try host.toRawMaybeAlloc(aa) else null;
    const username = if (uri.user) |user| try user.toRawMaybeAlloc(aa) else "postgres";
    const password = if (uri.password) |password| try password.toRawMaybeAlloc(aa) else null;

    return .{ .arena = arena, .opts = .{
        .size = 0,
        .timeout = 0,
        .auth = .{
            .username = username,
            .password = password,
            .database = if (path.len == 0) null else path,
            .timeout = tcp_user_timeout orelse 10_000,
            .application_name = application_name,
        },
        .connect = .{
            .tls = tls_opt,
            .tls_direct = tls_direct,
            .port = uri.port orelse null,
            .host = host,
        },
    } };
}

pub const Binary = struct {
    data: []const u8,
};

const TestCase = struct {
    uri: []const u8,
    expected_opts: Pool.Opts,
};

pub const FailMode = enum {
    safe,
    unsafe,
};

pub const TypeError = error{
    InvalidType,
    UnexpectedNull,
    UnknownColumnName,
};

const valid_tcs: [2]TestCase = .{
    .{ .uri = "postgresql:///", .expected_opts = .{ .size = 0, .auth = .{ .username = "postgres" }, .connect = .{}, .timeout = 0 } },
    .{ .uri = "postgresql://user:pass@somehost:1234/somedb?tcp_user_timeout=5678", .expected_opts = .{ .size = 0, .auth = .{
        .username = "user",
        .password = "pass",
        .database = "somedb",
        .timeout = 5678,
    }, .connect = .{
        .host = "somehost",
        .port = 1234,
    }, .timeout = 0 } },
};

test "URI: parse valid" {
    const a = std.testing.allocator;
    for (valid_tcs) |tc| {
        var po = parseOpts(try std.Uri.parse(tc.uri), a) catch |e| {
            std.log.err("failed to parse URI {s}", .{tc.uri});
            return e;
        };
        defer po.deinit();
        try std.testing.expectEqualDeep(tc.expected_opts, po.opts);
    }
}

test "URI: TLS" {
    const a = std.testing.allocator;
    const Case = struct { uri: []const u8, tls: Conn.Opts.TLS, direct: bool = false };
    const cases = [_]Case{
        .{ .uri = "postgresql:///?sslmode=disable", .tls = .off },
        .{ .uri = "postgresql:///?sslmode=prefer", .tls = .prefer },
        .{ .uri = "postgresql:///?sslmode=require", .tls = .require },
        .{ .uri = "postgresql:///?sslmode=verify-ca", .tls = .{ .verify_ca = null } },
        .{ .uri = "postgresql:///?sslmode=verify-full", .tls = .{ .verify_full = null } },
        .{ .uri = "postgresql:///?sslmode=verify-full&sslrootcert=%2Fetc%2Froot.crt", .tls = .{ .verify_full = "/etc/root.crt" } },
        // as libpq: a root certificate makes require verify the chain
        .{ .uri = "postgresql:///?sslmode=require&sslrootcert=root.crt", .tls = .{ .verify_ca = "root.crt" } },
        // and sslrootcert=system means verify-full against the system's store
        .{ .uri = "postgresql:///?sslrootcert=system", .tls = .{ .verify_full = null } },
        .{ .uri = "postgresql:///?sslmode=require&sslnegotiation=direct", .tls = .require, .direct = true },
        .{ .uri = "postgresql:///?sslmode=require&sslnegotiation=postgres", .tls = .require },
    };
    for (cases) |tc| {
        var po = try parseOpts(try std.Uri.parse(tc.uri), a);
        defer po.deinit();
        try std.testing.expectEqualDeep(tc.tls, po.opts.connect.tls);
        try std.testing.expectEqual(tc.direct, po.opts.connect.tls_direct);
    }

    try std.testing.expectError(error.UnsupportedSSLModeValue, parseOpts(try std.Uri.parse("postgresql:///?sslmode=sometimes"), a));
    try std.testing.expectError(error.UnsupportedSSLNegotiationValue, parseOpts(try std.Uri.parse("postgresql:///?sslnegotiation=maybe"), a));
}

test "URI: application_name" {
    var po = try parseOpts(try std.Uri.parse("postgresql:///?application_name=my%20app"), std.testing.allocator);
    defer po.deinit();
    try std.testing.expectEqualStrings("my app", po.opts.auth.application_name.?);
}

test "URI: invalid scheme" {
    try std.testing.expectError(error.InvalidUriScheme, parseOpts(try std.Uri.parse("foobar:///"), std.testing.allocator));
}

test "URI: invalid params" {
    try std.testing.expectError(error.UnsupportedConnectionParam, parseOpts(try std.Uri.parse("postgresql:///?bar=baz"), std.testing.allocator));
}
