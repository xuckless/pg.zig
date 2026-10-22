const std = @import("std");
const lib = @import("lib.zig");

const log = lib.log;
const Conn = lib.Conn;
const Result = lib.Result;
const QueryRow = lib.QueryRow;
const QueryRowUnsafe = lib.QueryRowUnsafe;
const Listener = @import("listener.zig").Listener;

const Allocator = std.mem.Allocator;
const ArenaAllocator = std.heap.ArenaAllocator;

const Io = std.Io;

pub const Pool = struct {
    _io: Io,
    _opts: Opts,
    _timeout: u64,
    // idle connections; _conns[0.._available] are ready to be acquired
    _conns: []*Conn,
    _available: usize,
    // connections that are open or being opened, idle or in use; never more
    // than _conns.len
    _open: usize,
    _allocator: Allocator,
    _mutex: Io.Mutex,
    _cond: Io.Condition,
    // not to be used outside of init
    _arena: ArenaAllocator,

    pub const Opts = struct {
        size: u16 = 10,
        auth: Conn.AuthOpts = .{},
        connect: Conn.Opts = .{},
        timeout: u32 = 10 * std.time.ms_per_s,
        connect_on_init_count: ?u16 = null,

        // Milliseconds, from when it was opened, after which a connection is
        // closed instead of being reused. null for no limit.
        max_lifetime: ?u32 = null,

        // Milliseconds a connection may sit idle in the pool before it's
        // closed. null for no limit.
        idle_timeout: ?u32 = null,

        // What the pool does to a connection's session when the connection
        // comes back, so that what one user of it set for the session (SET,
        // set_config(..., false), SET ROLE, temporary tables, advisory locks,
        // LISTEN, cursors WITH HOLD) doesn't carry over to the next. A reset
        // is sent with the release and its answer read when the connection
        // is next used, so it adds no round trip. A connection is never
        // handed on inside a transaction: one released in a transaction (or
        // a failed one) is closed.
        reset: Reset = .off,
    };

    pub const Reset = union(enum) {
        // Nothing: only SET LOCAL (and set_config(..., true)) inside a
        // transaction is safe to use with the pool.
        off,
        // This SQL on every release: reset_sql, or SQL of your own. Must
        // outlive the pool.
        always: []const u8,
        // Reset a connection only when what it ran may have changed the
        // session, judged from the SQL (session.zig) and from the settings
        // the server reports changed, with just the statements that undo
        // it. PREPARE, DEALLOCATE, DISCARD ALL and LOAD close the
        // connection instead. What a server-side function does is not in
        // the SQL: DO and CALL get the full reset, a plain function call
        // none; use .always when functions change session state.
        auto,
    };

    // DISCARD ALL without what it would undo for the statement cache
    // (DEALLOCATE ALL) or what a hot standby refuses (UNLISTEN).
    pub const reset_sql = lib.session.full_reset;

    pub const AcquireOpts = struct {
        // When the pool opens a connection for this call and the server
        // refuses it (error.PG: a wrong password, a database that doesn't
        // exist), the server's error is copied here.
        connect_error: ?*ConnectError = null,
    };

    // The server's error from a failed connect, owned by `allocator`.
    pub const ConnectError = struct {
        allocator: Allocator,
        err: ?lib.proto.Error = null,
        _data: ?[]u8 = null,

        pub fn deinit(self: *ConnectError) void {
            if (self._data) |d| self.allocator.free(d);
            self.* = .{ .allocator = self.allocator };
        }

        fn set(self: *ConnectError, data: []const u8) void {
            const owned = self.allocator.dupe(u8, data) catch return;
            self.deinit();
            self._data = owned;
            self.err = lib.proto.Error.parse(owned);
        }
    };

    pub const Stats = struct {
        size: usize,
        available: usize,
        missing: usize,
        in_use: usize,
    };

    pub fn initUri(io: Io, allocator: Allocator, uri: std.Uri, opts: Opts) !*Pool {
        var po = try lib.parseOpts(uri, allocator);
        // po.opts references memory owned by po.arena (or by `uri`). init dupes
        // everything it needs into the pool's own arena, so this temporary arena
        // can be freed as soon as init returns.
        defer po.deinit();
        po.opts.size = opts.size;
        po.opts.timeout = opts.timeout;
        po.opts.max_lifetime = opts.max_lifetime;
        po.opts.idle_timeout = opts.idle_timeout;
        po.opts.reset = opts.reset;
        return init(io, allocator, po.opts);
    }

    pub fn init(io: Io, allocator: Allocator, opts: Opts) !*Pool {
        var arena = ArenaAllocator.init(allocator);
        errdefer arena.deinit();

        const aa = arena.allocator();
        const pool = try aa.create(Pool);
        const size = opts.size;
        const conns = try aa.alloc(*Conn, size);

        // Copy every caller-provided string into our arena so the pool owns them
        // outright. Callers (including initUri) don't need to keep `opts`'s strings
        // alive past this call.
        var opts_copy = opts;
        opts_copy.auth.username = try aa.dupe(u8, opts.auth.username);
        if (opts.auth.password) |v| opts_copy.auth.password = try aa.dupe(u8, v);
        if (opts.auth.database) |v| opts_copy.auth.database = try aa.dupe(u8, v);
        if (opts.auth.application_name) |v| opts_copy.auth.application_name = try aa.dupe(u8, v);
        if (opts.connect.host) |v| opts_copy.connect.host = try aa.dupe(u8, v);
        if (opts.auth.startup_parameters) |params| {
            var owned = std.StringHashMap([]const u8).init(aa);
            try owned.ensureTotalCapacity(params.count());
            var it = params.iterator();
            while (it.next()) |kv| {
                owned.putAssumeCapacity(try aa.dupe(u8, kv.key_ptr.*), try aa.dupe(u8, kv.value_ptr.*));
            }
            opts_copy.auth.startup_parameters = owned;
        }

        // the root certificate path is read on every (re)connect, so own it too
        switch (opts.connect.tls) {
            .verify_ca => |path| if (path) |p| {
                opts_copy.connect.tls = .{ .verify_ca = try aa.dupe(u8, p) };
            },
            .verify_full => |path| if (path) |p| {
                opts_copy.connect.tls = .{ .verify_full = try aa.dupe(u8, p) };
            },
            else => {},
        }
        const connect_on_init_count = opts.connect_on_init_count orelse size;

        pool.* = .{
            ._io = io,
            ._cond = .init,
            ._mutex = .init,
            ._conns = conns,
            ._arena = arena,
            ._opts = opts_copy,
            ._open = connect_on_init_count,
            ._allocator = allocator,
            ._available = connect_on_init_count,
            ._timeout = @as(u64, @intCast(opts.timeout)) * std.time.ns_per_ms,
        };

        var opened_connections: usize = 0;
        errdefer {
            for (0..opened_connections) |i| {
                conns[i].deinit();
            }
        }

        for (0..connect_on_init_count) |i| {
            conns[i] = try newConnection(pool, true, null);
            opened_connections += 1;
        }

        return pool;
    }

    pub fn deinit(self: *Pool) void {
        const allocator = self._allocator;
        for (self._conns[0..self._available]) |conn| {
            conn.deinit();
            allocator.destroy(conn);
        }
        self._arena.deinit();
    }

    pub fn acquire(self: *Pool) !*Conn {
        return self.acquireOpts(.{});
    }

    pub fn acquireOpts(self: *Pool, opts: AcquireOpts) !*Conn {
        const conns = self._conns;
        const io = self._io;
        const deadline: Io.Clock.Timestamp = .fromNow(io, .{
            .raw = .fromNanoseconds(self._timeout),
            .clock = .awake,
        });

        // Connections that outlived max_lifetime or idle_timeout, which we
        // close once the lock is released. One more than takeExpired takes,
        // for an expired connection at the top of the stack.
        var expired_buf: [max_expired_per_call + 1]*Conn = undefined;
        var expired_count: usize = 0;
        defer self.closeExpired(expired_buf[0..expired_count]);

        try self._mutex.lock(io);
        // null: the pool is empty but below its size, and we reserved a slot
        // for a new connection, which we open outside the lock
        const idle: ?*Conn = blk: {
            errdefer self._mutex.unlock(io);

            var timed_out = false;
            while (true) {
                expired_count += self.takeExpired(expired_buf[expired_count..max_expired_per_call]);

                const available = self._available;
                if (available > 0) {
                    const index = available - 1;
                    self._available = index;
                    const conn = conns[index];
                    if (self.isExpired(conn, Io.Timestamp.now(io, .awake))) {
                        // we keep its slot for the connection that replaces it
                        expired_buf[expired_count] = conn;
                        expired_count += 1;
                        break :blk null;
                    }
                    break :blk conn;
                }

                if (self._open < conns.len) {
                    self._open += 1;
                    break :blk null;
                }

                lib.metrics.poolEmpty();

                // checked only after looking for a connection one more time
                if (timed_out) {
                    return error.Timeout;
                }

                self._cond.waitTimeout(io, &self._mutex, .{ .deadline = deadline }) catch |err| switch (err) {
                    error.Timeout => timed_out = true,
                    error.Canceled => |e| return e,
                };
            }
        };
        self._mutex.unlock(io);

        // close before opening, so we never hold more than `size` connections
        self.closeExpired(expired_buf[0..expired_count]);
        expired_count = 0;

        return idle orelse self.openConnection(opts.connect_error);
    }

    // Opens a connection for a slot that acquire already reserved in _open.
    fn openConnection(self: *Pool, connect_error: ?*ConnectError) !*Conn {
        return newConnection(self, false, connect_error) catch |err| {
            self.dropSlot();
            return err;
        };
    }

    pub fn release(self: *Pool, conn: *Conn) void {
        const io = self._io;
        const now = Io.Timestamp.now(io, .awake);

        if (conn._state != .idle or self.pastLifetime(conn, now)) {
            lib.metrics.poolDirty();
            // conn should always be idle when being released. It's possible we can
            // recover from this (e.g. maybe we just need to read until we get a
            // ReadyForQuery), but we wouldn't want to block for too long. For now,
            // we'll just close the connection; the next acquire that finds the
            // pool empty opens a new one.
            conn.deinit();
            self._allocator.destroy(conn);
            self.dropSlot();
            return;
        }

        const reset_ok = switch (self._opts.reset) {
            .off => true,
            .always => |sql| if (conn.queueReset(sql)) true else |_| false,
            .auto => blk: {
                const effect = conn._session;
                conn._session = .{};
                if (effect.close) break :blk false;
                if (!effect.any()) break :blk true;
                var buf: [lib.session.max_reset_len]u8 = undefined;
                break :blk if (conn.queueReset(lib.session.resetSql(effect, &buf))) true else |_| false;
            },
        };
        if (!reset_ok) {
            conn.deinit();
            self._allocator.destroy(conn);
            self.dropSlot();
            return;
        }

        conn._idle_since = now;

        var expired_buf: [max_expired_per_call]*Conn = undefined;
        var expired_count: usize = 0;
        defer self.closeExpired(expired_buf[0..expired_count]);

        var conns = self._conns;
        self._mutex.lockUncancelable(io);
        expired_count = self.takeExpired(&expired_buf);
        const available = self._available;
        conns[available] = conn;
        self._available = available + 1;
        self._mutex.unlock(io);
        self._cond.signal(io);
    }

    // How many expired connections acquire or release takes out of the pool
    // per call, so that a call never closes many connections at once.
    const max_expired_per_call = 4;

    fn pastLifetime(self: *const Pool, conn: *const Conn, now: Io.Timestamp) bool {
        const ms = self._opts.max_lifetime orelse return false;
        return conn._opened_at.durationTo(now).toMilliseconds() >= ms;
    }

    fn isExpired(self: *const Pool, conn: *const Conn, now: Io.Timestamp) bool {
        if (self.pastLifetime(conn, now)) {
            return true;
        }
        const ms = self._opts.idle_timeout orelse return false;
        return conn._idle_since.durationTo(now).toMilliseconds() >= ms;
    }

    // Must be called with the lock held. Moves expired connections out of
    // the idle ones into `into` and gives up their slots. The idle stack is
    // LIFO, so the connections idle the longest are at the bottom, and we
    // only look there.
    fn takeExpired(self: *Pool, into: []*Conn) usize {
        if (self._opts.max_lifetime == null and self._opts.idle_timeout == null) {
            return 0;
        }
        const now = Io.Timestamp.now(self._io, .awake);
        const conns = self._conns;
        var n: usize = 0;
        while (n < into.len and self._available > 0) {
            const conn = conns[0];
            if (self.isExpired(conn, now) == false) {
                break;
            }
            into[n] = conn;
            n += 1;
            const available = self._available - 1;
            std.mem.copyForwards(*Conn, conns[0..available], conns[1 .. available + 1]);
            self._available = available;
            self._open -= 1;
        }
        return n;
    }

    // Closes connections taken by takeExpired, outside the lock. The slots
    // they gave up may let a waiter open a new connection.
    fn closeExpired(self: *Pool, expired: []const *Conn) void {
        if (expired.len == 0) {
            return;
        }
        for (expired) |conn| {
            conn.deinit();
            self._allocator.destroy(conn);
        }
        self._cond.broadcast(self._io);
    }

    // Gives up a slot in _open and wakes a waiter, which can now open a
    // connection in its place.
    fn dropSlot(self: *Pool) void {
        const io = self._io;
        self._mutex.lockUncancelable(io);
        self._open -= 1;
        self._mutex.unlock(io);
        self._cond.signal(io);
    }

    pub fn newListener(self: *Pool) !Listener {
        var listener = try Listener.open(self._io, self._allocator, self._opts.connect);
        try listener.auth(self._opts.auth);
        return listener;
    }

    pub fn stats(self: *Pool) Stats {
        const io = self._io;
        self._mutex.lockUncancelable(io);
        defer self._mutex.unlock(io);

        const available = self._available;
        const open = self._open;
        const size = self._conns.len;

        return .{
            .size = size,
            .available = available,
            .missing = size - open,
            .in_use = open - available,
        };
    }

    pub fn exec(self: *Pool, sql: []const u8, values: anytype) !?i64 {
        return self.execOpts(sql, values, .{});
    }

    pub fn execOpts(self: *Pool, sql: []const u8, values: anytype, opts: Conn.QueryOpts) !?i64 {
        var conn = try self.acquire();
        defer self.release(conn);
        return conn.execOpts(sql, values, opts);
    }

    pub fn query(self: *Pool, sql: []const u8, values: anytype) !*Result {
        return self.queryOpts(sql, values, .{});
    }

    pub fn queryOpts(self: *Pool, sql: []const u8, values: anytype, opts_: Conn.QueryOpts) !*Result {
        var opts = opts_;
        opts.release_conn = true;
        var conn = try self.acquire();
        // queryOpts will manage conn
        return conn.queryOpts(sql, values, opts);
    }

    pub fn row(self: *Pool, sql: []const u8, values: anytype) !?QueryRow {
        return self.rowOpts(sql, values, .{});
    }

    pub fn rowUnsafe(self: *Pool, sql: []const u8, values: anytype) !?QueryRowUnsafe {
        return self.rowUnsafeOpts(sql, values, .{});
    }

    pub fn rowOpts(self: *Pool, sql: []const u8, values: anytype, opts_: Conn.QueryOpts) !?QueryRow {
        var opts = opts_;
        opts.release_conn = true;
        var conn = try self.acquire();
        return conn.rowOpts(sql, values, opts);
    }

    pub fn rowUnsafeOpts(self: *Pool, sql: []const u8, values: anytype, opts_: Conn.QueryOpts) !?QueryRowUnsafe {
        var opts = opts_;
        opts.release_conn = true;
        var conn = try self.acquire();
        return conn.rowUnsafeOpts(sql, values, opts);
    }
};

fn newConnection(pool: *Pool, log_failure: bool, connect_error: ?*Pool.ConnectError) !*Conn {
    const opts = &pool._opts;
    const allocator = pool._allocator;
    const io = pool._io;

    const conn = allocator.create(Conn) catch |err| {
        if (log_failure) log.err("connect error: {}", .{err});
        return err;
    };
    errdefer allocator.destroy(conn);

    conn.* = Conn.open(io, allocator, opts.connect) catch |err| {
        if (log_failure) log.err("connect error: {}", .{err});
        return err;
    };
    errdefer conn.deinit();

    conn.auth(opts.auth) catch |err| {
        if (connect_error) |ce| {
            if (conn._err_data) |data| ce.set(data);
        }
        if (log_failure) {
            if (conn.err) |pg_err| {
                log.err("connect error: {s}", .{pg_err.message});
            } else {
                log.err("connect error: {}", .{err});
            }
        }
        return err;
    };
    conn._pool = pool;
    // what the startup sent (ParameterStatus) isn't a change
    conn._session = .{};
    conn._track_session = opts.reset == .auto;
    conn._opened_at = Io.Timestamp.now(io, .awake);
    conn._idle_since = conn._opened_at;
    return conn;
}

const t = lib.testing;
test "Pool" {
    var pool = try Pool.init(t.io, t.allocator, .{
        .size = 2,
        .auth = t.authOpts(.{}),
        .connect_on_init_count = 1,
    });
    defer pool.deinit();

    {
        const c1 = try pool.acquire();
        defer pool.release(c1);
        _ = try c1.exec(
            \\ drop table if exists pool_test;
            \\ create table pool_test (id int not null)
        , .{});
    }

    // Concurrent tasks rather than threads, so that it works on any Io (on
    // std's Threaded they're threads anyway).
    var f1 = try t.io.concurrent(testPool, .{pool});
    var f2 = try t.io.concurrent(testPool, .{pool});
    var f3 = try t.io.concurrent(testPool, .{pool});

    f1.await(t.io);
    f2.await(t.io);
    f3.await(t.io);

    {
        const c1 = try pool.acquire();
        defer c1.release();

        const affected = try c1.exec("delete from pool_test", .{});
        try t.expectEqual(1500, affected.?);
    }
}

test "Pool: acquireOpts copies the server's error when a connect is refused" {
    var pool = try Pool.init(t.io, t.allocator, .{
        .size = 1,
        .auth = .{ .username = "pgz_user_scram_sha256", .password = "wrong", .database = "postgres" },
        .connect_on_init_count = 0,
    });
    defer pool.deinit();

    var ce = Pool.ConnectError{ .allocator = t.allocator };
    defer ce.deinit();
    try t.expectError(error.PG, pool.acquireOpts(.{ .connect_error = &ce }));
    try t.expectString("28P01", ce.err.?.code);
    try t.expectString("password authentication failed for user \"pgz_user_scram_sha256\"", ce.err.?.message);

    // the slot it reserved was given back
    try t.expectEqual(0, pool.stats().in_use);
    try t.expectError(error.PG, pool.acquire());
}

test "Pool: grows on demand" {
    var pool = try Pool.init(t.io, t.allocator, .{
        .size = 3,
        .auth = t.authOpts(.{}),
        .connect_on_init_count = 1,
    });
    defer pool.deinit();

    try expectStats(pool, .{ .size = 3, .available = 1, .missing = 2, .in_use = 0 });

    const c1 = try pool.acquire();
    try expectStats(pool, .{ .size = 3, .available = 0, .missing = 2, .in_use = 1 });

    // the pool is empty, so this opens a new connection
    const c2 = try pool.acquire();
    try expectStats(pool, .{ .size = 3, .available = 0, .missing = 1, .in_use = 2 });

    pool.release(c1);
    pool.release(c2);
    try expectStats(pool, .{ .size = 3, .available = 2, .missing = 1, .in_use = 0 });

    // idle connections are reused before opening more
    const c3 = try pool.acquire();
    defer pool.release(c3);
    try expectStats(pool, .{ .size = 3, .available = 1, .missing = 1, .in_use = 1 });
}

test "Pool: acquire times out when the pool is full" {
    var pool = try Pool.init(t.io, t.allocator, .{
        .size = 1,
        .auth = t.authOpts(.{}),
        .timeout = 50,
    });
    defer pool.deinit();

    const c1 = try pool.acquire();
    defer pool.release(c1);

    try t.expectError(error.Timeout, pool.acquire());
    try expectStats(pool, .{ .size = 1, .available = 0, .missing = 0, .in_use = 1 });
}

test "Pool: acquire returns the connect error and frees the slot" {
    const io = t.io;

    // bound but never listening, so connects are refused. Holding it for the
    // duration of the test keeps anything else off the port.
    const addr: Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var socket = try addr.bind(io, .{ .mode = .stream });
    var socket_open = true;
    defer if (socket_open) socket.close(io);
    if (comptime @import("builtin").os.tag.isDarwin()) {
        // macOS doesn't refuse a connection to a bound socket that isn't
        // listening, it lets it time out: give the port up instead.
        socket.close(io);
        socket_open = false;
    }

    var pool = try Pool.init(io, t.allocator, .{
        .size = 1,
        .connect_on_init_count = 0,
        .connect = .{ .port = socket.address.ip4.port, .host = "127.0.0.1" },
        .auth = t.authOpts(.{}),
    });
    defer pool.deinit();

    // nothing happens in the background: the error goes to the caller, and the
    // slot is free for the next attempt
    try t.expectError(error.ConnectionRefused, pool.acquire());
    try expectStats(pool, .{ .size = 1, .available = 0, .missing = 1, .in_use = 0 });
    try t.expectError(error.ConnectionRefused, pool.acquire());
    try expectStats(pool, .{ .size = 1, .available = 0, .missing = 1, .in_use = 0 });
}

test "Pool: a dirty connection is closed on release and replaced on demand" {
    var pool = try Pool.init(t.io, t.allocator, .{ .size = 1, .auth = t.authOpts(.{}) });
    defer pool.deinit();

    const c1 = try pool.acquire();
    c1._state = .fail;
    pool.release(c1);
    try expectStats(pool, .{ .size = 1, .available = 0, .missing = 1, .in_use = 0 });

    const c2 = try pool.acquire();
    defer pool.release(c2);
    try expectStats(pool, .{ .size = 1, .available = 0, .missing = 0, .in_use = 1 });
    _ = try c2.exec("select 1", .{});
}

test "Pool: reset clears the session between users" {
    var pool = try Pool.init(t.io, t.allocator, .{ .size = 1, .auth = t.authOpts(.{}), .reset = .{ .always = Pool.reset_sql }, .connect = .{ .statement_cache_size = 8 } });
    defer pool.deinit();

    {
        const c = try pool.acquire();
        defer pool.release(c);
        _ = try c.exec("select set_config('pgz.tenant', '42', false)", .{});
        _ = try c.exec("set search_path = pg_catalog", .{});
        _ = try c.exec("create temp table pgz_reset_tmp (id int)", .{});
        // and a cached statement, which must survive the reset
        var row = (try c.row("select $1::int", .{@as(i32, 7)})).?;
        defer row.deinit() catch {};
        try t.expectEqual(7, try row.get(i32, 0));
    }
    for (0..2) |_| {
        // the same connection: nothing of what the last user set is left
        const c = try pool.acquire();
        defer pool.release(c);
        {
            var row = (try c.row("select coalesce(current_setting('pgz.tenant', true), ''), current_setting('search_path'), to_regclass('pgz_reset_tmp') is null", .{})).?;
            defer row.deinit() catch {};
            try t.expectString("", try row.get([]const u8, 0));
            try t.expectString("\"$user\", public", try row.get([]const u8, 1));
            try t.expectEqual(true, try row.get(bool, 2));
        }
        var row = (try c.row("select $1::int", .{@as(i32, 8)})).?;
        defer row.deinit() catch {};
        try t.expectEqual(8, try row.get(i32, 0));
    }
    try expectStats(pool, .{ .size = 1, .available = 1, .missing = 0, .in_use = 0 });
}

test "Pool: .auto undoes each kind of session state, and only that" {
    {
        var c = try t.connect(.{});
        defer c.deinit();
        _ = c.exec(
            \\ drop table if exists pgz_reset_serial;
            \\ create table pgz_reset_serial (id serial primary key);
            \\ drop function if exists pgz_reset_tz();
            \\ create function pgz_reset_tz() returns text language sql as $$ select set_config('TimeZone', 'Asia/Tokyo', false) $$;
            \\ do $$ begin create role pgz_reset_role; exception when duplicate_object then null; end $$;
        , .{}) catch |err| {
            if (c.err) |e| std.debug.print("{s}\n", .{e.message});
            return err;
        };
    }

    var pool = try Pool.init(t.io, t.allocator, .{ .size = 1, .auth = t.authOpts(.{}), .reset = .auto, .connect = .{ .statement_cache_size = 8 } });
    defer pool.deinit();

    const Case = struct {
        // run by one user of the connection
        set: []const u8,
        // by the next one: true when nothing of `set` is left
        check: []const u8,
        // the connection is closed rather than reset
        closes: bool = false,
    };
    const cases = [_]Case{
        .{ .set = "set search_path = pg_catalog", .check = "select current_setting('search_path') = '\"$user\", public'" },
        .{ .set = "select set_config('pgz.tenant', '42', false)", .check = "select coalesce(current_setting('pgz.tenant', true), '') = ''" },
        .{ .set = "set role pgz_reset_role", .check = "select current_user = 'postgres'" },
        .{ .set = "set session authorization pgz_reset_role", .check = "select session_user = 'postgres' and current_user = 'postgres'" },
        .{ .set = "create temp table pgz_reset_tmp (id int)", .check = "select to_regclass('pgz_reset_tmp') is null" },
        .{ .set = "select pg_advisory_lock(4242)", .check = "select count(*) = 0 from pg_locks where locktype = 'advisory' and pid = pg_backend_pid()" },
        .{ .set = "listen pgz_reset_chan", .check = "select count(*) = 0 from pg_listening_channels()" },
        .{ .set = "declare pgz_reset_cur cursor with hold for select 1", .check = "select count(*) = 0 from pg_cursors where name = 'pgz_reset_cur'" },
        .{ .set = "do $$ begin perform set_config('pgz.tenant', '9', false); end $$", .check = "select coalesce(current_setting('pgz.tenant', true), '') = ''" },
        // not in the SQL: the server reports the changed setting
        .{ .set = "select pgz_reset_tz()", .check = "select current_setting('TimeZone') <> 'Asia/Tokyo'" },
        .{ .set = "prepare pgz_reset_q as select 1", .check = "select count(*) = 0 from pg_prepared_statements where name = 'pgz_reset_q'", .closes = true },
        .{ .set = "discard all", .check = "select true", .closes = true },
    };

    for (cases) |case| {
        errdefer std.debug.print("case: {s}\n", .{case.set});
        var pid: u32 = 0;
        {
            const c = try pool.acquire();
            defer pool.release(c);
            _ = c.exec(case.set, .{}) catch |err| {
                if (c.err) |e| std.debug.print("{s}\n", .{e.message});
                return err;
            };
            pid = c.backendPid();
        }
        {
            const c = try pool.acquire();
            defer pool.release(c);
            var row = (try c.row(case.check, .{})).?;
            defer row.deinit() catch {};
            try t.expectEqual(true, try row.get(bool, 0));
            try t.expectEqual(case.closes, c.backendPid() != pid);
        }
    }

    // lastval(): the next user can't see the id the last one got
    {
        const c = try pool.acquire();
        defer pool.release(c);
        _ = try c.exec("insert into pgz_reset_serial default values", .{});
    }
    {
        const c = try pool.acquire();
        defer pool.release(c);
        try t.expectError(error.PG, c.exec("select lastval()", .{}));
        try t.expectString("55000", c.err.?.code);
    }

    // a cached statement changes the session on every run, not only the
    // first, which prepared it
    for (0..3) |i| {
        {
            const c = try pool.acquire();
            defer pool.release(c);
            var row = (try c.row("select set_config('pgz.tenant', $1, false)", .{"7"})).?;
            defer row.deinit() catch {};
            try t.expectString("7", try row.get([]const u8, 0));
        }
        const c = try pool.acquire();
        defer pool.release(c);
        var row = (try c.row("select coalesce(current_setting('pgz.tenant', true), '')", .{})).?;
        defer row.deinit() catch {};
        try t.expectString("", try row.get([]const u8, 0));
        if (i > 0) try t.expectEqual(true, c.statementCacheStats().hits > 0);
    }
    try expectStats(pool, .{ .size = 1, .available = 1, .missing = 0, .in_use = 0 });
}

test "Pool: .auto sends no reset after what leaves the session as it was" {
    var pool = try Pool.init(t.io, t.allocator, .{ .size = 1, .auth = t.authOpts(.{}), .reset = .auto, .connect = .{ .statement_cache_size = 8 } });
    defer pool.deinit();

    const clean = [_][]const u8{
        "select 1",
        "select $1::int",
        "update simple_table set value = 'x' where false",
        "begin; set local work_mem = '8MB'; select set_config('pgz.tenant', '1', true); commit",
        "select pg_advisory_xact_lock(4243)",
    };
    var pid: u32 = 0;
    for (clean) |sql| {
        const c = try pool.acquire();
        if (pid == 0) pid = c.backendPid();
        try t.expectEqual(pid, c.backendPid());
        if (std.mem.indexOfScalar(u8, sql, '$') != null) {
            var row = (try c.row(sql, .{@as(i32, 1)})).?;
            row.deinit() catch {};
        } else {
            _ = try c.exec(sql, .{});
        }
        pool.release(c);
        // nothing was sent
        try t.expectEqual(false, c._reset_pending);
    }

    // and one after what does
    const c = try pool.acquire();
    _ = try c.exec("set search_path = pg_catalog", .{});
    pool.release(c);
    try t.expectEqual(true, c._reset_pending);
}

test "Pool: a connection released inside a transaction is closed, never handed on" {
    var pool = try Pool.init(t.io, t.allocator, .{ .size = 1, .auth = t.authOpts(.{}), .reset = .auto });
    defer pool.deinit();

    for ([_][]const u8{ "begin; set local work_mem = '1234kB'", "begin; set local work_mem = '1234kB'; select 1/0" }) |sql| {
        const c1 = try pool.acquire();
        const pid = c1.backendPid();
        _ = c1.exec(sql, .{}) catch {};
        pool.release(c1);
        try expectStats(pool, .{ .size = 1, .available = 0, .missing = 1, .in_use = 0 });

        // a new connection, in no transaction (an aborted one would refuse this)
        const c2 = try pool.acquire();
        defer pool.release(c2);
        try t.expectEqual(true, c2.backendPid() != pid);
        var row = (try c2.row("select current_setting('work_mem') <> '1234kB'", .{})).?;
        defer row.deinit() catch {};
        try t.expectEqual(true, try row.get(bool, 0));
    }
}

test "Pool: a connection whose reset fails is closed" {
    var pool = try Pool.init(t.io, t.allocator, .{ .size = 1, .auth = t.authOpts(.{}), .reset = .{ .always = "select 1/0" } });
    defer pool.deinit();

    const c1 = try pool.acquire();
    _ = try c1.exec("select 1", .{});
    pool.release(c1);

    const c2 = try pool.acquire();
    try t.expectError(error.SessionResetFailed, c2.exec("select 2", .{}));
    pool.release(c2);
    try expectStats(pool, .{ .size = 1, .available = 0, .missing = 1, .in_use = 0 });

    const c3 = try pool.acquire();
    defer pool.release(c3);
    _ = try c3.exec("select 3", .{});
}

test "Pool: a waiter opens a connection when a dirty one is released" {
    const io = t.io;

    var pool = try Pool.init(io, t.allocator, .{ .size = 1, .auth = t.authOpts(.{}) });
    defer pool.deinit();

    const c1 = try pool.acquire();

    const S = struct {
        fn run(p: *Pool) !void {
            // waits for c1, which comes back dirty, so it opens its own
            const c = try p.acquire();
            defer p.release(c);
            _ = try c.exec("select 1", .{});
        }
    };

    var future = try io.concurrent(S.run, .{pool});
    defer future.cancel(io) catch {};
    try std.Io.sleep(io, .fromMilliseconds(100), .awake);

    const start = std.Io.Timestamp.now(io, .awake);
    c1._state = .fail;
    pool.release(c1);

    // woken by the release, not by acquire's 10s timeout
    try future.await(io);
    const elapsed = start.durationTo(std.Io.Timestamp.now(io, .awake)).toNanoseconds();
    try t.expectEqual(true, elapsed < std.time.ns_per_s);
    try expectStats(pool, .{ .size = 1, .available = 1, .missing = 0, .in_use = 0 });
}

test "Pool: a canceled query doesn't reconnect in the canceled task" {
    const io = t.io;

    var pool = try Pool.init(io, t.allocator, .{ .size = 1, .auth = t.authOpts(.{}) });
    defer pool.deinit();

    // listening but never accepting: a reconnect to it would block in auth
    const addr: Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var server = try addr.listen(io, .{});
    defer server.deinit(io);
    pool._opts.connect.port = server.socket.address.ip4.port;

    const S = struct {
        fn run(p: *Pool) !void {
            _ = try p.exec("select pg_sleep(10)", .{});
        }
    };

    var future = try io.concurrent(S.run, .{pool});
    defer future.cancel(io) catch {};
    try std.Io.sleep(io, .fromMilliseconds(100), .awake);

    // the cancel lands on the query's read; release drops the connection
    // instead of opening a replacement
    const start = std.Io.Timestamp.now(io, .awake);
    const result = future.cancel(io);
    const elapsed = start.durationTo(std.Io.Timestamp.now(io, .awake)).toNanoseconds();

    try t.expectError(error.Canceled, result);
    try t.expectEqual(true, elapsed < std.time.ns_per_s);
    try expectStats(pool, .{ .size = 1, .available = 0, .missing = 1, .in_use = 0 });
}

test "Pool: max_lifetime" {
    var pool = try Pool.init(t.io, t.allocator, .{
        .size = 1,
        .auth = t.authOpts(.{}),
        .max_lifetime = 200,
    });
    defer pool.deinit();

    // an expired idle connection is replaced on acquire
    const pid1 = try backendPid(pool);
    try t.io.sleep(.fromMilliseconds(250), .awake);
    const pid2 = try backendPid(pool);
    try t.expectEqual(false, pid1 == pid2);
    try expectStats(pool, .{ .size = 1, .available = 1, .missing = 0, .in_use = 0 });

    // an expired connection is closed on release, and its slot freed
    const c = try pool.acquire();
    try t.expectEqual(pid2, t.scalar(c, "select pg_backend_pid()"));
    try t.io.sleep(.fromMilliseconds(250), .awake);
    pool.release(c);
    try expectStats(pool, .{ .size = 1, .available = 0, .missing = 1, .in_use = 0 });

    const pid3 = try backendPid(pool);
    try t.expectEqual(false, pid2 == pid3);
}

test "Pool: idle_timeout" {
    var pool = try Pool.init(t.io, t.allocator, .{
        .size = 3,
        .auth = t.authOpts(.{}),
        .idle_timeout = 200,
    });
    defer pool.deinit();
    try expectStats(pool, .{ .size = 3, .available = 3, .missing = 0, .in_use = 0 });

    // connections in use don't expire, and their idle time starts on release
    const c1 = try pool.acquire();
    const c2 = try pool.acquire();
    try t.io.sleep(.fromMilliseconds(250), .awake);
    pool.release(c1);
    pool.release(c2);
    // the one that stayed idle was closed by those releases
    try expectStats(pool, .{ .size = 3, .available = 2, .missing = 1, .in_use = 0 });

    // after the timeout, acquire closes them all and opens a fresh one
    try t.io.sleep(.fromMilliseconds(250), .awake);
    const c3 = try pool.acquire();
    try t.expectEqual(false, c3 == c1 or c3 == c2);
    try expectStats(pool, .{ .size = 3, .available = 0, .missing = 2, .in_use = 1 });
    pool.release(c3);
}

fn backendPid(pool: *Pool) !i32 {
    const c = try pool.acquire();
    defer pool.release(c);
    return t.scalar(c, "select pg_backend_pid()");
}

test "Pool: Release" {
    var pool = try Pool.init(t.io, t.allocator, .{
        .size = 2,
        .auth = .{
            .database = "postgres",
            .username = "postgres",
            .password = "postgres",
        },
    });
    defer pool.deinit();

    const c1 = try pool.acquire();
    c1._state = .query;
    pool.release(c1);
}

test "Pool: stats" {
    var pool = try Pool.init(t.io, t.allocator, .{
        .size = 3,
        .auth = t.authOpts(.{}),
    });
    defer pool.deinit();

    // Initial state: all connections available
    {
        const s = pool.stats();
        try t.expectEqual(3, s.size);
        try t.expectEqual(3, s.available);
        try t.expectEqual(0, s.missing);
        try t.expectEqual(0, s.in_use);
    }

    // Acquire one connection
    const c1 = try pool.acquire();
    {
        const s = pool.stats();
        try t.expectEqual(3, s.size);
        try t.expectEqual(2, s.available);
        try t.expectEqual(0, s.missing);
        try t.expectEqual(1, s.in_use);
    }

    // Acquire another
    const c2 = try pool.acquire();
    {
        const s = pool.stats();
        try t.expectEqual(3, s.size);
        try t.expectEqual(1, s.available);
        try t.expectEqual(0, s.missing);
        try t.expectEqual(2, s.in_use);
    }

    // Release one
    pool.release(c1);
    {
        const s = pool.stats();
        try t.expectEqual(3, s.size);
        try t.expectEqual(2, s.available);
        try t.expectEqual(0, s.missing);
        try t.expectEqual(1, s.in_use);
    }

    // Release the other
    pool.release(c2);
    {
        const s = pool.stats();
        try t.expectEqual(3, s.size);
        try t.expectEqual(3, s.available);
        try t.expectEqual(0, s.missing);
        try t.expectEqual(0, s.in_use);
    }
}

test "Pool: exec" {
    var pool = try Pool.init(t.io, t.allocator, .{ .size = 1, .auth = t.authOpts(.{}) });
    defer pool.deinit();

    {
        const n = try pool.exec("insert into simple_table values ($1), ($2), ($3)", .{ "pool_insert_args_a", "pool_insert_args_b", "pool_insert_args_c" });
        try t.expectEqual(3, n.?);
    }

    {
        // this makes sure the connection was returned to the pool
        const n = try pool.exec("insert into simple_table values ($1)", .{"pool_insert_args_a"});
        try t.expectEqual(1, n.?);
    }
}

test "Pool: Query/Row" {
    var pool = try Pool.init(t.io, t.allocator, .{ .size = 1, .auth = t.authOpts(.{}) });
    defer pool.deinit();

    {
        _ = try pool.exec("insert into all_types (id, col_int8, col_text) values ($1, $2, $3)", .{ 100, 1, "val-1" });
        _ = try pool.exec("insert into all_types (id, col_int8, col_text) values ($1, $2, $3)", .{ 101, 2, "val-2" });
    }

    for (0..3) |_| {
        var result = try pool.query("select col_int8, col_text from all_types where id = any($1)", .{[2]i32{ 100, 101 }});
        defer result.deinit();

        const row1 = (try result.nextUnsafe()) orelse unreachable;
        try t.expectEqual(1, row1.get(i64, 0));
        try t.expectString("val-1", row1.get([]u8, 1));

        const row2 = (try result.nextUnsafe()) orelse unreachable;
        try t.expectEqual(2, row2.get(i64, 0));
        try t.expectString("val-2", row2.get([]u8, 1));

        try t.expectEqual(null, result.nextUnsafe());
    }

    for (0..3) |_| {
        var row = try pool.rowUnsafe("select col_int8, col_text from all_types where id = $1", .{101}) orelse unreachable;
        defer row.deinit() catch {};

        try t.expectEqual(2, row.get(i64, 0));
        try t.expectString("val-2", row.get([]u8, 1));
    }
}

test "Pool: Row error" {
    var pool = try Pool.init(t.io, t.allocator, .{ .size = 1, .auth = t.authOpts(.{}) });
    defer pool.deinit();

    _ = try pool.rowUnsafe("insert into all_types (id) values ($1)", .{200});

    // This would segfault:
    // https://github.com/karlseguin/pg.zig/issues/34
    try t.expectError(error.PG, pool.rowUnsafe("insert into all_types (id) values ($1)", .{200}));

    try t.expectEqual(1, pool._available);
}

test "Pool: connection is released on every query error path" {
    // https://github.com/karlseguin/pg.zig/issues/130
    var pool = try Pool.init(t.io, t.allocator, .{ .size = 1, .auth = t.authOpts(.{}) });
    defer pool.deinit();

    // prepare (parse) fails
    try t.expectError(error.PG, pool.row("select from does_not_exist_130", .{}));
    try t.expectEqual(1, pool._available);
    try t.expectError(error.PG, pool.query("select from does_not_exist_130", .{}));
    try t.expectEqual(1, pool._available);
    try t.expectError(error.PG, pool.rowUnsafe("select from does_not_exist_130", .{}));
    try t.expectEqual(1, pool._available);

    // wrong number of parameters
    try t.expectError(error.WrongNumberOfParameters, pool.row("select $1::int", .{}));
    try t.expectEqual(1, pool._available);
    try t.expectError(error.WrongNumberOfParameters, pool.query("select $1::int", .{}));
    try t.expectEqual(1, pool._available);

    // execute fails (duplicate key)
    _ = try pool.exec("insert into all_types (id) values ($1)", .{201});
    try t.expectError(error.PG, pool.row("insert into all_types (id) values ($1)", .{201}));
    try t.expectEqual(1, pool._available);
    try t.expectError(error.PG, pool.query("insert into all_types (id) values ($1)", .{201}));
    try t.expectEqual(1, pool._available);

    // and the pool still works afterwards
    var row = (try pool.row("select $1::int", .{130})) orelse unreachable;
    defer row.deinit() catch {};
    try t.expectEqual(130, row.get(i32, 0));
    try t.expectEqual(0, pool._available);
}

test "Pool: init owns its connection strings" {
    // Heap-allocate the auth strings and free them right after init to prove the
    // pool kept its own copies and doesn't depend on the caller's `opts`.
    const username = try t.allocator.dupe(u8, "postgres");
    const password = try t.allocator.dupe(u8, "postgres");
    const database = try t.allocator.dupe(u8, "postgres");
    const host = try t.allocator.dupe(u8, "127.0.0.1");

    var pool = try Pool.init(t.io, t.allocator, .{
        .size = 2,
        .auth = .{ .username = username, .password = password, .database = database },
        .connect = .{ .host = host },
    });
    defer pool.deinit();

    t.allocator.free(username);
    t.allocator.free(password);
    t.allocator.free(database);
    t.allocator.free(host);

    try forceReconnect(pool);
}

test "Pool: init owns its startup parameters" {
    // Build the map on the heap and free it right after init; a reconnect has to
    // send the parameters from the pool's own copy.
    var params = std.StringHashMap([]const u8).init(t.allocator);
    const key = try t.allocator.dupe(u8, "statement_timeout");
    const value = try t.allocator.dupe(u8, "4321ms");
    try params.put(key, value);

    var pool = try Pool.init(t.io, t.allocator, .{
        .size = 1,
        .auth = .{ .username = "postgres", .password = "postgres", .database = "postgres", .startup_parameters = params },
    });
    defer pool.deinit();

    params.deinit();
    t.allocator.free(key);
    t.allocator.free(value);

    try forceReconnect(pool);

    const c = try pool.acquire();
    defer pool.release(c);
    var row = (try c.rowUnsafe("show statement_timeout", .{})) orelse unreachable;
    defer row.deinit() catch {};
    try t.expectString("4321ms", row.get([]const u8, 0));
}

test "Pool: initUri owns its connection strings" {
    // Heap-allocate the URI string and free it right after init to prove the pool
    // doesn't retain pointers into it. %73 == 's': decodes to "postgres" while also
    // forcing Uri to allocate a decoded copy into the parse arena.
    const uri_str = try t.allocator.dupe(u8, "postgresql://postgre%73:postgres@127.0.0.1/postgres");
    const uri = try std.Uri.parse(uri_str);

    var pool = try Pool.initUri(t.io, t.allocator, uri, .{ .size = 2 });
    defer pool.deinit();

    t.allocator.free(uri_str);

    try forceReconnect(pool);
}

fn testPool(p: *Pool) void {
    for (0..500) |i| {
        const conn = p.acquire() catch unreachable;
        _ = conn.exec("insert into pool_test (id) values ($1)", .{i}) catch unreachable;
        conn.release();
    }
}

// forces release() to discard the connection and acquire() to open a fresh one,
// exercising reconnect with the pool's stored auth strings.
fn forceReconnect(pool: *Pool) !void {
    const c1 = try pool.acquire();
    c1._state = .query;
    pool.release(c1);

    const c2 = try pool.acquire();
    defer pool.release(c2);
    _ = try c2.exec("select 1", .{});
}

fn expectStats(pool: *Pool, expected: Pool.Stats) !void {
    const actual = pool.stats();
    try t.expectEqual(expected.size, actual.size);
    try t.expectEqual(expected.available, actual.available);
    try t.expectEqual(expected.missing, actual.missing);
    try t.expectEqual(expected.in_use, actual.in_use);
}
