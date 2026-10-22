// What a statement may leave behind in a connection's session, judged from
// its SQL text, so that a pool can reset only the connections that need it
// (Pool.Opts.reset = .auto) and send only the statements that undo what was
// flagged.
//
// The scan reads tokens the way PostgreSQL's lexer splits them: it skips
// string literals ('...', E'...' with backslash escapes, $tag$...$tag$),
// comments (-- and nested /* */) and parameters ($1), compares keywords
// without regard to case, and treats a quoted identifier ("SET") as a name,
// never as a keyword. It errs on the side of flagging: a word it can't place
// counts as a change.
//
// Its limit: what a server-side function or trigger does is not in the
// statement's text. SELECT my_function() is clean even when the function
// calls set_config(..., false); DO and CALL are flagged (they run procedural
// code), plain function calls are not. Use Pool.Opts.reset = .{ .always = ...
// } when functions change session state.
const std = @import("std");

pub const Effect = packed struct(u8) {
    // SET (not LOCAL), RESET, set_config(..., not true), SET ROLE, SET
    // SESSION AUTHORIZATION, or a ParameterStatus from the server.
    settings: bool = false,
    // DECLARE ... WITH HOLD
    cursors: bool = false,
    // CREATE TEMP/TEMPORARY, SELECT INTO TEMP, anything in pg_temp
    temp: bool = false,
    // pg_advisory_lock(_shared), pg_try_advisory_lock(_shared)
    advisory: bool = false,
    // LISTEN
    listen: bool = false,
    // currval()/lastval() state: nextval, setval, and INSERT, MERGE, COPY or
    // DEFAULT, which may call nextval for a serial column
    sequences: bool = false,
    // DO, CALL: procedural code, the full reset
    unknown: bool = false,
    // PREPARE, DEALLOCATE, DISCARD ALL, LOAD, dblink_connect: state a reset
    // can't undo without breaking the connection's statement cache, or can't
    // undo at all. The pool closes the connection.
    close: bool = false,

    pub fn any(self: Effect) bool {
        return @as(u8, @bitCast(self)) != 0;
    }

    pub fn merge(self: Effect, other: Effect) Effect {
        return @bitCast(@as(u8, @bitCast(self)) | @as(u8, @bitCast(other)));
    }
};

// DISCARD ALL without what it would undo for the statement cache
// (DEALLOCATE ALL) or what a hot standby refuses (UNLISTEN).
pub const full_reset = "CLOSE ALL; SET SESSION AUTHORIZATION DEFAULT; RESET ALL; SELECT pg_advisory_unlock_all(); DISCARD TEMP; DISCARD SEQUENCES";

// The longest SQL resetSql writes.
pub const max_reset_len = full_reset.len + "; UNLISTEN *".len;

// The statements that undo `effect` (which must not ask for `close`), in
// DISCARD ALL's order, written into `buf`. Empty when there is nothing to
// undo.
pub fn resetSql(effect: Effect, buf: *[max_reset_len]u8) []const u8 {
    var w: std.Io.Writer = .fixed(buf);
    if (effect.unknown) {
        w.writeAll(full_reset) catch unreachable;
        if (effect.listen) w.writeAll("; UNLISTEN *") catch unreachable;
        return w.buffered();
    }
    const parts = [_]struct { bool, []const u8 }{
        .{ effect.cursors, "CLOSE ALL" },
        .{ effect.settings, "SET SESSION AUTHORIZATION DEFAULT; RESET ALL" },
        .{ effect.listen, "UNLISTEN *" },
        .{ effect.advisory, "SELECT pg_advisory_unlock_all()" },
        .{ effect.temp, "DISCARD TEMP" },
        .{ effect.sequences, "DISCARD SEQUENCES" },
    };
    for (parts) |p| {
        if (!p[0]) continue;
        if (w.end > 0) w.writeAll("; ") catch unreachable;
        w.writeAll(p[1]) catch unreachable;
    }
    return w.buffered();
}

pub fn scan(sql: []const u8) Effect {
    var s: Scanner = .{ .sql = sql };
    return s.run();
}

const Word = enum {
    // statement keywords (only as a statement's first word)
    set,
    reset,
    listen,
    declare,
    prepare,
    deallocate,
    discard,
    load,
    do,
    call,
    // words the statement rules look at
    local,
    transaction,
    constraints,
    all,
    hold,
    create,
    replace,
    global,
    into,
    temp,
    temporary,
    true,
    // anywhere
    set_config,
    pg_advisory_lock,
    pg_advisory_lock_shared,
    pg_try_advisory_lock,
    pg_try_advisory_lock_shared,
    nextval,
    setval,
    insert,
    merge,
    copy,
    default,
    dblink_connect,
    dblink_connect_u,
    // any other word
    other,

    const max_len = blk: {
        var n = 0;
        for (std.meta.fieldNames(Word)) |name| n = @max(n, name.len);
        break :blk n;
    };

    // `text` an unquoted word: compared without regard to (ASCII) case.
    fn of(text: []const u8) Word {
        if (text.len > max_len) return .other;
        var lower: [max_len]u8 = undefined;
        const l = std.ascii.lowerString(&lower, text);
        return std.meta.stringToEnum(Word, l) orelse .other;
    }
};

const Scanner = struct {
    sql: []const u8,
    pos: usize = 0,
    effect: Effect = .{},

    // the statement so far
    words: u32 = 0, // tokens seen in this statement (words, names, literals)
    first: Word = .other,
    prev: Word = .other, // the last unquoted word, .other after anything else
    declare_hold: bool = false,

    // set_config( ... ): its third argument decides
    config_depth: u32 = 0, // paren depth inside the call; 0: not in one
    config_commas: u32 = 0,
    config_third: u32 = 0, // tokens of the third argument
    config_local: bool = false, // the third argument's token is `true`
    config_open: bool = false, // `set_config` was the last token, `(` must follow

    fn run(self: *Scanner) Effect {
        const sql = self.sql;
        while (self.pos < sql.len) {
            const c = sql[self.pos];
            switch (c) {
                ' ', '\t', '\n', '\r', '\x0b', '\x0c' => self.pos += 1,
                '-' => if (self.peek(1) == '-') self.lineComment() else self.punct(c),
                '/' => if (self.peek(1) == '*') self.blockComment() else self.punct(c),
                '\'' => {
                    self.pos += 1;
                    self.string(false);
                    self.token(.other);
                },
                '"' => {
                    const text = self.quoted();
                    self.quotedName(text);
                },
                '$' => self.dollar(),
                '0'...'9' => {
                    while (self.pos < sql.len and (std.ascii.isAlphanumeric(sql[self.pos]) or sql[self.pos] == '_' or sql[self.pos] == '.')) self.pos += 1;
                    self.token(.other);
                },
                ';' => {
                    self.pos += 1;
                    self.endStatement();
                    self.* = .{ .sql = self.sql, .pos = self.pos, .effect = self.effect };
                },
                else => if (isIdentStart(c)) self.word() else self.punct(c),
            }
        }
        self.endStatement();
        return self.effect;
    }

    fn peek(self: *const Scanner, n: usize) u8 {
        const i = self.pos + n;
        return if (i < self.sql.len) self.sql[i] else 0;
    }

    fn lineComment(self: *Scanner) void {
        const nl = std.mem.indexOfScalarPos(u8, self.sql, self.pos, '\n') orelse self.sql.len;
        self.pos = nl;
    }

    // PostgreSQL's block comments nest.
    fn blockComment(self: *Scanner) void {
        const sql = self.sql;
        var depth: usize = 0;
        while (self.pos < sql.len) {
            if (sql[self.pos] == '/' and self.peek(1) == '*') {
                depth += 1;
                self.pos += 2;
            } else if (sql[self.pos] == '*' and self.peek(1) == '/') {
                depth -= 1;
                self.pos += 2;
                if (depth == 0) return;
            } else self.pos += 1;
        }
    }

    // After the opening quote. '' is a quote; with `escapes` (E'...'), so is \'.
    fn string(self: *Scanner, escapes: bool) void {
        const sql = self.sql;
        while (self.pos < sql.len) {
            const c = sql[self.pos];
            if (escapes and c == '\\') {
                self.pos += 2;
            } else if (c == '\'') {
                if (self.peek(1) == '\'') {
                    self.pos += 2;
                } else {
                    self.pos += 1;
                    return;
                }
            } else self.pos += 1;
        }
    }

    // A quoted identifier; returns what is between the quotes ("" left as is).
    fn quoted(self: *Scanner) []const u8 {
        const sql = self.sql;
        self.pos += 1;
        const start = self.pos;
        while (self.pos < sql.len) {
            if (sql[self.pos] == '"') {
                if (self.peek(1) == '"') {
                    self.pos += 2;
                    continue;
                }
                const text = sql[start..self.pos];
                self.pos += 1;
                return text;
            }
            self.pos += 1;
        }
        return sql[start..];
    }

    // $1 (a parameter), $tag$...$tag$ or $$...$$ (a string), else a lone $.
    fn dollar(self: *Scanner) void {
        const sql = self.sql;
        if (std.ascii.isDigit(self.peek(1))) {
            self.pos += 1;
            while (self.pos < sql.len and std.ascii.isDigit(sql[self.pos])) self.pos += 1;
            self.token(.other);
            return;
        }
        var end = self.pos + 1;
        if (end < sql.len and isIdentStart(sql[end])) {
            end += 1;
            while (end < sql.len and isTagChar(sql[end])) end += 1;
        }
        if (end >= sql.len or sql[end] != '$') {
            self.punct('$');
            return;
        }
        const tag = sql[self.pos .. end + 1];
        const body = end + 1;
        if (std.mem.indexOfPos(u8, sql, body, tag)) |close| {
            self.pos = close + tag.len;
        } else {
            self.pos = sql.len;
        }
        self.token(.other);
    }

    fn word(self: *Scanner) void {
        const sql = self.sql;
        const start = self.pos;
        while (self.pos < sql.len and isIdentChar(sql[self.pos])) self.pos += 1;
        const text = sql[start..self.pos];
        if (self.pos < sql.len and text.len == 1) {
            const p = text[0] | 0x20;
            // E'...': backslash escapes
            if (p == 'e' and sql[self.pos] == '\'') {
                self.pos += 1;
                self.string(true);
                self.token(.other);
                return;
            }
            // U&'...', U&"..."
            if (p == 'u' and sql[self.pos] == '&' and (self.peek(1) == '\'' or self.peek(1) == '"')) {
                self.pos += 1;
                return;
            }
        }
        // pg_temp, pg_temp_3: the session's temporary schema
        if (startsWithIgnoreCase(text, "pg_temp")) self.effect.temp = true;
        self.token(Word.of(text));
    }

    // A quoted identifier: never a keyword, but it can name a function or
    // the temporary schema (case-sensitively).
    fn quotedName(self: *Scanner, text: []const u8) void {
        if (std.mem.startsWith(u8, text, "pg_temp")) self.effect.temp = true;
        const w = std.meta.stringToEnum(Word, text) orelse .other;
        const is_function = switch (w) {
            .set_config, .pg_advisory_lock, .pg_advisory_lock_shared, .pg_try_advisory_lock, .pg_try_advisory_lock_shared, .nextval, .setval, .dblink_connect, .dblink_connect_u => true,
            else => false,
        };
        self.token(if (is_function) w else .other);
        // after the token, so that "temp" is no keyword for the next word
        self.prev = .other;
    }

    fn punct(self: *Scanner, c: u8) void {
        self.pos += 1;
        if (self.config_open) {
            self.config_open = false;
            if (c == '(') {
                self.config_depth = 1;
                return;
            }
            // set_config not called here: count it
            self.effect.settings = true;
        }
        if (self.config_depth > 0) {
            switch (c) {
                '(' => self.config_depth += 1,
                ')' => {
                    self.config_depth -= 1;
                    if (self.config_depth == 0) self.endSetConfig();
                },
                ',' => if (self.config_depth == 1) {
                    self.config_commas += 1;
                },
                else => if (self.config_depth == 1 and self.config_commas == 2) {
                    // part of an expression: not a plain `true`
                    self.config_third += 2;
                },
            }
        }
        self.prev = .other;
    }

    fn endSetConfig(self: *Scanner) void {
        if (!(self.config_commas == 2 and self.config_third == 1 and self.config_local)) {
            self.effect.settings = true;
        }
        self.config_commas = 0;
        self.config_third = 0;
        self.config_local = false;
    }

    fn token(self: *Scanner, w: Word) void {
        if (self.config_open) {
            // set_config not followed by `(`
            self.config_open = false;
            self.effect.settings = true;
        }
        if (self.config_depth == 1 and self.config_commas == 2) {
            self.config_third += 1;
            self.config_local = w == .true;
        }

        const e = &self.effect;
        if (self.words == 0) {
            self.first = w;
            switch (w) {
                .reset => e.settings = true,
                .listen => e.listen = true,
                .prepare, .deallocate, .load => e.close = true,
                .do, .call => e.unknown = true,
                else => {},
            }
        } else if (self.words == 1) {
            switch (self.first) {
                // SET LOCAL, SET TRANSACTION and SET CONSTRAINTS last until
                // the transaction ends; any other SET is for the session
                .set => switch (w) {
                    .local, .transaction, .constraints => {},
                    else => e.settings = true,
                },
                .discard => if (w == .all) {
                    e.close = true;
                },
                else => {},
            }
        }
        if (self.first == .declare and w == .hold) e.cursors = true;

        switch (w) {
            .temp, .temporary => switch (self.prev) {
                .create, .replace, .global, .local, .into => e.temp = true,
                else => {},
            },
            .set_config => {
                if (self.config_depth > 0) {
                    // nested: don't try
                    e.settings = true;
                } else self.config_open = true;
            },
            .pg_advisory_lock, .pg_advisory_lock_shared, .pg_try_advisory_lock, .pg_try_advisory_lock_shared => e.advisory = true,
            .nextval, .setval, .insert, .merge, .copy, .default => e.sequences = true,
            .dblink_connect, .dblink_connect_u => e.close = true,
            else => {},
        }
        self.words += 1;
        self.prev = w;
    }

    fn endStatement(self: *Scanner) void {
        // `SET` alone, or a set_config left open: count it
        if (self.words == 1 and self.first == .set) self.effect.settings = true;
        if (self.config_open or self.config_depth > 0) self.effect.settings = true;
    }
};

fn isIdentStart(c: u8) bool {
    return std.ascii.isAlphabetic(c) or c == '_' or c >= 0x80;
}

fn isIdentChar(c: u8) bool {
    return isIdentStart(c) or std.ascii.isDigit(c) or c == '$';
}

fn isTagChar(c: u8) bool {
    return isIdentStart(c) or std.ascii.isDigit(c);
}

fn startsWithIgnoreCase(text: []const u8, prefix: []const u8) bool {
    return text.len >= prefix.len and std.ascii.eqlIgnoreCase(text[0..prefix.len], prefix);
}

fn expectEffect(sql: []const u8, expected: Effect) !void {
    const got = scan(sql);
    if (got != expected) {
        std.debug.print("scan({s}): {any}, expected {any}\n", .{ sql, got, expected });
        return error.TestUnexpectedResult;
    }
}

test "session.scan: clean statements" {
    const clean = [_][]const u8{
        "",
        "select 1",
        "SELECT id, randomNumber FROM world WHERE id = $1",
        "update world set randomnumber = $1 where id = $2",
        "UPDATE t SET a = 1, b = 'x' WHERE c IN (SELECT c FROM u)",
        "delete from t where id = $1",
        "begin",
        "commit",
        "rollback",
        "SET LOCAL search_path = app",
        "set local role reader",
        "SET LOCAL SESSION AUTHORIZATION bob",
        "SET TRANSACTION ISOLATION LEVEL SERIALIZABLE",
        "set constraints all deferred",
        "select set_config('app.tenant', $1, true)",
        "SELECT pg_catalog.set_config('app.tenant', '42', TRUE)",
        "select set_config('a', concat('x', 'y'), true), 1",
        "select pg_advisory_xact_lock(1)",
        "SELECT pg_try_advisory_xact_lock_shared($1)",
        "select pg_advisory_unlock(1)",
        "select currval('s')",
        "SELECT temp FROM weather WHERE temp > 20",
        "declare c cursor for select 1",
        "close all",
        "fetch 10 from c",
        "discard temp",
        "DISCARD PLANS",
        "explain select 1",
        "show search_path",
        "notify chan, 'set role admin'",
        "select current_setting('search_path')",
        "with x as (select 1) select * from x",
        "lock table t in exclusive mode",
        // a keyword only as a statement's first word
        "select listen, prepare, \"do\", call from t",
    };
    for (clean) |sql| try expectEffect(sql, .{});
}

test "session.scan: what changes the session" {
    try expectEffect("SET search_path = app", .{ .settings = true });
    try expectEffect("set session search_path to app", .{ .settings = true });
    try expectEffect("SeT TimeZone = 'UTC'", .{ .settings = true });
    try expectEffect("set role admin", .{ .settings = true });
    try expectEffect("SET SESSION AUTHORIZATION bob", .{ .settings = true });
    try expectEffect("set session characteristics as transaction read only", .{ .settings = true });
    try expectEffect("set \"my.var\" = 1", .{ .settings = true });
    try expectEffect("reset role", .{ .settings = true });
    try expectEffect("RESET ALL", .{ .settings = true });
    try expectEffect("select set_config('app.tenant', '42', false)", .{ .settings = true });
    try expectEffect("select set_config('app.tenant', $1, $2)", .{ .settings = true });
    try expectEffect("select set_config('a', 'b', true and false)", .{ .settings = true });
    try expectEffect("select set_config('a', 'b', 'true')", .{ .settings = true });
    try expectEffect("select set_config('a', 'b')", .{ .settings = true });
    try expectEffect("select \"set_config\"('a', 'b', false)", .{ .settings = true });
    try expectEffect("select set_config('a', set_config('b', 'c', true), true)", .{ .settings = true });
    try expectEffect("select array_agg(set_config) from t", .{ .settings = true });

    try expectEffect("create temp table t (id int)", .{ .temp = true });
    try expectEffect("CREATE TEMPORARY TABLE t AS SELECT 1", .{ .temp = true });
    try expectEffect("create global temporary table t (id int)", .{ .temp = true });
    try expectEffect("create local temp table t (id int)", .{ .temp = true });
    try expectEffect("create or replace temp view v as select 1", .{ .temp = true });
    try expectEffect("create temp sequence s", .{ .temp = true });
    try expectEffect("select * into temp t from u", .{ .temp = true });
    try expectEffect("create table pg_temp.t (id int)", .{ .temp = true });
    try expectEffect("create function \"pg_temp\".f() returns int language sql as 'select 1'", .{ .temp = true });

    try expectEffect("select pg_advisory_lock(1)", .{ .advisory = true });
    try expectEffect("SELECT pg_try_advisory_lock($1, $2)", .{ .advisory = true });
    try expectEffect("select pg_advisory_lock_shared(1)", .{ .advisory = true });
    try expectEffect("select pg_catalog.pg_try_advisory_lock_shared(1)", .{ .advisory = true });

    try expectEffect("listen jobs", .{ .listen = true });
    try expectEffect("declare c cursor with hold for select 1", .{ .cursors = true });
    try expectEffect("DECLARE c NO SCROLL CURSOR WITH HOLD FOR SELECT 1", .{ .cursors = true });

    try expectEffect("insert into t (a) values (1) returning id", .{ .sequences = true });
    try expectEffect("with x as (insert into t default values returning id) select id from x", .{ .sequences = true });
    try expectEffect("select nextval('s')", .{ .sequences = true });
    try expectEffect("select setval('s', 10)", .{ .sequences = true });
    try expectEffect("update t set id = default where false", .{ .sequences = true });
    try expectEffect("merge into t using u on t.id = u.id when not matched then insert values (u.id)", .{ .sequences = true });
    try expectEffect("copy t from stdin", .{ .sequences = true });

    try expectEffect("do $$ begin perform 1; end $$", .{ .unknown = true });
    try expectEffect("CALL p(1)", .{ .unknown = true });

    try expectEffect("prepare q as select 1", .{ .close = true });
    try expectEffect("deallocate all", .{ .close = true });
    try expectEffect("discard all", .{ .close = true });
    try expectEffect("load 'auto_explain'", .{ .close = true });
    try expectEffect("select dblink_connect('c', 'dbname=x')", .{ .close = true });
}

test "session.scan: strings, names and comments are not keywords" {
    // in a string
    try expectEffect("select 'set role admin; create temp table t()'", .{});
    try expectEffect("select 'it''s; set role admin'", .{});
    try expectEffect("select E'it\\'s; set role admin'", .{});
    try expectEffect("select e'\\\\'; set role admin", .{ .settings = true });
    // a backslash ends no plain string (standard_conforming_strings)
    try expectEffect("select 'a\\'; set role admin", .{ .settings = true });
    try expectEffect("select $$; set role admin; $$, $tag$ $$ set role x $tag$", .{});
    try expectEffect("select $a$ $b$ set role x $b$ $a$", .{});
    try expectEffect("select U&'set role x'", .{});
    // a quoted identifier
    try expectEffect("\"SET\" role admin", .{});
    try expectEffect("select \"set_config(\" from t", .{});
    try expectEffect("select \"pg_advisory_lock\"(1)", .{ .advisory = true });
    try expectEffect("select \"PG_ADVISORY_LOCK\"(1)", .{});
    try expectEffect("select \"a\"\"; set role x\"", .{});
    // in a comment
    try expectEffect("-- set role admin\nselect 1", .{});
    try expectEffect("/* set role admin */ select 1", .{});
    try expectEffect("/* nested /* set */ role */ select 1", .{});
    try expectEffect("/* set */ set role admin", .{ .settings = true });
    try expectEffect("  \n-- a comment\nSET search_path = app", .{ .settings = true });
    // identifiers that contain a keyword
    try expectEffect("select reset_at, settings, temp_c from t", .{});
    try expectEffect("select my$set from t", .{});
    // parameters
    try expectEffect("select $1, $2::text", .{});
}

test "session.scan: each statement of several" {
    try expectEffect("select 1; set role admin", .{ .settings = true });
    try expectEffect("set local role a; select 1", .{});
    try expectEffect("begin; set local role a; commit", .{});
    try expectEffect("select 1;set search_path=x;listen c", .{ .settings = true, .listen = true });
    try expectEffect("insert into t values (1); select pg_advisory_lock(1); create temp table x()", .{ .sequences = true, .advisory = true, .temp = true });
    try expectEffect("set", .{ .settings = true });
    try expectEffect("select set_config(", .{ .settings = true });
}

test "session.resetSql" {
    var buf: [max_reset_len]u8 = undefined;
    try std.testing.expectEqualStrings("", resetSql(.{}, &buf));
    try std.testing.expectEqualStrings("SET SESSION AUTHORIZATION DEFAULT; RESET ALL", resetSql(.{ .settings = true }, &buf));
    try std.testing.expectEqualStrings("DISCARD SEQUENCES", resetSql(.{ .sequences = true }, &buf));
    try std.testing.expectEqualStrings("CLOSE ALL; UNLISTEN *; DISCARD TEMP", resetSql(.{ .cursors = true, .listen = true, .temp = true }, &buf));
    try std.testing.expectEqualStrings(full_reset, resetSql(.{ .unknown = true, .settings = true }, &buf));
    try std.testing.expectEqualStrings(full_reset ++ "; UNLISTEN *", resetSql(.{ .unknown = true, .listen = true }, &buf));
    const everything: Effect = .{ .settings = true, .cursors = true, .temp = true, .advisory = true, .listen = true, .sequences = true };
    try std.testing.expectEqualStrings("CLOSE ALL; SET SESSION AUTHORIZATION DEFAULT; RESET ALL; UNLISTEN *; SELECT pg_advisory_unlock_all(); DISCARD TEMP; DISCARD SEQUENCES", resetSql(everything, &buf));
}
