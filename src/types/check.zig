// Checks a value the server sent in binary format against what its type
// allows, before any decoder reads it: a fixed-size type has exactly its
// size, a numeric's digit count matches its length, an array's elements fit
// in it. The decoders read without checking, so a value from a broken or
// hostile server must not reach them unchecked.
const std = @import("std");

pub const Error = error{InvalidDataRow};

// How deep a record (anonymous composite) may nest in another before it is
// refused.
const max_record_depth = 16;

pub fn value(oid: i32, data: []const u8) Error!void {
    return check(oid, data, 0);
}

fn check(oid: i32, data: []const u8, depth: usize) Error!void {
    if (fixedSize(oid)) |size| {
        if (data.len != size) return error.InvalidDataRow;
        return;
    }
    switch (oid) {
        numeric => return checkNumeric(data),
        cidr, inet => return checkInet(data),
        jsonb => if (data.len == 0 or data[0] != 1) return error.InvalidDataRow,
        record => return checkRecord(data, depth),
        else => if (arrayElement(oid)) |element| return checkArray(data, element, depth),
    }
}

const numeric = 1700;
const cidr = 650;
const inet = 869;
const jsonb = 3802;
const record = 2249;

// The size of each fixed-size type pg.zig asks for in binary.
fn fixedSize(oid: i32) ?usize {
    return switch (oid) {
        16, 18 => 1, // bool, "char"
        21 => 2, // int2
        23, 26, 28, 700, 1082 => 4, // int4, oid, xid, float4, date
        20, 701, 790, 1083, 1114, 1184, 3220, 5069 => 8, // int8, float8, money, time, timestamp, timestamptz, pg_lsn, xid8
        1266 => 12, // timetz
        1186, 2950 => 16, // interval, uuid
        829 => 6, // macaddr
        774 => 8, // macaddr8
        else => null,
    };
}

// The element type of the array types whose element pg.zig knows; null for
// other types. An array of an element type not listed here is still checked
// for its structure, with its elements unchecked (anyArray).
fn arrayElement(oid: i32) ?i32 {
    return switch (oid) {
        1000 => 16, // bool[]
        1001 => 17, // bytea[]
        1002 => 18, // "char"[]
        1005 => 21, // int2[]
        1007 => 23, // int4[]
        1016 => 20, // int8[]
        1021 => 700, // float4[]
        1022 => 701, // float8[]
        1028 => 26, // oid[]
        1011 => 28, // xid[]
        1182 => 1082, // date[]
        1183 => 1083, // time[]
        1115 => 1114, // timestamp[]
        1185 => 1184, // timestamptz[]
        1187 => 1186, // interval[]
        1270 => 1266, // timetz[]
        1231 => numeric, // numeric[]
        651 => cidr, // cidr[]
        1041 => inet, // inet[]
        1040 => 829, // macaddr[]
        775 => 774, // macaddr8[]
        2951 => 2950, // uuid[]
        199 => 114, // json[]
        3807 => jsonb, // jsonb[]
        1009 => 25, // text[]
        1014 => 1042, // bpchar[]
        1015 => 1043, // varchar[]
        791 => 790, // money[]
        3221 => 3220, // pg_lsn[]
        271 => 5069, // xid8[]
        2287 => record, // record[]
        else => null,
    };
}

fn checkNumeric(data: []const u8) Error!void {
    if (data.len < 8) return error.InvalidDataRow;
    const ndigits = std.mem.readInt(u16, data[0..2], .big);
    if (data.len - 8 != @as(usize, ndigits) * 2) return error.InvalidDataRow;
    switch (std.mem.readInt(u16, data[4..6], .big)) {
        0x0000, 0x4000, 0xc000, 0xd000, 0xf000 => {},
        else => return error.InvalidDataRow,
    }
    // PostgreSQL's NUMERIC_DSCALE_MAX
    if (std.mem.readInt(u16, data[6..8], .big) > 0x3fff) return error.InvalidDataRow;
    var digits = data[8..];
    while (digits.len > 0) : (digits = digits[2..]) {
        const d = std.mem.readInt(i16, digits[0..2], .big);
        if (d < 0 or d > 9999) return error.InvalidDataRow;
    }
}

fn checkInet(data: []const u8) Error!void {
    // family, netmask, is_cidr, address length, then the address
    if (data.len != 8 and data.len != 20) return error.InvalidDataRow;
    if (data[3] != data.len - 4) return error.InvalidDataRow;
}

// ndim, has_nulls, element type, a (length, lower bound) per dimension, then
// each element as a length (-1 for NULL) and its bytes.
fn checkArray(data: []const u8, element: i32, depth: usize) Error!void {
    if (data.len < 12) return error.InvalidDataRow;
    const ndim = std.mem.readInt(i32, data[0..4], .big);
    const has_nulls = std.mem.readInt(i32, data[4..8], .big);
    // PostgreSQL's MAXDIM
    if (ndim < 0 or ndim > 6) return error.InvalidDataRow;
    if (has_nulls != 0 and has_nulls != 1) return error.InvalidDataRow;
    if (std.mem.readInt(i32, data[8..12], .big) != element) return error.InvalidDataRow;

    const dims_end = 12 + @as(usize, @intCast(ndim)) * 8;
    if (data.len < dims_end) return error.InvalidDataRow;
    var count: usize = if (ndim == 0) 0 else 1;
    var pos: usize = 12;
    while (pos < dims_end) : (pos += 8) {
        const len = std.mem.readInt(i32, data[pos..][0..4], .big);
        if (len < 0) return error.InvalidDataRow;
        count = std.math.mul(usize, count, @intCast(len)) catch return error.InvalidDataRow;
    }

    for (0..count) |_| {
        if (data.len - pos < 4) return error.InvalidDataRow;
        const len = std.mem.readInt(i32, data[pos..][0..4], .big);
        pos += 4;
        if (len == -1) {
            if (has_nulls == 0) return error.InvalidDataRow;
            continue;
        }
        if (len < 0 or len > data.len - pos) return error.InvalidDataRow;
        const end = pos + @as(usize, @intCast(len));
        try check(element, data[pos..end], depth);
        pos = end;
    }
    if (pos != data.len) return error.InvalidDataRow;
}

// A record: its field count, then for each field its type, a length (-1 for
// NULL) and its bytes.
fn checkRecord(data: []const u8, depth: usize) Error!void {
    if (depth >= max_record_depth) return error.InvalidDataRow;
    if (data.len < 4) return error.InvalidDataRow;
    const fields = std.mem.readInt(i32, data[0..4], .big);
    if (fields < 0) return error.InvalidDataRow;
    var pos: usize = 4;
    for (0..@intCast(fields)) |_| {
        if (data.len - pos < 8) return error.InvalidDataRow;
        const oid = std.mem.readInt(i32, data[pos..][0..4], .big);
        const len = std.mem.readInt(i32, data[pos + 4 ..][0..4], .big);
        pos += 8;
        if (len == -1) continue;
        if (len < 0 or len > data.len - pos) return error.InvalidDataRow;
        const end = pos + @as(usize, @intCast(len));
        try check(oid, data[pos..end], depth + 1);
        pos = end;
    }
    if (pos != data.len) return error.InvalidDataRow;
}

const t = std.testing;

test "check: fixed sizes" {
    try value(23, &.{ 0, 0, 0, 1 });
    try t.expectError(error.InvalidDataRow, value(23, &.{ 0, 1 }));
    try t.expectError(error.InvalidDataRow, value(20, &.{ 0, 0, 0, 1 }));
    try t.expectError(error.InvalidDataRow, value(16, &.{}));
    try t.expectError(error.InvalidDataRow, value(2950, &.{ 1, 2, 3 }));
    // types with no fixed size, or unknown, pass
    try value(25, "anything");
    try value(17, "");
    try value(123456, "?");
}

test "check: numeric" {
    try value(numeric, &.{ 0, 1, 0, 0, 0, 0, 0, 0, 0, 7 });
    try value(numeric, &.{ 0, 0, 0, 0, 0xc0, 0, 0, 0 }); // NaN
    // a digit count that disagrees with the length
    try t.expectError(error.InvalidDataRow, value(numeric, &.{ 0, 2, 0, 0, 0, 0, 0, 0, 0, 7 }));
    try t.expectError(error.InvalidDataRow, value(numeric, &.{ 0, 0, 0, 0, 0, 0, 0, 0, 0 }));
    // a digit over 9999, a negative digit, an unknown sign
    try t.expectError(error.InvalidDataRow, value(numeric, &.{ 0, 1, 0, 0, 0, 0, 0, 0, 0x27, 0x10 }));
    try t.expectError(error.InvalidDataRow, value(numeric, &.{ 0, 1, 0, 0, 0, 0, 0, 0, 0xff, 0xff }));
    try t.expectError(error.InvalidDataRow, value(numeric, &.{ 0, 0, 0, 0, 0x12, 0, 0, 0 }));
    try t.expectError(error.InvalidDataRow, value(numeric, &.{1}));
}

test "check: arrays" {
    // int4[] {1, NULL}
    const good = [_]u8{ 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 23, 0, 0, 0, 2, 0, 0, 0, 1, 0, 0, 0, 4, 0, 0, 0, 1, 255, 255, 255, 255 };
    try value(1007, &good);
    // empty
    try value(1007, &.{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 23 });

    var bad = good;
    // a NULL with has_nulls 0
    bad[7] = 0;
    try t.expectError(error.InvalidDataRow, value(1007, &bad));
    // another element type than the column's
    bad = good;
    bad[11] = 25;
    try t.expectError(error.InvalidDataRow, value(1007, &bad));
    // more elements than there are
    bad = good;
    bad[15] = 3;
    try t.expectError(error.InvalidDataRow, value(1007, &bad));
    // an element that is not 4 bytes
    bad = good;
    bad[23] = 2;
    try t.expectError(error.InvalidDataRow, value(1007, &bad));
    // an element longer than the array
    bad = good;
    bad[20] = 1;
    try t.expectError(error.InvalidDataRow, value(1007, &bad));
    // a negative dimension, too many dimensions
    bad = good;
    bad[12] = 255;
    try t.expectError(error.InvalidDataRow, value(1007, &bad));
    bad = good;
    bad[3] = 7;
    try t.expectError(error.InvalidDataRow, value(1007, &bad));
    // bytes after the last element
    try t.expectError(error.InvalidDataRow, value(1007, &(good ++ [_]u8{0})));
    // dimensions whose product overflows
    const dim = [_]u8{ 127, 255, 255, 255, 0, 0, 0, 1 };
    const huge = [_]u8{ 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 23 } ++ dim ++ dim ++ dim;
    try t.expectError(error.InvalidDataRow, value(1007, &huge));
}

test "check: records" {
    // (int4 5, text NULL)
    const good = [_]u8{ 0, 0, 0, 2, 0, 0, 0, 23, 0, 0, 0, 4, 0, 0, 0, 5, 0, 0, 0, 25, 255, 255, 255, 255 };
    try value(record, &good);
    var bad = good;
    bad[11] = 3;
    try t.expectError(error.InvalidDataRow, value(record, &bad));
    bad = good;
    bad[3] = 3;
    try t.expectError(error.InvalidDataRow, value(record, &bad));

    // records in records, deeper than allowed
    var nested: [4 + (max_record_depth + 1) * 12]u8 = undefined;
    var pos: usize = 0;
    for (0..max_record_depth + 1) |i| {
        const rest: u32 = @intCast(nested.len - pos - 12);
        std.mem.writeInt(i32, nested[pos..][0..4], 1, .big);
        std.mem.writeInt(i32, nested[pos + 4 ..][0..4], record, .big);
        std.mem.writeInt(u32, nested[pos + 8 ..][0..4], rest, .big);
        pos += 12;
        _ = i;
    }
    std.mem.writeInt(i32, nested[pos..][0..4], 0, .big);
    try t.expectError(error.InvalidDataRow, value(record, &nested));
}
