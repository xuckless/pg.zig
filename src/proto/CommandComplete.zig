const std = @import("std");
const proto = @import("_proto.zig");
const Reader = proto.Reader;

const CommandComplete = @This();

tag: []const u8,

pub fn parse(data: []const u8) !CommandComplete {
    var reader = Reader.init(data);
    return .{
        .tag = try reader.restAsString(),
    };
}

// Finds the last number in the tag of the command completed. If no number is
// found, than 0 rows were affected. Commands like "create table" or "create
// role" have a tag that's just "CREATE XYZ".
// But update/delete/select/... have something like "delete #"
// "insert" is a bit more complicated, but the rows inserted is the last number
// so this works for it too.
pub fn rowsAffected(self: CommandComplete) ?i64 {
    // the digits at the end of the tag, if any
    const tag = self.tag;
    var i: usize = tag.len;
    while (i > 0 and std.ascii.isDigit(tag[i - 1])) {
        i -= 1;
    }
    if (i == tag.len) {
        return null;
    }
    return std.fmt.parseInt(i64, tag[i..], 10) catch null;
}

const t = proto.testing;
test "CommandComplete: parse" {
    var buf = try proto.Buffer.init(t.allocator, 128);
    defer buf.deinit();

    {
        // not a string (not null terminated)
        try buf.write("123");
        try t.expectError(error.NotAString, CommandComplete.parse(buf.string()));
    }

    {
        // success
        buf.reset();
        try buf.write("CREATE ROLE");
        try buf.writeByte(0);

        const c = try CommandComplete.parse(buf.string());
        try t.expectString("CREATE ROLE", c.tag);
    }
}

test "CommandComplete: rowsAffected" {
    {
        // what a server would not send
        try t.expectEqual(null, (CommandComplete{ .tag = "" }).rowsAffected());
        try t.expectEqual(12, (CommandComplete{ .tag = "12" }).rowsAffected());
        try t.expectEqual(null, (CommandComplete{ .tag = "UPDATE 99999999999999999999999" }).rowsAffected());
    }

    {
        const c = CommandComplete{ .tag = "DROP ROLE" };
        try t.expectEqual(null, c.rowsAffected());
    }

    {
        const c = CommandComplete{ .tag = "INSERT 392 1" };
        try t.expectEqual(1, c.rowsAffected());
    }

    {
        const c = CommandComplete{ .tag = "DELETE 9392" };
        try t.expectEqual(9392, c.rowsAffected());
    }
}
