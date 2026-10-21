// Stands in for karlseguin/metrics.zig when pg.zig is built with
// -Dmetrics=false: the same calls, doing nothing, so src/metrics.zig needs no
// changes and the counters (process-wide, one cache line every connection
// writes to) cost nothing.
pub fn Counter(comptime T: type) type {
    return struct {
        pub const Impl = struct {
            pub fn init(_: []const u8, _: anytype) Impl {
                return .{};
            }

            pub fn incr(_: *Impl) void {}

            pub fn incrBy(_: *Impl, _: T) void {}

            pub fn write(_: *const Impl, _: anytype) !void {}
        };
    };
}
