// The `tls` module on Zig's std.crypto.tls (-Dtls=std): no system library
// needed. Its limits are std's: no client certificates and no ALPN, so no
// direct TLS (sslnegotiation=direct) either, and verify_ca isn't available
// (std checks the host name whenever it checks the chain).
//
// An application can inject its own module instead (-Dtls=injected), see
// TlsHandshake in stream.zig.
const std = @import("std");

const Io = std.Io;
const Client = std.crypto.tls.Client;
const Certificate = std.crypto.Certificate;

pub const input_buffer_len = Client.min_buffer_len;
pub const output_buffer_len = Client.min_buffer_len;

pub const Config = struct {};

pub const Connection = struct {
    client: Client,
    // the Client's read buffer (decrypted records)
    read_buffer: []u8,
    allocator: std.mem.Allocator,

    pub const Reader = struct {
        conn: *Connection,
        interface: Io.Reader,

        fn stream(r: *Io.Reader, w: *Io.Writer, limit: Io.Limit) Io.Reader.StreamError!usize {
            const self: *Reader = @alignCast(@fieldParentPtr("interface", r));
            return self.conn.client.reader.stream(w, limit);
        }
    };

    pub const Writer = struct {
        conn: *Connection,
        interface: Io.Writer,

        fn drain(w: *Io.Writer, data: []const []const u8, splat: usize) Io.Writer.Error!usize {
            const self: *Writer = @alignCast(@fieldParentPtr("interface", w));
            const cw = &self.conn.client.writer;
            try cw.writeAll(w.buffered());
            w.end = 0;
            return cw.writeSplat(data, splat);
        }

        fn flush(w: *Io.Writer) Io.Writer.Error!void {
            const self: *Writer = @alignCast(@fieldParentPtr("interface", w));
            const c = &self.conn.client;
            try c.writer.writeAll(w.buffered());
            w.end = 0;
            // The Client has no write buffer (so nothing to flush, and its
            // flush would send an empty record): drain encrypted everything.
            try c.output.flush();
        }
    };

    pub fn reader(self: *Connection, buffer: []u8) Reader {
        return .{
            .conn = self,
            .interface = .{
                .vtable = &.{ .stream = Reader.stream },
                .buffer = buffer,
                .seek = 0,
                .end = 0,
            },
        };
    }

    pub fn writer(self: *Connection, buffer: []u8) Writer {
        return .{
            .conn = self,
            .interface = .{
                .vtable = &.{ .drain = Writer.drain, .flush = Writer.flush },
                .buffer = buffer,
                .end = 0,
            },
        };
    }

    pub fn close(self: *Connection) void {
        self.client.end() catch return;
        self.client.output.flush() catch {};
    }

    pub fn deinit(self: *Connection) void {
        self.allocator.free(self.read_buffer);
    }
};

pub fn client(input: *Io.Reader, output: *Io.Writer, handshake: anytype) !Connection {
    if (handshake.direct) {
        // the server requires ALPN, which std's client can't send
        return error.TlsAlpnNotSupported;
    }

    const io = handshake.io;
    const allocator = handshake.allocator;
    const now = Io.Clock.real.now(io);

    var bundle: Certificate.Bundle = .empty;
    defer bundle.deinit(allocator);
    var lock: Io.RwLock = .init;

    const host: @FieldType(Client.Options, "host") = switch (handshake.mode) {
        .require => .no_verification,
        .verify_ca => return error.TlsVerifyCaNotSupported,
        .verify_full => .{ .explicit = handshake.host },
    };
    const ca: @FieldType(Client.Options, "ca") = switch (handshake.mode) {
        .require => .no_verification,
        .verify_ca, .verify_full => blk: {
            if (handshake.root_cert) |path| {
                try bundle.addCertsFromFilePath(allocator, io, now, Io.Dir.cwd(), path);
            } else {
                try bundle.rescan(allocator, io, now);
            }
            break :blk .{ .bundle = .{ .gpa = allocator, .io = io, .lock = &lock, .bundle = &bundle } };
        },
    };

    const read_buffer = try allocator.alloc(u8, Client.min_buffer_len);
    errdefer allocator.free(read_buffer);

    var entropy: [Client.Options.entropy_len]u8 = undefined;
    io.random(&entropy);

    return .{
        .allocator = allocator,
        .read_buffer = read_buffer,
        .client = try Client.init(input, output, .{
            .host = host,
            .ca = ca,
            .read_buffer = read_buffer,
            .write_buffer = &.{},
            .entropy = &entropy,
            .realtime_now = now,
        }),
    };
}
