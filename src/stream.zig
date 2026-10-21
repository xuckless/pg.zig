const std = @import("std");
const builtin = @import("builtin");
const lib = @import("lib.zig");

const tls = lib.tls;
const has_tls = lib.has_tls;

const posix = std.posix;

const Conn = lib.Conn;
const Allocator = std.mem.Allocator;
const Io = std.Io;

const DEFAULT_HOST = "127.0.0.1";

// The SSLRequest message: length 8, then the code 80877103.
const ssl_request = [_]u8{ 0, 0, 0, 8, 4, 210, 22, 47 };

// What a TLS connection offers in ALPN. PostgreSQL 17+ requires it for
// direct TLS, and checks it, when it's sent, after an SSLRequest.
const alpn_protocols: []const []const u8 = &.{"postgresql"};

pub const TlsMode = enum {
    // encrypt, but don't verify the server's certificate
    require,
    // verify the server's certificate chain, but not its name
    verify_ca,
    // verify the server's certificate chain and that it was issued for the host
    verify_full,
};

// What the `tls` module's `client` function is given, besides the socket's
// reader and writer. A module (see build.zig) declares:
//
//   pub fn client(input: *std.Io.Reader, output: *std.Io.Writer, handshake: anytype) !Connection
//   pub const Connection = struct {
//       pub fn reader(self: *Connection, buffer: []u8) R // R has `interface: std.Io.Reader`
//       pub fn writer(self: *Connection, buffer: []u8) W // W has `interface: std.Io.Writer`
//       pub fn close(self: *Connection) void // sends close_notify, best effort
//       pub fn deinit(self: *Connection) void
//   };
//
// and optionally:
//
//   pub const Config = struct { ... } // Conn.Opts.tls_config; `.{}` must be valid
//   pub const input_buffer_len: usize // buffer of the socket reader it's given
//   pub const output_buffer_len: usize // buffer of the socket writer it's given
//
// `client` runs the handshake over `input` and `output`, which read and write
// the socket through Io and report socket errors (including error.Timeout and
// error.Canceled) as error.ReadFailed/WriteFailed; the Stream recovers the
// cause. The Connection must stay where it is once `reader` or `writer` has
// been called: the Stream keeps it at a stable address.
pub const TlsHandshake = struct {
    io: Io,
    allocator: Allocator,
    // The server's name: for SNI (when it's not an IP address) and, with
    // verify_full, for checking its certificate.
    host: []const u8,
    mode: TlsMode,
    // A PEM file of trusted root certificates (sslrootcert). null: the
    // module's default, e.g. the system's trust store or something in
    // `config`.
    root_cert: ?[]const u8,
    // To offer in ALPN.
    alpn: []const []const u8,
    // Direct TLS (sslnegotiation=direct): no SSLRequest came first, and the
    // server only accepts a client that offers ALPN "postgresql".
    direct: bool,
    config: *const lib.TlsConfig,
};

// A connection to the server: a socket and, when the connection uses TLS,
// the TLS session on top of it. A small handle to state on the heap, so it
// can be copied (the Reader keeps a copy); `close` frees it.
pub const Stream = struct {
    inner: *Inner,

    const Inner = struct {
        io: Io,
        allocator: Allocator,
        net: Io.net.Stream,
        socket_reader: SocketReader,
        socket_writer: Io.net.Stream.Writer,
        tls: if (has_tls) ?TlsState else void,
        // socket_reader's and socket_writer's buffers, when TLS uses them
        buffers: []u8,
    };

    const TlsState = if (has_tls) struct {
        conn: tls.Connection,
        reader: ReaderOf(tls.Connection),
        writer: WriterOf(tls.Connection),
    } else void;

    pub fn connect(io: Io, allocator: Allocator, opts: Conn.Opts) !Stream {
        const host = opts.host orelse DEFAULT_HOST;
        const is_unix = host.len > 0 and host[0] == '/';

        const net = try blk: {
            if (is_unix) {
                if (comptime Io.net.has_unix_sockets == false or std.posix.AF == void) {
                    return error.UnixPathNotSupported;
                }
                const addr: Io.net.UnixAddress = try .init(host);
                break :blk addr.connect(io);
            }
            const port = opts.port orelse lib.default_port;
            const hostname: Io.net.HostName = try .init(host);
            break :blk hostname.connect(io, port, .{ .mode = .stream });
        };
        errdefer net.close(io);

        if (is_unix == false) {
            try setKeepalive(net.socket.handle, opts);
        }

        const inner = try allocator.create(Inner);
        errdefer allocator.destroy(inner);
        inner.* = .{
            .io = io,
            .allocator = allocator,
            .net = net,
            .socket_reader = .init(io, net.socket.handle, &.{}),
            .socket_writer = net.writer(io, &.{}),
            .tls = if (has_tls) null else {},
            .buffers = &.{},
        };
        const stream = Stream{ .inner = inner };
        errdefer allocator.free(inner.buffers);

        // As libpq does, TLS is never used over a unix socket.
        if (is_unix == false) {
            try stream.startTls(host, opts);
        }
        return stream;
    }

    fn startTls(self: Stream, host: []const u8, opts: Conn.Opts) !void {
        const mode: TlsMode, const root_cert: ?[]const u8 = switch (opts.tls) {
            .off => return,
            .prefer => if (comptime has_tls) .{ .require, null } else return,
            .require => .{ .require, null },
            .verify_ca => |path| .{ .verify_ca, path },
            .verify_full => |path| .{ .verify_full, path },
        };
        if (comptime has_tls == false) {
            return error.TlsNotAvailable;
        }

        const inner = self.inner;
        const io = inner.io;
        if (opts.tls_direct == false) {
            // PostgreSQL TLS starts off as a plain connection which we upgrade
            try self.writeAll(&ssl_request);
            // Exactly one byte: anything the server sent after it, before the
            // handshake, must not be taken as coming from inside TLS.
            var answer = [1]u8{0};
            if (try inner.socket_reader.readOnce(&answer) == 0) {
                return error.Closed;
            }
            switch (answer[0]) {
                'S' => {},
                'N' => if (opts.tls == .prefer) return else return error.TlsNotSupportedByServer,
                else => return error.UnexpectedDBMessage,
            }
        }

        const input_len: usize = if (@hasDecl(tls, "input_buffer_len")) tls.input_buffer_len else 0;
        const output_len: usize = if (@hasDecl(tls, "output_buffer_len")) tls.output_buffer_len else 0;
        const allocator = inner.allocator;
        inner.buffers = try allocator.alloc(u8, input_len + output_len);
        inner.socket_reader.interface.buffer = inner.buffers[0..input_len];
        inner.socket_writer = inner.net.writer(io, inner.buffers[input_len..]);

        const handshake = TlsHandshake{
            .io = io,
            .allocator = allocator,
            .host = host,
            .mode = mode,
            .root_cert = root_cert,
            .alpn = alpn_protocols,
            .direct = opts.tls_direct,
            .config = &opts.tls_config,
        };
        inner.tls = .{
            .conn = tls.client(&inner.socket_reader.interface, &inner.socket_writer.interface, handshake) catch |err| {
                return self.socketError(err);
            },
            .reader = undefined,
            .writer = undefined,
        };
        const state = &inner.tls.?;
        errdefer {
            state.conn.deinit();
            inner.tls = null;
        }
        if (comptime @hasField(tls.Connection, "alpn_protocol")) {
            if (opts.tls_direct and !std.mem.eql(u8, state.conn.alpn_protocol orelse "", "postgresql")) {
                return error.TlsAlpnNotNegotiated;
            }
        }
        state.reader = state.conn.reader(&.{});
        state.writer = state.conn.writer(&.{});
    }

    // Whether the connection uses TLS.
    pub fn isTls(self: Stream) bool {
        if (comptime has_tls == false) return false;
        return self.inner.tls != null;
    }

    pub fn close(self: Stream) void {
        const inner = self.inner;
        const io = inner.io;
        if (comptime has_tls) {
            if (inner.tls) |*state| {
                // best effort, and not something a cancel should interrupt
                const prev = io.swapCancelProtection(.blocked);
                state.conn.close();
                _ = io.swapCancelProtection(prev);
                state.conn.deinit();
            }
        }
        inner.net.close(io);
        const allocator = inner.allocator;
        allocator.free(inner.buffers);
        allocator.destroy(inner);
    }

    pub fn shutdown(self: Stream, how: Io.net.ShutdownHow) !void {
        const inner = self.inner;
        return inner.net.shutdown(inner.io, how);
    }

    // Bounds each following read (null or 0: no timeout). A read that waits
    // longer fails with error.Timeout.
    pub fn setReadTimeout(self: Stream, timeout_ms: ?u32) !void {
        self.inner.socket_reader.timeout = toTimeout(timeout_ms);
    }

    pub fn writeAll(self: Stream, data: []const u8) !void {
        const inner = self.inner;
        inner.socket_writer.err = null;
        if (comptime has_tls) {
            if (inner.tls) |*state| {
                const w = &state.writer.interface;
                w.writeAll(data) catch |err| return self.socketError(err);
                w.flush() catch |err| return self.socketError(err);
                return;
            }
        }
        const w = &inner.socket_writer.interface;
        w.writeAll(data) catch return inner.socket_writer.err orelse error.WriteFailed;
        w.flush() catch return inner.socket_writer.err orelse error.WriteFailed;
    }

    // Reads at least 1 byte into buf, or returns 0 when the server closed the
    // connection.
    pub fn read(self: Stream, buf: []u8) !usize {
        const inner = self.inner;
        if (comptime has_tls) {
            if (inner.tls) |*state| {
                inner.socket_reader.err = null;
                var vecs = [1][]u8{buf};
                while (true) {
                    // 0 means it filled the reader's own buffer instead (it
                    // has none, but that's for the module to decide)
                    const n = state.reader.interface.readVec(&vecs) catch |err| switch (err) {
                        error.EndOfStream => return 0,
                        error.ReadFailed => return self.socketError(err),
                    };
                    if (n > 0) return n;
                }
            }
        }
        return inner.socket_reader.readOnce(buf);
    }

    // A TLS module reports socket errors as ReadFailed/WriteFailed (and its
    // own errors as anything else). The socket reader and writer kept the
    // cause, which is what callers care about: error.Timeout, error.Canceled,
    // error.ConnectionResetByPeer...
    fn socketError(self: Stream, err: anytype) SocketError(@TypeOf(err)) {
        const inner = self.inner;
        if (@as(anyerror, err) == error.ReadFailed) {
            if (inner.socket_reader.err) |e| return e;
            return error.TlsReadFailed;
        }
        if (@as(anyerror, err) == error.WriteFailed) {
            if (inner.socket_writer.err) |e| return e;
            return error.TlsWriteFailed;
        }
        return err;
    }

    fn SocketError(comptime E: type) type {
        return E || SocketReader.Error || Io.net.Stream.Writer.Error || error{ TlsReadFailed, TlsWriteFailed };
    }
};

// The TLS module's reader and writer types.
fn ReaderOf(comptime C: type) type {
    return @typeInfo(@TypeOf(C.reader)).@"fn".return_type.?;
}

fn WriterOf(comptime C: type) type {
    return @typeInfo(@TypeOf(C.writer)).@"fn".return_type.?;
}

// Reads the socket through Io, every read bounded by `timeout`. As an
// Io.Reader, it's what a TLS module reads ciphertext from; on a plain
// connection, `readOnce` reads straight into the caller's buffer.
const SocketReader = struct {
    io: Io,
    handle: Io.net.Socket.Handle,
    timeout: Io.Timeout = .none,
    // the cause of the last error.ReadFailed
    err: ?Error = null,
    interface: Io.Reader,

    const Error = Io.net.Stream.Reader.Error || Io.Timeout.Error || Io.ConcurrentError;

    fn init(io: Io, handle: Io.net.Socket.Handle, buffer: []u8) SocketReader {
        return .{
            .io = io,
            .handle = handle,
            .interface = .{
                .vtable = &.{
                    .stream = streamImpl,
                    .readVec = readVec,
                },
                .buffer = buffer,
                .seek = 0,
                .end = 0,
            },
        };
    }

    // Reads into buf, without going through the interface's buffer. 0 means
    // the server closed the connection.
    fn readOnce(self: *SocketReader, buf: []u8) Error!usize {
        var vecs = [1][]u8{buf};
        return self.readSocket(&vecs);
    }

    fn readSocket(self: *SocketReader, data: [][]u8) Error!usize {
        const io = self.io;
        const op: Io.Operation = .{ .net_read = .{ .socket_handle = self.handle, .data = data } };
        const result = if (self.timeout == .none)
            try io.operate(op)
        else
            try io.operateTimeout(op, self.timeout);
        return (try result.net_read).data_len;
    }

    fn streamImpl(io_r: *Io.Reader, io_w: *Io.Writer, limit: Io.Limit) Io.Reader.StreamError!usize {
        const dest = limit.slice(try io_w.writableSliceGreedy(1));
        var data: [1][]u8 = .{dest};
        const n = try readVec(io_r, &data);
        io_w.advance(n);
        return n;
    }

    fn readVec(io_r: *Io.Reader, data: [][]u8) Io.Reader.Error!usize {
        const self: *SocketReader = @alignCast(@fieldParentPtr("interface", io_r));
        var iovecs_buffer: [8][]u8 = undefined;
        const dest_n, const data_size = try io_r.writableVector(&iovecs_buffer, data);
        const n = self.readSocket(iovecs_buffer[0..dest_n]) catch |err| {
            self.err = err;
            return error.ReadFailed;
        };
        if (n == 0) {
            return error.EndOfStream;
        }
        if (n > data_size) {
            io_r.end += n - data_size;
            return data_size;
        }
        return n;
    }
};

fn toTimeout(timeout_ms: ?u32) Io.Timeout {
    const ms = timeout_ms orelse return .none;
    if (ms == 0) return .none;
    return .{ .duration = .{ .raw = .fromMilliseconds(ms), .clock = .awake } };
}

// Sends a best-effort Terminate ('X') message, shielded from cancellation so
// teardown can't be interrupted.
pub fn sendTerminate(stream: *Stream, io: Io) void {
    const prev = io.swapCancelProtection(.blocked);
    defer _ = io.swapCancelProtection(prev);
    stream.writeAll(&.{ 'X', 0, 0, 0, 4 }) catch {};
}

const TCP = switch (builtin.os.tag) {
    // Zig doesn't expose these /shrug
    .freebsd, .dragonfly => struct {
        pub const KEEPIDLE = 256;
        pub const KEEPINTVL = 512;
        pub const KEEPCNT = 1024;
    },
    .netbsd => struct {
        pub const KEEPIDLE = 3;
        pub const KEEPINTVL = 5;
        pub const KEEPCNT = 6;
    },
    .illumos => struct {
        pub const KEEPIDLE = 0x22;
        pub const KEEPCNT = 0x23;
        pub const KEEPINTVL = 0x24;
    },
    else => if (posix.TCP == void) struct {} else posix.TCP,
};

fn setKeepalive(handle: posix.socket_t, opts: Conn.Opts) !void {
    if (opts.keepalive == false) {
        return;
    }
    const on: c_int = 1;
    try setsockopt(handle, posix.SOL.SOCKET, posix.SO.KEEPALIVE, std.mem.asBytes(&on));

    const level = posix.IPPROTO.TCP;

    if (opts.keepalive_idle) |idle| {
        const optname: ?u32 = comptime if (@hasDecl(TCP, "KEEPIDLE"))
            TCP.KEEPIDLE
        else if (@hasDecl(TCP, "KEEPALIVE"))
            TCP.KEEPALIVE
        else
            null;
        if (optname) |name| {
            const v: c_int = @intCast(idle);
            setsockopt(handle, level, name, std.mem.asBytes(&v)) catch {};
        }
    }

    if (opts.keepalive_interval) |intvl| {
        if (comptime @hasDecl(TCP, "KEEPINTVL")) {
            const v: c_int = @intCast(intvl);
            setsockopt(handle, level, TCP.KEEPINTVL, std.mem.asBytes(&v)) catch {};
        }
    }

    if (opts.keepalive_count) |cnt| {
        if (comptime @hasDecl(TCP, "KEEPCNT")) {
            const v: c_int = @intCast(cnt);
            setsockopt(handle, level, TCP.KEEPCNT, std.mem.asBytes(&v)) catch {};
        }
    }
}

fn setsockopt(fd: posix.socket_t, level: i32, optname: u32, opt: []const u8) !void {
    if (@import("builtin").os.tag != .windows) {
        return posix.setsockopt(fd, level, optname, opt);
    }

    const SO = posix.SO;
    const SOL = posix.SOL;
    const timeval = posix.timeval;

    var ms_buf: u32 = 0;
    var opt_ptr: [*]const u8 = opt.ptr;
    var opt_len: i32 = @intCast(opt.len);
    if (level == SOL.SOCKET and (optname == SO.RCVTIMEO or optname == SO.SNDTIMEO) and opt.len == @sizeOf(timeval)) {
        const tv: *const timeval = @ptrCast(@alignCast(opt.ptr));
        const total_ms = @as(i64, tv.sec) * 1000 + @divTrunc(@as(i64, tv.usec), 1000);
        ms_buf = if (total_ms < 0) 0 else @intCast(@min(total_ms, std.math.maxInt(u32)));
        opt_ptr = @ptrCast(&ms_buf);
        opt_len = @sizeOf(u32);
    }

    const in: []const u8 = @ptrCast(&std.os.windows.AFD.SOCKOPT_INFO{
        .mode = .set,
        .level = level,
        .optname = optname,
        .optval = opt_ptr,
        .optlen = @intCast(opt_len),
    });

    var iosb: std.os.windows.IO_STATUS_BLOCK = undefined;
    switch (std.os.windows.ntdll.NtDeviceIoControlFile(
        fd,
        null, // event
        null, // APC routine
        null, // APC context
        &iosb,
        std.os.windows.IOCTL.AFD.SOCKOPT,
        if (in.len > 0) in.ptr else null,
        @intCast(in.len),
        null,
        0,
    )) {
        .SUCCESS => return,
        .CANCELLED => return error.Canceled,
        .INSUFFICIENT_RESOURCES => return error.SystemResources,
        else => |status| return std.os.windows.unexpectedStatus(status),
    }
}


const windows = @import("windows.zig");
