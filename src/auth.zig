const std = @import("std");
const lib = @import("lib.zig");
const Buffer = @import("buffer").Buffer;

const proto = lib.proto;
const Reader = lib.Reader;
const Stream = lib.Stream;

const Allocator = std.mem.Allocator;
const Io = std.Io;

const Opts = lib.Conn.AuthOpts;

// Weird return (but Zig has no error payloads, so..)
// null on success
// a []const on a PG error
//   - can be be passed to  proto.Error.parse(owned)
//   - is only valid until the next call to reader.next() or reader.endFlow()
//     (we expect our caller to clone the value)
// a normal zig error on any other error
//
// The caller owns the reader flow: it must run startFlow before and endFlow
// after it has copied a returned error.
pub fn auth(io: Io, stream: *Stream, buf: *Buffer, reader: *Reader, opts: Opts) !?[]const u8 {
    {
        // write our startup message
        const startup_message = proto.StartupMessage{
            .username = opts.username,
            .application_name = opts.application_name,
            .database = opts.database orelse opts.username,
            .params = opts.startup_parameters,
        };

        buf.resetRetainingCapacity();
        try startup_message.write(buf);
        try stream.writeAll(buf.string());
    }

    // read the server's response
    {
        const msg = try reader.next();
        switch (msg.type) {
            'R' => {},
            'E' => return msg.data,
            else => return error.UnexpectedDBMessage,
        }

        switch (try proto.AuthenticationRequest.parse(msg.data)) {
            .ok => {
                try allowed(opts, opts.allow.none);
                return null;
            },
            .sasl => |sasl| {
                if (!opts.allow.scram_sha_256) return error.AuthMethodNotAllowed;
                if (try saslAuth(io, sasl, stream, buf, reader, opts)) |raw_pg_err| {
                    return raw_pg_err;
                }
            },
            .md5 => |salt| {
                try allowed(opts, opts.allow.md5);
                try md5PasswordAuth(salt, stream, buf, opts);
            },
            .password => {
                try allowed(opts, opts.allow.password);
                try passwordAuth(opts.password orelse "", stream, buf);
            },
        }
    }

    {
        // if we're here, it's because we sent more data to the server (e.g. a password)
        // and we're now waiting for a reply, server should send a final auth ok message
        const msg = try reader.next();
        switch (msg.type) {
            'R' => {},
            'E' => return msg.data,
            else => return error.UnexpectedDBMessage,
        }

        switch (try proto.AuthenticationRequest.parse(msg.data)) {
            .ok => return null,
            else => return error.UnexpectedDBMessage,
        }
    }
}

// A way of logging in other than SCRAM: refused when not in opts.allow, or
// when channel binding is required (only SCRAM-SHA-256-PLUS has it).
fn allowed(opts: Opts, method_allowed: bool) !void {
    if (!method_allowed) return error.AuthMethodNotAllowed;
    if (opts.channel_binding == .require) return error.ChannelBindingRequired;
}

fn saslAuth(io: Io, req: proto.AuthenticationRequest.SASL, stream: *Stream, buf: *Buffer, reader: *Reader, opts: Opts) !?[]const u8 {
    var end_point_buf: [64]u8 = undefined;
    const end_point = if (opts.channel_binding == .disable) null else stream.tlsServerEndPoint(&end_point_buf);
    const binding: SASL.Binding = blk: {
        if (end_point) |data| {
            if (req.scram_sha_256_plus) break :blk .{ .end_point = data };
            // Over TLS, with a server that doesn't offer channel binding:
            // "y" tells a server that does (behind something that removed
            // it from the list) that it was removed.
            if (opts.channel_binding == .require) return error.ChannelBindingRequired;
            break :blk .supported;
        }
        if (opts.channel_binding == .require) return error.ChannelBindingRequired;
        break :blk .none;
    };
    if (binding != .end_point and !req.scram_sha_256) {
        return error.UnexpectedDBMessage;
    }
    var sasl_buf: [2048]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&sasl_buf);
    var sasl = try SASL.initWith(io, fba.allocator(), binding);

    {
        // send the client initial response
        const msg = proto.SASLInitialResponse{
            .response = sasl.client_first_message,
            .mechanism = if (binding == .end_point) "SCRAM-SHA-256-PLUS" else "SCRAM-SHA-256",
        };
        buf.resetRetainingCapacity();
        try msg.write(buf);
        try stream.writeAll(buf.string());
    }

    {
        // read the server continue response
        const msg = try reader.next();
        switch (msg.type) {
            'R' => {},
            'E' => return msg.data,
            else => return error.InvalidSASLFlow,
        }
        const c = try proto.AuthenticationSASLContinue.parse(msg.data);
        try sasl.serverResponse(c.data);
    }

    {
        // send the client final response
        const msg = proto.SASLResponse{
            .data = try sasl.clientFinalMessage(opts.password orelse ""),
        };
        buf.resetRetainingCapacity();
        try msg.write(buf);
        try stream.writeAll(buf.string());
    }

    {
        // read the server final response
        const msg = try reader.next();
        switch (msg.type) {
            'R' => {},
            'E' => return msg.data,
            else => return error.InvalidSASLFlow,
        }
        const final = try proto.AuthenticationSASLFinal.parse(msg.data);
        try sasl.verifyServerFinal(final.data);
    }
    return null;
}

fn md5PasswordAuth(salt: []const u8, stream: *Stream, buf: *Buffer, opts: Opts) !void {
    var hash: [16]u8 = undefined;
    {
        var hasher = std.crypto.hash.Md5.init(.{});
        hasher.update(opts.password orelse "");
        hasher.update(opts.username);
        hasher.final(&hash);
    }

    {
        const hex_hash = std.fmt.bytesToHex(&hash, .lower);
        var hasher = std.crypto.hash.Md5.init(.{});
        hasher.update(&hex_hash);
        hasher.update(salt);
        hasher.final(&hash);
    }
    var hashed_password: [35]u8 = undefined;
    const password = try std.fmt.bufPrint(&hashed_password, "md5{s}", .{&std.fmt.bytesToHex(&hash, .lower)});
    try passwordAuth(password, stream, buf);
}

fn passwordAuth(password: []const u8, stream: *Stream, buf: *Buffer) !void {
    buf.resetRetainingCapacity();
    const pw = proto.PasswordMessage{ .password = password };
    try pw.write(buf);
    try stream.writeAll(buf.string());
}

// The most PBKDF2 iterations a server may ask for (PostgreSQL's default is
// 4096). Each is an HMAC the client computes before the server has proven
// anything, so a server asking for billions would hold the client for minutes.
pub const max_iterations = 1_000_000;

const SASL = struct {
    allocator: Allocator,
    // "n,," without channel binding, "y,," when the client could bind but
    // the server didn't offer it, "p=tls-server-end-point,," when it binds
    gs2_header: []const u8,
    // what it binds to: the hash of the server's certificate, for "p"
    cbind_data: []const u8,
    // the gs2 header, then "n=,r=" and the nonce
    client_first_message: []u8,
    nonce: []const u8,
    auth_message: ?[]const u8 = null,
    salted_password: ?[32]u8 = null,
    server_response: ?ServerResponse = null,

    const Base64Encoder = std.base64.standard.Encoder;
    const Base64Decoder = std.base64.standard.Decoder;

    pub const Binding = union(enum) {
        none,
        supported,
        end_point: []const u8,
    };

    pub fn init(io: Io, allocator: Allocator) !SASL {
        return initWith(io, allocator, .none);
    }

    pub fn initWith(io: Io, allocator: Allocator, binding: Binding) !SASL {
        var nonce: [18]u8 = undefined;
        std.Io.random(io, &nonce);

        const gs2_header = switch (binding) {
            .none => "n,,",
            .supported => "y,,",
            .end_point => "p=tls-server-end-point,,",
        };
        var encoded_nonce: [24]u8 = undefined;
        _ = Base64Encoder.encode(&encoded_nonce, &nonce);
        const client_first_message = try std.fmt.allocPrint(allocator, "{s}n=,r={s}", .{ gs2_header, encoded_nonce });

        return .{
            .allocator = allocator,
            .gs2_header = gs2_header,
            .cbind_data = switch (binding) {
                .end_point => |data| try allocator.dupe(u8, data),
                else => "",
            },
            .client_first_message = client_first_message,
            .nonce = client_first_message[client_first_message.len - encoded_nonce.len ..],
        };
    }

    pub fn serverResponse(self: *SASL, data: []const u8) !void {
        if (data.len < 8) {
            return error.InvalidLength;
        }

        // Specification states the attribute positions are fixed, so we expect r=X,s=Y,i=Z
        if (data[0] != 'r' or data[1] != '=') {
            return error.InvalidNoncePrefix;
        }

        const owned = try self.allocator.dupe(u8, data);

        var res = ServerResponse{
            .raw = owned,
            .nonce = undefined,
            .base64_salt = undefined,
            .iterations = undefined,
        };

        var pos: usize = 2;
        {
            const sep = std.mem.indexOfScalarPos(u8, owned, pos, ',') orelse return error.MissingSalt;
            res.nonce = owned[2..sep];
            pos = sep + 1;
        }

        {
            const value_start = pos + 2;
            if (owned.len < value_start or owned[pos] != 's' or owned[pos + 1] != '=') {
                return error.InvalidSaltPrefix;
            }
            pos = value_start;

            const sep = std.mem.indexOfScalarPos(u8, owned, pos, ',') orelse return error.MissingIterations;
            res.base64_salt = owned[pos..sep];
            pos = sep + 1;
        }

        {
            const value_start = pos + 2;
            if (owned.len < value_start or owned[pos] != 'i' or owned[pos + 1] != '=') {
                return error.InvalidIterationPrefix;
            }
            pos = value_start;
            const sep = std.mem.indexOfScalarPos(u8, owned, pos, ',') orelse owned.len;
            res.iterations = std.fmt.parseInt(u32, owned[pos..sep], 10) catch return error.InvalidIteration;
            if (res.iterations == 0 or res.iterations > max_iterations) {
                return error.InvalidIteration;
            }
        }

        // RFC 5802: the server's nonce starts with ours, and adds its own.
        const client_nonce = self.nonce;
        if (res.nonce.len <= client_nonce.len or !std.mem.startsWith(u8, res.nonce, client_nonce)) {
            return error.InvalidNonce;
        }

        self.server_response = res;
    }

    pub fn clientFinalMessage(self: *SASL, password: []const u8) ![]const u8 {
        const sr = self.server_response orelse return error.MissingServerResponse;
        const allocator = self.allocator;

        const salt = blk: {
            const s = try allocator.alloc(u8, try Base64Decoder.calcSizeForSlice(sr.base64_salt));
            try Base64Decoder.decode(s, sr.base64_salt);
            break :blk s;
        };

        // c=: the gs2 header and the channel binding data, in base64
        const cbind_input = try std.mem.concat(allocator, u8, &.{ self.gs2_header, self.cbind_data });
        const cbind = try allocator.alloc(u8, Base64Encoder.calcSize(cbind_input.len));
        _ = Base64Encoder.encode(cbind, cbind_input);
        const unproved = try std.fmt.allocPrint(allocator, "c={s},r={s}", .{ cbind, sr.nonce });
        const auth_message = try std.fmt.allocPrint(allocator, "{s},{s},{s}", .{ self.client_first_message[self.gs2_header.len..], sr.raw, unproved });
        const salted_password = blk: {
            var buf: [32]u8 = undefined;
            try std.crypto.pwhash.pbkdf2(&buf, password, salt, sr.iterations, std.crypto.auth.hmac.sha2.HmacSha256);
            break :blk buf;
        };

        const proof = blk: {
            var client_key: [32]u8 = undefined;
            std.crypto.auth.hmac.sha2.HmacSha256.create(&client_key, "Client Key", &salted_password);

            var stored_key: [32]u8 = undefined;
            std.crypto.hash.sha2.Sha256.hash(&client_key, &stored_key, .{});

            var client_signature: [32]u8 = undefined;
            std.crypto.auth.hmac.sha2.HmacSha256.create(&client_signature, auth_message, &stored_key);

            var proof: [32]u8 = undefined;
            for (client_key, client_signature, 0..) |ck, cs, i| {
                proof[i] = ck ^ cs;
            }

            var encoded_proof: [44]u8 = undefined;
            _ = Base64Encoder.encode(&encoded_proof, &proof);
            break :blk encoded_proof;
        };

        self.auth_message = auth_message;
        self.salted_password = salted_password;
        return std.fmt.allocPrint(allocator, "{s},p={s}", .{ unproved, proof });
    }

    pub fn verifyServerFinal(self: *SASL, data: []const u8) !void {
        if (data.len < 46) {
            return error.InvalidLength;
        }
        const auth_message = self.auth_message orelse return error.MissingAutMessage;
        const salted_password = if (self.salted_password) |*sp| sp else return error.MissingSaltedPassword;

        const computed_signature = blk: {
            var server_key: [32]u8 = undefined;
            std.crypto.auth.hmac.sha2.HmacSha256.create(&server_key, "Server Key", salted_password);

            var server_signature: [32]u8 = undefined;
            std.crypto.auth.hmac.sha2.HmacSha256.create(&server_signature, auth_message, &server_key);

            var encoded_signature: [44]u8 = undefined;
            _ = Base64Encoder.encode(&encoded_signature, &server_signature);
            break :blk encoded_signature;
        };

        if (data.len != 46 or !std.mem.startsWith(u8, data, "v=")) {
            return error.InvalidServerSignature;
        }
        if (!std.crypto.timing_safe.eql([44]u8, computed_signature, data[2..46].*)) {
            return error.InvalidServerSignature;
        }
    }
};

// The tls-server-end-point channel binding data (RFC 5929) of the server
// certificate `der`: its hash, by the hash of its signature algorithm (SHA-256
// for MD5 and SHA-1), as PostgreSQL computes it. Null for a certificate it
// can't be computed for (Ed25519, RSA-PSS, or DER it doesn't follow).
pub fn serverEndPoint(der: []const u8, out: *[64]u8) ?[]const u8 {
    // Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, ... }
    const cert = derElement(der, 0, 0x30) orelse return null;
    const tbs = derElement(der, cert.start, 0x30) orelse return null;
    const algorithm = derElement(der, tbs.end, 0x30) orelse return null;
    const oid = derElement(der, algorithm.start, 0x06) orelse return null;
    if (algorithm.end > cert.end or oid.end > algorithm.end) return null;
    const Hash = enum { sha224, sha256, sha384, sha512 };
    const map = std.StaticStringMap(Hash).initComptime(.{
        .{ "\x2a\x86\x48\x86\xf7\x0d\x01\x01\x04", .sha256 }, // md5WithRSAEncryption
        .{ "\x2a\x86\x48\x86\xf7\x0d\x01\x01\x05", .sha256 }, // sha1WithRSAEncryption
        .{ "\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0e", .sha224 }, // sha224WithRSAEncryption
        .{ "\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0b", .sha256 }, // sha256WithRSAEncryption
        .{ "\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0c", .sha384 }, // sha384WithRSAEncryption
        .{ "\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0d", .sha512 }, // sha512WithRSAEncryption
        .{ "\x2a\x86\x48\xce\x3d\x04\x01", .sha256 }, // ecdsa-with-SHA1
        .{ "\x2a\x86\x48\xce\x3d\x04\x03\x01", .sha224 }, // ecdsa-with-SHA224
        .{ "\x2a\x86\x48\xce\x3d\x04\x03\x02", .sha256 }, // ecdsa-with-SHA256
        .{ "\x2a\x86\x48\xce\x3d\x04\x03\x03", .sha384 }, // ecdsa-with-SHA384
        .{ "\x2a\x86\x48\xce\x3d\x04\x03\x04", .sha512 }, // ecdsa-with-SHA512
    });
    const hash = map.get(der[oid.start..oid.end]) orelse return null;
    const sha2 = std.crypto.hash.sha2;
    switch (hash) {
        inline else => |h| {
            const H = switch (h) {
                .sha224 => sha2.Sha224,
                .sha256 => sha2.Sha256,
                .sha384 => sha2.Sha384,
                .sha512 => sha2.Sha512,
            };
            H.hash(der, out[0..H.digest_length], .{});
            return out[0..H.digest_length];
        },
    }
}

const DerSlice = struct { start: usize, end: usize };

// The contents of the DER element at `pos` if its tag is `tag` and it fits
// in `der`.
fn derElement(der: []const u8, pos: usize, tag: u8) ?DerSlice {
    if (der.len < 2 or pos > der.len - 2 or der[pos] != tag) return null;
    var i = pos + 2;
    var len: usize = der[pos + 1];
    if (len >= 0x80) {
        const n = len & 0x7f;
        if (n == 0 or n > 4 or n > der.len - i) return null;
        len = 0;
        for (der[i..][0..n]) |b| len = (len << 8) | b;
        i += n;
    }
    if (len > der.len - i) return null;
    return .{ .start = i, .end = i + len };
}

pub const ServerResponse = struct {
    raw: []const u8,
    nonce: []const u8,
    base64_salt: []const u8,
    iterations: u32,
};

const t = @import("lib.zig").testing;
test "SASL: init" {
    defer t.reset();
    var sasl1 = try SASL.init(t.io, t.arena.allocator());

    try t.expectString("n,,n=,r=", sasl1.client_first_message[0..8]);

    var sasl2 = try SASL.init(t.io, t.arena.allocator());
    try t.expectString("n,,n=,r=", sasl2.client_first_message[0..8]);

    var sasl3 = try SASL.init(t.io, t.arena.allocator());
    try t.expectString("n,,n=,r=", sasl3.client_first_message[0..8]);

    var sasl4 = try SASL.init(t.io, t.arena.allocator());
    try t.expectString("n,,n=,r=", sasl4.client_first_message[0..8]);

    // The nonce should be random. It's unlikely that if we generate 4, we'd get
    // the same value at a given byte.
    const nonce1 = sasl1.client_first_message[8..];
    const nonce2 = sasl2.client_first_message[8..];
    const nonce3 = sasl3.client_first_message[8..];
    const nonce4 = sasl4.client_first_message[8..];
    for (0..18) |i| {
        try t.expectEqual(true, nonce1[i] != nonce2[i] or
            nonce2[i] != nonce3[i] or
            nonce1[i] != nonce3[i] or
            nonce3[i] != nonce4[i] or
            nonce1[i] != nonce4[i] or
            nonce2[i] != nonce4[i]);
    }
}

test "SASL: serverResponse invalid" {
    //invalid response
    const InvalidTest = struct {
        input: []const u8,
        expected: anyerror,
    };

    const test_cases = [_]InvalidTest{
        .{ .input = "", .expected = error.InvalidLength },
        .{ .input = "r", .expected = error.InvalidLength },
        .{ .input = "r=", .expected = error.InvalidLength },
        .{ .input = "s=abc,r=123,i=32", .expected = error.InvalidNoncePrefix },
        .{ .input = "r=abc123,i=32,s=aaa", .expected = error.InvalidSaltPrefix },
        .{ .input = "r=abc123,s=aaa,x=32", .expected = error.InvalidIterationPrefix },
        .{ .input = "r=abc123", .expected = error.MissingSalt },
        .{ .input = "r=abc123,s=aaaa", .expected = error.MissingIterations },
        .{ .input = "r=abc123,s=aaaa,i=123a", .expected = error.InvalidIteration },
    };

    defer t.reset();
    var sasl = try SASL.init(t.io, t.arena.allocator());

    for (test_cases) |tc| {
        try t.expectError(tc.expected, sasl.serverResponse(tc.input));
        try t.expectEqual(null, sasl.server_response);
    }
}

test "SASL: serverResponse" {
    defer t.reset();
    var sasl = try SASL.init(t.io, t.arena.allocator());

    const nonce = try std.fmt.allocPrint(t.arena.allocator(), "{s}abc123", .{sasl.client_first_message[8..]});
    try sasl.serverResponse(try std.fmt.allocPrint(t.arena.allocator(), "r={s},s=aaaaxa,i=4096", .{nonce}));
    try t.expectString(nonce, sasl.server_response.?.nonce);
    try t.expectString("aaaaxa", sasl.server_response.?.base64_salt);
    try t.expectEqual(4096, sasl.server_response.?.iterations);
}

test "SASL: serverResponse checks the nonce and the iteration count" {
    defer t.reset();
    const a = t.arena.allocator();
    var sasl = try SASL.init(t.io, a);
    const client_nonce = sasl.client_first_message[8..];

    // the server's nonce must extend ours
    try t.expectError(error.InvalidNonce, sasl.serverResponse("r=abc123,s=aaaaxa,i=4096"));
    try t.expectError(error.InvalidNonce, sasl.serverResponse(try std.fmt.allocPrint(a, "r={s},s=aaaaxa,i=4096", .{client_nonce})));
    try t.expectError(error.InvalidNonce, sasl.serverResponse(try std.fmt.allocPrint(a, "r=x{s}x,s=aaaaxa,i=4096", .{client_nonce})));
    // an iteration count that would keep the client hashing for minutes
    try t.expectError(error.InvalidIteration, sasl.serverResponse(try std.fmt.allocPrint(a, "r={s}x,s=aaaaxa,i=4000000000", .{client_nonce})));
    try t.expectError(error.InvalidIteration, sasl.serverResponse(try std.fmt.allocPrint(a, "r={s}x,s=aaaaxa,i=0", .{client_nonce})));
    try t.expectEqual(null, sasl.server_response);

    try sasl.serverResponse(try std.fmt.allocPrint(a, "r={s}x,s=aaaaxa,i={d}", .{ client_nonce, max_iterations }));
    try t.expectEqual(max_iterations, sasl.server_response.?.iterations);
}

test "SASL: channel binding" {
    defer t.reset();
    const a = t.arena.allocator();
    for ([_]SASL.Binding{ .none, .supported, .{ .end_point = &.{ 1, 2, 3, 250 } } }, [_][]const u8{ "n,,", "y,,", "p=tls-server-end-point,," }, [_][]const u8{ "biws", "eSws", "cD10bHMtc2VydmVyLWVuZC1wb2ludCwsAQID+g==" }) |binding, header, cbind| {
        var sasl = try SASL.initWith(t.io, a, binding);
        try t.expectString(header, sasl.client_first_message[0..header.len]);
        try t.expectString("n=,r=", sasl.client_first_message[header.len..][0..5]);
        try t.expectEqual(24, sasl.nonce.len);
        try sasl.serverResponse(try std.fmt.allocPrint(a, "r={s}srv,s=c2FsdA==,i=4096", .{sasl.nonce}));
        const final = try sasl.clientFinalMessage("pw");
        try t.expectString(try std.fmt.allocPrint(a, "c={s},r={s}srv,", .{ cbind, sasl.nonce }), final[0 .. final.len - 46]);
        // the auth message has the bare client-first message, without the gs2 header
        try t.expectString(sasl.client_first_message[header.len..], sasl.auth_message.?[0 .. sasl.client_first_message.len - header.len]);
    }
}

test "serverEndPoint" {
    var out: [64]u8 = undefined;
    // A certificate signed with ecdsa-with-SHA256 (DER cut down to the
    // parts serverEndPoint reads): the SHA-256 of all of it.
    const cert = [_]u8{ 0x30, 0x10, 0x30, 0x02, 0x05, 0x00, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02 };
    var expected: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&cert, &expected, .{});
    try t.expectSlice(u8, &expected, serverEndPoint(&cert, &out).?);
    // ecdsa-with-SHA384: SHA-384
    var cert384 = cert;
    cert384[17] = 0x03;
    var expected384: [48]u8 = undefined;
    std.crypto.hash.sha2.Sha384.hash(&cert384, &expected384, .{});
    try t.expectSlice(u8, &expected384, serverEndPoint(&cert384, &out).?);
    // Ed25519: none
    const ed = [_]u8{ 0x30, 0x0b, 0x30, 0x02, 0x05, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70 };
    try t.expectEqual(null, serverEndPoint(&ed, &out));
    // DER that runs past its end
    try t.expectEqual(null, serverEndPoint(cert[0 .. cert.len - 1], &out));
    try t.expectEqual(null, serverEndPoint(&.{ 0x30, 0x84, 0xff, 0xff, 0xff, 0xff }, &out));
    try t.expectEqual(null, serverEndPoint(&.{}, &out));
}

// Logs in to a fake server that answers the startup message with `request`.
fn fakeLogin(comptime request: []const u8, opts: Opts) !void {
    var server: t.FakeServer = undefined;
    // (only `ok` is followed by what comes next; the others are refused first)
    try server.start(&.{.{ .wait = 0, .reply = comptime &(t.message('R', request) ++ t.message('Z', "I")) }});
    defer server.stop();
    var c = try lib.Conn.open(t.io, t.allocator, .{ .host = "127.0.0.1", .port = server.port, .tls = .off });
    defer c.deinit();
    try c.auth(opts);
}

test "auth: only the ways of logging in allowed" {
    const password = [_]u8{ 0, 0, 0, 3 };
    const md5 = [_]u8{ 0, 0, 0, 5, 1, 2, 3, 4 };
    const ok = [_]u8{ 0, 0, 0, 0 };
    const scram = [_]u8{ 0, 0, 0, 10 } ++ "SCRAM-SHA-256\x00\x00".*;
    const base: Opts = .{ .username = "u", .password = "secret" };

    // allowed by default
    try fakeLogin(&ok, base);

    var o = base;
    o.allow.password = false;
    try t.expectError(error.AuthMethodNotAllowed, fakeLogin(&password, o));
    o = base;
    o.allow.md5 = false;
    try t.expectError(error.AuthMethodNotAllowed, fakeLogin(&md5, o));
    o = base;
    o.allow.none = false;
    try t.expectError(error.AuthMethodNotAllowed, fakeLogin(&ok, o));
    o = base;
    o.allow.scram_sha_256 = false;
    try t.expectError(error.AuthMethodNotAllowed, fakeLogin(&scram, o));

    // channel binding required: nothing but SCRAM-SHA-256-PLUS will do, and
    // without TLS there's nothing to bind to
    o = base;
    o.channel_binding = .require;
    try t.expectError(error.ChannelBindingRequired, fakeLogin(&ok, o));
    try t.expectError(error.ChannelBindingRequired, fakeLogin(&password, o));
    try t.expectError(error.ChannelBindingRequired, fakeLogin(&md5, o));
    try t.expectError(error.ChannelBindingRequired, fakeLogin(&scram, o));
    try t.expectError(error.ChannelBindingRequired, fakeLogin(&([_]u8{ 0, 0, 0, 10 } ++ "SCRAM-SHA-256-PLUS\x00\x00".*), o));
}
