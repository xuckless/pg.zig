// The `tls` module when pg.zig is built without TLS (-Dtls=none). Connections
// with `.tls = .prefer` stay unencrypted; any other TLS mode fails with
// error.TlsNotAvailable.
pub const pg_tls_disabled = true;
