#!/usr/bin/env bash
# Runs the test suite against a throwaway postgres:17 in Docker, in each
# configuration: std's Threaded Io and a zio runtime (pinned executors), with
# std's TLS and without TLS.
#
# The server gets a CA and a certificate made here for this run (in a
# temporary directory, copied to tests/root.crt and tests/other.crt for the
# tests, all removed on exit), TLS on, and users for trust, cleartext, md5 and
# scram-sha-256 authentication (tests/pg_hba.conf). The container is removed
# on exit.
#
#   tests/run.sh                 # every configuration
#   CONFIGS="threaded" tests/run.sh
#   PG_TEST_PORT=55432 ZIG=zig TEST_FILTER=Pool tests/run.sh
set -euo pipefail

cd "$(dirname "$0")/.."
ZIG=${ZIG:-zig}
PORT=${PG_TEST_PORT:-55432}
IMAGE=${PG_TEST_IMAGE:-postgres:17}
NAME=pgzig-test-$$
CONFIGS=${CONFIGS:-"threaded threaded-notls zio zio-notls"}

CERTS=$(mktemp -d)
cleanup() {
  docker rm -f "$NAME" >/dev/null 2>&1 || true
  rm -rf "$CERTS"
  rm -f tests/root.crt tests/other.crt
}
trap cleanup EXIT

# A CA, a server certificate for localhost and 127.0.0.1 (the address also as
# a DNS name, for verifiers that only compare DNS names), and an unrelated CA
# for the verification failure tests. Valid for a day.
(
  cd "$CERTS"
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 1 \
    -subj '/CN=pg.zig test CA' -keyout ca.key -out root.crt \
    -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign 2>/dev/null
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
    -subj '/CN=localhost' -keyout server.key -out server.csr 2>/dev/null
  printf 'subjectAltName=DNS:localhost,IP:127.0.0.1,DNS:127.0.0.1\nbasicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\n' > server.ext
  openssl x509 -req -in server.csr -CA root.crt -CAkey ca.key -CAcreateserial -days 1 \
    -extfile server.ext -out server.crt 2>/dev/null
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 1 \
    -subj '/CN=other CA' -keyout other.key -out other.crt 2>/dev/null
  rm -f server.csr server.ext ca.key other.key root.srl
)
cp "$CERTS/root.crt" tests/root.crt
cp "$CERTS/other.crt" tests/other.crt

docker run -d --rm --name "$NAME" -p "127.0.0.1:$PORT:5432" \
  -e POSTGRES_PASSWORD=postgres \
  -v "$CERTS/server.crt:/etc/pgtls/server.crt:ro" \
  -v "$CERTS/server.key:/etc/pgtls/server.key.host:ro" \
  -v "$PWD/tests/pg_hba.conf:/etc/pgtls/pg_hba.conf:ro" \
  -v "$PWD/tests/postgresql.conf:/etc/pgtls/postgresql.conf:ro" \
  "$IMAGE" bash -ec '
    # the key must belong to the server user, whatever owns it on the host
    cp /etc/pgtls/server.key.host /etc/pgtls/server.key
    chown postgres:postgres /etc/pgtls/server.key
    chmod 600 /etc/pgtls/server.key
    exec docker-entrypoint.sh postgres \
      -c config_file=/etc/pgtls/postgresql.conf \
      -c hba_file=/etc/pgtls/pg_hba.conf \
      -c ssl=on -c ssl_cert_file=/etc/pgtls/server.crt -c ssl_key_file=/etc/pgtls/server.key' >/dev/null

# The entrypoint starts the server once to initialize it, then restarts it.
for _ in $(seq 1 60); do
  if docker exec "$NAME" pg_isready -h 127.0.0.1 -U postgres >/dev/null 2>&1; then
    sleep 1
    docker exec "$NAME" pg_isready -h 127.0.0.1 -U postgres >/dev/null 2>&1 && break
  fi
  sleep 1
done
docker exec "$NAME" pg_isready -h 127.0.0.1 -U postgres >/dev/null

status=0
for config in $CONFIGS; do
  case "$config" in
    threaded) args=(-Dtls=std) ;;
    threaded-notls) args=(-Dtls=none) ;;
    zio) args=(-Dtls=std -Dzio=true) ;;
    zio-notls) args=(-Dtls=none -Dzio=true) ;;
    *) echo "unknown configuration $config" >&2; exit 1 ;;
  esac
  echo "== $config"
  if ! "$ZIG" build test -Dtest_port="$PORT" "${args[@]}" "$@"; then
    status=1
  fi
done
exit $status
