#!/bin/sh
# Check the PQTLS endpoints against an independent TLS 1.3 stack (OpenSSL
# >= 3.5, which ships X25519MLKEM768), both ways round, and check that each
# endpoint refuses a peer that only offers classical key exchange.
#
#   tools/tls-check.sh [port] [message]
#
# TLS only: OpenSSL has no DTLS 1.3 to test the --dtls path against.

set -u

PORT=${1:-4433}
MSG=${2:-sensor=temp value=23.4C}
ROOT=$(cd "$(dirname "$0")/.." && pwd)
CERT=build/certs/server.pem
KEY=build/certs/server.key
CA=build/certs/ca.pem
NAME=server.pqiot.test
LOG=$(mktemp)
FAILS=0

cd "$ROOT"
trap 'rm -f "$LOG"' EXIT

if [ ! -x ./pqtls-server ] || [ ! -x ./pqtls-client ] || [ ! -f "$CA" ]; then
    echo "tls-check: build first (make tls)" >&2
    exit 1
fi

pass() { echo "ok    $1"; }
fail() { echo "FAIL  $1"; sed 's/^/      | /' "$LOG"; FAILS=$((FAILS + 1)); }

# OpenSSL client -> our server. $1: groups OpenSSL offers.
openssl_client() {
    ./pqtls-server "$PORT" >"$LOG" 2>&1 &
    srv=$!
    sleep 0.5
    # -ign_eof: keep reading after stdin ends, so the reply is printed.
    printf '%s' "$MSG" | timeout 10 openssl s_client -connect "127.0.0.1:$PORT" \
        -tls1_3 -groups "$1" -CAfile "$CA" -verify_hostname "$NAME" \
        -verify_return_error -ign_eof >>"$LOG" 2>&1
    cli=$?
    wait $srv
    srv=$?
}

# Our client -> OpenSSL server, which echoes lines back reversed.
# $1: groups OpenSSL accepts.
openssl_server() {
    # s_server drops the connection when its stdin hits EOF; hold it open.
    sleep 3 | timeout 10 openssl s_server -accept "$PORT" -cert "$CERT" \
        -key "$KEY" -tls1_3 -groups "$1" -naccept 1 -rev -quiet \
        >/dev/null 2>&1 &
    sleep 0.5
    timeout 10 ./pqtls-client 127.0.0.1 "$PORT" "$MSG
" >"$LOG" 2>&1
    cli=$?
    wait
}

REV=$(printf '%s' "$MSG" | rev)

openssl_client X25519MLKEM768
if [ $cli = 0 ] && [ $srv = 0 ] &&
   grep -q "Negotiated TLS1.3 group: X25519MLKEM768" "$LOG" &&
   grep -q "Verify return code: 0 (ok)" "$LOG" &&
   grep -q "ack: telemetry received" "$LOG"; then
    pass "OpenSSL client -> pqtls-server: X25519MLKEM768, cert verified"
else
    fail "OpenSSL client -> pqtls-server"
fi

openssl_server X25519MLKEM768
if [ $cli = 0 ] && grep -q "key exchange X25519MLKEM768" "$LOG" &&
   grep -qF "$REV" "$LOG"; then
    pass "pqtls-client -> OpenSSL server: X25519MLKEM768, reply decrypted"
else
    fail "pqtls-client -> OpenSSL server"
fi

openssl_client X25519
if [ $srv != 0 ] && ! grep -q "ack: telemetry received" "$LOG"; then
    pass "pqtls-server refuses a classical-only (X25519) client"
else
    fail "pqtls-server accepted a classical-only client"
fi

openssl_server X25519
if [ $cli != 0 ] && ! grep -q "handshake OK" "$LOG"; then
    pass "pqtls-client refuses a classical-only (X25519) server"
else
    fail "pqtls-client accepted a classical-only server"
fi

echo
if [ $FAILS != 0 ]; then
    echo "$FAILS check(s) failed" >&2
    exit 1
fi
echo "all TLS checks passed"
