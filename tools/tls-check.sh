#!/bin/sh
# Check the PQTLS endpoints against an independent TLS 1.3 stack (OpenSSL
# >= 3.5, which ships X25519MLKEM768 and ML-DSA), both ways round, and check
# that each endpoint refuses a peer that falls short of the policy:
# classical-only key exchange, no certificate, a certificate from another
# CA, or a classical (ECDSA) certificate from our own CA.
#
#   tools/tls-check.sh [port] [message]
#
# TLS only: OpenSSL has no DTLS 1.3 to test the --dtls path against.

set -u

PORT=${1:-4433}
MSG=${2:-sensor=temp value=23.4C}
ROOT=$(cd "$(dirname "$0")/.." && pwd)
PKI=build/certs
BAD=build/certs/bad # certificates to refuse, from `make certs`
NAME=server.pqiot.test
LOG=$(mktemp)
FAILS=0

cd "$ROOT"
trap 'rm -f "$LOG"' EXIT

if [ ! -x ./pqtls-server ] || [ ! -x ./pqtls-client ] || [ ! -f $BAD/ecdsa-dev.pem ]; then
    echo "tls-check: build first (make tls certs)" >&2
    exit 1
fi


pass() { echo "ok    $1"; }
fail() { echo "FAIL  $1"; sed 's/^/      | /' "$LOG"; FAILS=$((FAILS + 1)); }

# OpenSSL client -> our server. $1: groups OpenSSL offers, rest: extra
# s_client arguments (the client certificate, or none).
openssl_client() {
    groups=$1; shift
    ./pqtls-server "$PORT" >"$LOG" 2>&1 &
    srv=$!
    sleep 0.5
    # -ign_eof: keep reading after stdin ends, so the reply is printed.
    printf '%s' "$MSG" | timeout 10 openssl s_client -connect "127.0.0.1:$PORT" \
        -tls1_3 -groups "$groups" -CAfile $PKI/ca.pem -verify_hostname "$NAME" \
        -verify_return_error -ign_eof "$@" >>"$LOG" 2>&1
    cli=$?
    wait $srv
    srv=$?
}

# Our client -> OpenSSL server, which demands a client certificate from our
# CA and echoes lines back reversed. $1: groups, $2: server cert/key prefix.
openssl_server() {
    # s_server drops the connection when its stdin hits EOF; hold it open.
    sleep 3 | timeout 10 openssl s_server -accept "$PORT" -cert "$2.pem" \
        -key "$2.key" -tls1_3 -groups "$1" -Verify 1 -CAfile $PKI/ca.pem \
        -verify_return_error -naccept 1 -rev -quiet >/dev/null 2>&1 &
    sleep 0.5
    timeout 10 ./pqtls-client 127.0.0.1 "$PORT" "$MSG
" >"$LOG" 2>&1
    cli=$?
    wait
}

DEV="-cert $PKI/device.pem -key $PKI/device.key"
REV=$(printf '%s' "$MSG" | rev)

echo "== interop with OpenSSL, mutual ML-DSA-65"

openssl_client X25519MLKEM768 $DEV
if [ $cli = 0 ] && [ $srv = 0 ] &&
   grep -q "Negotiated TLS1.3 group: X25519MLKEM768" "$LOG" &&
   grep -q "Peer signature type: mldsa65" "$LOG" &&
   grep -q "Verify return code: 0 (ok)" "$LOG" &&
   grep -q "peer authenticated: CN=device-0001.pqiot.test" "$LOG" &&
   grep -q "ack: telemetry received" "$LOG"; then
    pass "OpenSSL client -> pqtls-server"
else
    fail "OpenSSL client -> pqtls-server"
fi

openssl_server X25519MLKEM768 $PKI/server
if [ $cli = 0 ] && grep -q "key exchange X25519MLKEM768" "$LOG" &&
   grep -q "peer authenticated: CN=$NAME (ML-DSA-65)" "$LOG" &&
   grep -qF "$REV" "$LOG"; then
    pass "pqtls-client -> OpenSSL server (which required its certificate)"
else
    fail "pqtls-client -> OpenSSL server"
fi

echo
echo "== refusals: each differs from the passing run above in one way"

# Each failure must also come from the handshake, not from some other
# breakage, hence the grep for the endpoint's own error.
refused_by_server() {
    [ $srv != 0 ] && grep -q "server: handshake failed" "$LOG" &&
        ! grep -q "ack: telemetry received" "$LOG"
}

openssl_client X25519 $DEV
refused_by_server && pass "server refuses classical-only (X25519) key exchange" ||
    fail "server accepted classical-only key exchange"

openssl_client X25519MLKEM768
refused_by_server && pass "server refuses a client with no certificate" ||
    fail "server accepted a client with no certificate"

openssl_client X25519MLKEM768 -cert $BAD/ecdsa-dev.pem -key $BAD/ecdsa-dev.key
if [ $srv != 0 ] && grep -q "server: peer certificate is not ML-DSA-65" "$LOG" &&
   ! grep -q "ack: telemetry received" "$LOG"; then
    pass "server refuses an ECDSA client certificate from our own CA"
else
    fail "server accepted an ECDSA client certificate"
fi

openssl_server X25519 $PKI/server
[ $cli != 0 ] && grep -q "client: handshake failed" "$LOG" &&
    pass "client refuses classical-only (X25519) key exchange" ||
    fail "client accepted classical-only key exchange"

openssl_server X25519MLKEM768 $BAD/rogue
[ $cli != 0 ] && grep -q "client: handshake failed" "$LOG" &&
    pass "client refuses an ML-DSA server certificate from another CA" ||
    fail "client accepted a server certificate from another CA"

openssl_server X25519MLKEM768 $BAD/ecdsa-srv
if [ $cli != 0 ] && grep -q "device: peer certificate is not ML-DSA-65" "$LOG" &&
   ! grep -qF "plaintext was" "$LOG"; then
    pass "client refuses an ECDSA server certificate from our own CA"
else
    fail "client accepted an ECDSA server certificate"
fi

echo
if [ $FAILS != 0 ]; then
    echo "$FAILS check(s) failed" >&2
    exit 1
fi
echo "all TLS checks passed"
