#!/bin/sh
# Capture one TLS 1.3 and one DTLS 1.3 PQTLS session on loopback and prove
# from the packets alone that the key exchange was X25519MLKEM768 (group
# 0x11ec = 4588) on both, and that the payload was encrypted.
#
#   tools/tls-capture.sh [port] [message]
#
# CLIENT picks the device binary, e.g. the emulated RISC-V build:
#   CLIENT="qemu-riscv64 ./pqtls-client.rv64" tools/tls-capture.sh
#
# Capture permissions: see tools/capture.sh.

set -e

PORT=${1:-4433}
MSG=${2:-sensor=temp value=23.4C}
OUT=${OUT:-demo-tls.pcap}
CLIENT=${CLIENT:-./pqtls-client}
ROOT=$(cd "$(dirname "$0")/.." && pwd)
MLKEM=4588 # X25519MLKEM768

cd "$ROOT"

if [ ! -x ./pqtls-server ] || [ ! -x "${CLIENT##* }" ]; then
    echo "tls-capture: build first (make tls)" >&2
    exit 1
fi
if ! dumpcap -D >/dev/null 2>&1; then
    echo "tls-capture: no permission to capture on loopback." >&2
    echo "  fix:  sudo usermod -aG wireshark \"\$USER\"   (then log out and back in)" >&2
    echo "  or, if already in the group:  newgrp wireshark   (then re-run)" >&2
    exit 1
fi

rm -f "$OUT"
echo "== capturing port $PORT (TCP and UDP) on lo -> $OUT"
tshark -i lo -f "port $PORT" -w "$OUT" -q -a duration:30 &
CAP=$!
trap 'kill $CAP 2>/dev/null || true' EXIT
sleep 2 # let tshark attach before the handshake we want to see

for mode in "" --dtls; do
    echo
    echo "== running ${mode:+D}TLS 1.3 session"
    ./pqtls-server $mode "$PORT" &
    SRV=$!
    sleep 0.5
    $CLIENT $mode 127.0.0.1 "$PORT" "$MSG"
    wait $SRV
done

sleep 1
kill $CAP 2>/dev/null || true
wait $CAP 2>/dev/null || true
trap - EXIT

# Nonstandard port: tell tshark what the traffic is.
read_pcap() {
    tshark -r "$OUT" -d "tcp.port==$PORT,tls" -d "udp.port==$PORT,dtls" "$@"
}

FAIL=0
for p in tls dtls; do
    echo
    echo "== $p handshake: every offered and chosen key share group"
    read_pcap -Y "$p.handshake.type == 1 || $p.handshake.type == 2" \
        -T fields -e frame.number -e $p.handshake.type \
        -e $p.handshake.extensions_supported_group \
        -e $p.handshake.extensions_key_share_group \
        -E header=y -E separator=' '

    # Every group in every hello -- offered, supported or chosen -- must be
    # the hybrid one. A lone classical group anywhere would be a fallback.
    groups=$(read_pcap -Y "$p.handshake.type == 1 || $p.handshake.type == 2" \
        -T fields -e $p.handshake.extensions_supported_group \
        -e $p.handshake.extensions_key_share_group | tr ',\t' '\n\n' | grep . |
        # supported_group prints as hex, key_share_group as decimal
        while read -r g; do printf '%d\n' "$g"; done | sort -u)
    if [ "$groups" = "$MLKEM" ]; then
        echo "ok: $p key exchange is X25519MLKEM768 ($MLKEM) and nothing else"
    else
        echo "FAIL: $p hellos carry groups: $(echo $groups)" >&2
        FAIL=1
    fi
done

echo
echo "== the plaintext never appears in any captured packet"
if read_pcap -Y "frame contains \"$MSG\"" -T fields -e frame.number | grep -q .; then
    echo "FAIL: plaintext \"$MSG\" found in the capture" >&2
    FAIL=1
else
    echo "ok: \"$MSG\" does not appear in $OUT"
fi

echo
echo "wrote $OUT  --  open with:"
echo "  wireshark -d tcp.port==$PORT,tls -d udp.port==$PORT,dtls $OUT"
exit $FAIL
