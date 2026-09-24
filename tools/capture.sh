#!/bin/sh
# Capture a PQIOT session on loopback and prove from the packets alone that
# the ML-KEM exchange really happened and the payload really was encrypted.
#
#   tools/capture.sh [port] [message]
#
# Loopback capture needs privileges. Either add yourself to the wireshark
# group once (then re-login):
#     sudo usermod -aG wireshark "$USER"
# or run this script under sudo.

set -e

PORT=${1:-4433}
MSG=${2:-sensor=temp value=23.4C}
OUT=${OUT:-demo.pcap}
ROOT=$(cd "$(dirname "$0")/.." && pwd)

cd "$ROOT"

if [ ! -x ./pqiot-server ] || [ ! -x ./pqiot-client ]; then
    echo "capture: build first (make)" >&2
    exit 1
fi

# Fail early and legibly if we cannot capture, rather than producing an
# empty pcap and a confusing analysis.
if ! dumpcap -D >/dev/null 2>&1; then
    echo "capture: no permission to capture on loopback." >&2
    echo "  fix:  sudo usermod -aG wireshark \"\$USER\"   (then log out and back in)" >&2
    echo "  or:   sudo tools/capture.sh $PORT" >&2
    exit 1
fi

rm -f "$OUT"
echo "== capturing tcp port $PORT on lo -> $OUT"
tshark -i lo -f "tcp port $PORT" -w "$OUT" -q -a duration:15 &
CAP=$!
trap 'kill $CAP 2>/dev/null || true' EXIT

# tshark needs a moment before the socket is actually being watched; starting
# the session too early loses the handshake we are trying to prove.
sleep 2

echo
echo "== running session"
./pqiot-server "$PORT" &
SRV=$!
sleep 0.5
./pqiot-client 127.0.0.1 "$PORT" "$MSG"
wait $SRV

sleep 1
kill $CAP 2>/dev/null || true
wait $CAP 2>/dev/null || true
trap - EXIT

echo
echo "== PQIOT frames on the wire (magic 'PQIO' = 50:51:49:4f)"
tshark -r "$OUT" -Y 'tcp.payload contains 50:51:49:4f' \
       -T fields -e frame.number -e tcp.srcport -e tcp.dstport -e tcp.len \
       -E header=y -E separator=' '

echo
echo "== the 1184-byte ML-KEM-768 public key and 1088-byte cipher text"
tshark -r "$OUT" -Y 'tcp.len > 900' \
       -T fields -e frame.number -e tcp.srcport -e tcp.len \
       -E header=y -E separator=' '

echo
echo "== the plaintext never appears in any captured packet"
if tshark -r "$OUT" -Y "tcp.payload contains \"$MSG\"" -T fields -e frame.number \
        | grep -q .; then
    echo "FAIL: plaintext \"$MSG\" found in the capture" >&2
    exit 1
fi
echo "ok: \"$MSG\" does not appear in $OUT"

echo
echo "wrote $OUT  --  open with:  wireshark $OUT"
