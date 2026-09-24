#!/bin/sh
# Capture a PQIOT session on loopback and prove from the packets alone that
# the ML-KEM exchange and the ML-DSA authentication really happened and the
# payload really was encrypted.
#
#   tools/capture.sh [port] [message]
#
# CLIENT picks the device binary, e.g. the emulated RISC-V build:
#   CLIENT="qemu-riscv64 ./pqiot-client.rv64" OUT=demo-riscv.pcap tools/capture.sh
#
# Loopback capture needs privileges. Either add yourself to the wireshark
# group once (then re-login):
#     sudo usermod -aG wireshark "$USER"
# If a re-login isn't practical (e.g. a long-running terminal app), a
# `newgrp wireshark` shell picks the group up immediately.
# Running under sudo doesn't work: tshark as root fails to write the pcap.

set -e

PORT=${1:-4433}
MSG=${2:-sensor=temp value=23.4C}
OUT=${OUT:-demo.pcap}
CLIENT=${CLIENT:-./pqiot-client}
ROOT=$(cd "$(dirname "$0")/.." && pwd)

cd "$ROOT"

# Last word of CLIENT is the binary; anything before it is a wrapper (qemu).
if [ ! -x ./pqiot-server ] || [ ! -x "${CLIENT##* }" ]; then
    echo "capture: build first (make)" >&2
    exit 1
fi

# Fail early and legibly if we cannot capture, rather than producing an
# empty pcap and a confusing analysis.
if ! dumpcap -D >/dev/null 2>&1; then
    echo "capture: no permission to capture on loopback." >&2
    echo "  fix:  sudo usermod -aG wireshark \"\$USER\"   (then log out and back in)" >&2
    echo "  or, if already in the group:  newgrp wireshark   (then re-run)" >&2
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
$CLIENT 127.0.0.1 "$PORT" "$MSG"
wait $SRV

sleep 1
kill $CAP 2>/dev/null || true
wait $CAP 2>/dev/null || true
trap - EXIT

echo
# TCP coalesces back-to-back messages (CERT+VERIFY, say) into one segment,
# so this lists segments that *start* with a PQIOT header.
echo "== TCP segments starting with a PQIOT header (magic 'PQIO' = 50:51:49:4f)"
tshark -r "$OUT" -Y 'tcp.payload contains 50:51:49:4f' \
       -T fields -e frame.number -e tcp.srcport -e tcp.dstport -e tcp.len \
       -E header=y -E separator=' '

echo
echo "== handshake bodies: ML-KEM-768 public key (1184) and cipher text (1088),"
echo "   then each side's sealed ML-DSA-65 CERT + VERIFY (~5.5 KB + 3309, one segment)"
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

# CERT and VERIFY are sealed, so neither side's identity is readable either.
# (Against a PQIOT/2 build that sent them in clear, this check fails.)
echo
echo "== neither certificate's name appears in any captured packet"
for name in server.pqiot.test device-0001.pqiot.test; do
    if tshark -r "$OUT" -Y "tcp.payload contains \"$name\"" -T fields \
            -e frame.number | grep -q .; then
        echo "FAIL: certificate name \"$name\" found in the capture" >&2
        exit 1
    fi
    echo "ok: \"$name\" does not appear in $OUT"
done

echo
echo "wrote $OUT  --  open with:  wireshark $OUT"
