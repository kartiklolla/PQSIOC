#!/bin/sh
# The bare-metal device on the simulated network: boot the networked firmware
# in the LiteX simulator with its Ethernet MAC on the host's tap0, relay its
# UDP stream to an ordinary TCP pqiot-server, and pass only if the device,
# the server and the bridge all finish cleanly.
#
#   tools/fw-net-demo.sh build/fw-net/pqiot-fw-net.bin
#
# LITEX_SIM, FW_SIM_ARGS and SERVER_PORT come from `make fw-net-demo`.
# CAPTURE=1 also records tap0 into demo-fw-net.pcap and checks it (needs
# capture rights, see tools/capture.sh).
#
# tap0 must exist, be owned by you and carry 192.168.1.100 (one-time, root):
#   sudo ip tuntap add dev tap0 mode tap user "$USER"
#   sudo ip addr add 192.168.1.100/24 dev tap0
#   sudo ip link set tap0 up

set -u

BIN=$1
SERVER_PORT=${SERVER_PORT:-4434}
TIMEOUT=${FW_TIMEOUT:-3600}
OUT=build/fw-net
LOG=$OUT/sim.log
PCAP=demo-fw-net.pcap
MSG="sensor=temp value=23.4C"
PATH="$(dirname "$LITEX_SIM"):$PATH"
export PATH

fail() { echo "fw-net-demo: $*" >&2; exit 1; }

[ -f "$BIN" ] || fail "no firmware at $BIN (make fw-net)"
ip -4 addr show dev tap0 2>/dev/null | grep -q "192.168.1.100/" ||
    fail "tap0 missing or without 192.168.1.100 -- see the top of $0"

PIDS=""
cleanup() {
    [ -n "${SIM:-}" ] && kill -- -"$SIM" 2>/dev/null
    for p in $PIDS; do kill "$p" 2>/dev/null; done
}
trap cleanup EXIT INT TERM

if [ "${CAPTURE:-0}" = 1 ]; then
    rm -f "$PCAP"
    tshark -i tap0 -f "udp port 4433" -w "$PCAP" -q 2>/dev/null &
    CAP=$!
    PIDS="$PIDS $CAP"
    sleep 2
fi

./pqiot-server "$SERVER_PORT" > "$OUT/server.log" 2>&1 &
SRV=$!
PIDS="$PIDS $SRV"
python3 tools/udp-bridge.py --listen 192.168.1.100:4433 \
    --server "127.0.0.1:$SERVER_PORT" > "$OUT/bridge.log" 2>&1 &
BRIDGE=$!
PIDS="$PIDS $BRIDGE"
sleep 0.5

# litex_sim runs any Ethernet simulation under `sudo`, so it can create the
# tap device. tap0 already exists and is ours, so no root is needed: a `sudo`
# earlier in PATH that just runs the command as us keeps it unprivileged.
mkdir -p "$OUT/nosudo"
printf '#!/bin/sh\nexec "$@"\n' > "$OUT/nosudo/sudo"
chmod +x "$OUT/nosudo/sudo"

# shellcheck disable=SC2086 # FW_SIM_ARGS is a word list on purpose
PATH="$PWD/$OUT/nosudo:$PATH" setsid "$LITEX_SIM" $FW_SIM_ARGS \
    --ram-init="$BIN" --non-interactive > "$LOG" 2>&1 &
SIM=$!

tail -n +1 -f "$LOG" &
TAIL=$!
PIDS="$PIDS $TAIL"

start=$(date +%s)
# The console prefixes lines with \r, so no ^ anchors.
while ! grep -aq "PQIOT bare-metal demo:" "$LOG"; do
    kill -0 "$SIM" 2>/dev/null || fail "simulator exited early, see $LOG"
    [ $(( $(date +%s) - start )) -lt "$TIMEOUT" ] ||
        fail "no verdict after ${TIMEOUT}s, see $LOG"
    sleep 1
done
sleep 1
kill "$TAIL"

# The server and bridge finish on their own once the session is over; if
# the device failed partway they may not, so they get 15 s.
reap() {
    i=0
    while kill -0 "$1" 2>/dev/null && [ $i -lt 15 ]; do sleep 1; i=$((i + 1)); done
    kill "$1" 2>/dev/null
    wait "$1"
}
reap "$SRV"; srv_rc=$?
reap "$BRIDGE"; bridge_rc=$?
echo
sed 's/^/  /' "$OUT/server.log"
sed 's/^/  /' "$OUT/bridge.log"
echo "fw-net-demo: verdict after $(( $(date +%s) - start ))s" \
     "(wall clock, incl. Verilator build)"

rc=0
grep -aq "PQIOT bare-metal demo: OK" "$LOG" || { echo "FAIL: device" >&2; rc=1; }
[ "$srv_rc" = 0 ] || { echo "FAIL: pqiot-server exited $srv_rc" >&2; rc=1; }
[ "$bridge_rc" = 0 ] || { echo "FAIL: bridge exited $bridge_rc" >&2; rc=1; }

if [ "${CAPTURE:-0}" = 1 ]; then
    sleep 1
    kill "$CAP" 2>/dev/null; wait "$CAP" 2>/dev/null
    echo
    echo "== $PCAP: UDP datagrams on tap0 between the SoC and the host"
    tshark -r "$PCAP" -q -z conv,udp 2>/dev/null | grep -E "<->|Filter"
    echo "== PQIOT headers seen (magic 'PQIO'): $(tshark -r "$PCAP" \
        -Y 'udp.payload contains 50:51:49:4f' 2>/dev/null | wc -l) datagrams"
    for s in "$MSG" server.pqiot.test device-0001.pqiot.test; do
        if tshark -r "$PCAP" -Y "udp.payload contains \"$s\"" -T fields \
                -e frame.number 2>/dev/null | grep -q .; then
            echo "FAIL: \"$s\" readable on the wire" >&2; rc=1
        else
            echo "ok: \"$s\" does not appear in $PCAP"
        fi
    done
fi
exit $rc
