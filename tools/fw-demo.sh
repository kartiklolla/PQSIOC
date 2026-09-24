#!/bin/sh
# Boot the bare-metal PQIOT/2 firmware in the LiteX VexRiscv simulator, show
# its console live, and exit with its verdict. litex_sim never exits on its
# own, so this waits for the firmware's "PQIOT bare-metal demo:" line.
#
#   tools/fw-demo.sh build/fw/pqiot-fw.bin
#
# LITEX_SIM and FW_SIM_ARGS come from the Makefile (`make fw-demo`).
# FW_TIMEOUT (seconds, default 3600) bounds a hung simulation.

set -u

BIN=$1
LOG=${LOG:-build/fw/sim.log}
TIMEOUT=${FW_TIMEOUT:-3600}
PATH="$(dirname "$LITEX_SIM"):$PATH"
export PATH

if [ ! -f "$BIN" ]; then
    echo "fw-demo: no firmware at $BIN (make fw)" >&2
    exit 1
fi

# setsid: litex_sim starts make and the Verilator binary as children; its
# own process group lets us stop all of them at once.
# shellcheck disable=SC2086 # FW_SIM_ARGS is a word list on purpose
setsid "$LITEX_SIM" $FW_SIM_ARGS --ram-init="$BIN" --non-interactive \
    > "$LOG" 2>&1 &
SIM=$!
trap 'kill -- -$SIM 2>/dev/null' EXIT INT TERM

tail -n +1 -f "$LOG" &
TAIL=$!

start=$(date +%s)
# The console prefixes lines with \r, so no ^ anchors below.
while ! grep -aq "PQIOT bare-metal demo:" "$LOG"; do
    if ! kill -0 $SIM 2>/dev/null; then
        kill $TAIL
        echo "fw-demo: simulator exited early, see $LOG" >&2
        exit 1
    fi
    if [ $(( $(date +%s) - start )) -ge "$TIMEOUT" ]; then
        kill $TAIL
        echo "fw-demo: no verdict after ${TIMEOUT}s, see $LOG" >&2
        exit 1
    fi
    sleep 1
done
sleep 1 # let tail print the last lines
kill $TAIL

echo "fw-demo: verdict after $(( $(date +%s) - start ))s (wall clock, incl. Verilator build)"
grep -aq "PQIOT bare-metal demo: OK" "$LOG"
