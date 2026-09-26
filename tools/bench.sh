#!/bin/sh
# Host-side benchmarks (`make bench`):
#   1. every primitive + whole PQIOT/2 sessions (pqiot-bench)
#   2. TLS 1.3 and DTLS 1.3 handshake latency, N runs each, and how many
#      succeeded
#   3. bytes on the wire per session, from the capture files if present
#      (make capture tls-capture; reading a pcap needs no privileges)
#   4. firmware image sizes, if built (make fw fw-net)
# Bare-metal cycle counts are separate: make fw-bench.
#
#   tools/bench.sh [runs] [port]

set -u

RUNS=${1:-50}
PORT=${2:-4900}
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"

for b in pqiot-bench pqtls-server pqtls-client; do
    [ -x "./$b" ] || { echo "bench: build first (make all tls)" >&2; exit 1; }
done

echo "== machine"
echo "  cpu: $(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2- | sed 's/^ *//')"
echo "  cc:  $(${CC:-cc} --version | head -1)"
echo

./pqiot-bench 50 "$RUNS" || exit 1

# One (D)TLS session per run; the client prints "handshake took X ms".
tls_runs() {
    mode=$1 label=$2 ok=0
    : > build/bench-hs.txt
    i=0
    while [ $i -lt "$RUNS" ]; do
        ./pqtls-server $mode "$PORT" > /dev/null 2>&1 &
        srv=$!
        sleep 0.2
        if out=$(./pqtls-client $mode 127.0.0.1 "$PORT" 2>&1) &&
           wait $srv; then
            ok=$((ok + 1))
            echo "$out" | sed -n 's/.*handshake took \([0-9.]*\) ms.*/\1/p' \
                >> build/bench-hs.txt
        else
            kill $srv 2>/dev/null; wait $srv 2>/dev/null
        fi
        i=$((i + 1))
    done
    sort -n build/bench-hs.txt | awk -v l="$label" -v ok=$ok -v n="$RUNS" '
        { v[NR] = $1 }
        END { if (NR) printf "  %-44s %9.3f %9.3f %9.3f ms (min median max)\n",
                             l, v[1], v[int((NR + 1) / 2)], v[NR];
              printf "  %-44s %d / %d\n", l " succeeded", ok, n }'
}

echo
echo "== TLS/DTLS 1.3 handshakes (X25519MLKEM768 + mutual ML-DSA-65), $RUNS runs each"
tls_runs ""     "TLS 1.3 handshake, loopback TCP"
tls_runs --dtls "DTLS 1.3 handshake, loopback UDP"
rm -f build/bench-hs.txt

# Bytes each way on the wire, whole session, from a capture: payload only
# (tcp.len / udp.length - 8), plus the packet count, by sender address:port
# (on loopback both ends are 127.0.0.1, so the port tells them apart).
wire() {
    pcap=$1 proto=$2 label=$3
    [ -f "$pcap" ] || { echo "  $label: no $pcap (run the capture target)"; return; }
    if [ "$proto" = tcp ]; then len=tcp.len; hdr=0; else len=udp.length; hdr=8; fi
    tshark -r "$pcap" -Y "$proto && $len > $hdr" -T fields -E separator=' ' \
           -e ip.src -e "$proto.srcport" -e "$len" 2>/dev/null |
        awk -v l="$label" -v h=$hdr '
        { k = $1 ":" $2; n[k]++; b[k] += $3 - h }
        END { s = ""; for (k in b) s = s sprintf("  %s: %d B/%d pkts", k, b[k], n[k]);
              printf "  %-30s%s\n", l, s }'
}

echo
echo "== bytes on the wire per session (payload bytes / packets, by sender)"
wire demo.pcap        tcp "PQIOT/2 over TCP"
wire demo-tls.pcap    tcp "TLS 1.3 session"
wire demo-tls.pcap    udp "DTLS 1.3 session"
wire demo-fw-net.pcap udp "PQIOT/2, bare-metal over UDP"

echo
echo "== firmware images (bytes)"
for elf in build/fw/pqiot-fw.elf build/fw-net/pqiot-fw-net.elf; do
    [ -f "$elf" ] && riscv64-elf-size "$elf" | awk -v f="$elf" \
        'NR == 2 { printf "  %-34s code+rodata %7d  data %5d  bss %7d\n", f, $1, $2, $3 }'
done
exit 0
