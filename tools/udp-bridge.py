#!/usr/bin/env python3
"""Relay one PQIOT/2 session between the bare-metal device and pqiot-server.

The bare-metal firmware (firmware/udp_stream.c) has UDP but no TCP, so it
speaks a small reliable stream over UDP; this turns that into an ordinary TCP
connection to the unmodified pqiot-server. It only moves bytes: it holds no
keys and can't read the session.

    tools/udp-bridge.py [--listen 192.168.1.100:4433] [--server 127.0.0.1:4434]

Datagram: [kind 1B][seq 4B big-endian][payload]; kind 0 DATA, 1 ACK,
2 HELLO. Stop-and-wait each way, retransmit until ACKed (see udp_stream.c).
Exits 0 once the server closes and everything reached the device.
"""
import argparse
import select
import socket
import struct
import sys
import time

DATA, ACK, HELLO = 0, 1, 2
CHUNK = 1024
RTO = 1.0         # s without an ACK before resending: the simulator is slow
GIVE_UP = 600.0   # s without hearing from the device at all


def addr(s):
    host, port = s.rsplit(":", 1)
    return host, int(port)


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--listen", type=addr, default=("192.168.1.100", 4433))
    ap.add_argument("--server", type=addr, default=("127.0.0.1", 4434))
    args = ap.parse_args()

    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    udp.bind(args.listen)
    print(f"[bridge] waiting for the device on udp {args.listen[0]}:{args.listen[1]}",
          flush=True)

    def send(kind, seq, payload=b""):
        udp.sendto(struct.pack(">BI", kind, seq) + payload, device)

    # HELLO opens the session: answer it, then connect to the server.
    device = None
    while device is None:
        pkt, src = udp.recvfrom(2048)
        if len(pkt) >= 5 and pkt[0] == HELLO:
            device = src
    send(ACK, struct.unpack(">I", pkt[1:5])[0])
    tcp = socket.create_connection(args.server)
    print(f"[bridge] device {device[0]}:{device[1]} <-> "
          f"tcp {args.server[0]}:{args.server[1]}", flush=True)

    to_device = b""          # server bytes not yet ACKed by the device
    tx_seq, tx_len, tx_at = 0, 0, 0.0   # outstanding DATA: seq, size, sent at
    rx_expected = 1          # device DATA starts at 1 (HELLO was 0)
    server_open = True
    heard = time.monotonic()
    moved = [0, 0]           # bytes device->server, server->device

    while server_open or to_device:
        now = time.monotonic()
        if now - heard > GIVE_UP:
            print("[bridge] device went quiet, giving up", file=sys.stderr)
            return 1
        # (Re)send the chunk at the head of the queue.
        if to_device and (tx_len == 0 or now - tx_at > RTO):
            tx_len = min(len(to_device), CHUNK)
            send(DATA, tx_seq, to_device[:tx_len])
            tx_at = now

        rd = [udp] + ([tcp] if server_open else [])
        ready, _, _ = select.select(rd, [], [], 0.2)

        if tcp in ready:
            data = tcp.recv(65536)
            if data:
                to_device += data
            else:
                server_open = False

        if udp in ready:
            pkt, src = udp.recvfrom(2048)
            if src != device or len(pkt) < 5:
                continue
            heard = time.monotonic()
            kind, seq = struct.unpack(">BI", pkt[:5])
            if kind == ACK and tx_len and seq == tx_seq:
                moved[1] += tx_len
                to_device = to_device[tx_len:]
                tx_seq, tx_len = tx_seq + 1, 0
            elif kind == DATA:
                if seq == rx_expected:
                    tcp.sendall(pkt[5:])
                    moved[0] += len(pkt) - 5
                    rx_expected += 1
                if seq in (rx_expected - 1,):   # new or duplicate: ACK it
                    send(ACK, seq)
            elif kind == HELLO:
                send(ACK, seq)                  # our first ACK got lost

    tcp.close()
    print(f"[bridge] done: {moved[0]} bytes device->server, "
          f"{moved[1]} bytes server->device", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
