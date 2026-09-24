# PQIOT — Post-Quantum Secure IoT Communication

A client/server channel whose key exchange is a post-quantum KEM. The server
holds an **ML-KEM-768** (Kyber) key pair; the client — standing in for a
constrained IoT device — encapsulates against it, and the resulting shared
secret keys **AES-256-GCM** for the actual payload. Built on
[wolfSSL](https://www.wolfssl.com/)'s wolfCrypt.

## Build

Needs wolfSSL built with ML-KEM (`WOLFSSL_HAVE_MLKEM`), AES-GCM and HKDF.
Check the system library has it:

```bash
grep -E "WOLFSSL_HAVE_MLKEM|HAVE_AESGCM|HAVE_HKDF" /usr/include/wolfssl/options.h
```

Then:

```bash
make
```

## Run

Everything in one shot — starts the server, runs one device session, exits
non-zero if either side fails:

```bash
make demo
```

```
[server] -> PUBKEY   1184 bytes (ML-KEM-768 public key)
[server] <- KEMCT    1088 bytes (ML-KEM cipher text)
[server] shared secret established, AES-256 keys derived
[server] <- DATA     51 bytes -> decrypted: "sensor=temp value=23.4C"
[device] <- DATA     51 bytes -> decrypted: "ack: telemetry received"
```

Or drive the two sides by hand:

```bash
./pqiot-server 4433
./pqiot-client 127.0.0.1 4433 "sensor=temp value=23.4C"
```

## Verify the crypto

```bash
make check
```

Asserts that encapsulation and decapsulation agree on the same secret, that
HKDF separates the two directions, that AES-GCM round-trips, and that a
tampered tag, a flipped cipher-text bit, a wrong key, a truncated frame, an
oversized frame and a bad magic are all rejected.

## Verify on the wire

```bash
make capture
```

Captures loopback with tshark into `demo.pcap`, then shows the PQIOT frames,
points at the 1184- and 1088-byte handshake packets, and asserts the
plaintext appears in **no** captured packet.

Loopback capture needs privileges — add yourself to the `wireshark` group
once and log back in:

```bash
sudo usermod -aG wireshark "$USER"
```

If you can't log out, `newgrp wireshark` opens a shell that already has the
group. Don't use `sudo make capture`: tshark running as root fails to write
the pcap.

## RISC-V target

The device side is meant for small hardware, so it also builds for
**riscv64** and runs under QEMU user-mode emulation. Needs
`riscv64-linux-gnu-gcc` and `qemu-riscv64` (Arch: `riscv64-linux-gnu-gcc`,
`qemu-user`).

```bash
make riscv         # cross-build pqiot-*.rv64 (static)
make riscv-check   # self-check under qemu-riscv64
make riscv-demo    # emulated RISC-V device <-> native x86-64 server
make riscv-capture # same, under tshark -> demo-riscv.pcap
```

wolfSSL isn't packaged for riscv64, so the first `make riscv` clones
`v5.9.2-stable` (the same version as the host library) into `build/` and
cross-builds a static wolfCrypt with ML-KEM, HKDF and AES-GCM. Later builds
reuse it; `make distclean` removes it.

`riscv-demo` runs the RISC-V client against the **native** server. The
handshake only completes if both architectures derive the same ML-KEM shared
secret, so a passing run shows the two builds interoperate.

## Protocol — PQIOT/1

Three message types over TCP. Every message carries an 8-byte header, so
frames are easy to pick out of a capture:

```
0      4     5     6         8
+------+-----+-----+---------+------------------+
| PQIO | typ | ver | len(be) | body (len bytes) |
+------+-----+-----+---------+------------------+
```

| Step | Direction | Type | Body |
|------|-----------|------|------|
| 1 | server → device | `PUBKEY` (0x01) | ML-KEM-768 public key, 1184 B |
| 2 | device → server | `KEMCT` (0x02) | ML-KEM cipher text, 1088 B |
| 3 | either way | `DATA` (0x03) | `[12B IV][16B tag][cipher text]` |

The device encapsulates against the server's public key: that produces the
cipher text for step 2 and, locally, a 32-byte shared secret. The server
decapsulates the cipher text and arrives at the identical secret — with no
key material derived from any quantum-vulnerable primitive.

That secret is **not** used as an AES key directly. HKDF-SHA256 expands it
into one key per direction (`"PQIOT/1 c2s"` and `"PQIOT/1 s2c"`), so the two
sides can never collide on a (key, IV) pair. Each `DATA` message gets a fresh
random 96-bit IV, since GCM breaks catastrophically if one is reused.

### Why raw sockets rather than TLS

The KEM is the point of the exercise, and on a raw socket the ML-KEM cipher
text sits on the wire where a capture can show it plainly. Under TLS it would
be buried in a handshake — and this wolfSSL build sets
`WOLFSSL_TLS_NO_MLKEM_STANDALONE`, so TLS would only offer *hybrid* groups
anyway. TLS/DTLS 1.3 is tracked below as a stretch goal.

## Layout

```
src/pqiot.h      protocol constants and wire format
src/pqiot.c      KEM helpers, AEAD, framed socket I/O   (shared)
src/client.c     the IoT device — encapsulates, encrypts
src/server.c     holds the key pair — decapsulates, decrypts
src/selftest.c   the assertions behind `make check`
tools/capture.sh packet capture and verification
```

## Status

- [x] TCP client/server
- [x] ML-KEM-768 key exchange via wolfSSL
- [x] AES-256-GCM payload encryption under the KEM-derived key
- [x] Packet capture + verification script
- [x] RISC-V emulator target (riscv64 under qemu-user)
- [ ] TLS/DTLS 1.3 integration *(stretch)*
- [ ] ML-DSA mutual authentication *(stretch — needs wolfSSL rebuilt with
      `--enable-dilithium`; the system build has `WOLFSSL_HAVE_MLDSA` off)*
