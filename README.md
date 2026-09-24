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
make riscv             # cross-build pqiot-*.rv64 and pqtls-*.rv64 (static)
make riscv-check       # self-check under qemu-riscv64
make riscv-demo        # emulated RISC-V device <-> native x86-64 server
make riscv-capture     # same, under tshark -> demo-riscv.pcap
make riscv-tls-demo    # same over TLS 1.3 and DTLS 1.3
make riscv-tls-capture # same, under tshark -> demo-riscv-tls.pcap
```

wolfSSL isn't packaged for riscv64, so the first `make riscv` clones
`v5.9.2-stable` (the same version as the host library) into `build/` and
cross-builds a static wolfSSL (see [TLS / DTLS 1.3](#tls--dtls-13) for the
feature set). Later builds reuse it; `make distclean` removes it.

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

### Why PQIOT/1 as well as TLS

The KEM is the point of the exercise, and on a raw socket the ML-KEM cipher
text sits on the wire where a capture can show it plainly. Under TLS it is
inside a hybrid key share in the handshake. The TLS endpoints below are the
standards-based version of the same channel.

## TLS / DTLS 1.3

`pqtls-server` and `pqtls-client` carry the same device session over
standard **TLS 1.3** (TCP) or, with `--dtls`, **DTLS 1.3** (UDP, the usual
choice for constrained devices, e.g. under CoAP). Key exchange is pinned to
**X25519MLKEM768**, the hybrid group current TLS stacks deploy: the session
key stays safe unless *both* X25519 and ML-KEM-768 are broken. Neither side
offers any other group, so there is no classical key exchange to downgrade to.

```bash
make tls           # endpoints + a demo CA and server certificate
make tls-demo      # one TLS 1.3 session, then one DTLS 1.3 session
make tls-check     # interop with OpenSSL, both ways; refuse classical peers
make tls-capture   # under tshark -> demo-tls.pcap
```

```
[device] handshake OK: DTLSv1.3, TLS_AES_256_GCM_SHA384, key exchange X25519MLKEM768
```

- **wolfSSL from source.** The system wolfSSL has no DTLS, so `make tls`
  builds v5.9.2 into `build/host`, with TLS 1.3, DTLS 1.3, ML-KEM and
  Curve25519. The same recipe builds `build/riscv`. `--enable-dtls-frag-ch`
  is needed because a ClientHello carrying the 1216-byte hybrid key share
  can be larger than one datagram. The PQIOT/1 binaries still use the system
  library.
- **Server authentication is classical.** `make certs` creates a
  throwaway ECDSA P-256 CA and a certificate for `server.pqiot.test` in
  `build/certs`. The client verifies the chain and the name. Replacing ECDSA
  with ML-DSA is the separate stretch goal below.
- **`tls-check`** runs against OpenSSL (≥ 3.5, which has X25519MLKEM768):
  OpenSSL's client talks to our server, and our client talks to OpenSSL's
  server. It also checks that each of our endpoints refuses an OpenSSL peer
  that offers only X25519. OpenSSL has no DTLS 1.3, so this covers TLS only.
- **`tls-capture`** reads the handshakes from the pcap and fails unless every
  group offered, supported or chosen, in both the TLS and DTLS hellos, is
  X25519MLKEM768 (`0x11ec`). It also checks that the plaintext appears in no
  packet.

## Layout

```
src/pqiot.h      protocol constants and wire format
src/pqiot.c      KEM helpers, AEAD, framed socket I/O   (shared)
src/client.c     the IoT device — encapsulates, encrypts
src/server.c     holds the key pair — decapsulates, decrypts
src/selftest.c   the assertions behind `make check`
src/pqtls.h      TLS/DTLS 1.3 settings: group, certificate paths
src/tls_client.c the IoT device over TLS/DTLS 1.3
src/tls_server.c the server over TLS/DTLS 1.3
tools/capture.sh packet capture and verification
tools/tls-check.sh     OpenSSL interop and downgrade refusal
tools/tls-capture.sh   TLS/DTLS capture: key share groups on the wire
```

## Status

- [x] TCP client/server
- [x] ML-KEM-768 key exchange via wolfSSL
- [x] AES-256-GCM payload encryption under the KEM-derived key
- [x] Packet capture + verification script
- [x] RISC-V emulator target (riscv64 under qemu-user)
- [x] TLS/DTLS 1.3 integration (X25519MLKEM768 hybrid key exchange)
- [ ] ML-DSA mutual authentication *(stretch — needs wolfSSL rebuilt with
      `--enable-dilithium`; the system build has `WOLFSSL_HAVE_MLDSA` off)*
