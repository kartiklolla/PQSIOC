# PQIOT — Post-Quantum Secure IoT Communication

A client/server channel whose key exchange is a post-quantum KEM and whose
two ends authenticate each other with a post-quantum signature. The server
holds an **ML-KEM-768** (Kyber) key pair; the client — standing in for a
constrained IoT device — encapsulates against it, and the resulting shared
secret keys **AES-256-GCM** for the actual payload. Both sides prove who they
are with **ML-DSA-65** (Dilithium) certificates. Built on
[wolfSSL](https://www.wolfssl.com/).

## Build

```bash
make
```

The first build clones wolfSSL `v5.9.2-stable` into `build/` and builds it
from source, because distribution packages don't include ML-DSA or DTLS 1.3
(see [TLS / DTLS 1.3](#tls--dtls-13) for the feature set). Later builds
reuse it. `make certs` (run automatically by the targets that need it)
creates the demo PKI with OpenSSL ≥ 3.5. You'll need git, autotools and a C
compiler.

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
[server] -> CERT     5556 bytes, VERIFY 3309 bytes (ML-DSA-65)
[device] <- CERT, VERIFY: server authenticated: CN=server.pqiot.test (ML-DSA-65)
[device] -> CERT     5531 bytes, VERIFY 3309 bytes (ML-DSA-65)
[server] <- CERT, VERIFY: device authenticated: CN=device-0001.pqiot.test (ML-DSA-65)
[server] <- DATA     51 bytes -> decrypted: "sensor=temp value=23.4C"
[device] <- DATA     51 bytes -> decrypted: "ack: telemetry received"
```

Or drive the two sides by hand, from the repo root (they read their keys
from `build/certs`):

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

For authentication, it signs a handshake transcript and checks that the
genuine server and device verify. It then checks that each of these is
refused:

- a different transcript (as if someone in the middle swapped the cipher
  text)
- the server's signature presented as a device's
- a flipped signature bit
- a genuine device certificate posing as the server
- the server's name on a certificate from another CA
- an ECDSA certificate from our own CA
- a truncated certificate

## Verify on the wire

```bash
make capture
```

Captures loopback with tshark into `demo.pcap`, then shows the PQIOT
messages, including the 1184- and 1088-byte ML-KEM packets and each side's
certificate and signature, and asserts the plaintext appears in **no**
captured packet.

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

## Protocol — PQIOT/2

Five message types over TCP. Every message carries an 8-byte header, so
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
| 3 | server → device | `CERT` (0x04) | server's ML-DSA-65 certificate, DER |
| 4 | server → device | `VERIFY` (0x05) | ML-DSA-65 signature over the transcript, 3309 B |
| 5 | device → server | `CERT` (0x04) | device's ML-DSA-65 certificate, DER |
| 6 | device → server | `VERIFY` (0x05) | ML-DSA-65 signature over the transcript, 3309 B |
| 7+ | either way | `DATA` (0x03) | `[12B IV][16B tag][cipher text]` |

The device encapsulates against the server's public key: that produces the
cipher text for step 2 and, locally, a 32-byte shared secret. The server
decapsulates the cipher text and arrives at the identical secret — with no
key material derived from any quantum-vulnerable primitive.

That secret is **not** used as an AES key directly. HKDF-SHA256 expands it
into one key per direction (`"PQIOT/2 c2s"` and `"PQIOT/2 s2c"`), so the two
sides can never collide on a (key, IV) pair. Each `DATA` message gets a fresh
random 96-bit IV, since GCM breaks catastrophically if one is reused.

### Authentication

Without steps 3–6, anyone in the path could hand the device their own ML-KEM
public key and read everything, and the server would accept any device. That
was PQIOT/1. Each side now proves who it is, the way TLS 1.3 does:

- **The transcript** is a SHA-256 hash of every message so far, headers
  included. Each `VERIFY` signs the transcript up to and including the
  sender's `CERT`. That binds the ML-KEM public key and cipher text used in
  this session, and everything the other side has already said. Changing any
  of it breaks a signature, and a signature can't be replayed, because
  every session has a fresh ML-KEM key pair.
- **Roles are domain-separated.** The server signs with the ML-DSA context
  `"PQIOT/2 server"` and the device with `"PQIOT/2 device"`, so one role's
  signature never verifies as the other's.
- **Certificate checks.** Each side checks that the peer's certificate chains
  to the demo CA and carries an ML-DSA-65 key. The device also requires the
  name `server.pqiot.test`, so a genuine device certificate can't pose as the
  server. The server accepts any device certificate from the CA and logs its
  name.
- **Ordering.** The device sends no telemetry until the server is
  authenticated, and the server reads no telemetry until the device is.

Certificates travel in the clear, unlike TLS 1.3, so a passive observer can
see which device is talking. `CERT` and `VERIFY` could be sent encrypted
under the derived keys if that matters.

The version byte is now 2. A PQIOT/1 peer gets its frames rejected rather
than silently skipping authentication.

### Why PQIOT/2 as well as TLS

The post-quantum primitives are the point of the exercise, and on a raw
socket the ML-KEM cipher text sits on the wire where a capture can show it
plainly. Under TLS it is
inside a hybrid key share in the handshake. The TLS endpoints below are the
standards-based version of the same channel.

## TLS / DTLS 1.3

`pqtls-server` and `pqtls-client` carry the same device session over
standard **TLS 1.3** (TCP) or, with `--dtls`, **DTLS 1.3** (UDP, the usual
choice for constrained devices, e.g. under CoAP). Key exchange is pinned to
**X25519MLKEM768**, the hybrid group current TLS stacks deploy: the session
key stays safe unless *both* X25519 and ML-KEM-768 are broken. Neither side
offers any other group, so there is no classical key exchange to downgrade to.

Authentication is **mutual and ML-DSA-65**. The server and the device each
hold an ML-DSA-65 certificate from a demo CA. Each side requires the other's
certificate and checks it against the CA, and each rejects a peer whose
certificate key is anything other than ML-DSA-65. So both the key exchange
and the signatures that prove identity are post-quantum.

```bash
make tls           # endpoints + the demo ML-DSA-65 CA, server and device certs
make tls-demo      # one TLS 1.3 session, then one DTLS 1.3 session
make tls-check     # interop with OpenSSL, both ways; 6 refusal cases
make tls-capture   # under tshark -> demo-tls.pcap
```

```
[server] handshake OK: DTLSv1.3, TLS_AES_256_GCM_SHA384, key exchange X25519MLKEM768
[server] peer authenticated: CN=device-0001.pqiot.test (ML-DSA-65)
[device] peer authenticated: CN=server.pqiot.test (ML-DSA-65)
```

- **wolfSSL from source.** Every binary links wolfSSL v5.9.2 built into
  `build/host`, with TLS 1.3, DTLS 1.3, ML-KEM, ML-DSA
  and Curve25519, and without RSA or DH. The same recipe builds
  `build/riscv`. `--enable-dtls-frag-ch` is needed because a ClientHello
  carrying the 1216-byte hybrid key share can be larger than one datagram.
  Changing the configure flags rebuilds both. The PQIOT/2 binaries link the
  same library.
- **Why the key-type check.** wolfSSL v5.9.2 won't compile without ECC, so
  the library could still verify an ECDSA certificate. If the demo CA ever
  signed one, the chain would check out and the handshake signature would be
  classical. After the handshake, each endpoint therefore reads the peer's
  certificate and refuses anything that isn't ML-DSA-65
  (`pqtls_check_peer` in `src/pqtls.h`). `tls-check` shows this check is
  what stops it: with the check disabled, wolfSSL accepts ECDSA
  certificates from our CA.
- **Demo PKI.** It's the same as PQIOT/2's (`src/pki.h`). `make certs`
  creates the CA, a server certificate for `server.pqiot.test` and a device
  certificate for `device-0001.pqiot.test` in `build/certs`. It also creates
  the certificates the checks must refuse, in `build/certs/bad`. The client
  checks the server's name; the server accepts any device certificate from
  the CA. These are throwaway keys.
- **`tls-check`** runs against OpenSSL (≥ 3.5, which has X25519MLKEM768 and
  ML-DSA). OpenSSL's client talks to our server, and our client talks to
  OpenSSL's server, with a client certificate required both ways. Then each
  refusal case changes one thing from a passing run and requires the
  handshake to fail:
  - either side: the peer offers only X25519 key exchange
  - server: the client sends no certificate
  - server: the client's ECDSA certificate is signed by our CA
  - client: the server's ML-DSA certificate is signed by a different CA
  - client: the server's ECDSA certificate is signed by our CA

  OpenSSL has no DTLS 1.3, so this covers TLS only.
- **`tls-capture`** reads the handshakes from the pcap and fails unless every
  group offered, supported or chosen, in both the TLS and DTLS hellos, is
  X25519MLKEM768 (`0x11ec`). It also checks that the plaintext appears in no
  packet. TLS 1.3 encrypts certificates, so the capture can't show ML-DSA;
  `tls-check` covers authentication.

## Layout

```
src/pqiot.h      protocol constants and wire format
src/pqiot.c      KEM, AEAD, framing, transcript, ML-DSA auth (shared)
src/pki.h        demo PKI paths and server name (both protocols)
src/client.c     the IoT device — encapsulates, authenticates, encrypts
src/server.c     holds the key pair — decapsulates, authenticates, decrypts
src/selftest.c   the assertions behind `make check`
src/pqtls.h      TLS/DTLS 1.3 policy: group, certificates, peer key check
src/tls_client.c the IoT device over TLS/DTLS 1.3
src/tls_server.c the server over TLS/DTLS 1.3
tools/capture.sh packet capture and verification
tools/tls-check.sh     OpenSSL interop and refusal cases
tools/tls-capture.sh   TLS/DTLS capture: key share groups on the wire
```

## Status

- [x] TCP client/server
- [x] ML-KEM-768 key exchange via wolfSSL
- [x] AES-256-GCM payload encryption under the KEM-derived key
- [x] Packet capture + verification script
- [x] RISC-V emulator target (riscv64 under qemu-user)
- [x] TLS/DTLS 1.3 integration (X25519MLKEM768 hybrid key exchange)
- [x] ML-DSA mutual authentication (ML-DSA-65 certificates, PQIOT/2 and
      TLS/DTLS 1.3)
