# PQIOT — Post-Quantum Secure IoT Communication

A client/server channel whose key exchange is a post-quantum KEM and whose
two ends authenticate each other with a post-quantum signature. The server
holds an **ML-KEM-768** (Kyber) key pair; the client — standing in for a
constrained IoT device — encapsulates against it, and the resulting shared
secret keys **AES-256-GCM** for the actual payload. Both sides prove who they
are with **ML-DSA-65** (Dilithium) certificates. Built on
[wolfSSL](https://www.wolfssl.com/).

The device runs **bare-metal on RISC-V** (a LiteX VexRiscv SoC simulated with
Verilator, no OS) and talks over the simulated SoC's Ethernet to the server
on the host. The same session code also runs natively, under Linux on
RISC-V, and over TLS/DTLS 1.3.

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
oversized frame and a bad magic are all rejected. It also checks that all
four derived keys differ, and that a sealed frame hides its body and only
opens under the right key as the right type.

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
sealed certificate and signature. It asserts that **no** captured packet
contains the plaintext or either certificate's name. Without the sealing,
both names show up in the capture, so this check really does fail.

Loopback capture needs privileges — add yourself to the `wireshark` group
once and log back in:

```bash
sudo usermod -aG wireshark "$USER"
```

If you can't log out, `newgrp wireshark` opens a shell that already has the
group. Don't use `sudo make capture`: tshark running as root fails to write
the pcap.

## Bare-metal RISC-V

This is the problem statement's target platform: a **LiteX SoC with a
32-bit VexRiscv CPU** (100 MB RAM, 1 MHz nominal clock) simulated
cycle-accurately with Verilator, running firmware with **no operating
system**. It's the same SoC as the reference environment,
[QTrino-Labs/Constraint_Env_Sim](https://github.com/QTrino-Labs-Pvt-Ltd/Constraint_Env_Sim).

```bash
make fw-demo       # device and server both on the bare-metal CPU
make fw-net-demo   # bare-metal device on the simulated Ethernet <-> host server
CAPTURE=1 make fw-net-demo   # ... and record/check tap0 -> demo-fw-net.pcap
```

```
[fw] PQIOT/2 bare-metal device on VexRiscv_Full @ 1000000 Hz, no OS
[fw] ethernet up: 192.168.1.50 -> bridge 192.168.1.100:4433
[device] -> KEMCT    1088 bytes (ML-KEM cipher text)
[device] <- CERT, VERIFY: server authenticated: CN=server.pqiot.test (ML-DSA-65)
[device] <- DATA     51 bytes -> decrypted: "ack: telemetry received"
[fw] whole session: 142809619 cycles
PQIOT bare-metal demo: OK
  [server] <- CERT, VERIFY: device authenticated: CN=device-0001.pqiot.test (ML-DSA-65)
```

Each target builds the firmware, simulates the SoC and exits with the
firmware's verdict, in about two to three minutes of real time.

- **`fw-demo`** runs one full session with **both ends on the RISC-V CPU**.
  They are two cooperative threads (a small assembly context switch,
  `firmware/switch.S`) exchanging messages through in-memory pipes. The whole
  session takes 280–295 M cycles, about 5 minutes of simulated time at
  1 MHz. The count varies between builds because each image has its own
  seed, and ML-DSA signing retries a random number of times.
- **`fw-net-demo`** runs **only the device** on the SoC, with its Ethernet
  MAC on the host's `tap0`. It talks to the **unmodified native
  `pqiot-server`**, which can't tell it from the Linux client. The device
  side takes about 143 M cycles. The run passes only if the device, the
  server and the bridge all succeed.
- **Same protocol code.** Both images run `src/session.c` and `src/pqiot.c`,
  the code the Linux binaries use. Only the transport underneath differs:
  pipes in `firmware/pipes.c`, UDP in `firmware/udp_stream.c`, sockets in
  `src/pqiot_posix.c`.
- **Networking.** LiteX's bare-metal network stack (`libliteeth`) has UDP
  but no TCP, and PQIOT messages are up to about 8.9 KB. So
  `firmware/udp_stream.c` carries the byte stream in 1 KB chunks, with
  stop-and-wait acknowledgements and retransmission. `tools/udp-bridge.py`
  on the host relays it to the server over TCP. The bridge only moves bytes:
  it holds no keys and can't read the session. It was tested with 20%
  packet loss in both directions.
- **wolfSSL** is compiled from the same pinned v5.9.2 source, configured by
  `firmware/user_settings.h` with the same algorithms as the host build. The
  image is about 270 KB. The device-only image carries the CA and the
  device's key, never the server's.

**Setup**, once (Arch package names):

```bash
sudo pacman -S --needed verilator riscv64-elf-gcc riscv64-elf-newlib riscv64-elf-binutils
```
```bash
mkdir -p ~/litex && cd ~/litex && python3 -m venv venv && . venv/bin/activate && pip install meson ninja && curl -fsSLO https://raw.githubusercontent.com/enjoy-digital/litex/master/litex_setup.py && python3 litex_setup.py --init --install --config=standard
```

The Makefile looks for LiteX in `~/litex/venv` (override with
`LITEX_VENV=...`). `fw-net-demo` also needs a `tap0` interface that you own,
created once with root:

```bash
sudo ip tuntap add dev tap0 mode tap user "$USER"
```
```bash
sudo ip addr add 192.168.1.100/24 dev tap0
```
```bash
sudo ip link set tap0 up
```

`litex_sim` normally runs any Ethernet simulation under `sudo`, because it
may have to create the tap device. Since `tap0` already exists and is yours,
`tools/fw-net-demo.sh` runs the simulation unprivileged.

**No hardware random source or clock.** The simulated SoC has neither, and
a simulation is deterministic anyway. Each image therefore gets a 32-byte
DRBG seed drawn from the build host's `/dev/urandom`, stretched with SHA-256
(`firmware/platform.c`). The limitation is that every boot of one image
replays the same randomness, so rebuild for fresh keys, and real hardware
must feed a TRNG into `pqiot_fw_seed`. The reference firmware's placeholder
generator (`i*37+123`) isn't random at all. Certificate dates are checked
against the image's build time.

## RISC-V under Linux (QEMU user mode)

The device side also builds for **riscv64 Linux** and runs under QEMU
user-mode emulation. Needs
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
| 3 | server → device | `CERT` (0x04) | sealed: server's ML-DSA-65 certificate, DER |
| 4 | server → device | `VERIFY` (0x05) | sealed: ML-DSA-65 signature over the transcript, 3309 B |
| 5 | device → server | `CERT` (0x04) | sealed: device's ML-DSA-65 certificate, DER |
| 6 | device → server | `VERIFY` (0x05) | sealed: ML-DSA-65 signature over the transcript, 3309 B |
| 7+ | either way | `DATA` (0x03) | `[12B IV][16B tag][cipher text]` |

*Sealed* bodies have the same `[12B IV][16B tag][cipher text]` layout as
`DATA`, under the handshake keys.

The device encapsulates against the server's public key: that produces the
cipher text for step 2 and, locally, a 32-byte shared secret. The server
decapsulates the cipher text and arrives at the identical secret — with no
key material derived from any quantum-vulnerable primitive.

That secret is **not** used as an AES key directly. HKDF-SHA256 expands it
into four keys: one per direction for the handshake (`"PQIOT/2 hs c2s"`,
`"PQIOT/2 hs s2c"`) and one per direction for `DATA` (`"PQIOT/2 c2s"`,
`"PQIOT/2 s2c"`). So the two sides can never collide on a (key, IV) pair,
and a sealed `CERT` or `VERIFY` can never pass as `DATA`. Each `DATA` message gets a fresh
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

**Identity privacy.** `CERT` and `VERIFY` are sealed under the handshake
keys, as in TLS 1.3, so a passive observer can't tell which device is
talking or to which server. The device sends its certificate only after the
server has authenticated, so even an active attacker who runs the KEM with
the device never sees the device's identity. The server's certificate goes
to whoever runs the KEM with it, which is fine: the server's identity is
public. The transcript hashes the plaintext messages, so encryption doesn't
change what the signatures cover.

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
src/pqiot.c      KEM, AEAD, framing, transcript, ML-DSA auth (no OS calls)
src/session.c    one PQIOT/2 session per role: the protocol itself
src/pqiot_posix.c   sockets and PEM files behind pqiot.c's platform hooks
src/pki.h        demo PKI paths and server name (both protocols)
src/client.c     the IoT device, TCP front end
src/server.c     the server, TCP front end
src/selftest.c   the assertions behind `make check`
src/pqtls.h      TLS/DTLS 1.3 policy: group, certificates, peer key check
src/tls_client.c the IoT device over TLS/DTLS 1.3
src/tls_server.c the server over TLS/DTLS 1.3
tools/capture.sh packet capture and verification
tools/tls-check.sh     OpenSSL interop and refusal cases
tools/tls-capture.sh   TLS/DTLS capture: key share groups on the wire
tools/fw-demo.sh       boot the bare-metal firmware, wait for its verdict
tools/fw-net-demo.sh   bare-metal device + bridge + native server (+ capture)
tools/udp-bridge.py    device's reliable UDP stream <-> TCP pqiot-server
firmware/main.c        bare metal: device and server as coroutines
firmware/main_net.c    bare metal: device only, over Ethernet
firmware/pipes.c, udp_stream.c   the two bare-metal transports
firmware/platform.c    DRBG seed and clock for bare metal
firmware/switch.S      coroutine context switch (RV32/RV64)
firmware/user_settings.h   wolfSSL configuration for bare metal
firmware/linker.ld, certs.S, Makefile   image layout, embedded PKI, build
```

## Status

- [x] TCP client/server
- [x] ML-KEM-768 key exchange via wolfSSL
- [x] AES-256-GCM payload encryption under the KEM-derived key
- [x] Packet capture + verification script
- [x] Bare-metal RISC-V (LiteX VexRiscv under Verilator, no OS): full
      session on-chip, and a bare-metal device over simulated Ethernet to
      the native server
- [x] RISC-V Linux target (riscv64 under qemu-user)
- [x] TLS/DTLS 1.3 integration (X25519MLKEM768 hybrid key exchange)
- [x] ML-DSA mutual authentication (ML-DSA-65 certificates, PQIOT/2 and
      TLS/DTLS 1.3)
- [x] Encrypted PQIOT/2 handshake (sealed `CERT`/`VERIFY`: device identity
      hidden from passive and active attackers)

### Known limits

- **Demo PKI only.** Keys sit unencrypted in `build/certs`, and there's no
  revocation (CRL/OCSP) or enrolment of new devices.
- **Servers are single-session.** Each binary serves one device, then
  exits.
- **No entropy source on bare metal.** Each firmware image replays its build
  seed's randomness on every boot (see Bare-metal RISC-V).
- **Stop-and-wait over UDP.** The bare-metal stream acknowledges every 1 KB
  chunk: fine for a ~20 KB handshake, slow for bulk data.
- **PQIOT/2 checks only the certificate's CN.** It doesn't read the SAN;
  our certificates put the same name in both.
- **ECC is still compiled into wolfSSL.** v5.9.2 won't build without it.
  Each endpoint instead refuses any peer key that isn't ML-DSA-65.
- **DTLS 1.3 isn't tested against another implementation.** OpenSSL has no
  DTLS 1.3, so `tls-check` covers TLS only.
- **No end-to-end man-in-the-middle test.** `make check` tests transcript
  binding at the function level, not with an attacker in the path.
