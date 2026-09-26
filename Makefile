# PQIOT -- post-quantum secure IoT communication
#
#   make          build client, server and the self-check
#   make check    run the crypto/framing/authentication self-check
#   make demo     run a full loopback session (mutual ML-DSA-65 auth)
#   make capture  same, under tshark, writing demo.pcap
#   make bench    latency, reliability, wire and image sizes (fw-bench: cycles)
#
#   make riscv        cross-build all three for riscv64 (static)
#   make riscv-check  run the self-check under qemu-riscv64
#   make riscv-demo   RISC-V device (qemu) talking to the native server
#   make riscv-capture  riscv-demo under tshark, writing demo-riscv.pcap
#   make riscv-tls-demo RISC-V device over TLS and DTLS 1.3
#   make riscv-tls-capture  riscv-tls-demo under tshark -> demo-riscv-tls.pcap
#
#   make fw           bare-metal RISC-V firmware (LiteX VexRiscv, no OS)
#   make fw-demo      boot it in the LiteX/Verilator simulator: full PQIOT/2
#                     session, device and server both on the bare-metal CPU
#   make fw-net-demo  bare-metal device on the simulated Ethernet, talking to
#                     the native pqiot-server (needs tap0, see README)
#
#   make tls          TLS/DTLS 1.3 endpoints (X25519MLKEM768), + demo certs
#   make tls-demo     one TLS session, then one DTLS session
#   make tls-check    interop with OpenSSL, plus refusal cases
#   make certs        the demo PKI (also built on demand by the above)
#   make tls-capture  tls-demo under tshark, writing demo-tls.pcap

CC      ?= cc
# -D_GNU_SOURCE: memmem() in the self-check.
# No -DNDEBUG anywhere: the self-check is built out of assert().
CFLAGS  ?= -std=c11 -O2 -g -Wall -Wextra -D_GNU_SOURCE

# Everything links a static wolfSSL built from source (see below): the
# system library has neither ML-DSA nor DTLS.
HOST_LIB := build/host/lib/libwolfssl.a
RV_LIB   := build/riscv/lib/libwolfssl.a
LDLIBS   := $(HOST_LIB) -lm

# Demo PKI (`make certs`, recipes below). Prerequisites expand as make reads
# them, so these must be defined before the first rule that names them.
CERTS     := build/certs/ca.pem build/certs/server.pem build/certs/server.key \
             build/certs/device.pem build/certs/device.key
BAD_CERTS := build/certs/bad/rogue.pem build/certs/bad/ecdsa-srv.pem \
             build/certs/bad/ecdsa-dev.pem

PORT ?= 4433
MSG  ?= sensor=temp value=23.4C

BINS := pqiot-server pqiot-client pqiot-selftest pqiot-bench
OBJS := src/pqiot.o src/pqiot_posix.o src/session.o \
        src/server.o src/client.o src/selftest.o src/bench.o src/bench_main.o
# Shared by every native binary: protocol core + the POSIX platform hooks.
CORE := src/pqiot.o src/pqiot_posix.o

all: $(BINS)

pqiot-server: src/server.o src/session.o $(CORE)
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

pqiot-client: src/client.o src/session.o $(CORE)
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

pqiot-selftest: src/selftest.o $(CORE)
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

pqiot-bench: src/bench_main.o src/bench.o src/session.o $(CORE)
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

src/%.o: src/%.c src/pqiot.h src/pki.h
	$(CC) $(CFLAGS) -Ibuild/host/include -c -o $@ $<

# Not in the pattern above: there, a prerequisite that another pattern rule
# must build first makes make fall back to its built-in %.o: %.c rule, which
# compiles against the system headers instead.
$(OBJS): $(HOST_LIB)

check: pqiot-selftest $(CERTS) $(BAD_CERTS)
	./pqiot-selftest

# Latency, reliability, wire size and firmware size (tools/bench.sh);
# bare-metal cycle counts: make fw-bench.
bench: pqiot-bench pqtls-server pqtls-client $(CERTS)
	@tools/bench.sh 50 $(PORT)

# Server runs in the background; its exit status is folded into ours so a
# failed session fails the target.
demo: pqiot-server pqiot-client $(CERTS)
	@./pqiot-server $(PORT) & srv=$$!; \
	 sleep 0.5; \
	 ./pqiot-client 127.0.0.1 $(PORT) "$(MSG)"; rc=$$?; \
	 wait $$srv || rc=1; \
	 exit $$rc

capture: pqiot-server pqiot-client $(CERTS)
	@tools/capture.sh $(PORT) "$(MSG)"

# --- wolfSSL from source ------------------------------------------------
# The system wolfSSL has no ML-DSA, no DTLS and no riscv64 build, so
# everything links a static wolfSSL built here instead: one out-of-tree
# build per architecture from a single checkout, pinned to v5.9.2.
WOLFSSL_TAG ?= v5.9.2-stable
WOLF_SRC    := build/wolfssl-src
WOLF_CONF   := --enable-static --disable-shared \
               --enable-tls13 --enable-dtls --enable-dtls13 \
               --enable-dtls-frag-ch \
               --enable-mlkem --enable-mldsa \
               --disable-rsa --disable-dh \
               --enable-curve25519 --enable-hkdf --enable-aesgcm \
               --disable-examples --disable-crypttests \
               CPPFLAGS=-DKEEP_PEER_CERT
# --enable-dtls-frag-ch: a ClientHello carrying a 1216-byte X25519MLKEM768
# key share can exceed one datagram; without this the DTLS 1.3 server
# rejects the fragmented hello.
# --enable-mldsa, --disable-rsa/dh: authentication is ML-DSA only. ECC
# can't be disabled too (v5.9.2 fails to compile without it), so the
# endpoints check the peer's key type after the handshake instead -- which
# needs KEEP_PEER_CERT for wolfSSL_get_peer_certificate().

$(WOLF_SRC):
	git clone -q --depth 1 --branch $(WOLFSSL_TAG) \
	    https://github.com/wolfSSL/wolfssl.git $@
	cd $@ && ./autogen.sh

$(HOST_LIB): WOLF_CROSS :=
$(RV_LIB):   WOLF_CROSS  = --host=$(RV_HOST) CC=$(RV_CC)
# Named after a hash of WOLF_CONF, so changing the flags rebuilds wolfSSL in
# an existing build/ instead of silently linking the old feature set.
WOLF_STAMP := build/wolfssl-$(shell echo '$(WOLF_CONF)' | md5sum | cut -c1-8).stamp
$(WOLF_STAMP):
	@mkdir -p build && rm -f build/wolfssl-*.stamp && touch $@

build/%/lib/libwolfssl.a: $(WOLF_STAMP) | $(WOLF_SRC)
	mkdir -p build/obj-$*
	cd build/obj-$* && ../wolfssl-src/configure $(WOLF_CROSS) \
	    --prefix=$(CURDIR)/build/$* $(WOLF_CONF) && \
	$(MAKE) && $(MAKE) install

# --- TLS / DTLS 1.3 ------------------------------------------------------
TLS_BINS := pqtls-server pqtls-client
TLS_OBJS := build/tls/tls_server.o build/tls/tls_client.o

build/tls/%.o: src/%.c src/pqtls.h src/pki.h $(HOST_LIB)
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -Ibuild/host/include -c -o $@ $<

$(TLS_BINS): pqtls-%: build/tls/tls_%.o
	$(CC) $(CFLAGS) -o $@ $^ $(HOST_LIB) -lm

# Demo PKI, all ML-DSA-65: a throwaway CA, a server certificate for
# PKI_SERVER_NAME and one device certificate. Never reuse these keys.
# $(1): name, $(2): CN, $(3): extensions for the CSR, $(4): -newkey
# arguments (default ML-DSA-65).
issue = openssl req -newkey $(or $(4),ML-DSA-65) -nodes -subj /CN=$(2) $(3) \
	    -keyout $(1).key -out $(1).csr && \
	openssl x509 -req -in $(1).csr -CA ca.pem -CAkey ca.key \
	    -CAcreateserial -copy_extensions copy -days 825 -out $(1).pem

$(CERTS) &:
	@mkdir -p build/certs
	cd build/certs && \
	openssl req -x509 -newkey ML-DSA-65 -nodes -days 3650 \
	    -subj /CN=PQIOT-demo-CA -keyout ca.key -out ca.pem && \
	$(call issue,server,server.pqiot.test,\
	    -addext subjectAltName=DNS:server.pqiot.test \
	    -addext extendedKeyUsage=serverAuth) && \
	$(call issue,device,device-0001.pqiot.test,\
	    -addext extendedKeyUsage=clientAuth)

# Certificates the endpoints must refuse, for `make check` and tls-check:
# the server's name from a rogue CA, and ECDSA keys from our own CA.
EC_P256   := EC -pkeyopt ec_paramgen_curve:P-256

$(BAD_CERTS) &: $(CERTS)
	@mkdir -p build/certs/bad
	cd build/certs && \
	openssl req -x509 -newkey ML-DSA-65 -nodes -days 825 \
	    -subj /CN=server.pqiot.test \
	    -addext subjectAltName=DNS:server.pqiot.test \
	    -keyout bad/rogue.key -out bad/rogue.pem && \
	$(call issue,bad/ecdsa-srv,server.pqiot.test,\
	    -addext subjectAltName=DNS:server.pqiot.test,$(EC_P256)) && \
	$(call issue,bad/ecdsa-dev,device-0001.pqiot.test,,$(EC_P256))

certs: $(CERTS) $(BAD_CERTS)

tls: $(TLS_BINS) $(CERTS)

# $(1): server command, $(2): client command. Server's exit status is folded
# into ours, like `make demo`.
tls_session = ./$(1) $(PORT) & srv=$$!; \
	 sleep 0.5; \
	 $(2) 127.0.0.1 $(PORT) "$(MSG)"; rc=$$?; \
	 wait $$srv || rc=1; \
	 [ $$rc = 0 ] || exit $$rc

tls-demo: tls
	@echo "== TLS 1.3 over TCP"; \
	 $(call tls_session,pqtls-server,./pqtls-client); \
	 echo; echo "== DTLS 1.3 over UDP"; \
	 $(call tls_session,pqtls-server --dtls,./pqtls-client --dtls)

tls-check: tls $(BAD_CERTS)
	@tools/tls-check.sh $(PORT) "$(MSG)"

tls-capture: tls
	@tools/tls-capture.sh $(PORT) "$(MSG)"

# --- RISC-V -------------------------------------------------------------
# Binaries are static so qemu-riscv64 needs no sysroot at run time.
RV_CC   ?= riscv64-linux-gnu-gcc
RV_HOST ?= riscv64-linux-gnu
QEMU    ?= qemu-riscv64

RV_CFLAGS := $(CFLAGS) -Ibuild/riscv/include

PQ_RV_BINS  := pqiot-server.rv64 pqiot-client.rv64 pqiot-selftest.rv64
TLS_RV_BINS := pqtls-server.rv64 pqtls-client.rv64
RV_BINS := $(PQ_RV_BINS) $(TLS_RV_BINS)
RV_OBJS := $(patsubst src/%.o,build/rv64/%.o,$(OBJS)) \
           build/rv64/tls_server.o build/rv64/tls_client.o

build/rv64/%.o: src/%.c src/pqiot.h src/pqtls.h src/pki.h $(RV_LIB)
	@mkdir -p $(@D)
	$(RV_CC) $(RV_CFLAGS) -c -o $@ $<

RV_CORE := build/rv64/pqiot.o build/rv64/pqiot_posix.o build/rv64/session.o
$(PQ_RV_BINS): pqiot-%.rv64: build/rv64/%.o $(RV_CORE)
	$(RV_CC) $(RV_CFLAGS) -static -o $@ $^ $(RV_LIB) -lm

$(TLS_RV_BINS): pqtls-%.rv64: build/rv64/tls_%.o
	$(RV_CC) $(RV_CFLAGS) -static -o $@ $^ $(RV_LIB) -lm

riscv: $(RV_BINS)

riscv-check: pqiot-selftest.rv64 $(CERTS) $(BAD_CERTS)
	$(QEMU) ./pqiot-selftest.rv64

# The native server and an emulated RISC-V device: proves the cross-built
# endpoint interoperates, not just that it runs.
riscv-demo: pqiot-server pqiot-client.rv64 $(CERTS)
	@./pqiot-server $(PORT) & srv=$$!; \
	 sleep 0.5; \
	 $(QEMU) ./pqiot-client.rv64 127.0.0.1 $(PORT) "$(MSG)"; rc=$$?; \
	 wait $$srv || rc=1; \
	 exit $$rc

riscv-capture: pqiot-server pqiot-client.rv64 $(CERTS)
	@CLIENT="$(QEMU) ./pqiot-client.rv64" OUT=demo-riscv.pcap \
	 tools/capture.sh $(PORT) "$(MSG)"

# Same, over TLS and DTLS 1.3.
riscv-tls-demo: tls pqtls-client.rv64
	@echo "== TLS 1.3: native server, RISC-V device"; \
	 $(call tls_session,pqtls-server,$(QEMU) ./pqtls-client.rv64); \
	 echo; echo "== DTLS 1.3: native server, RISC-V device"; \
	 $(call tls_session,pqtls-server --dtls,$(QEMU) ./pqtls-client.rv64 --dtls)

riscv-tls-capture: tls pqtls-client.rv64
	@CLIENT="$(QEMU) ./pqtls-client.rv64" OUT=demo-riscv-tls.pcap \
	 tools/tls-capture.sh $(PORT) "$(MSG)"

# --- bare-metal RISC-V (LiteX VexRiscv simulator) -------------------------
# The PS's target platform: no OS at all. The SoC is the one the reference
# environment (QTrino-Labs/Constraint_Env_Sim) simulates. Needs LiteX in
# LITEX_VENV (see README), verilator, and riscv64-elf-gcc.
LITEX_VENV  ?= $(HOME)/litex/venv
LITEX_SIM   := $(LITEX_VENV)/bin/litex_sim
FW_SIM_DIR  := build/litex-sim
FW_SIM_ARGS := --cpu-type=vexriscv --cpu-variant=full \
               --integrated-main-ram-size=0x06400000 --libc-mode=full \
               --output-dir=$(CURDIR)/$(FW_SIM_DIR)
FW_SOC      := $(FW_SIM_DIR)/software/include/generated/variables.mak
FW_BIN      := build/fw/pqiot-fw.bin

# The SoC's headers, libc and support libraries (no gateware yet).
$(FW_SOC):
	PATH=$(LITEX_VENV)/bin:$$PATH $(LITEX_SIM) $(FW_SIM_ARGS) --no-compile-gateware

fw: $(FW_SOC) $(CERTS) | $(WOLF_SRC)
	PATH=$(LITEX_VENV)/bin:$$PATH $(MAKE) -C firmware \
	    BUILD_DIR=$(CURDIR)/$(FW_SIM_DIR)

fw-demo: fw
	@LITEX_SIM="$(LITEX_SIM)" FW_SIM_ARGS="$(FW_SIM_ARGS)" \
	 tools/fw-demo.sh $(FW_BIN)

# Per-operation cycle counts on the same bare-metal SoC (src/bench.c).
FW_BENCH_BIN := build/fw-bench/pqiot-fw-bench.bin
fw-bench: $(FW_SOC) $(CERTS) | $(WOLF_SRC)
	PATH=$(LITEX_VENV)/bin:$$PATH $(MAKE) -C firmware BENCH=1 \
	    BUILD_DIR=$(CURDIR)/$(FW_SIM_DIR)
	@LOG=build/fw-bench/sim.log LITEX_SIM="$(LITEX_SIM)" \
	 FW_SIM_ARGS="$(FW_SIM_ARGS)" tools/fw-demo.sh $(FW_BENCH_BIN)

# Same SoC plus an Ethernet MAC on the host's tap0: 192.168.1.50 on the SoC,
# 192.168.1.100 on the host (litex_sim's defaults).
FW_NET_SIM_DIR  := build/litex-sim-eth
FW_NET_SIM_ARGS := $(subst $(FW_SIM_DIR),$(FW_NET_SIM_DIR),$(FW_SIM_ARGS)) \
                   --with-ethernet
FW_NET_SOC      := $(FW_NET_SIM_DIR)/software/include/generated/variables.mak
FW_NET_BIN      := build/fw-net/pqiot-fw-net.bin

$(FW_NET_SOC):
	PATH=$(LITEX_VENV)/bin:$$PATH $(LITEX_SIM) $(FW_NET_SIM_ARGS) --no-compile-gateware

fw-net: $(FW_NET_SOC) $(CERTS) | $(WOLF_SRC)
	PATH=$(LITEX_VENV)/bin:$$PATH $(MAKE) -C firmware NET=1 \
	    BUILD_DIR=$(CURDIR)/$(FW_NET_SIM_DIR)

# pqiot-server on TCP $(FW_NET_PORT), the UDP<->TCP bridge on tap0, then the
# simulated device; passes only if the device *and* the server both succeed.
FW_NET_PORT ?= 4434
fw-net-demo: fw-net pqiot-server
	@LITEX_SIM="$(LITEX_SIM)" FW_SIM_ARGS="$(FW_NET_SIM_ARGS)" \
	 SERVER_PORT=$(FW_NET_PORT) tools/fw-net-demo.sh $(FW_NET_BIN)

clean:
	rm -f $(BINS) $(OBJS) $(TLS_BINS) $(TLS_OBJS) $(RV_BINS) $(RV_OBJS) \
	      demo.pcap demo-riscv.pcap demo-tls.pcap demo-riscv-tls.pcap

# Also drops the from-source wolfSSL builds and the demo certificates.
distclean: clean
	rm -rf build

.PHONY: all check demo capture certs tls tls-demo tls-check tls-capture fw fw-demo fw-bench fw-net fw-net-demo bench \
        riscv riscv-check riscv-demo riscv-capture riscv-tls-demo \
        riscv-tls-capture \
        clean distclean
