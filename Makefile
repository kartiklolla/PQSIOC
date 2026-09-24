# PQIOT -- post-quantum secure IoT communication
#
#   make          build client, server and the self-check
#   make check    run the crypto/framing self-check
#   make demo     run a full loopback session
#   make capture  same, under tshark, writing demo.pcap
#
#   make riscv        cross-build all three for riscv64 (static)
#   make riscv-check  run the self-check under qemu-riscv64
#   make riscv-demo   RISC-V device (qemu) talking to the native server
#   make riscv-capture  riscv-demo under tshark, writing demo-riscv.pcap
#   make riscv-tls-demo RISC-V device over TLS and DTLS 1.3
#   make riscv-tls-capture  riscv-tls-demo under tshark -> demo-riscv-tls.pcap
#
#   make tls          TLS/DTLS 1.3 endpoints (X25519MLKEM768), + demo certs
#   make tls-demo     one TLS session, then one DTLS session
#   make tls-check    interop with OpenSSL, and refuse a classical-only server
#   make tls-capture  tls-demo under tshark, writing demo-tls.pcap

CC      ?= cc
# -D_GNU_SOURCE: memmem() in the self-check.
# No -DNDEBUG anywhere: the self-check is built out of assert().
CFLAGS  ?= -std=c11 -O2 -g -Wall -Wextra -D_GNU_SOURCE
LDLIBS  := -lwolfssl

PORT ?= 4433
MSG  ?= sensor=temp value=23.4C

BINS := pqiot-server pqiot-client pqiot-selftest
OBJS := src/pqiot.o src/server.o src/client.o src/selftest.o

all: $(BINS)

pqiot-server: src/server.o src/pqiot.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

pqiot-client: src/client.o src/pqiot.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

pqiot-selftest: src/selftest.o src/pqiot.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

src/%.o: src/%.c src/pqiot.h
	$(CC) $(CFLAGS) -c -o $@ $<

check: pqiot-selftest
	./pqiot-selftest

# Server runs in the background; its exit status is folded into ours so a
# failed session fails the target.
demo: pqiot-server pqiot-client
	@./pqiot-server $(PORT) & srv=$$!; \
	 sleep 0.5; \
	 ./pqiot-client 127.0.0.1 $(PORT) "$(MSG)"; rc=$$?; \
	 wait $$srv || rc=1; \
	 exit $$rc

capture: pqiot-server pqiot-client
	@tools/capture.sh $(PORT) "$(MSG)"

# --- wolfSSL from source ------------------------------------------------
# The system wolfSSL has no DTLS and no riscv64 build, so the TLS endpoints
# and everything RISC-V link a static wolfSSL built here instead: one
# out-of-tree build per architecture from a single checkout, pinned to the
# same release as the host library. The plain PQIOT binaries keep using the
# system library.
WOLFSSL_TAG ?= v5.9.2-stable
WOLF_SRC    := build/wolfssl-src
WOLF_CONF   := --enable-static --disable-shared \
               --enable-tls13 --enable-dtls --enable-dtls13 \
               --enable-dtls-frag-ch \
               --enable-mlkem --enable-curve25519 --enable-hkdf --enable-aesgcm \
               --disable-examples --disable-crypttests
# --enable-dtls-frag-ch: a ClientHello carrying a 1216-byte X25519MLKEM768
# key share can exceed one datagram; without this the DTLS 1.3 server
# rejects the fragmented hello.

$(WOLF_SRC):
	git clone -q --depth 1 --branch $(WOLFSSL_TAG) \
	    https://github.com/wolfSSL/wolfssl.git $@
	cd $@ && ./autogen.sh

HOST_LIB := build/host/lib/libwolfssl.a
RV_LIB   := build/riscv/lib/libwolfssl.a

$(HOST_LIB): WOLF_CROSS :=
$(RV_LIB):   WOLF_CROSS  = --host=$(RV_HOST) CC=$(RV_CC)
build/%/lib/libwolfssl.a: | $(WOLF_SRC)
	mkdir -p build/obj-$*
	cd build/obj-$* && ../wolfssl-src/configure $(WOLF_CROSS) \
	    --prefix=$(CURDIR)/build/$* $(WOLF_CONF) && \
	$(MAKE) && $(MAKE) install

# --- TLS / DTLS 1.3 ------------------------------------------------------
TLS_BINS := pqtls-server pqtls-client
TLS_OBJS := build/tls/tls_server.o build/tls/tls_client.o
CERTS    := build/certs/ca.pem build/certs/server.pem build/certs/server.key

build/tls/%.o: src/%.c src/pqtls.h $(HOST_LIB)
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -Ibuild/host/include -c -o $@ $<

$(TLS_BINS): pqtls-%: build/tls/tls_%.o
	$(CC) $(CFLAGS) -o $@ $^ $(HOST_LIB) -lm

# Demo PKI: a throwaway ECDSA P-256 CA and a server certificate for
# PQTLS_SERVER_NAME. Never reuse these keys for anything real.
$(CERTS) &:
	@mkdir -p build/certs
	cd build/certs && \
	openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
	    -days 3650 -subj /CN=PQIOT-demo-CA -keyout ca.key -out ca.pem && \
	openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
	    -subj /CN=server.pqiot.test -addext subjectAltName=DNS:server.pqiot.test \
	    -keyout server.key -out server.csr && \
	openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key \
	    -CAcreateserial -copy_extensions copy -days 825 -out server.pem

certs: $(CERTS)

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

tls-check: tls
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

build/rv64/%.o: src/%.c src/pqiot.h src/pqtls.h $(RV_LIB)
	@mkdir -p $(@D)
	$(RV_CC) $(RV_CFLAGS) -c -o $@ $<

$(PQ_RV_BINS): pqiot-%.rv64: build/rv64/%.o build/rv64/pqiot.o
	$(RV_CC) $(RV_CFLAGS) -static -o $@ $^ $(RV_LIB) -lm

$(TLS_RV_BINS): pqtls-%.rv64: build/rv64/tls_%.o
	$(RV_CC) $(RV_CFLAGS) -static -o $@ $^ $(RV_LIB) -lm

riscv: $(RV_BINS)

riscv-check: pqiot-selftest.rv64
	$(QEMU) ./pqiot-selftest.rv64

# The native server and an emulated RISC-V device: proves the cross-built
# endpoint interoperates, not just that it runs.
riscv-demo: pqiot-server pqiot-client.rv64
	@./pqiot-server $(PORT) & srv=$$!; \
	 sleep 0.5; \
	 $(QEMU) ./pqiot-client.rv64 127.0.0.1 $(PORT) "$(MSG)"; rc=$$?; \
	 wait $$srv || rc=1; \
	 exit $$rc

riscv-capture: pqiot-server pqiot-client.rv64
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

clean:
	rm -f $(BINS) $(OBJS) $(TLS_BINS) $(TLS_OBJS) $(RV_BINS) $(RV_OBJS) \
	      demo.pcap demo-riscv.pcap demo-tls.pcap demo-riscv-tls.pcap

# Also drops the from-source wolfSSL builds and the demo certificates.
distclean: clean
	rm -rf build

.PHONY: all check demo capture certs tls tls-demo tls-check tls-capture \
        riscv riscv-check riscv-demo riscv-capture riscv-tls-demo \
        riscv-tls-capture \
        clean distclean
