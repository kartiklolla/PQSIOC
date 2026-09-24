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

# --- RISC-V -------------------------------------------------------------
# wolfCrypt is cross-built once from source into build/riscv, pinned to the
# same release as the host library so both ends run the same ML-KEM code.
# Binaries are static so qemu-riscv64 needs no sysroot at run time.
RV_CC      ?= riscv64-linux-gnu-gcc
RV_HOST    ?= riscv64-linux-gnu
QEMU       ?= qemu-riscv64
WOLFSSL_TAG ?= v5.9.2-stable

RV_WOLF := $(CURDIR)/build/riscv
RV_SRC  := build/wolfssl-src
RV_LIB  := $(RV_WOLF)/lib/libwolfssl.a
RV_CFLAGS := $(CFLAGS) -I$(RV_WOLF)/include

RV_BINS := pqiot-server.rv64 pqiot-client.rv64 pqiot-selftest.rv64
RV_OBJS := $(patsubst src/%.o,build/rv64/%.o,$(OBJS))

$(RV_SRC):
	git clone -q --depth 1 --branch $(WOLFSSL_TAG) \
	    https://github.com/wolfSSL/wolfssl.git $@

$(RV_LIB): | $(RV_SRC)
	cd $(RV_SRC) && ./autogen.sh && \
	./configure --host=$(RV_HOST) CC=$(RV_CC) --prefix=$(RV_WOLF) \
	    --enable-static --disable-shared --enable-cryptonly \
	    --enable-mlkem --enable-hkdf --enable-aesgcm \
	    --disable-examples --disable-crypttests && \
	$(MAKE) && $(MAKE) install

build/rv64/%.o: src/%.c src/pqiot.h $(RV_LIB)
	@mkdir -p $(@D)
	$(RV_CC) $(RV_CFLAGS) -c -o $@ $<

$(RV_BINS): pqiot-%.rv64: build/rv64/%.o build/rv64/pqiot.o
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

clean:
	rm -f $(BINS) $(OBJS) $(RV_BINS) $(RV_OBJS) demo.pcap

# Also drops the cross-built wolfSSL; the next `make riscv` rebuilds it.
distclean: clean
	rm -rf build

.PHONY: all check demo capture riscv riscv-check riscv-demo clean distclean
