# PQIOT -- post-quantum secure IoT communication
#
#   make          build client, server and the self-check
#   make check    run the crypto/framing self-check
#   make demo     run a full loopback session
#   make capture  same, under tshark, writing demo.pcap

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

clean:
	rm -f $(BINS) $(OBJS) demo.pcap

.PHONY: all check demo capture clean
