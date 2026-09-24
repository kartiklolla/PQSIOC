/* Network transport for the device-only firmware (main_net.c): a reliable
 * byte stream over LiteX's bare-metal UDP stack (libliteeth), carrying the
 * PQIOT/2 frames to tools/udp-bridge.py on the host, which relays them to
 * the ordinary TCP pqiot-server.
 *
 * libliteeth has UDP but no TCP, and PQIOT messages (up to ~8.9 KB) exceed
 * one datagram, so the stream is chunked and made reliable here. Datagram:
 *
 *   [kind 1B][seq 4B big-endian][payload]
 *     kind 0 DATA   payload 1..PQUDP_CHUNK bytes of stream
 *     kind 1 ACK    no payload; acknowledges DATA `seq`
 *     kind 2 HELLO  no payload; the device opening a session
 *
 * Stop-and-wait in each direction: one DATA outstanding, retransmitted until
 * ACKed; the receiver delivers seq == expected, re-ACKs duplicates.
 * ponytail: stop-and-wait costs a round trip per KB; a window if throughput
 * ever matters more than the ~50 KB a session moves.
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <generated/csr.h>
#include <generated/soc.h>
#include <libliteeth/udp.h>

#include "pqiot.h" /* pqiot_sys_read/write */
#include "udp_stream.h"

#define PQUDP_DATA  0
#define PQUDP_ACK   1
#define PQUDP_HELLO 2
#define PQUDP_HDR   5
#define PQUDP_CHUNK 1024

/* Retransmit after this much simulated time without an ACK; give up on the
 * peer after PQUDP_TRIES of them. Simulated seconds pass slower than real
 * ones, so this is generous in wall-clock terms. */
#define PQUDP_RTO_TICKS (CONFIG_CLOCK_FREQUENCY / 4)
#define PQUDP_TRIES     200

static uint32_t peer_ip;
static uint16_t local_port, peer_port;

static uint32_t tx_seq;       /* seq of the DATA we are sending/sent last */
static int      tx_acked = 1; /* has tx_seq been ACKed? */
static uint32_t rx_expected;  /* next DATA seq we will deliver */

/* Received stream bytes not yet read. Only filled while the application is
 * blocked in send or read, and one chunk at a time, so it stays small. */
static uint8_t rx_buf[16 * 1024];
static size_t  rx_rd, rx_wr;

static uint32_t ticks(void)
{
    timer0_update_value_write(1);
    return 0xffffffff - timer0_value_read(); /* main_net.c starts timer0 */
}

static void put32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);  p[3] = (uint8_t)v;
}

static uint32_t get32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8)  |  (uint32_t)p[3];
}

static int send_dgram(uint8_t kind, uint32_t seq, const void *data, size_t len)
{
    uint8_t *tx = udp_get_tx_buffer();

    tx[0] = kind;
    put32(tx + 1, seq);
    if (len)
        memcpy(tx + PQUDP_HDR, data, len);
    return udp_send(local_port, peer_port, PQUDP_HDR + len) ? 0 : -1;
}

/* libliteeth calls this from udp_service() for every datagram to us. */
static void on_dgram(uint32_t src_ip, uint16_t src_port, uint16_t dst_port,
                     void *data, uint32_t length)
{
    const uint8_t *d = data;
    uint32_t seq;
    size_t n;

    if (src_ip != peer_ip || src_port != peer_port || dst_port != local_port ||
        length < PQUDP_HDR)
        return; /* not our session */
    seq = get32(d + 1);

    switch (d[0]) {
    case PQUDP_ACK:
        if (seq == tx_seq)
            tx_acked = 1;
        break;
    case PQUDP_DATA:
        n = length - PQUDP_HDR;
        if (seq == rx_expected) {
            if (n == 0 || n > sizeof(rx_buf) - rx_wr)
                return; /* no room: drop, the peer retransmits */
            memcpy(rx_buf + rx_wr, d + PQUDP_HDR, n);
            rx_wr += n;
            rx_expected++;
        } else if (seq != rx_expected - 1) {
            return; /* not the next one, not a duplicate: ignore */
        }
        send_dgram(PQUDP_ACK, seq, NULL, 0); /* new or duplicate: ACK it */
        break;
    }
}

int udp_stream_open(uint32_t ip, uint16_t lport, uint16_t rport)
{
    int tries;

    peer_ip = ip;
    local_port = lport;
    peer_port = rport;
    udp_set_callback(on_dgram);

    if (!udp_arp_resolve(ip))
        return -1;

    /* HELLO is sent as DATA-less seq 0 and must be ACKed, so we know the
     * bridge is there before the handshake starts. */
    tx_seq = 0;
    tx_acked = 0;
    for (tries = 0; tries < PQUDP_TRIES && !tx_acked; tries++) {
        uint32_t t0 = ticks();

        send_dgram(PQUDP_HELLO, tx_seq, NULL, 0);
        while (!tx_acked && ticks() - t0 < PQUDP_RTO_TICKS)
            udp_service();
    }
    return tx_acked ? 0 : -1;
}

long pqiot_sys_write(int fd, const void *buf, size_t len)
{
    size_t n = len < PQUDP_CHUNK ? len : PQUDP_CHUNK;
    int tries;

    (void)fd;
    if (n == 0)
        return 0;
    tx_seq++;
    tx_acked = 0;
    for (tries = 0; tries < PQUDP_TRIES && !tx_acked; tries++) {
        uint32_t t0 = ticks();

        if (send_dgram(PQUDP_DATA, tx_seq, buf, n) != 0)
            return -1;
        while (!tx_acked && ticks() - t0 < PQUDP_RTO_TICKS)
            udp_service();
    }
    return tx_acked ? (long)n : -1; /* pqiot's write_full sends the rest */
}

long pqiot_sys_read(int fd, void *buf, size_t len)
{
    uint32_t t0 = ticks();
    size_t n;

    (void)fd;
    while (rx_rd == rx_wr) {
        udp_service();
        if (ticks() - t0 > (uint32_t)PQUDP_TRIES * PQUDP_RTO_TICKS)
            return -1; /* the peer has gone quiet for good */
    }
    n = rx_wr - rx_rd;
    if (n > len)
        n = len;
    memcpy(buf, rx_buf + rx_rd, n);
    rx_rd += n;
    if (rx_rd == rx_wr)
        rx_rd = rx_wr = 0;
    return (long)n;
}
