/* PQIOT/2 on bare-metal RISC-V (LiteX VexRiscv, no OS).
 *
 * Runs one full session -- ML-KEM-768 key exchange, mutual ML-DSA-65
 * authentication, AES-256-GCM telemetry -- between a device and a server,
 * both on this CPU. They run the exact session code the Linux binaries do
 * (src/session.c) as two cooperative coroutines, talking through in-memory
 * pipes (platform.c) in place of a socket.
 *
 * Prints a verdict line the host's `make fw-demo` waits for:
 *   PQIOT bare-metal demo: OK | FAILED
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <generated/csr.h>
#include <generated/soc.h>

#include "pqiot.h"
#include "fw.h"

/* ---- coroutines ---------------------------------------------------------- */

typedef struct { unsigned long r[14]; } coro_ctx; /* ra, sp, s0-s11 */
void coro_switch(coro_ctx *from, coro_ctx *to);   /* switch.S */

enum { DEVICE = 0, SERVER = 1 }; /* also each role's pipe fd */

static struct coro {
    coro_ctx ctx;
    int    (*fn)(void);
    int      rc;
    int      done;
} co[2];

static coro_ctx main_ctx;
static int cur;

/* Generous: the session keeps several 8 KB frame buffers on its stack. */
static uint8_t stacks[2][256 * 1024] __attribute__((aligned(16)));

static void coro_entry(void)
{
    struct coro *c = &co[cur];

    c->rc = c->fn();
    c->done = 1;
    coro_switch(&c->ctx, &main_ctx); /* never resumed */
    for (;;)
        ;
}

void fw_yield(void)
{
    coro_switch(&co[cur].ctx, &main_ctx);
}

int fw_peer_done(void)
{
    return co[1 - cur].done;
}

/* Round-robin until both ends finish. A full round in which nothing was
 * sent and nobody finished is a deadlock: fail the pipes so both unwind. */
static void run_both(void)
{
    size_t last = (size_t)-1;
    int i, finished;

    for (i = 0; i < 2; i++) {
        co[i].ctx.r[0] = (unsigned long)coro_entry;
        co[i].ctx.r[1] = (unsigned long)(stacks[i] + sizeof(stacks[i]));
    }
    while (!(co[DEVICE].done && co[SERVER].done)) {
        size_t moved;

        finished = 0;
        for (i = 0; i < 2; i++) {
            if (co[i].done)
                continue;
            cur = i;
            coro_switch(&main_ctx, &co[i].ctx);
            finished += co[i].done;
        }
        moved = fw_wire_bytes(0) + fw_wire_bytes(1);
        if (moved == last && !finished) {
            printf("[fw] deadlock: neither side can make progress\n");
            fw_wire_abort();
        }
        last = moved;
    }
}

/* ---- the demo ------------------------------------------------------------ */

/* The demo PKI from build/certs, linked in by certs.S. Both identities live
 * in this one image only because both ends run here. */
#define PEM(name) \
    extern const uint8_t name[], name##_end[];
PEM(fw_ca_pem) PEM(fw_server_pem) PEM(fw_server_key) PEM(fw_device_pem) PEM(fw_device_key)
#define LEN(name) ((size_t)(name##_end - name))

static pqiot_identity server_id, device_id;

static int server_main(void)
{
    return pqiot_server_session(SERVER, &server_id);
}

static int device_main(void)
{
    return pqiot_device_session(DEVICE, "sensor=temp value=23.4C", &device_id);
}

/* LiteX timer0 as a free-running down-counter of system clock cycles. */
static void cycles_start(void)
{
    timer0_en_write(0);
    timer0_reload_write(0xffffffff);
    timer0_load_write(0xffffffff);
    timer0_en_write(1);
}

static uint32_t cycles_now(void)
{
    timer0_update_value_write(1);
    return 0xffffffff - timer0_value_read();
}

int main(void)
{
    uint32_t t0, t1;
    int ok;

    printf("\n[fw] PQIOT/2 bare-metal demo on %s @ %lu Hz, no OS\n",
           CONFIG_CPU_HUMAN_NAME, (unsigned long)CONFIG_CLOCK_FREQUENCY);
    cycles_start();

    if (pqiot_rng() == NULL ||
        pqiot_identity_parse(&server_id, fw_server_pem, LEN(fw_server_pem),
                             fw_server_key, LEN(fw_server_key),
                             fw_ca_pem, LEN(fw_ca_pem)) != 0 ||
        pqiot_identity_parse(&device_id, fw_device_pem, LEN(fw_device_pem),
                             fw_device_key, LEN(fw_device_key),
                             fw_ca_pem, LEN(fw_ca_pem)) != 0) {
        printf("[fw] RNG or identity setup failed\n");
        printf("PQIOT bare-metal demo: FAILED\n");
        for (;;)
            ;
    }
    printf("[fw] identities loaded (ML-DSA-65), starting session\n\n");

    co[SERVER].fn = server_main;
    co[DEVICE].fn = device_main;
    t0 = cycles_now();
    run_both();
    t1 = cycles_now();

    ok = co[SERVER].rc == 0 && co[DEVICE].rc == 0;
    printf("\n[server] %s\n[device] %s\n",
           co[SERVER].rc == 0 ? "session OK" : "session FAILED",
           co[DEVICE].rc == 0 ? "session OK" : "session FAILED");
    printf("[fw] wire: %lu bytes device->server, %lu bytes server->device\n",
           (unsigned long)fw_wire_bytes(0), (unsigned long)fw_wire_bytes(1));
    printf("[fw] whole session: %lu cycles\n", (unsigned long)(t1 - t0));
    printf("PQIOT bare-metal demo: %s\n", ok ? "OK" : "FAILED");

    for (;;)
        ;
    return 0;
}
