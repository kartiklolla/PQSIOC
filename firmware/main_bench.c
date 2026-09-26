/* Bare-metal benchmark image (`make fw-bench`): times every operation a
 * PQIOT/2 session performs (src/bench.c) in VexRiscv CPU cycles, the
 * number that matters for a constrained device. Divide by the clock rate
 * for time: 1 MHz in the simulator, e.g. 100 MHz on a small FPGA/MCU.
 *
 * Prints the verdict line `make fw-bench` waits for:
 *   PQIOT bare-metal demo: OK | FAILED
 */
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

#include <generated/csr.h>
#include <generated/soc.h>

#include "pqiot.h"

#define BENCH_ITERS 3 /* each ML-DSA sign costs tens of Mcycles in simulation */

extern const uint8_t fw_ca_pem[], fw_ca_pem_end[];
extern const uint8_t fw_server_pem[], fw_server_pem_end[];
extern const uint8_t fw_server_key[], fw_server_key_end[];
extern char __heap_start[];
#define LEN(name) ((size_t)(name##_end - name))

static pqiot_identity id;

/* No transport in this image: pqiot.c's framed I/O is linked but unused. */
long pqiot_sys_read(int fd, void *buf, size_t len)
{
    (void)fd; (void)buf; (void)len;
    return -1;
}

long pqiot_sys_write(int fd, const void *buf, size_t len)
{
    (void)fd; (void)buf; (void)len;
    return -1;
}

static uint64_t cycles(void)
{
    timer0_update_value_write(1);
    return 0xffffffffu - timer0_value_read();
}

int main(void)
{
    int rc;

    printf("\n[fw] PQIOT/2 bare-metal benchmark on %s @ %lu Hz, no OS\n",
           CONFIG_CPU_HUMAN_NAME, (unsigned long)CONFIG_CLOCK_FREQUENCY);
    timer0_en_write(0);
    timer0_reload_write(0xffffffff);
    timer0_load_write(0xffffffff);
    timer0_en_write(1);

    rc = pqiot_rng() == NULL ||
         pqiot_identity_parse(&id, fw_server_pem, LEN(fw_server_pem),
                              fw_server_key, LEN(fw_server_key),
                              fw_ca_pem, LEN(fw_ca_pem)) != 0;
    if (rc == 0) {
        printf("[fw] %d iterations each, in CPU cycles\n", BENCH_ITERS);
        rc = pqiot_bench(BENCH_ITERS, cycles, "cycles", &id);
    }
    printf("[fw] heap high-water: %lu bytes\n",
           (unsigned long)((char *)sbrk(0) - __heap_start));
    printf("PQIOT bare-metal demo: %s\n", rc == 0 ? "OK" : "FAILED");
    for (;;)
        ;
    return 0;
}
