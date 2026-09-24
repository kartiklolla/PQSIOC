/* PQIOT/2 device on bare-metal RISC-V, over the (simulated) network.
 *
 * The LiteX VexRiscv SoC with an Ethernet MAC, no OS. Runs the device side
 * of the same session code the Linux client does (src/session.c), over a
 * reliable UDP stream (udp_stream.c) to tools/udp-bridge.py on the host,
 * which hands the bytes to the ordinary TCP pqiot-server. The server cannot
 * tell this device from the Linux one.
 *
 * Prints a verdict line the host's `make fw-net-demo` waits for:
 *   PQIOT bare-metal demo: OK | FAILED
 */
#include <stdint.h>
#include <stdio.h>

#include <generated/csr.h>
#include <generated/soc.h>
#include <libliteeth/udp.h>

#include "pqiot.h"
#include "udp_stream.h"

/* The demo PKI, device side only (certs.S with PQIOT_FW_DEVICE_ONLY). */
extern const uint8_t fw_ca_pem[], fw_ca_pem_end[];
extern const uint8_t fw_device_pem[], fw_device_pem_end[];
extern const uint8_t fw_device_key[], fw_device_key_end[];
#define LEN(name) ((size_t)(name##_end - name))

/* Addresses come from litex_sim's --local-ip/--remote-ip (soc.h);
 * IPTOINT is libliteeth's. */
static const uint8_t mac[6] = { 0x10, 0xe2, 0xd5, 0x00, 0x00, 0x01 };

#define PQUDP_PORT 4433 /* device and bridge both use it */

static pqiot_identity device_id;

static void halt(int ok)
{
    printf("PQIOT bare-metal demo: %s\n", ok ? "OK" : "FAILED");
    for (;;)
        ;
}

int main(void)
{
    uint32_t local  = IPTOINT(LOCALIP1, LOCALIP2, LOCALIP3, LOCALIP4);
    uint32_t remote = IPTOINT(REMOTEIP1, REMOTEIP2, REMOTEIP3, REMOTEIP4);
    uint32_t t0, t1;
    int rc;

    printf("\n[fw] PQIOT/2 bare-metal device on %s @ %lu Hz, no OS\n",
           CONFIG_CPU_HUMAN_NAME, (unsigned long)CONFIG_CLOCK_FREQUENCY);

    /* timer0: free-running down-counter, read by udp_stream.c and below. */
    timer0_en_write(0);
    timer0_reload_write(0xffffffff);
    timer0_load_write(0xffffffff);
    timer0_en_write(1);

    if (pqiot_rng() == NULL ||
        pqiot_identity_parse(&device_id, fw_device_pem, LEN(fw_device_pem),
                             fw_device_key, LEN(fw_device_key),
                             fw_ca_pem, LEN(fw_ca_pem)) != 0) {
        printf("[fw] RNG or identity setup failed\n");
        halt(0);
    }
    printf("[fw] device identity loaded (ML-DSA-65)\n");

    eth_init();
    udp_start(mac, local);
    printf("[fw] ethernet up: %d.%d.%d.%d -> bridge %d.%d.%d.%d:%d\n",
           LOCALIP1, LOCALIP2, LOCALIP3, LOCALIP4,
           REMOTEIP1, REMOTEIP2, REMOTEIP3, REMOTEIP4, PQUDP_PORT);
    if (udp_stream_open(remote, PQUDP_PORT, PQUDP_PORT) != 0) {
        printf("[fw] no answer from the bridge (tools/udp-bridge.py)\n");
        halt(0);
    }
    printf("[fw] bridge answered, starting session\n\n");

    timer0_update_value_write(1);
    t0 = 0xffffffff - timer0_value_read();
    rc = pqiot_device_session(0, "sensor=temp value=23.4C", &device_id);
    timer0_update_value_write(1);
    t1 = 0xffffffff - timer0_value_read();

    printf("\n[device] %s\n", rc == 0 ? "session OK" : "session FAILED");
    printf("[fw] whole session: %lu cycles\n", (unsigned long)(t1 - t0));
    halt(rc == 0);
    return 0;
}
