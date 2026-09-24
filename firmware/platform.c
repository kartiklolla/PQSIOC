/* Bare-metal platform pieces shared by both firmware images (the POSIX
 * counterpart is src/pqiot_posix.c; the transports behind pqiot_sys_read and
 * pqiot_sys_write are pipes.c and udp_stream.c):
 *
 *  - pqiot_fw_seed: wolfSSL's DRBG seed source (CUSTOM_RAND_GENERATE_SEED).
 *  - gettimeofday: the wall clock X.509 validity checks read.
 */
#include <stdint.h>
#include <string.h>
#include <sys/time.h>

#include <generated/csr.h>

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/sha256.h>

#include "fw_build.h" /* PQIOT_FW_SEED, PQIOT_FW_BUILD_TIME: made per build */

/* ---- entropy ------------------------------------------------------------ */

/* The simulated SoC has no TRNG, and a simulation is deterministic anyway,
 * so the only unpredictable input available is a 32-byte seed the Makefile
 * draws from the build host's /dev/urandom into each image. It is stretched
 * with SHA-256 in counter mode, mixed with the cycle timer (which only adds
 * anything on real hardware). Consequence: every boot of one image replays
 * the same randomness. Real hardware must feed a TRNG in here instead. */
int pqiot_fw_seed(unsigned char *output, unsigned int sz)
{
    static const uint8_t seed[32] = PQIOT_FW_SEED;
    static uint32_t counter;
    uint8_t block[WC_SHA256_DIGEST_SIZE];
    wc_Sha256 sha;
    uint32_t t;

    while (sz > 0) {
        unsigned int n = sz < sizeof(block) ? sz : sizeof(block);

        timer0_update_value_write(1);
        t = timer0_value_read();
        counter++;
        if (wc_InitSha256(&sha) != 0 ||
            wc_Sha256Update(&sha, seed, sizeof(seed)) != 0 ||
            wc_Sha256Update(&sha, (const uint8_t *)&counter, sizeof(counter)) != 0 ||
            wc_Sha256Update(&sha, (const uint8_t *)&t, sizeof(t)) != 0 ||
            wc_Sha256Final(&sha, block) != 0)
            return -1;
        wc_Sha256Free(&sha);
        memcpy(output, block, n);
        output += n;
        sz -= n;
    }
    return 0;
}

/* ---- time --------------------------------------------------------------- */

/* No RTC either. Certificates are checked against the image's build time:
 * a lower bound on the real date, so an expired certificate is still
 * refused once the firmware is rebuilt after its expiry. */
int gettimeofday(struct timeval *tv, void *tz)
{
    (void)tz;
    if (tv != NULL) {
        tv->tv_sec  = PQIOT_FW_BUILD_TIME;
        tv->tv_usec = 0;
    }
    return 0;
}
