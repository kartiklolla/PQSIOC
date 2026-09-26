/* Microbenchmarks of every operation a PQIOT/2 session performs, on
 * whatever clock the platform has: nanoseconds natively (bench_main.c,
 * `make bench`), CPU cycles on bare metal (firmware/main_bench.c,
 * `make fw-bench`). Same code, same inputs, so the two are comparable. */
#include "pqiot.h"

#include <stdio.h>
#include <string.h>

#include <wolfssl/wolfcrypt/aes.h>

#define BENCH_MAX_ITERS 64

static uint64_t (*clk)(void);
static const char *unit;

/* min / median / max of n samples (sorted in place). */
static void report(const char *name, uint64_t *t, int n)
{
    int i, j;

    for (i = 1; i < n; i++)
        for (j = i; j > 0 && t[j - 1] > t[j]; j--) {
            uint64_t x = t[j];
            t[j] = t[j - 1];
            t[j - 1] = x;
        }
    printf("  %-44s %12llu %12llu %12llu %s\n", name,
           (unsigned long long)t[0], (unsigned long long)t[n / 2],
           (unsigned long long)t[n - 1], unit);
}

/* AES-256 block cipher alone over `len` bytes (ECB, one block at a time):
 * separates the cipher's cost from GHASH's in the AES-GCM rows. */
static int aes_blocks(Aes *aes, const uint8_t *in, uint8_t *out, size_t len)
{
    size_t i;

    for (i = 0; i + WC_AES_BLOCK_SIZE <= len; i += WC_AES_BLOCK_SIZE)
        if (wc_AesEncryptDirect(aes, out + i, in + i) != 0)
            return -1;
    return 0;
}

/* Time `stmt` (an int expression, 0 = success) `iters` times. */
#define TIME(name, stmt)                                              \
    do {                                                              \
        uint64_t s_[BENCH_MAX_ITERS];                                 \
        int k_;                                                       \
        for (k_ = 0; k_ < iters; k_++) {                              \
            uint64_t a_ = clk();                                      \
            if ((stmt) != 0) {                                        \
                printf("bench: %s failed\n", name);                   \
                goto out;                                             \
            }                                                         \
            s_[k_] = clk() - a_;                                      \
        }                                                             \
        report(name, s_, iters);                                      \
    } while (0)

int pqiot_bench(int iters, uint64_t (*now)(void), const char *clock_unit,
                pqiot_identity *id)
{
    static const char telemetry[] = "sensor=temp value=23.4C";
    static uint8_t kb[1024], frame[PQIOT_MAX_BODY], pt[PQIOT_MAX_BODY];
    uint8_t ct[PQIOT_KEMCT_SZ], ss[PQIOT_SS_SZ], ss2[PQIOT_SS_SZ];
    uint8_t sig[PQIOT_SIG_SZ];
    size_t len, ptlen, siglen = 0;
    pqiot_keys keys;
    uint8_t tag[16], iv[12] = {0};
    Aes aes;
    MlKemKey kem;
    wc_Sha256 th;
    char cn[256];
    int rc = -1;

    memset(&keys, 0, sizeof(keys)); /* the first free below is a no-op */
    if (iters < 1 || iters > BENCH_MAX_ITERS || now == NULL || id == NULL)
        return -1;
    clk = now;
    unit = clock_unit;
    memset(kb, 0x5a, sizeof(kb));

    if (wc_MlKemKey_Init(&kem, PQIOT_MLKEM_LEVEL, NULL, INVALID_DEVID) != 0)
        return -1;
    if (wc_AesInit(&aes, NULL, INVALID_DEVID) != 0) {
        wc_MlKemKey_Free(&kem);
        return -1;
    }
    if (wc_InitSha256(&th) != 0 ||
        pqiot_transcript_add(&th, PQIOT_MSG_CERT, id->cert, id->cert_len) != 0)
        goto out;

    printf("  %-44s %12s %12s %12s\n", "operation", "min", "median", "max");

    /* The KEM: server keygen, device encapsulation, server decapsulation. */
    TIME("ML-KEM-768 keygen", wc_MlKemKey_MakeKey(&kem, pqiot_rng()));
    TIME("ML-KEM-768 encapsulate",
         wc_MlKemKey_Encapsulate(&kem, ct, ss, pqiot_rng()));
    TIME("ML-KEM-768 decapsulate",
         wc_MlKemKey_Decapsulate(&kem, ss2, ct, sizeof(ct)));
    if (memcmp(ss, ss2, sizeof(ss)) != 0) {
        printf("bench: KEM secrets differ\n");
        goto out;
    }

    /* Symmetric side: key schedule and the AEAD. */
    /* Derive-and-free per iteration: the timed step includes keying tx/rx
     * for the handshake, as a session does once (and once more for DATA). */
    TIME("HKDF + key tx/rx AES-GCM (per phase)",
         (pqiot_keys_free(&keys), pqiot_derive_keys(ss, sizeof(ss), 1, &keys)));
    TIME("AES-256-GCM seal, 23 B telemetry",
         pqiot_seal(&keys.tx, (const uint8_t *)telemetry, sizeof(telemetry) - 1,
                    frame, sizeof(frame), &len));
    TIME("AES-256-GCM open, 23 B telemetry",
         pqiot_open(&keys.tx, frame, len, pt, sizeof(pt), &ptlen));
    TIME("AES-256-GCM seal, 1 KB",
         pqiot_seal(&keys.tx, kb, sizeof(kb), frame, sizeof(frame), &len));
    /* ...and its parts: the block cipher one block at a time (GCM batches
     * blocks, so with bitsliced AES this is an upper bound, not a share),
     * key setup, and GHASH (GCM over 1 KB of authenticated-only data). */
    if (wc_AesSetKey(&aes, keys.c2s, PQIOT_KEY_SZ, NULL, AES_ENCRYPTION) != 0)
        goto out;
    TIME("  AES-256 one block at a time, 1 KB",
         aes_blocks(&aes, kb, frame, sizeof(kb)));
    TIME("  AES-256-GCM key setup, one context",
         wc_AesGcmSetKey(&aes, keys.c2s, PQIOT_KEY_SZ));
    TIME("  GHASH alone, 1 KB",
         wc_AesGcmEncrypt(&aes, NULL, NULL, 0, iv, sizeof(iv), tag, sizeof(tag),
                          kb, sizeof(kb)));

    /* Authentication: sign the transcript, and verify a peer (X.509 chain
     * to the CA + key-type check + ML-DSA signature over the transcript). */
    TIME("ML-DSA-65 sign transcript",
         pqiot_auth_sign(id, &th, PQIOT_ROLE_SERVER, sig, &siglen));
    TIME("peer auth: X.509 chain + ML-DSA-65 verify",
         pqiot_auth_verify(id, id->cert, id->cert_len, NULL, &th,
                           PQIOT_ROLE_SERVER, sig, siglen, cn, sizeof(cn)));
    rc = 0;
out:
    pqiot_keys_free(&keys);
    wc_AesFree(&aes);
    wc_MlKemKey_Free(&kem);
    wc_Sha256Free(&th);
    return rc;
}
