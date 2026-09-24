#include "pqiot.h"

#include <errno.h>
#include <string.h>
#include <unistd.h>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/random.h>

#define PQIOT_ERR -1

/* One process-wide CSPRNG. wolfSSL's Hash-DRBG is seeded from the OS on first
 * use; re-seeding it per call would be pure overhead.
 * ponytail: not thread-safe. Client and server are both single-threaded; give
 * each thread its own WC_RNG if that ever stops being true. */
WC_RNG *pqiot_rng(void)
{
    static WC_RNG rng;
    static int ready = 0;

    if (!ready) {
        if (wc_InitRng(&rng) != 0)
            return NULL;
        ready = 1;
    }
    return &rng;
}

int pqiot_derive_keys(const uint8_t *ss, size_t ss_len, pqiot_keys *out)
{
    /* Distinct info strings => independent keys from one secret. No salt: the
     * KEM secret is already uniformly random, which is what a salt buys. */
    static const char info_c2s[] = "PQIOT/1 c2s";
    static const char info_s2c[] = "PQIOT/1 s2c";

    if (ss == NULL || out == NULL || ss_len != PQIOT_SS_SZ)
        return PQIOT_ERR;

    if (wc_HKDF(WC_SHA256, ss, (word32)ss_len, NULL, 0,
                (const byte *)info_c2s, (word32)(sizeof(info_c2s) - 1),
                out->c2s, PQIOT_KEY_SZ) != 0)
        return PQIOT_ERR;

    if (wc_HKDF(WC_SHA256, ss, (word32)ss_len, NULL, 0,
                (const byte *)info_s2c, (word32)(sizeof(info_s2c) - 1),
                out->s2c, PQIOT_KEY_SZ) != 0)
        return PQIOT_ERR;

    return 0;
}

int pqiot_seal(const uint8_t key[PQIOT_KEY_SZ], const uint8_t *pt, size_t ptlen,
               uint8_t *out, size_t outcap, size_t *outlen)
{
    Aes aes;
    WC_RNG *rng;
    uint8_t *iv  = out;                   /* [0 ..12) */
    uint8_t *tag = out + PQIOT_IV_SZ;     /* [12..28) */
    uint8_t *ct  = out + PQIOT_AEAD_OVERHEAD;
    int rc;

    if (key == NULL || out == NULL || outlen == NULL || (pt == NULL && ptlen))
        return PQIOT_ERR;
    if (outcap < ptlen + PQIOT_AEAD_OVERHEAD)
        return PQIOT_ERR;

    rng = pqiot_rng();
    if (rng == NULL)
        return PQIOT_ERR;

    /* A fresh random 96-bit IV per message: GCM forbids reuse under one key. */
    if (wc_RNG_GenerateBlock(rng, iv, PQIOT_IV_SZ) != 0)
        return PQIOT_ERR;

    if (wc_AesInit(&aes, NULL, INVALID_DEVID) != 0)
        return PQIOT_ERR;

    rc = wc_AesGcmSetKey(&aes, key, PQIOT_KEY_SZ);
    if (rc == 0)
        rc = wc_AesGcmEncrypt(&aes, ct, pt, (word32)ptlen,
                              iv, PQIOT_IV_SZ, tag, PQIOT_TAG_SZ, NULL, 0);
    wc_AesFree(&aes);

    if (rc != 0)
        return PQIOT_ERR;

    *outlen = ptlen + PQIOT_AEAD_OVERHEAD;
    return 0;
}

int pqiot_open(const uint8_t key[PQIOT_KEY_SZ], const uint8_t *in, size_t inlen,
               uint8_t *pt, size_t ptcap, size_t *ptlen)
{
    Aes aes;
    const uint8_t *iv  = in;
    const uint8_t *tag = in + PQIOT_IV_SZ;
    const uint8_t *ct  = in + PQIOT_AEAD_OVERHEAD;
    size_t ctlen;
    int rc;

    if (key == NULL || in == NULL || pt == NULL || ptlen == NULL)
        return PQIOT_ERR;
    /* Attacker-controlled length: a short frame must not underflow ctlen. */
    if (inlen < PQIOT_AEAD_OVERHEAD)
        return PQIOT_ERR;

    ctlen = inlen - PQIOT_AEAD_OVERHEAD;
    if (ctlen > ptcap)
        return PQIOT_ERR;

    if (wc_AesInit(&aes, NULL, INVALID_DEVID) != 0)
        return PQIOT_ERR;

    rc = wc_AesGcmSetKey(&aes, key, PQIOT_KEY_SZ);
    if (rc == 0)
        rc = wc_AesGcmDecrypt(&aes, pt, ct, (word32)ctlen,
                              iv, PQIOT_IV_SZ, tag, PQIOT_TAG_SZ, NULL, 0);
    wc_AesFree(&aes);

    /* wc_AesGcmDecrypt returns AES_GCM_AUTH_E on a bad tag. */
    if (rc != 0)
        return PQIOT_ERR;

    *ptlen = ctlen;
    return 0;
}

static int write_full(int fd, const uint8_t *buf, size_t len)
{
    while (len > 0) {
        ssize_t n = write(fd, buf, len);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return PQIOT_ERR;
        }
        buf += n;
        len -= (size_t)n;
    }
    return 0;
}

static int read_full(int fd, uint8_t *buf, size_t len)
{
    while (len > 0) {
        ssize_t n = read(fd, buf, len);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return PQIOT_ERR;
        }
        if (n == 0)
            return PQIOT_ERR; /* peer closed mid-frame */
        buf += n;
        len -= (size_t)n;
    }
    return 0;
}

int pqiot_send(int fd, uint8_t type, const uint8_t *body, size_t len)
{
    uint8_t hdr[PQIOT_HDR_SZ];

    if (len > PQIOT_MAX_BODY || (body == NULL && len))
        return PQIOT_ERR;

    hdr[0] = PQIOT_MAGIC0;
    hdr[1] = PQIOT_MAGIC1;
    hdr[2] = PQIOT_MAGIC2;
    hdr[3] = PQIOT_MAGIC3;
    hdr[4] = type;
    hdr[5] = PQIOT_VER;
    hdr[6] = (uint8_t)(len >> 8);
    hdr[7] = (uint8_t)(len & 0xff);

    if (write_full(fd, hdr, sizeof(hdr)) != 0)
        return PQIOT_ERR;
    return write_full(fd, body, len);
}

int pqiot_recv(int fd, uint8_t *type, uint8_t *body, size_t cap, size_t *len)
{
    uint8_t hdr[PQIOT_HDR_SZ];
    size_t blen;

    if (type == NULL || body == NULL || len == NULL)
        return PQIOT_ERR;

    if (read_full(fd, hdr, sizeof(hdr)) != 0)
        return PQIOT_ERR;

    /* Trust boundary: everything below comes off the network. */
    if (hdr[0] != PQIOT_MAGIC0 || hdr[1] != PQIOT_MAGIC1 ||
        hdr[2] != PQIOT_MAGIC2 || hdr[3] != PQIOT_MAGIC3)
        return PQIOT_ERR;
    if (hdr[5] != PQIOT_VER)
        return PQIOT_ERR;

    blen = ((size_t)hdr[6] << 8) | hdr[7];
    if (blen > cap)
        return PQIOT_ERR; /* never read more than the caller's buffer holds */

    if (read_full(fd, body, blen) != 0)
        return PQIOT_ERR;

    *type = hdr[4];
    *len  = blen;
    return 0;
}

const char *pqiot_msg_name(uint8_t type)
{
    switch (type) {
    case PQIOT_MSG_PUBKEY: return "PUBKEY";
    case PQIOT_MSG_KEMCT:  return "KEMCT";
    case PQIOT_MSG_DATA:   return "DATA";
    default:               return "UNKNOWN";
    }
}
