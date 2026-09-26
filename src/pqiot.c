#include "pqiot.h"

/* No OS calls in here: socket and file access live behind the hooks in
 * src/pqiot_posix.c, so this file also builds for bare metal. */
#include <stdio.h>
#include <string.h>

/* Configure-built wolfSSL records its options here; the bare-metal build
 * uses firmware/user_settings.h via -DWOLFSSL_USER_SETTINGS instead. */
#ifndef WOLFSSL_USER_SETTINGS
#include <wolfssl/options.h>
#endif
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/memory.h>
#include <wolfssl/wolfcrypt/random.h>

#if !defined(WOLFSSL_HAVE_MLDSA) || !defined(KEEP_PEER_CERT)
#error "wolfSSL needs ML-DSA and KEEP_PEER_CERT (link build/<arch> from the Makefile)"
#endif

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

int pqiot_derive_keys(const uint8_t *ss, size_t ss_len, int server,
                      pqiot_keys *out)
{
    /* Distinct info strings => independent keys from one secret. No salt: the
     * KEM secret is already uniformly random, which is what a salt buys. */
    const struct { const char *info; uint8_t *key; } k[] = {
        { "PQIOT/2 hs c2s", out ? out->hs_c2s : NULL },
        { "PQIOT/2 hs s2c", out ? out->hs_s2c : NULL },
        { "PQIOT/2 c2s",    out ? out->c2s    : NULL },
        { "PQIOT/2 s2c",    out ? out->s2c    : NULL },
    };
    size_t i;

    if (ss == NULL || out == NULL || ss_len != PQIOT_SS_SZ)
        return PQIOT_ERR;

    out->server = server;
    if (wc_AesInit(&out->tx, NULL, INVALID_DEVID) != 0)
        return PQIOT_ERR;
    if (wc_AesInit(&out->rx, NULL, INVALID_DEVID) != 0) {
        wc_AesFree(&out->tx);
        return PQIOT_ERR;
    }
    for (i = 0; i < sizeof(k) / sizeof(k[0]); i++)
        if (wc_HKDF(WC_SHA256, ss, (word32)ss_len, NULL, 0,
                    (const byte *)k[i].info, (word32)strlen(k[i].info),
                    k[i].key, PQIOT_KEY_SZ) != 0) {
            pqiot_keys_free(out);
            return PQIOT_ERR;
        }
    if (pqiot_keys_phase(out, PQIOT_PHASE_HANDSHAKE) != 0) {
        pqiot_keys_free(out);
        return PQIOT_ERR;
    }
    return 0;
}

int pqiot_keys_phase(pqiot_keys *k, int phase)
{
    const uint8_t *c2s, *s2c;

    if (k == NULL)
        return PQIOT_ERR;
    c2s = phase == PQIOT_PHASE_HANDSHAKE ? k->hs_c2s : k->c2s;
    s2c = phase == PQIOT_PHASE_HANDSHAKE ? k->hs_s2c : k->s2c;
    if (wc_AesGcmSetKey(&k->tx, k->server ? s2c : c2s, PQIOT_KEY_SZ) != 0 ||
        wc_AesGcmSetKey(&k->rx, k->server ? c2s : s2c, PQIOT_KEY_SZ) != 0)
        return PQIOT_ERR;
    return 0;
}

void pqiot_keys_free(pqiot_keys *k)
{
    if (k == NULL)
        return;
    wc_AesFree(&k->tx);
    wc_AesFree(&k->rx);
    wc_ForceZero(k, sizeof(*k)); /* raw keys and expanded round keys */
}

int pqiot_aead_init(Aes *aes, const uint8_t key[PQIOT_KEY_SZ])
{
    if (aes == NULL || key == NULL || wc_AesInit(aes, NULL, INVALID_DEVID) != 0)
        return PQIOT_ERR;
    if (wc_AesGcmSetKey(aes, key, PQIOT_KEY_SZ) != 0) {
        wc_AesFree(aes);
        return PQIOT_ERR;
    }
    return 0;
}

int pqiot_seal(Aes *aes, const uint8_t *pt, size_t ptlen,
               uint8_t *out, size_t outcap, size_t *outlen)
{
    WC_RNG *rng;
    uint8_t *iv  = out;                   /* [0 ..12) */
    uint8_t *tag = out + PQIOT_IV_SZ;     /* [12..28) */
    uint8_t *ct  = out + PQIOT_AEAD_OVERHEAD;
    int rc;

    if (aes == NULL || out == NULL || outlen == NULL || (pt == NULL && ptlen))
        return PQIOT_ERR;
    if (outcap < ptlen + PQIOT_AEAD_OVERHEAD)
        return PQIOT_ERR;

    rng = pqiot_rng();
    if (rng == NULL)
        return PQIOT_ERR;

    /* A fresh random 96-bit IV per message: GCM forbids reuse under one key. */
    if (wc_RNG_GenerateBlock(rng, iv, PQIOT_IV_SZ) != 0)
        return PQIOT_ERR;

    rc = wc_AesGcmEncrypt(aes, ct, pt, (word32)ptlen,
                          iv, PQIOT_IV_SZ, tag, PQIOT_TAG_SZ, NULL, 0);
    if (rc != 0)
        return PQIOT_ERR;

    *outlen = ptlen + PQIOT_AEAD_OVERHEAD;
    return 0;
}

int pqiot_open(Aes *aes, const uint8_t *in, size_t inlen,
               uint8_t *pt, size_t ptcap, size_t *ptlen)
{
    const uint8_t *iv  = in;
    const uint8_t *tag = in + PQIOT_IV_SZ;
    const uint8_t *ct  = in + PQIOT_AEAD_OVERHEAD;
    size_t ctlen;
    int rc;

    if (aes == NULL || in == NULL || pt == NULL || ptlen == NULL)
        return PQIOT_ERR;
    /* Attacker-controlled length: a short frame must not underflow ctlen. */
    if (inlen < PQIOT_AEAD_OVERHEAD)
        return PQIOT_ERR;

    ctlen = inlen - PQIOT_AEAD_OVERHEAD;
    if (ctlen > ptcap)
        return PQIOT_ERR;

    rc = wc_AesGcmDecrypt(aes, pt, ct, (word32)ctlen,
                          iv, PQIOT_IV_SZ, tag, PQIOT_TAG_SZ, NULL, 0);

    /* wc_AesGcmDecrypt returns AES_GCM_AUTH_E on a bad tag. */
    if (rc != 0)
        return PQIOT_ERR;

    *ptlen = ctlen;
    return 0;
}

static int write_full(int fd, const uint8_t *buf, size_t len)
{
    while (len > 0) {
        long n = pqiot_sys_write(fd, buf, len);
        if (n <= 0)
            return PQIOT_ERR;
        buf += n;
        len -= (size_t)n;
    }
    return 0;
}

static int read_full(int fd, uint8_t *buf, size_t len)
{
    while (len > 0) {
        long n = pqiot_sys_read(fd, buf, len);
        if (n <= 0)
            return PQIOT_ERR; /* error, or peer closed mid-frame */
        buf += n;
        len -= (size_t)n;
    }
    return 0;
}

static void make_hdr(uint8_t hdr[PQIOT_HDR_SZ], uint8_t type, size_t len)
{
    hdr[0] = PQIOT_MAGIC0;
    hdr[1] = PQIOT_MAGIC1;
    hdr[2] = PQIOT_MAGIC2;
    hdr[3] = PQIOT_MAGIC3;
    hdr[4] = type;
    hdr[5] = PQIOT_VER;
    hdr[6] = (uint8_t)(len >> 8);
    hdr[7] = (uint8_t)(len & 0xff);
}

int pqiot_send(int fd, uint8_t type, const uint8_t *body, size_t len)
{
    uint8_t hdr[PQIOT_HDR_SZ];

    if (len > PQIOT_MAX_BODY || (body == NULL && len))
        return PQIOT_ERR;

    make_hdr(hdr, type, len);
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

int pqiot_send_sealed(int fd, Aes *aes, uint8_t type,
                      const uint8_t *pt, size_t ptlen)
{
    uint8_t frame[PQIOT_MAX_BODY];
    size_t len;

    if (pqiot_seal(aes, pt, ptlen, frame, sizeof(frame), &len) != 0)
        return PQIOT_ERR;
    return pqiot_send(fd, type, frame, len);
}

int pqiot_recv_sealed(int fd, Aes *aes, uint8_t want,
                      uint8_t *pt, size_t ptcap, size_t *ptlen)
{
    uint8_t frame[PQIOT_MAX_BODY];
    uint8_t type;
    size_t len;

    if (pqiot_recv(fd, &type, frame, sizeof(frame), &len) != 0 ||
        type != want)
        return PQIOT_ERR;
    return pqiot_open(aes, frame, len, pt, ptcap, ptlen);
}

const char *pqiot_msg_name(uint8_t type)
{
    switch (type) {
    case PQIOT_MSG_PUBKEY: return "PUBKEY";
    case PQIOT_MSG_KEMCT:  return "KEMCT";
    case PQIOT_MSG_DATA:   return "DATA";
    case PQIOT_MSG_CERT:   return "CERT";
    case PQIOT_MSG_VERIFY: return "VERIFY";
    default:               return "UNKNOWN";
    }
}

/* ---- authentication ---------------------------------------------------- */

int pqiot_identity_parse(pqiot_identity *id,
                         const uint8_t *cert_pem, size_t cert_len,
                         const uint8_t *key_pem, size_t key_len,
                         const uint8_t *ca_pem, size_t ca_len)
{
    uint8_t der[8192];
    word32 idx = 0;
    int len, rc = PQIOT_ERR;

    if (id == NULL || cert_pem == NULL || key_pem == NULL || ca_pem == NULL)
        return PQIOT_ERR;
    if (wc_MlDsaKey_Init(&id->key, NULL, INVALID_DEVID) != 0)
        return PQIOT_ERR;

    len = wc_CertPemToDer(cert_pem, (int)cert_len, id->cert, sizeof(id->cert),
                          CERT_TYPE);
    if (len <= 0)
        goto out;
    id->cert_len = (size_t)len;

    len = wc_CertPemToDer(ca_pem, (int)ca_len, id->ca, sizeof(id->ca),
                          CERT_TYPE);
    if (len <= 0)
        goto out;
    id->ca_len = (size_t)len;

    len = wc_KeyPemToDer(key_pem, (int)key_len, der, sizeof(der), NULL);
    if (len <= 0 ||
        wc_MlDsaKey_SetParams(&id->key, WC_ML_DSA_65) != 0 ||
        wc_MlDsaKey_PrivateKeyDecode(&id->key, der, (word32)len, &idx) != 0)
        goto out;

    rc = 0;
out:
    wc_ForceZero(der, sizeof(der)); /* held the private key */
    if (rc != 0)
        wc_MlDsaKey_Free(&id->key);
    return rc;
}

void pqiot_identity_free(pqiot_identity *id)
{
    if (id != NULL)
        wc_MlDsaKey_Free(&id->key);
}

int pqiot_transcript_add(wc_Sha256 *th, uint8_t type, const uint8_t *body,
                         size_t len)
{
    uint8_t hdr[PQIOT_HDR_SZ];

    if (th == NULL || len > PQIOT_MAX_BODY || (body == NULL && len))
        return PQIOT_ERR;

    /* Header too: it carries the type and version, which must be bound as
     * well as the bytes. */
    make_hdr(hdr, type, len);
    if (wc_Sha256Update(th, hdr, sizeof(hdr)) != 0 ||
        wc_Sha256Update(th, body, (word32)len) != 0)
        return PQIOT_ERR;
    return 0;
}

int pqiot_auth_sign(pqiot_identity *id, wc_Sha256 *th, const char *role,
                    uint8_t *sig, size_t *siglen)
{
    uint8_t digest[WC_SHA256_DIGEST_SIZE];
    word32 slen = PQIOT_SIG_SZ;
    WC_RNG *rng = pqiot_rng();

    if (id == NULL || th == NULL || role == NULL || sig == NULL ||
        siglen == NULL || rng == NULL)
        return PQIOT_ERR;

    /* GetHash, not Final: the transcript keeps running after this. */
    if (wc_Sha256GetHash(th, digest) != 0 ||
        wc_MlDsaKey_SignCtx(&id->key, (const byte *)role, (byte)strlen(role),
                            sig, &slen, digest, sizeof(digest), rng) != 0)
        return PQIOT_ERR;

    *siglen = slen;
    return 0;
}

int pqiot_auth_verify(const pqiot_identity *self, const uint8_t *cert,
                      size_t cert_len, const char *want_cn, wc_Sha256 *th,
                      const char *role, const uint8_t *sig, size_t siglen,
                      char *cn, size_t cncap)
{
    WOLFSSL_CERT_MANAGER *cm = NULL;
    WOLFSSL_X509 *x509 = NULL;
    wc_MlDsaKey key;
    uint8_t spki[PQIOT_MAX_BODY];
    uint8_t digest[WC_SHA256_DIGEST_SIZE];
    int spki_len = sizeof(spki), key_ready = 0, verified = 0;
    const char *peer_cn;
    word32 idx = 0;
    int rc = PQIOT_ERR;

    if (self == NULL || cert == NULL || th == NULL || role == NULL ||
        sig == NULL || cn == NULL || cncap == 0 ||
        cert_len == 0 || cert_len > PQIOT_MAX_BODY)
        return PQIOT_ERR;
    cn[0] = '\0';

    /* 1. The certificate chains to our CA (signature, validity dates). */
    cm = wolfSSL_CertManagerNew();
    if (cm == NULL ||
        wolfSSL_CertManagerLoadCABuffer(cm, self->ca, (long)self->ca_len,
                                        WOLFSSL_FILETYPE_ASN1) != WOLFSSL_SUCCESS ||
        wolfSSL_CertManagerVerifyBuffer(cm, cert, (long)cert_len,
                                        WOLFSSL_FILETYPE_ASN1) != WOLFSSL_SUCCESS)
        goto out;

    /* 2. Its key is ML-DSA-65: the CA could in principle have signed a
     *    classical key, and then this signature would be classical too. */
    x509 = wolfSSL_X509_load_certificate_buffer(cert, (int)cert_len,
                                                WOLFSSL_FILETYPE_ASN1);
    if (x509 == NULL || wolfSSL_X509_get_pubkey_type(x509) != ML_DSA_65k)
        goto out;

    /* 3. It names who we expected. ponytail: CN only; our certificates put
     *    the same name in the SAN, check SANs if other CAs issue them. */
    peer_cn = wolfSSL_X509_get_subjectCN(x509);
    if (peer_cn == NULL)
        goto out;
    snprintf(cn, cncap, "%s", peer_cn);
    if (want_cn != NULL && strcmp(peer_cn, want_cn) != 0)
        goto out;

    /* 4. The peer's signature over our view of the transcript verifies
     *    under that key, as that role. */
    if (wolfSSL_X509_get_pubkey_buffer(x509, spki, &spki_len) != WOLFSSL_SUCCESS ||
        wc_MlDsaKey_Init(&key, NULL, INVALID_DEVID) != 0)
        goto out;
    key_ready = 1;
    if (wc_MlDsaKey_SetParams(&key, WC_ML_DSA_65) != 0 ||
        wc_MlDsaKey_PublicKeyDecode(&key, spki, (word32)spki_len, &idx) != 0 ||
        wc_Sha256GetHash(th, digest) != 0 ||
        wc_MlDsaKey_VerifyCtx(&key, sig, (word32)siglen, (const byte *)role,
                              (byte)strlen(role), digest, sizeof(digest),
                              &verified) != 0 ||
        verified != 1)
        goto out;

    rc = 0;
out:
    if (key_ready)
        wc_MlDsaKey_Free(&key);
    wolfSSL_X509_free(x509);
    wolfSSL_CertManagerFree(cm);
    return rc;
}
