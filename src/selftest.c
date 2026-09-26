/* Self-check for the PQIOT primitives. Fails loudly if any of the crypto,
 * the authentication or the frame parser regresses. Run with `make check`,
 * which also builds the demo PKI and the certificates it must refuse. */
#include "pqiot.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include <wolfssl/wolfcrypt/asn_public.h>
#include <sys/socket.h>
#include <unistd.h>

/* Encapsulate/decapsulate must land on the identical shared secret. */
static void test_kem_agreement(void)
{
    MlKemKey srv, cli;
    uint8_t pub[PQIOT_PUBKEY_SZ];
    uint8_t ct[PQIOT_KEMCT_SZ];
    uint8_t ss_srv[PQIOT_SS_SZ], ss_cli[PQIOT_SS_SZ];

    assert(wc_MlKemKey_Init(&srv, PQIOT_MLKEM_LEVEL, NULL, INVALID_DEVID) == 0);
    assert(wc_MlKemKey_Init(&cli, PQIOT_MLKEM_LEVEL, NULL, INVALID_DEVID) == 0);

    assert(wc_MlKemKey_MakeKey(&srv, pqiot_rng()) == 0);
    assert(wc_MlKemKey_EncodePublicKey(&srv, pub, sizeof(pub)) == 0);

    assert(wc_MlKemKey_DecodePublicKey(&cli, pub, sizeof(pub)) == 0);
    assert(wc_MlKemKey_Encapsulate(&cli, ct, ss_cli, pqiot_rng()) == 0);
    assert(wc_MlKemKey_Decapsulate(&srv, ss_srv, ct, sizeof(ct)) == 0);

    assert(memcmp(ss_cli, ss_srv, PQIOT_SS_SZ) == 0);

    wc_MlKemKey_Free(&srv);
    wc_MlKemKey_Free(&cli);
    printf("ok  kem agreement (ML-KEM-768, pub=%zu ct=%zu)\n",
           sizeof(pub), sizeof(ct));
}

/* Does a message sealed under `aes` open under a context keyed from `key`? */
static int seals_under(Aes *aes, const uint8_t key[PQIOT_KEY_SZ])
{
    uint8_t sealed[64], out[64];
    size_t slen, olen;
    Aes raw;
    int ok;

    assert(pqiot_seal(aes, (const uint8_t *)"x", 1, sealed, sizeof(sealed),
                      &slen) == 0);
    assert(pqiot_aead_init(&raw, key) == 0);
    ok = pqiot_open(&raw, sealed, slen, out, sizeof(out), &olen) == 0;
    wc_AesFree(&raw);
    return ok;
}

/* Same secret in => same keys out, all four keys differ, and each side's
 * tx/rx use the right ones. */
static void test_key_derivation(void)
{
    uint8_t ss[PQIOT_SS_SZ];
    pqiot_keys a, b;
    const uint8_t *k[4];
    int i, j;

    memset(ss, 0xA5, sizeof(ss));
    assert(pqiot_derive_keys(ss, sizeof(ss), 1, &a) == 0); /* as server */
    assert(pqiot_derive_keys(ss, sizeof(ss), 0, &b) == 0); /* as device */

    /* deterministic: the four raw keys lead the struct */
    assert(memcmp(a.hs_c2s, b.hs_c2s, 4 * PQIOT_KEY_SZ) == 0);
    k[0] = a.hs_c2s; k[1] = a.hs_s2c; k[2] = a.c2s; k[3] = a.s2c;
    for (i = 0; i < 4; i++)                  /* separated */
        for (j = i + 1; j < 4; j++)
            assert(memcmp(k[i], k[j], PQIOT_KEY_SZ) != 0);

    /* tx/rx are keyed from the right raw key for the role and phase: what
     * the server sends, the device receives, and each matches the raw key. */
    assert(seals_under(&a.tx, a.hs_s2c) && seals_under(&a.rx, a.hs_c2s));
    assert(seals_under(&b.tx, b.hs_c2s) && seals_under(&b.rx, b.hs_s2c));
    assert(pqiot_keys_phase(&a, PQIOT_PHASE_DATA) == 0);
    assert(pqiot_keys_phase(&b, PQIOT_PHASE_DATA) == 0);
    assert(seals_under(&a.tx, a.s2c) && seals_under(&a.rx, a.c2s));
    assert(seals_under(&b.tx, b.c2s) && seals_under(&b.rx, b.s2c));

    /* Freeing wipes the keys. */
    pqiot_keys_free(&b);
    for (i = 0; i < PQIOT_KEY_SZ; i++)
        assert(b.c2s[i] == 0);
    pqiot_keys_free(&a);

    /* A wrong-sized secret must be refused, not silently padded. */
    assert(pqiot_derive_keys(ss, sizeof(ss) - 1, 1, &a) != 0);

    printf("ok  key derivation (HKDF-SHA256, directions and phases separated)\n");
}

static void test_aead_roundtrip(void)
{
    static const char msg[] = "sensor=temp value=23.4C";
    uint8_t key[PQIOT_KEY_SZ];
    Aes aes;
    uint8_t sealed[256], out[256];
    size_t slen, olen;

    memset(key, 0x42, sizeof(key));
    assert(pqiot_aead_init(&aes, key) == 0);
    assert(pqiot_seal(&aes, (const uint8_t *)msg, strlen(msg),
                      sealed, sizeof(sealed), &slen) == 0);
    assert(slen == strlen(msg) + PQIOT_AEAD_OVERHEAD);

    /* The plaintext must not survive anywhere in the sealed frame. */
    assert(memmem(sealed, slen, msg, strlen(msg)) == NULL);

    assert(pqiot_open(&aes, sealed, slen, out, sizeof(out), &olen) == 0);
    assert(olen == strlen(msg) && memcmp(out, msg, olen) == 0);
    wc_AesFree(&aes);

    printf("ok  aead roundtrip (AES-256-GCM)\n");
}

static void test_aead_rejects_tampering(void)
{
    static const char msg[] = "open the door";
    uint8_t key[PQIOT_KEY_SZ], wrong[PQIOT_KEY_SZ];
    Aes aes, aes_wrong;
    uint8_t sealed[256], out[256];
    size_t slen, olen;

    memset(key, 0x42, sizeof(key));
    memset(wrong, 0x43, sizeof(wrong));
    assert(pqiot_aead_init(&aes, key) == 0);
    assert(pqiot_aead_init(&aes_wrong, wrong) == 0);
    assert(pqiot_seal(&aes, (const uint8_t *)msg, strlen(msg),
                      sealed, sizeof(sealed), &slen) == 0);

    /* Flipped cipher text bit. */
    sealed[PQIOT_AEAD_OVERHEAD] ^= 0x01;
    assert(pqiot_open(&aes, sealed, slen, out, sizeof(out), &olen) != 0);
    sealed[PQIOT_AEAD_OVERHEAD] ^= 0x01;

    /* Flipped tag bit. */
    sealed[PQIOT_IV_SZ] ^= 0x80;
    assert(pqiot_open(&aes, sealed, slen, out, sizeof(out), &olen) != 0);
    sealed[PQIOT_IV_SZ] ^= 0x80;

    /* Wrong key. */
    assert(pqiot_open(&aes_wrong, sealed, slen, out, sizeof(out), &olen) != 0);

    /* Truncated below the IV+tag header: must not underflow the length. */
    assert(pqiot_open(&aes, sealed, PQIOT_AEAD_OVERHEAD - 1,
                      out, sizeof(out), &olen) != 0);

    /* Output buffer too small for the plaintext. */
    assert(pqiot_open(&aes, sealed, slen, out, 1, &olen) != 0);

    wc_AesFree(&aes);
    wc_AesFree(&aes_wrong);
    printf("ok  aead rejects tampering, wrong key, truncation\n");
}

static void test_framing(void)
{
    uint8_t body[PQIOT_MAX_BODY], got[PQIOT_MAX_BODY];
    uint8_t type;
    size_t len;
    int sv[2];

    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);

    memset(body, 0x7e, sizeof(body));
    assert(pqiot_send(sv[0], PQIOT_MSG_KEMCT, body, PQIOT_KEMCT_SZ) == 0);
    assert(pqiot_recv(sv[1], &type, got, sizeof(got), &len) == 0);
    assert(type == PQIOT_MSG_KEMCT && len == PQIOT_KEMCT_SZ);
    assert(memcmp(got, body, len) == 0);

    /* Oversized body is refused before it reaches the socket. */
    assert(pqiot_send(sv[0], PQIOT_MSG_DATA, body, PQIOT_MAX_BODY + 1) != 0);

    /* A frame larger than the receiver's buffer must be rejected, not
     * allowed to overflow it. */
    assert(pqiot_send(sv[0], PQIOT_MSG_DATA, body, 512) == 0);
    assert(pqiot_recv(sv[1], &type, got, 64, &len) != 0);

    /* Garbage magic is rejected. */
    assert(write(sv[0], "XXXX\x03\x01\x00\x00", 8) == 8);
    assert(pqiot_recv(sv[1], &type, got, sizeof(got), &len) != 0);

    /* Sealed frames: the body on the wire is not the plaintext, and it
     * only opens under the right key and as the right type. Fresh pair:
     * the rejections above deliberately left bytes unread in the old one. */
    close(sv[0]);
    close(sv[1]);
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
    {
        static const char secret[] = "CN=device-0001.pqiot.test";
        uint8_t key[PQIOT_KEY_SZ], wrong[PQIOT_KEY_SZ];

        Aes aes, aes_wrong;

        memset(key, 0x11, sizeof(key));
        memset(wrong, 0x22, sizeof(wrong));
        assert(pqiot_aead_init(&aes, key) == 0);
        assert(pqiot_aead_init(&aes_wrong, wrong) == 0);

        assert(pqiot_send_sealed(sv[0], &aes, PQIOT_MSG_CERT,
                                 (const uint8_t *)secret, strlen(secret)) == 0);
        assert(pqiot_recv(sv[1], &type, got, sizeof(got), &len) == 0);
        assert(type == PQIOT_MSG_CERT && len == strlen(secret) + PQIOT_AEAD_OVERHEAD);
        assert(memmem(got, len, secret, strlen(secret)) == NULL);

        assert(pqiot_send_sealed(sv[0], &aes, PQIOT_MSG_CERT,
                                 (const uint8_t *)secret, strlen(secret)) == 0);
        assert(pqiot_recv_sealed(sv[1], &aes, PQIOT_MSG_CERT,
                                 got, sizeof(got), &len) == 0);
        assert(len == strlen(secret) && memcmp(got, secret, len) == 0);

        assert(pqiot_send_sealed(sv[0], &aes, PQIOT_MSG_CERT,
                                 (const uint8_t *)secret, strlen(secret)) == 0);
        assert(pqiot_recv_sealed(sv[1], &aes_wrong, PQIOT_MSG_CERT,
                                 got, sizeof(got), &len) != 0);

        assert(pqiot_send_sealed(sv[0], &aes, PQIOT_MSG_CERT,
                                 (const uint8_t *)secret, strlen(secret)) == 0);
        assert(pqiot_recv_sealed(sv[1], &aes, PQIOT_MSG_VERIFY,
                                 got, sizeof(got), &len) != 0);
        wc_AesFree(&aes);
        wc_AesFree(&aes_wrong);
    }

    close(sv[0]);
    close(sv[1]);
    printf("ok  framing (roundtrip, bounds, bad magic, sealed frames)\n");
}

/* A PEM certificate file as DER, as it would arrive in a CERT message. */
static size_t cert_der(const char *path, uint8_t *der, size_t cap)
{
    uint8_t pem[16384];
    FILE *f = fopen(path, "rb");
    size_t n;
    int len;

    assert(f != NULL);
    n = fread(pem, 1, sizeof(pem), f);
    fclose(f);
    len = wc_CertPemToDer(pem, (int)n, der, (int)cap, CERT_TYPE);
    assert(len > 0);
    return (size_t)len;
}

/* Run one handshake transcript through sign/verify, then show that every
 * way of getting it wrong is refused. */
static void test_auth(void)
{
    static const uint8_t kem_pub[] = "stand-in for PUBKEY";
    static const uint8_t kem_ct[]  = "stand-in for KEMCT";
    pqiot_identity server, device, rogue;
    wc_Sha256 th, other;
    uint8_t sig[PQIOT_SIG_SZ], dsig[PQIOT_SIG_SZ], ecdsa[PQIOT_MAX_BODY];
    size_t siglen, dsiglen, ecdsa_len;
    char cn[256];

    assert(pqiot_identity_load(&server, PKI_SERVER_CERT_FILE, PKI_SERVER_KEY_FILE,
                               PKI_CA_FILE) == 0);
    assert(pqiot_identity_load(&device, PKI_DEVICE_CERT_FILE, PKI_DEVICE_KEY_FILE,
                               PKI_CA_FILE) == 0);
    assert(pqiot_identity_load(&rogue, "build/certs/bad/rogue.pem",
                               "build/certs/bad/rogue.key", PKI_CA_FILE) == 0);
    /* An ECDSA key is not an identity we can even load. */
    assert(pqiot_identity_load(&(pqiot_identity){0}, "build/certs/bad/ecdsa-srv.pem",
                               "build/certs/bad/ecdsa-srv.key", PKI_CA_FILE) != 0);

    assert(wc_InitSha256(&th) == 0);
    assert(pqiot_transcript_add(&th, PQIOT_MSG_PUBKEY, kem_pub, sizeof(kem_pub)) == 0);
    assert(pqiot_transcript_add(&th, PQIOT_MSG_KEMCT, kem_ct, sizeof(kem_ct)) == 0);
    assert(pqiot_transcript_add(&th, PQIOT_MSG_CERT, server.cert, server.cert_len) == 0);
    assert(pqiot_auth_sign(&server, &th, PQIOT_ROLE_SERVER, sig, &siglen) == 0);
    assert(siglen == PQIOT_SIG_SZ);

    /* The genuine server, as the device sees it. */
    assert(pqiot_auth_verify(&server, server.cert, server.cert_len,
                             PKI_SERVER_NAME, &th, PQIOT_ROLE_SERVER,
                             sig, siglen, cn, sizeof(cn)) == 0);
    assert(strcmp(cn, PKI_SERVER_NAME) == 0);

    /* A different transcript -- e.g. a man in the middle swapped the KEM
     * cipher text -- must not verify. */
    assert(wc_InitSha256(&other) == 0);
    assert(pqiot_transcript_add(&other, PQIOT_MSG_PUBKEY, kem_pub, sizeof(kem_pub)) == 0);
    assert(pqiot_transcript_add(&other, PQIOT_MSG_KEMCT, kem_pub, sizeof(kem_pub)) == 0);
    assert(pqiot_transcript_add(&other, PQIOT_MSG_CERT, server.cert, server.cert_len) == 0);
    assert(pqiot_auth_verify(&server, server.cert, server.cert_len,
                             PKI_SERVER_NAME, &other, PQIOT_ROLE_SERVER,
                             sig, siglen, cn, sizeof(cn)) != 0);

    /* The server's signature replayed as if it were a device's. */
    assert(pqiot_auth_verify(&server, server.cert, server.cert_len, NULL,
                             &th, PQIOT_ROLE_DEVICE, sig, siglen,
                             cn, sizeof(cn)) != 0);

    /* One flipped bit in the signature. */
    sig[100] ^= 0x01;
    assert(pqiot_auth_verify(&server, server.cert, server.cert_len,
                             PKI_SERVER_NAME, &th, PQIOT_ROLE_SERVER,
                             sig, siglen, cn, sizeof(cn)) != 0);
    sig[100] ^= 0x01;

    /* A genuine device posing as the server: valid CA, valid signature,
     * wrong name. */
    assert(pqiot_auth_sign(&device, &th, PQIOT_ROLE_SERVER, dsig, &dsiglen) == 0);
    assert(pqiot_auth_verify(&server, device.cert, device.cert_len,
                             PKI_SERVER_NAME, &th, PQIOT_ROLE_SERVER,
                             dsig, dsiglen, cn, sizeof(cn)) != 0);

    /* The genuine device, as the server sees it (any CN from the CA). */
    assert(pqiot_auth_sign(&device, &th, PQIOT_ROLE_DEVICE, dsig, &dsiglen) == 0);
    assert(pqiot_auth_verify(&server, device.cert, device.cert_len, NULL,
                             &th, PQIOT_ROLE_DEVICE, dsig, dsiglen,
                             cn, sizeof(cn)) == 0);
    assert(strcmp(cn, "device-0001.pqiot.test") == 0);

    /* Right name, valid signature, but the certificate is from another CA. */
    assert(pqiot_auth_sign(&rogue, &th, PQIOT_ROLE_SERVER, sig, &siglen) == 0);
    assert(pqiot_auth_verify(&server, rogue.cert, rogue.cert_len,
                             PKI_SERVER_NAME, &th, PQIOT_ROLE_SERVER,
                             sig, siglen, cn, sizeof(cn)) != 0);

    /* Our own CA, right name, but a classical (ECDSA) key. */
    ecdsa_len = cert_der("build/certs/bad/ecdsa-srv.pem", ecdsa, sizeof(ecdsa));
    assert(pqiot_auth_sign(&server, &th, PQIOT_ROLE_SERVER, sig, &siglen) == 0);
    assert(pqiot_auth_verify(&server, ecdsa, ecdsa_len, PKI_SERVER_NAME,
                             &th, PQIOT_ROLE_SERVER, sig, siglen,
                             cn, sizeof(cn)) != 0);

    /* Truncated certificate. */
    assert(pqiot_auth_verify(&server, server.cert, server.cert_len / 2,
                             PKI_SERVER_NAME, &th, PQIOT_ROLE_SERVER,
                             sig, siglen, cn, sizeof(cn)) != 0);

    wc_Sha256Free(&th);
    wc_Sha256Free(&other);
    pqiot_identity_free(&server);
    pqiot_identity_free(&device);
    pqiot_identity_free(&rogue);
    printf("ok  auth (ML-DSA-65: transcript, role, name, CA, key type, tampering)\n");
}

int main(void)
{
    assert(pqiot_rng() != NULL);

    test_kem_agreement();
    test_key_derivation();
    test_aead_roundtrip();
    test_aead_rejects_tampering();
    test_framing();
    test_auth();

    printf("\nall self-checks passed\n");
    return 0;
}
