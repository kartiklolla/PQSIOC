/* Self-check for the PQIOT primitives. Fails loudly if any of the crypto or
 * the frame parser regresses. Run with `make check`. */
#include "pqiot.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>
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

/* Same secret in => same keys out, and the two directions must differ. */
static void test_key_derivation(void)
{
    uint8_t ss[PQIOT_SS_SZ];
    pqiot_keys a, b;

    memset(ss, 0xA5, sizeof(ss));
    assert(pqiot_derive_keys(ss, sizeof(ss), &a) == 0);
    assert(pqiot_derive_keys(ss, sizeof(ss), &b) == 0);

    assert(memcmp(a.c2s, b.c2s, PQIOT_KEY_SZ) == 0); /* deterministic */
    assert(memcmp(a.s2c, b.s2c, PQIOT_KEY_SZ) == 0);
    assert(memcmp(a.c2s, a.s2c, PQIOT_KEY_SZ) != 0); /* separated */

    /* A wrong-sized secret must be refused, not silently padded. */
    assert(pqiot_derive_keys(ss, sizeof(ss) - 1, &a) != 0);

    printf("ok  key derivation (HKDF-SHA256, directions separated)\n");
}

static void test_aead_roundtrip(void)
{
    static const char msg[] = "sensor=temp value=23.4C";
    uint8_t key[PQIOT_KEY_SZ];
    uint8_t sealed[256], out[256];
    size_t slen, olen;

    memset(key, 0x42, sizeof(key));
    assert(pqiot_seal(key, (const uint8_t *)msg, strlen(msg),
                      sealed, sizeof(sealed), &slen) == 0);
    assert(slen == strlen(msg) + PQIOT_AEAD_OVERHEAD);

    /* The plaintext must not survive anywhere in the sealed frame. */
    assert(memmem(sealed, slen, msg, strlen(msg)) == NULL);

    assert(pqiot_open(key, sealed, slen, out, sizeof(out), &olen) == 0);
    assert(olen == strlen(msg) && memcmp(out, msg, olen) == 0);

    printf("ok  aead roundtrip (AES-256-GCM)\n");
}

static void test_aead_rejects_tampering(void)
{
    static const char msg[] = "open the door";
    uint8_t key[PQIOT_KEY_SZ], wrong[PQIOT_KEY_SZ];
    uint8_t sealed[256], out[256];
    size_t slen, olen;

    memset(key, 0x42, sizeof(key));
    memset(wrong, 0x43, sizeof(wrong));
    assert(pqiot_seal(key, (const uint8_t *)msg, strlen(msg),
                      sealed, sizeof(sealed), &slen) == 0);

    /* Flipped cipher text bit. */
    sealed[PQIOT_AEAD_OVERHEAD] ^= 0x01;
    assert(pqiot_open(key, sealed, slen, out, sizeof(out), &olen) != 0);
    sealed[PQIOT_AEAD_OVERHEAD] ^= 0x01;

    /* Flipped tag bit. */
    sealed[PQIOT_IV_SZ] ^= 0x80;
    assert(pqiot_open(key, sealed, slen, out, sizeof(out), &olen) != 0);
    sealed[PQIOT_IV_SZ] ^= 0x80;

    /* Wrong key. */
    assert(pqiot_open(wrong, sealed, slen, out, sizeof(out), &olen) != 0);

    /* Truncated below the IV+tag header: must not underflow the length. */
    assert(pqiot_open(key, sealed, PQIOT_AEAD_OVERHEAD - 1,
                      out, sizeof(out), &olen) != 0);

    /* Output buffer too small for the plaintext. */
    assert(pqiot_open(key, sealed, slen, out, 1, &olen) != 0);

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

    close(sv[0]);
    close(sv[1]);
    printf("ok  framing (roundtrip, bounds, bad magic rejected)\n");
}

int main(void)
{
    assert(pqiot_rng() != NULL);

    test_kem_agreement();
    test_key_derivation();
    test_aead_roundtrip();
    test_aead_rejects_tampering();
    test_framing();

    printf("\nall self-checks passed\n");
    return 0;
}
