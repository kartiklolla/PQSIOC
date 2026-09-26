/* One PQIOT/2 session per role, from the ML-KEM exchange through
 * authentication to the DATA round trip. Transport-agnostic: all I/O goes
 * through pqiot_send/recv, so the same code runs over a TCP socket (server.c,
 * client.c) and over in-memory pipes on bare-metal RISC-V (firmware/). */
#include "pqiot.h"

#include <stdio.h>
#include <string.h>

#include <wolfssl/wolfcrypt/memory.h>

/* ---- server ------------------------------------------------------------ */

/* Steps 3-4: prove we are the server. Then 5-6: make the device prove who
 * it is, over the same transcript. All four travel sealed under the
 * handshake keys; the transcript hashes their plaintext. 0 on success. */
static int server_authenticate(int fd, pqiot_identity *id, wc_Sha256 *th,
                               pqiot_keys *keys)
{
    uint8_t cert[PQIOT_MAX_BODY], sig[PQIOT_SIG_SZ];
    size_t cert_len, siglen;
    char cn[256];

    if (pqiot_send_sealed(fd, &keys->tx, PQIOT_MSG_CERT,
                          id->cert, id->cert_len) != 0 ||
        pqiot_transcript_add(th, PQIOT_MSG_CERT, id->cert, id->cert_len) != 0 ||
        pqiot_auth_sign(id, th, PQIOT_ROLE_SERVER, sig, &siglen) != 0 ||
        pqiot_send_sealed(fd, &keys->tx, PQIOT_MSG_VERIFY, sig, siglen) != 0 ||
        pqiot_transcript_add(th, PQIOT_MSG_VERIFY, sig, siglen) != 0) {
        fprintf(stderr, "server: sending our CERT/VERIFY failed\n");
        return -1;
    }
    printf("[server] -> CERT     %zu bytes, VERIFY %zu bytes (ML-DSA-65, sealed)\n",
           id->cert_len, siglen);

    if (pqiot_recv_sealed(fd, &keys->rx, PQIOT_MSG_CERT,
                          cert, sizeof(cert), &cert_len) != 0 ||
        pqiot_transcript_add(th, PQIOT_MSG_CERT, cert, cert_len) != 0) {
        fprintf(stderr, "server: expected sealed device CERT\n");
        return -1;
    }
    if (pqiot_recv_sealed(fd, &keys->rx, PQIOT_MSG_VERIFY,
                          sig, sizeof(sig), &siglen) != 0) {
        fprintf(stderr, "server: expected sealed device VERIFY\n");
        return -1;
    }
    if (pqiot_auth_verify(id, cert, cert_len, NULL, th,
                          PQIOT_ROLE_DEVICE, sig, siglen,
                          cn, sizeof(cn)) != 0) {
        fprintf(stderr, "server: device authentication failed%s%s\n",
                cn[0] ? " for CN=" : "", cn);
        return -1;
    }
    printf("[server] <- CERT, VERIFY: device authenticated: CN=%s (ML-DSA-65)\n",
           cn);
    return 0;
}

/* Runs the whole PQIOT exchange on an accepted connection. 0 on success. */
int pqiot_server_session(int fd, pqiot_identity *id)
{
    MlKemKey kem;
    wc_Sha256 th;
    uint8_t pub[PQIOT_PUBKEY_SZ];
    uint8_t ct[PQIOT_MAX_BODY];
    uint8_t ss[PQIOT_SS_SZ];
    uint8_t frame[PQIOT_MAX_BODY];
    uint8_t pt[PQIOT_MAX_BODY];
    pqiot_keys keys;
    int keyed = 0;
    size_t len, ptlen;
    uint8_t type;
    int rc = -1;

    if (wc_InitSha256(&th) != 0)
        return -1;

    if (wc_MlKemKey_Init(&kem, PQIOT_MLKEM_LEVEL, NULL, INVALID_DEVID) != 0) {
        fprintf(stderr, "server: ML-KEM init failed\n");
        return -1;
    }

    /* 1. Fresh ML-KEM-768 key pair, then hand the public half to the device. */
    if (wc_MlKemKey_MakeKey(&kem, pqiot_rng()) != 0) {
        fprintf(stderr, "server: ML-KEM keygen failed\n");
        goto out;
    }
    if (wc_MlKemKey_EncodePublicKey(&kem, pub, sizeof(pub)) != 0) {
        fprintf(stderr, "server: public key encode failed\n");
        goto out;
    }
    if (pqiot_send(fd, PQIOT_MSG_PUBKEY, pub, sizeof(pub)) != 0 ||
        pqiot_transcript_add(&th, PQIOT_MSG_PUBKEY, pub, sizeof(pub)) != 0) {
        fprintf(stderr, "server: send PUBKEY failed\n");
        goto out;
    }
    printf("[server] -> PUBKEY   %zu bytes (ML-KEM-768 public key)\n",
           sizeof(pub));

    /* 2. Receive the encapsulation and recover the same shared secret. */
    if (pqiot_recv(fd, &type, ct, sizeof(ct), &len) != 0 ||
        type != PQIOT_MSG_KEMCT ||
        pqiot_transcript_add(&th, type, ct, len) != 0) {
        fprintf(stderr, "server: expected KEMCT\n");
        goto out;
    }
    printf("[server] <- KEMCT    %zu bytes (ML-KEM cipher text)\n", len);

    if (wc_MlKemKey_Decapsulate(&kem, ss, ct, (word32)len) != 0) {
        fprintf(stderr, "server: decapsulation failed\n");
        goto out;
    }
    if (pqiot_derive_keys(ss, sizeof(ss), 1, &keys) != 0) {
        fprintf(stderr, "server: key derivation failed\n");
        goto out;
    }
    keyed = 1;
    printf("[server] shared secret established, AES-256 keys derived\n");

    /* No DATA is read before the device has proven who it is. */
    if (server_authenticate(fd, id, &th, &keys) != 0)
        goto out;
    if (pqiot_keys_phase(&keys, PQIOT_PHASE_DATA) != 0) {
        fprintf(stderr, "server: data keys failed\n");
        goto out;
    }

    /* 7. Decrypt the device's payload under the KEM-derived key. */
    if (pqiot_recv(fd, &type, frame, sizeof(frame), &len) != 0 ||
        type != PQIOT_MSG_DATA) {
        fprintf(stderr, "server: expected DATA\n");
        goto out;
    }
    if (pqiot_open(&keys.rx, frame, len, pt, sizeof(pt) - 1, &ptlen) != 0) {
        fprintf(stderr, "server: decryption/auth failed\n");
        goto out;
    }
    pt[ptlen] = '\0';
    printf("[server] <- DATA     %zu bytes -> decrypted: \"%s\"\n", len, pt);

    /* 8. Reply on the other direction's key to prove both ways work. */
    {
        static const char reply[] = "ack: telemetry received";
        size_t sealed;

        if (pqiot_seal(&keys.tx, (const uint8_t *)reply, sizeof(reply) - 1,
                       frame, sizeof(frame), &sealed) != 0 ||
            pqiot_send(fd, PQIOT_MSG_DATA, frame, sealed) != 0) {
            fprintf(stderr, "server: reply failed\n");
            goto out;
        }
        printf("[server] -> DATA     %zu bytes (encrypted reply)\n", sealed);
    }

    rc = 0;
out:
    if (keyed)
        pqiot_keys_free(&keys);
    wc_ForceZero(ss, sizeof(ss));
    wc_MlKemKey_Free(&kem);
    wc_Sha256Free(&th);
    return rc;
}

/* ---- device ------------------------------------------------------------ */

/* Steps 3-4: the server proves it is PKI_SERVER_NAME. Then 5-6: we prove
 * who we are, over the same transcript. All four travel sealed under the
 * handshake keys; the transcript hashes their plaintext. Our CERT goes out
 * only after the server checks out, so our identity never reaches anyone
 * else. 0 on success. */
static int device_authenticate(int fd, pqiot_identity *id, wc_Sha256 *th,
                               pqiot_keys *keys)
{
    uint8_t cert[PQIOT_MAX_BODY], sig[PQIOT_SIG_SZ];
    size_t cert_len, siglen;
    char cn[256];

    if (pqiot_recv_sealed(fd, &keys->rx, PQIOT_MSG_CERT,
                          cert, sizeof(cert), &cert_len) != 0 ||
        pqiot_transcript_add(th, PQIOT_MSG_CERT, cert, cert_len) != 0) {
        fprintf(stderr, "client: expected sealed server CERT\n");
        return -1;
    }
    if (pqiot_recv_sealed(fd, &keys->rx, PQIOT_MSG_VERIFY,
                          sig, sizeof(sig), &siglen) != 0) {
        fprintf(stderr, "client: expected sealed server VERIFY\n");
        return -1;
    }
    if (pqiot_auth_verify(id, cert, cert_len, PKI_SERVER_NAME, th,
                          PQIOT_ROLE_SERVER, sig, siglen,
                          cn, sizeof(cn)) != 0) {
        fprintf(stderr, "client: server authentication failed%s%s\n",
                cn[0] ? " for CN=" : "", cn);
        return -1;
    }
    printf("[device] <- CERT, VERIFY: server authenticated: CN=%s (ML-DSA-65)\n",
           cn);

    if (pqiot_transcript_add(th, PQIOT_MSG_VERIFY, sig, siglen) != 0 ||
        pqiot_send_sealed(fd, &keys->tx, PQIOT_MSG_CERT,
                          id->cert, id->cert_len) != 0 ||
        pqiot_transcript_add(th, PQIOT_MSG_CERT, id->cert, id->cert_len) != 0 ||
        pqiot_auth_sign(id, th, PQIOT_ROLE_DEVICE, sig, &siglen) != 0 ||
        pqiot_send_sealed(fd, &keys->tx, PQIOT_MSG_VERIFY, sig, siglen) != 0) {
        fprintf(stderr, "client: sending our CERT/VERIFY failed\n");
        return -1;
    }
    printf("[device] -> CERT     %zu bytes, VERIFY %zu bytes (ML-DSA-65, sealed)\n",
           id->cert_len, siglen);
    return 0;
}

/* Runs the whole PQIOT exchange on a connected transport. 0 on success. */
int pqiot_device_session(int fd, const char *msg, pqiot_identity *id)
{
    MlKemKey kem;
    wc_Sha256 th;
    uint8_t pub[PQIOT_MAX_BODY];
    uint8_t ct[PQIOT_KEMCT_SZ];
    uint8_t ss[PQIOT_SS_SZ];
    uint8_t frame[PQIOT_MAX_BODY];
    uint8_t pt[PQIOT_MAX_BODY];
    pqiot_keys keys;
    int keyed = 0;
    size_t len, sealed, ptlen;
    uint8_t type;
    int rc = -1;

    if (wc_InitSha256(&th) != 0)
        return -1;

    if (wc_MlKemKey_Init(&kem, PQIOT_MLKEM_LEVEL, NULL, INVALID_DEVID) != 0) {
        fprintf(stderr, "client: ML-KEM init failed\n");
        return -1;
    }

    /* 1. Take the server's public key off the wire. */
    if (pqiot_recv(fd, &type, pub, sizeof(pub), &len) != 0 ||
        type != PQIOT_MSG_PUBKEY ||
        pqiot_transcript_add(&th, type, pub, len) != 0) {
        fprintf(stderr, "client: expected PUBKEY\n");
        goto out;
    }
    printf("[device] <- PUBKEY   %zu bytes (ML-KEM-768 public key)\n", len);

    if (wc_MlKemKey_DecodePublicKey(&kem, pub, (word32)len) != 0) {
        fprintf(stderr, "client: public key decode failed\n");
        goto out;
    }

    /* 2. Encapsulate: yields the cipher text for the peer and our copy of
     *    the shared secret. This is the post-quantum step. */
    if (wc_MlKemKey_Encapsulate(&kem, ct, ss, pqiot_rng()) != 0) {
        fprintf(stderr, "client: encapsulation failed\n");
        goto out;
    }
    if (pqiot_send(fd, PQIOT_MSG_KEMCT, ct, sizeof(ct)) != 0 ||
        pqiot_transcript_add(&th, PQIOT_MSG_KEMCT, ct, sizeof(ct)) != 0) {
        fprintf(stderr, "client: send KEMCT failed\n");
        goto out;
    }
    printf("[device] -> KEMCT    %zu bytes (ML-KEM cipher text)\n",
           sizeof(ct));

    if (pqiot_derive_keys(ss, sizeof(ss), 0, &keys) != 0) {
        fprintf(stderr, "client: key derivation failed\n");
        goto out;
    }
    keyed = 1;
    printf("[device] shared secret established, AES-256 keys derived\n");

    /* No telemetry leaves before the server has proven who it is. */
    if (device_authenticate(fd, id, &th, &keys) != 0)
        goto out;
    if (pqiot_keys_phase(&keys, PQIOT_PHASE_DATA) != 0) {
        fprintf(stderr, "client: data keys failed\n");
        goto out;
    }

    /* 7. Encrypt the payload under the KEM-derived key and ship it. */
    if (pqiot_seal(&keys.tx, (const uint8_t *)msg, strlen(msg),
                   frame, sizeof(frame), &sealed) != 0) {
        fprintf(stderr, "client: encryption failed\n");
        goto out;
    }
    if (pqiot_send(fd, PQIOT_MSG_DATA, frame, sealed) != 0) {
        fprintf(stderr, "client: send DATA failed\n");
        goto out;
    }
    printf("[device] -> DATA     %zu bytes, plaintext was \"%s\"\n",
           sealed, msg);

    /* 8. Read the server's encrypted acknowledgement. */
    if (pqiot_recv(fd, &type, frame, sizeof(frame), &len) != 0 ||
        type != PQIOT_MSG_DATA) {
        fprintf(stderr, "client: expected DATA reply\n");
        goto out;
    }
    if (pqiot_open(&keys.rx, frame, len, pt, sizeof(pt) - 1, &ptlen) != 0) {
        fprintf(stderr, "client: decryption/auth failed\n");
        goto out;
    }
    pt[ptlen] = '\0';
    printf("[device] <- DATA     %zu bytes -> decrypted: \"%s\"\n", len, pt);

    rc = 0;
out:
    if (keyed)
        pqiot_keys_free(&keys);
    wc_ForceZero(ss, sizeof(ss));
    wc_MlKemKey_Free(&kem);
    wc_Sha256Free(&th);
    return rc;
}
