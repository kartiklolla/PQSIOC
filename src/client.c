/* PQIOT client -- stands in for the constrained IoT device. Encapsulates
 * against the server's ML-KEM public key, checks the server's ML-DSA-65
 * signature and name, proves its own identity the same way, then sends
 * encrypted telemetry.
 *
 *   ./pqiot-client [host] [port] [message]
 */
#include "pqiot.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int connect_to(const char *host, uint16_t port)
{
    struct sockaddr_in addr;
    int fd;

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(port);
    if (inet_pton(AF_INET, host, &addr.sin_addr) != 1)
        return -1;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
        return -1;

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

/* Steps 3-4: the server proves it is PKI_SERVER_NAME. Then 5-6: we prove
 * who we are, over the same transcript. 0 on success. */
static int authenticate(int fd, pqiot_identity *id, wc_Sha256 *th)
{
    uint8_t cert[PQIOT_MAX_BODY], sig[PQIOT_SIG_SZ];
    size_t cert_len, siglen;
    char cn[256];
    uint8_t type;

    if (pqiot_recv(fd, &type, cert, sizeof(cert), &cert_len) != 0 ||
        type != PQIOT_MSG_CERT ||
        pqiot_transcript_add(th, type, cert, cert_len) != 0) {
        fprintf(stderr, "client: expected server CERT\n");
        return -1;
    }
    if (pqiot_recv(fd, &type, sig, sizeof(sig), &siglen) != 0 ||
        type != PQIOT_MSG_VERIFY) {
        fprintf(stderr, "client: expected server VERIFY\n");
        return -1;
    }
    if (pqiot_auth_verify(PKI_CA_FILE, cert, cert_len, PKI_SERVER_NAME, th,
                          PQIOT_ROLE_SERVER, sig, siglen,
                          cn, sizeof(cn)) != 0) {
        fprintf(stderr, "client: server authentication failed%s%s\n",
                cn[0] ? " for CN=" : "", cn);
        return -1;
    }
    printf("[device] <- CERT, VERIFY: server authenticated: CN=%s (ML-DSA-65)\n",
           cn);

    if (pqiot_transcript_add(th, PQIOT_MSG_VERIFY, sig, siglen) != 0 ||
        pqiot_send(fd, PQIOT_MSG_CERT, id->cert, id->cert_len) != 0 ||
        pqiot_transcript_add(th, PQIOT_MSG_CERT, id->cert, id->cert_len) != 0 ||
        pqiot_auth_sign(id, th, PQIOT_ROLE_DEVICE, sig, &siglen) != 0 ||
        pqiot_send(fd, PQIOT_MSG_VERIFY, sig, siglen) != 0) {
        fprintf(stderr, "client: sending our CERT/VERIFY failed\n");
        return -1;
    }
    printf("[device] -> CERT     %zu bytes, VERIFY %zu bytes (ML-DSA-65)\n",
           id->cert_len, siglen);
    return 0;
}

static int run(int fd, const char *msg, pqiot_identity *id)
{
    MlKemKey kem;
    wc_Sha256 th;
    uint8_t pub[PQIOT_MAX_BODY];
    uint8_t ct[PQIOT_KEMCT_SZ];
    uint8_t ss[PQIOT_SS_SZ];
    uint8_t frame[PQIOT_MAX_BODY];
    uint8_t pt[PQIOT_MAX_BODY];
    pqiot_keys keys;
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

    if (pqiot_derive_keys(ss, sizeof(ss), &keys) != 0) {
        fprintf(stderr, "client: key derivation failed\n");
        goto out;
    }
    printf("[device] shared secret established, AES-256 keys derived\n");

    /* No telemetry leaves before the server has proven who it is. */
    if (authenticate(fd, id, &th) != 0)
        goto out;

    /* 7. Encrypt the payload under the KEM-derived key and ship it. */
    if (pqiot_seal(keys.c2s, (const uint8_t *)msg, strlen(msg),
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
    if (pqiot_open(keys.s2c, frame, len, pt, sizeof(pt) - 1, &ptlen) != 0) {
        fprintf(stderr, "client: decryption/auth failed\n");
        goto out;
    }
    pt[ptlen] = '\0';
    printf("[device] <- DATA     %zu bytes -> decrypted: \"%s\"\n", len, pt);

    rc = 0;
out:
    wc_MlKemKey_Free(&kem);
    wc_Sha256Free(&th);
    return rc;
}

int main(int argc, char **argv)
{
    const char *host = (argc > 1) ? argv[1] : "127.0.0.1";
    uint16_t    port = (argc > 2) ? (uint16_t)atoi(argv[2]) : PQIOT_DEFAULT_PORT;
    const char *msg  = (argc > 3) ? argv[3] : "sensor=temp value=23.4C";
    pqiot_identity id;
    int fd, rc;

    if (pqiot_rng() == NULL) {
        fprintf(stderr, "client: RNG seeding failed\n");
        return 1;
    }

    if (pqiot_identity_load(&id, PKI_DEVICE_CERT_FILE, PKI_DEVICE_KEY_FILE) != 0) {
        fprintf(stderr, "client: cannot load %s / %s "
                        "(run `make certs` from the repo root)\n",
                PKI_DEVICE_CERT_FILE, PKI_DEVICE_KEY_FILE);
        return 1;
    }

    fd = connect_to(host, port);
    if (fd < 0) {
        perror("client: connect");
        pqiot_identity_free(&id);
        return 1;
    }
    printf("[device] connected to %s:%u\n", host, port);

    rc = run(fd, msg, &id);
    close(fd);
    pqiot_identity_free(&id);

    printf("[device] %s\n", rc == 0 ? "session OK" : "session FAILED");
    return rc == 0 ? 0 : 1;
}
