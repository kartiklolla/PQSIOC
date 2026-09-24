/* PQIOT server: owns the ML-KEM key pair, decapsulates, decrypts.
 * Authenticates itself and the device with ML-DSA-65; accepts any device
 * holding a certificate from the demo CA.
 *
 *   ./pqiot-server [port]
 */
#include "pqiot.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int listen_on(uint16_t port)
{
    struct sockaddr_in addr;
    int fd, yes = 1;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
        return -1;

    /* Otherwise a re-run inside TIME_WAIT fails to bind. */
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port        = htons(port);

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0 ||
        listen(fd, 1) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

/* Steps 3-4: prove we are the server. Then 5-6: make the device prove who
 * it is, over the same transcript. All four travel sealed under the
 * handshake keys; the transcript hashes their plaintext. 0 on success. */
static int authenticate(int fd, pqiot_identity *id, wc_Sha256 *th,
                        const pqiot_keys *keys)
{
    uint8_t cert[PQIOT_MAX_BODY], sig[PQIOT_SIG_SZ];
    size_t cert_len, siglen;
    char cn[256];

    if (pqiot_send_sealed(fd, keys->hs_s2c, PQIOT_MSG_CERT,
                          id->cert, id->cert_len) != 0 ||
        pqiot_transcript_add(th, PQIOT_MSG_CERT, id->cert, id->cert_len) != 0 ||
        pqiot_auth_sign(id, th, PQIOT_ROLE_SERVER, sig, &siglen) != 0 ||
        pqiot_send_sealed(fd, keys->hs_s2c, PQIOT_MSG_VERIFY, sig, siglen) != 0 ||
        pqiot_transcript_add(th, PQIOT_MSG_VERIFY, sig, siglen) != 0) {
        fprintf(stderr, "server: sending our CERT/VERIFY failed\n");
        return -1;
    }
    printf("[server] -> CERT     %zu bytes, VERIFY %zu bytes (ML-DSA-65, sealed)\n",
           id->cert_len, siglen);

    if (pqiot_recv_sealed(fd, keys->hs_c2s, PQIOT_MSG_CERT,
                          cert, sizeof(cert), &cert_len) != 0 ||
        pqiot_transcript_add(th, PQIOT_MSG_CERT, cert, cert_len) != 0) {
        fprintf(stderr, "server: expected sealed device CERT\n");
        return -1;
    }
    if (pqiot_recv_sealed(fd, keys->hs_c2s, PQIOT_MSG_VERIFY,
                          sig, sizeof(sig), &siglen) != 0) {
        fprintf(stderr, "server: expected sealed device VERIFY\n");
        return -1;
    }
    if (pqiot_auth_verify(PKI_CA_FILE, cert, cert_len, NULL, th,
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

/* Runs the whole PQIOT exchange on an accepted socket. 0 on success. */
static int serve(int fd, pqiot_identity *id)
{
    MlKemKey kem;
    wc_Sha256 th;
    uint8_t pub[PQIOT_PUBKEY_SZ];
    uint8_t ct[PQIOT_MAX_BODY];
    uint8_t ss[PQIOT_SS_SZ];
    uint8_t frame[PQIOT_MAX_BODY];
    uint8_t pt[PQIOT_MAX_BODY];
    pqiot_keys keys;
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
    if (pqiot_derive_keys(ss, sizeof(ss), &keys) != 0) {
        fprintf(stderr, "server: key derivation failed\n");
        goto out;
    }
    printf("[server] shared secret established, AES-256 keys derived\n");

    /* No DATA is read before the device has proven who it is. */
    if (authenticate(fd, id, &th, &keys) != 0)
        goto out;

    /* 7. Decrypt the device's payload under the KEM-derived key. */
    if (pqiot_recv(fd, &type, frame, sizeof(frame), &len) != 0 ||
        type != PQIOT_MSG_DATA) {
        fprintf(stderr, "server: expected DATA\n");
        goto out;
    }
    if (pqiot_open(keys.c2s, frame, len, pt, sizeof(pt) - 1, &ptlen) != 0) {
        fprintf(stderr, "server: decryption/auth failed\n");
        goto out;
    }
    pt[ptlen] = '\0';
    printf("[server] <- DATA     %zu bytes -> decrypted: \"%s\"\n", len, pt);

    /* 8. Reply on the other direction's key to prove both ways work. */
    {
        static const char reply[] = "ack: telemetry received";
        size_t sealed;

        if (pqiot_seal(keys.s2c, (const uint8_t *)reply, sizeof(reply) - 1,
                       frame, sizeof(frame), &sealed) != 0 ||
            pqiot_send(fd, PQIOT_MSG_DATA, frame, sealed) != 0) {
            fprintf(stderr, "server: reply failed\n");
            goto out;
        }
        printf("[server] -> DATA     %zu bytes (encrypted reply)\n", sealed);
    }

    rc = 0;
out:
    wc_MlKemKey_Free(&kem);
    wc_Sha256Free(&th);
    return rc;
}

int main(int argc, char **argv)
{
    uint16_t port = PQIOT_DEFAULT_PORT;
    pqiot_identity id;
    int lfd, cfd, rc;

    if (argc > 1)
        port = (uint16_t)atoi(argv[1]);

    if (pqiot_rng() == NULL) {
        fprintf(stderr, "server: RNG seeding failed\n");
        return 1;
    }

    if (pqiot_identity_load(&id, PKI_SERVER_CERT_FILE, PKI_SERVER_KEY_FILE) != 0) {
        fprintf(stderr, "server: cannot load %s / %s "
                        "(run `make certs` from the repo root)\n",
                PKI_SERVER_CERT_FILE, PKI_SERVER_KEY_FILE);
        return 1;
    }

    lfd = listen_on(port);
    if (lfd < 0) {
        perror("server: listen");
        pqiot_identity_free(&id);
        return 1;
    }
    printf("[server] listening on 127.0.0.1:%u\n", port);

    cfd = accept(lfd, NULL, NULL);
    if (cfd < 0) {
        perror("server: accept");
        close(lfd);
        pqiot_identity_free(&id);
        return 1;
    }
    printf("[server] device connected\n");

    rc = serve(cfd, &id);
    close(cfd);
    close(lfd);
    pqiot_identity_free(&id);

    printf("[server] %s\n", rc == 0 ? "session OK" : "session FAILED");
    return rc == 0 ? 0 : 1;
}
