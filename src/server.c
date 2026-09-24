/* PQIOT server: owns the ML-KEM key pair, decapsulates, decrypts.
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

/* Runs the whole PQIOT exchange on an accepted socket. 0 on success. */
static int serve(int fd)
{
    MlKemKey kem;
    uint8_t pub[PQIOT_PUBKEY_SZ];
    uint8_t ct[PQIOT_MAX_BODY];
    uint8_t ss[PQIOT_SS_SZ];
    uint8_t frame[PQIOT_MAX_BODY];
    uint8_t pt[PQIOT_MAX_BODY];
    pqiot_keys keys;
    size_t len, ptlen;
    uint8_t type;
    int rc = -1;

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
    if (pqiot_send(fd, PQIOT_MSG_PUBKEY, pub, sizeof(pub)) != 0) {
        fprintf(stderr, "server: send PUBKEY failed\n");
        goto out;
    }
    printf("[server] -> PUBKEY   %zu bytes (ML-KEM-768 public key)\n",
           sizeof(pub));

    /* 2. Receive the encapsulation and recover the same shared secret. */
    if (pqiot_recv(fd, &type, ct, sizeof(ct), &len) != 0 ||
        type != PQIOT_MSG_KEMCT) {
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

    /* 3. Decrypt the device's payload under the KEM-derived key. */
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

    /* 4. Reply on the other direction's key to prove both ways work. */
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
    return rc;
}

int main(int argc, char **argv)
{
    uint16_t port = PQIOT_DEFAULT_PORT;
    int lfd, cfd, rc;

    if (argc > 1)
        port = (uint16_t)atoi(argv[1]);

    if (pqiot_rng() == NULL) {
        fprintf(stderr, "server: RNG seeding failed\n");
        return 1;
    }

    lfd = listen_on(port);
    if (lfd < 0) {
        perror("server: listen");
        return 1;
    }
    printf("[server] listening on 127.0.0.1:%u\n", port);

    cfd = accept(lfd, NULL, NULL);
    if (cfd < 0) {
        perror("server: accept");
        close(lfd);
        return 1;
    }
    printf("[server] device connected\n");

    rc = serve(cfd);
    close(cfd);
    close(lfd);

    printf("[server] %s\n", rc == 0 ? "session OK" : "session FAILED");
    return rc == 0 ? 0 : 1;
}
