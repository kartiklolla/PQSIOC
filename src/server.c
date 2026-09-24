/* PQIOT server: owns the ML-KEM key pair, decapsulates, decrypts.
 * Authenticates itself and the device with ML-DSA-65; accepts any device
 * holding a certificate from the demo CA. The protocol itself is in
 * session.c; this is the TCP front end.
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

    if (pqiot_identity_load(&id, PKI_SERVER_CERT_FILE, PKI_SERVER_KEY_FILE,
                            PKI_CA_FILE) != 0) {
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

    rc = pqiot_server_session(cfd, &id);
    close(cfd);
    close(lfd);
    pqiot_identity_free(&id);

    printf("[server] %s\n", rc == 0 ? "session OK" : "session FAILED");
    return rc == 0 ? 0 : 1;
}
