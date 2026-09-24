/* PQIOT client -- stands in for the constrained IoT device. Encapsulates
 * against the server's ML-KEM public key, checks the server's ML-DSA-65
 * signature and name, proves its own identity the same way, then sends
 * encrypted telemetry. The protocol itself is in session.c; this is the
 * TCP front end.
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

    if (pqiot_identity_load(&id, PKI_DEVICE_CERT_FILE, PKI_DEVICE_KEY_FILE,
                            PKI_CA_FILE) != 0) {
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

    rc = pqiot_device_session(fd, msg, &id);
    close(fd);
    pqiot_identity_free(&id);

    printf("[device] %s\n", rc == 0 ? "session OK" : "session FAILED");
    return rc == 0 ? 0 : 1;
}
