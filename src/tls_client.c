/* PQTLS client -- the IoT device, over TLS 1.3 or DTLS 1.3 with the
 * X25519MLKEM768 hybrid group. Presents its own ML-DSA-65 certificate and
 * verifies the server's against the demo CA.
 *
 *   ./pqtls-client [--dtls] [host] [port] [message]
 */
#include "pqtls.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static double now_ms(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1e3 + ts.tv_nsec / 1e6;
}

int main(int argc, char **argv)
{
    struct sockaddr_in addr;
    WOLFSSL_CTX *ctx = NULL;
    WOLFSSL *ssl = NULL;
    const char *host, *msg;
    uint16_t port;
    char buf[1024];
    int dtls = 0, fd = -1, ret, rc = 1;
    double t0, t1;

    if (argc > 1 && strcmp(argv[1], "--dtls") == 0) {
        dtls = 1;
        argc--, argv++;
    }
    host = (argc > 1) ? argv[1] : "127.0.0.1";
    port = (argc > 2) ? (uint16_t)atoi(argv[2]) : PQTLS_DEFAULT_PORT;
    msg  = (argc > 3) ? argv[3] : "sensor=temp value=23.4C";

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(port);
    if (inet_pton(AF_INET, host, &addr.sin_addr) != 1) {
        fprintf(stderr, "client: bad address %s\n", host);
        return 1;
    }

    wolfSSL_Init();
    ctx = pqtls_ctx_new(dtls ? wolfDTLSv1_3_client_method()
                             : wolfTLSv1_3_client_method(),
                        PKI_DEVICE_CERT_FILE, PKI_DEVICE_KEY_FILE, "client");
    if (ctx == NULL)
        goto out;

    /* connect() on UDP just fixes the peer; nothing goes on the wire. */
    fd = socket(AF_INET, dtls ? SOCK_DGRAM : SOCK_STREAM, 0);
    if (fd < 0 || connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        perror("client: connect");
        goto out;
    }
    printf("[device] connected to %s:%u (%s)\n", host, port,
           dtls ? "UDP, DTLS 1.3" : "TCP, TLS 1.3");

    ssl = wolfSSL_new(ctx);
    if (ssl == NULL || wolfSSL_set_fd(ssl, fd) != WOLFSSL_SUCCESS ||
        (dtls && wolfSSL_dtls_set_peer(ssl, &addr, sizeof(addr)) != WOLFSSL_SUCCESS) ||
        /* Send the hybrid key share in the first flight, so the handshake
         * needs no HelloRetryRequest round trip. */
        wolfSSL_UseKeyShare(ssl, PQTLS_GROUP) != WOLFSSL_SUCCESS ||
        wolfSSL_check_domain_name(ssl, PKI_SERVER_NAME) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "client: session setup failed\n");
        goto out;
    }

    /* Timed for tools/bench.sh: the whole handshake, both flights and
     * mutual ML-DSA authentication, as the device experiences it. */
    t0 = now_ms();
    ret = wolfSSL_connect(ssl);
    t1 = now_ms();
    if (ret != WOLFSSL_SUCCESS) {
        pqtls_error(ssl, ret, "client", "handshake");
        goto out;
    }
    pqtls_report(ssl, "device");
    printf("[device] handshake took %.3f ms\n", t1 - t0);
    if (pqtls_check_peer(ssl, "device") != 0)
        goto out;

    ret = wolfSSL_write(ssl, msg, (int)strlen(msg));
    if (ret != (int)strlen(msg)) {
        pqtls_error(ssl, ret, "client", "write");
        goto out;
    }
    printf("[device] -> %d bytes, plaintext was \"%s\"\n", ret, msg);

    ret = wolfSSL_read(ssl, buf, sizeof(buf) - 1);
    if (ret <= 0) {
        pqtls_error(ssl, ret, "client", "read");
        goto out;
    }
    buf[ret] = '\0';
    printf("[device] <- %d bytes -> decrypted: \"%s\"\n", ret, buf);

    wolfSSL_shutdown(ssl);
    rc = 0;
out:
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
    if (fd >= 0)
        close(fd);
    wolfSSL_Cleanup();
    printf("[device] %s\n", rc == 0 ? "session OK" : "session FAILED");
    return rc;
}
