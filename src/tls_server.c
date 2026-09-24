/* PQTLS server: TLS 1.3 or DTLS 1.3 with the X25519MLKEM768 hybrid group.
 * Serves one device session, then exits.
 *
 *   ./pqtls-server [--dtls] [port]
 */
#include "pqtls.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/* TCP: listen and accept one connection. UDP: bind, wait for the first
 * datagram, then connect() the socket to its sender so the rest of the
 * session only ever talks to that one peer. Returns the session fd. */
static int accept_one(uint16_t port, int dtls, struct sockaddr_in *peer)
{
    struct sockaddr_in addr;
    socklen_t plen = sizeof(*peer);
    int fd, cfd, yes = 1;
    char probe;

    fd = socket(AF_INET, dtls ? SOCK_DGRAM : SOCK_STREAM, 0);
    if (fd < 0)
        return -1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port        = htons(port);
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0)
        goto fail;
    printf("[server] listening on 127.0.0.1:%u (%s)\n", port,
           dtls ? "UDP, DTLS 1.3" : "TCP, TLS 1.3");

    if (!dtls) {
        if (listen(fd, 1) != 0)
            goto fail;
        cfd = accept(fd, (struct sockaddr *)peer, &plen);
        close(fd);
        return cfd;
    }

    /* MSG_PEEK leaves the ClientHello queued for wolfSSL to read. */
    if (recvfrom(fd, &probe, 1, MSG_PEEK, (struct sockaddr *)peer, &plen) < 0 ||
        connect(fd, (struct sockaddr *)peer, plen) != 0)
        goto fail;
    return fd;

fail:
    close(fd);
    return -1;
}

int main(int argc, char **argv)
{
    static const int groups[] = { PQTLS_GROUP };
    static const char reply[] = "ack: telemetry received";
    struct sockaddr_in peer;
    WOLFSSL_CTX *ctx = NULL;
    WOLFSSL *ssl = NULL;
    uint16_t port = PQTLS_DEFAULT_PORT;
    char buf[1024];
    int dtls = 0, fd = -1, ret, rc = 1;

    if (argc > 1 && strcmp(argv[1], "--dtls") == 0) {
        dtls = 1;
        argc--, argv++;
    }
    if (argc > 1)
        port = (uint16_t)atoi(argv[1]);

    wolfSSL_Init();
    ctx = wolfSSL_CTX_new(dtls ? wolfDTLSv1_3_server_method()
                               : wolfTLSv1_3_server_method());
    if (ctx == NULL ||
        wolfSSL_CTX_use_certificate_chain_file(ctx, PQTLS_CERT_FILE) != WOLFSSL_SUCCESS ||
        wolfSSL_CTX_use_PrivateKey_file(ctx, PQTLS_KEY_FILE,
                                        WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "server: context/certificate setup failed "
                        "(run `make certs` from the repo root)\n");
        goto out;
    }
    /* Only the hybrid group: a client offering classical-only key exchange
     * gets a handshake failure, not a downgrade. */
    if (wolfSSL_CTX_set_groups(ctx, (int *)groups, 1) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "server: X25519MLKEM768 not available in this wolfSSL\n");
        goto out;
    }

    fd = accept_one(port, dtls, &peer);
    if (fd < 0) {
        perror("server: accept");
        goto out;
    }
    printf("[server] device connected from %s:%u\n",
           inet_ntoa(peer.sin_addr), ntohs(peer.sin_port));

    ssl = wolfSSL_new(ctx);
    if (ssl == NULL || wolfSSL_set_fd(ssl, fd) != WOLFSSL_SUCCESS ||
        (dtls && wolfSSL_dtls_set_peer(ssl, &peer, sizeof(peer)) != WOLFSSL_SUCCESS)) {
        fprintf(stderr, "server: session setup failed\n");
        goto out;
    }

    ret = wolfSSL_accept(ssl);
    if (ret != WOLFSSL_SUCCESS) {
        pqtls_error(ssl, ret, "server", "handshake");
        goto out;
    }
    pqtls_report(ssl, "server");

    ret = wolfSSL_read(ssl, buf, sizeof(buf) - 1);
    if (ret <= 0) {
        pqtls_error(ssl, ret, "server", "read");
        goto out;
    }
    buf[ret] = '\0';
    printf("[server] <- %d bytes -> decrypted: \"%s\"\n", ret, buf);

    ret = wolfSSL_write(ssl, reply, sizeof(reply) - 1);
    if (ret != (int)sizeof(reply) - 1) {
        pqtls_error(ssl, ret, "server", "write");
        goto out;
    }
    printf("[server] -> %d bytes (encrypted reply)\n", ret);

    wolfSSL_shutdown(ssl);
    rc = 0;
out:
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
    if (fd >= 0)
        close(fd);
    wolfSSL_Cleanup();
    printf("[server] %s\n", rc == 0 ? "session OK" : "session FAILED");
    return rc;
}
