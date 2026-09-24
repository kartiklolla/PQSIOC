/* PQTLS -- the same device/server pair as PQIOT, but over standard
 * TLS 1.3 (TCP) or DTLS 1.3 (UDP) instead of the hand-rolled PQIOT/1 frames.
 *
 * Key exchange is pinned to X25519MLKEM768, the hybrid group TLS stacks
 * actually deploy: the session key only falls if *both* X25519 and ML-KEM-768
 * are broken. Neither side offers anything else, so there is no classical
 * fallback to downgrade to. (Pure ML-KEM as a TLS group is compiled out of
 * wolfSSL by default -- WOLFSSL_TLS_NO_MLKEM_STANDALONE.)
 *
 * Server authentication is an ECDSA P-256 certificate from a demo CA
 * (`make certs`). That part is still classical; ML-DSA certificates are a
 * separate stretch goal.
 */
#ifndef PQTLS_H
#define PQTLS_H

#include <stdio.h>

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>

#if !defined(WOLFSSL_TLS13) || !defined(WOLFSSL_HAVE_MLKEM)
#error "wolfSSL needs TLS 1.3 and ML-KEM (build/<arch> from `make tls`)"
#endif

#define PQTLS_GROUP       WOLFSSL_X25519MLKEM768
/* CN/SAN of the demo certificate. wolfSSL only checks FQDNs, and .test is
 * reserved (RFC 2606), so this can never be a real host. */
#define PQTLS_SERVER_NAME "server.pqiot.test"
#define PQTLS_DEFAULT_PORT 4433

/* Relative to the repo root, where the Makefile runs everything. */
#define PQTLS_CA_FILE   "build/certs/ca.pem"
#define PQTLS_CERT_FILE "build/certs/server.pem"
#define PQTLS_KEY_FILE  "build/certs/server.key"

/* Lets the negotiated group be read back by name after the handshake. */
static inline void pqtls_report(WOLFSSL *ssl, const char *who)
{
    printf("[%s] handshake OK: %s, %s, key exchange %s\n", who,
           wolfSSL_get_version(ssl), wolfSSL_get_cipher(ssl),
           wolfSSL_get_curve_name(ssl));
}

static inline void pqtls_error(WOLFSSL *ssl, int ret, const char *who,
                               const char *what)
{
    char buf[WOLFSSL_MAX_ERROR_SZ];
    int err = wolfSSL_get_error(ssl, ret);

    fprintf(stderr, "%s: %s failed: %d %s\n", who, what, err,
            wolfSSL_ERR_error_string((unsigned long)err, buf));
}

#endif /* PQTLS_H */
