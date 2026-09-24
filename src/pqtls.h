/* PQTLS -- the same device/server pair as PQIOT, but over standard
 * TLS 1.3 (TCP) or DTLS 1.3 (UDP) instead of the hand-rolled PQIOT/1 frames.
 *
 * Key exchange is pinned to X25519MLKEM768, the hybrid group TLS stacks
 * actually deploy: the session key only falls if *both* X25519 and ML-KEM-768
 * are broken. Neither side offers anything else, so there is no classical
 * fallback to downgrade to. (Pure ML-KEM as a TLS group is compiled out of
 * wolfSSL by default -- WOLFSSL_TLS_NO_MLKEM_STANDALONE.)
 *
 * Authentication is mutual and ML-DSA-65 on both sides: the server and each
 * device hold an ML-DSA-65 certificate from the demo CA (`make certs`), each
 * side demands the other's, and each refuses a peer whose certificate key
 * is anything but ML-DSA-65 -- so the CertificateVerify signatures that
 * prove possession of those keys are post-quantum too.
 */
#ifndef PQTLS_H
#define PQTLS_H

#include <stdio.h>

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/asn_public.h>

#include "pki.h"

#if !defined(WOLFSSL_TLS13) || !defined(WOLFSSL_HAVE_MLKEM) || \
    !defined(WOLFSSL_HAVE_MLDSA) || !defined(KEEP_PEER_CERT)
#error "wolfSSL needs TLS 1.3, ML-KEM, ML-DSA and KEEP_PEER_CERT (build/<arch> from `make tls`)"
#endif

#define PQTLS_GROUP       WOLFSSL_X25519MLKEM768
#define PQTLS_PEER_KEY    ML_DSA_65k /* the only certificate key we accept */
#define PQTLS_DEFAULT_PORT 4433

/* Context shared by both ends: our own certificate and key, the demo CA to
 * verify the peer against, a peer certificate required either way, and the
 * hybrid group only. NULL (after saying why) on failure. */
static WOLFSSL_CTX *pqtls_ctx_new(WOLFSSL_METHOD *method, const char *cert,
                                  const char *key, const char *who)
{
    static const int groups[] = { PQTLS_GROUP };
    WOLFSSL_CTX *ctx = wolfSSL_CTX_new(method);

    if (ctx == NULL ||
        wolfSSL_CTX_load_verify_locations(ctx, PKI_CA_FILE, NULL) != WOLFSSL_SUCCESS ||
        wolfSSL_CTX_use_certificate_chain_file(ctx, cert) != WOLFSSL_SUCCESS ||
        wolfSSL_CTX_use_PrivateKey_file(ctx, key, WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "%s: certificate setup failed "
                        "(run `make certs` from the repo root)\n", who);
        wolfSSL_CTX_free(ctx);
        return NULL;
    }
    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER |
                                WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    if (wolfSSL_CTX_set_groups(ctx, (int *)groups, 1) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "%s: X25519MLKEM768 not available in this wolfSSL\n", who);
        wolfSSL_CTX_free(ctx);
        return NULL;
    }
    return ctx;
}

/* wolfSSL has already verified the peer's chain up to the demo CA and its
 * CertificateVerify signature. This additionally pins the key type: the
 * build still has ECC (see WOLF_CONF in the Makefile), so an ECDSA leaf
 * under the same CA would otherwise pass with a classical signature.
 * 0 if the peer is ML-DSA-65. */
static int pqtls_check_peer(WOLFSSL *ssl, const char *who)
{
    WOLFSSL_X509 *peer = wolfSSL_get_peer_certificate(ssl);
    int ok = peer != NULL &&
             wolfSSL_X509_get_pubkey_type(peer) == PQTLS_PEER_KEY;

    if (ok)
        printf("[%s] peer authenticated: CN=%s (ML-DSA-65)\n", who,
               wolfSSL_X509_get_subjectCN(peer));
    else
        fprintf(stderr, "%s: peer certificate is not ML-DSA-65, refusing\n",
                who);
    wolfSSL_X509_free(peer);
    return ok ? 0 : -1;
}

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
