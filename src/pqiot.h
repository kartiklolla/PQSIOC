/* PQIOT/2 -- post-quantum secure channel for constrained devices, with
 * mutual ML-DSA-65 authentication.
 *
 * Wire format, every message:
 *
 *   0      4     5     6         8
 *   +------+-----+-----+---------+------------------+
 *   | PQIO | typ | ver | len(be) | body (len bytes) |
 *   +------+-----+-----+---------+------------------+
 *
 * Handshake:
 *   server -> device  PUBKEY  ML-KEM-768 public key            (1184 B)
 *   device -> server  KEMCT   ML-KEM-768 cipher text           (1088 B)
 *   server -> device  CERT    server's ML-DSA-65 certificate   (DER)  *
 *   server -> device  VERIFY  ML-DSA-65 signature over the transcript *
 *   device -> server  CERT    device's ML-DSA-65 certificate   (DER)  *
 *   device -> server  VERIFY  ML-DSA-65 signature over the transcript *
 *   either direction  DATA    [12B IV][16B tag][ct]
 *
 *   * sealed like DATA, under the handshake keys: [12B IV][16B tag][ct]
 *
 * CERT and VERIFY are encrypted so an observer can't tell which device is
 * talking, or to whom. The device only sends its CERT once the server has
 * proven itself, so even an active attacker never sees the device's
 * identity (the server's goes to whoever ran the KEM, as in TLS 1.3).
 *
 * The transcript is SHA-256 over every handshake message (header and
 * plaintext body) sent or received so far, so each signature covers the ML-KEM public key,
 * the cipher text, and everything the peer has said. Swapping any of them --
 * a man in the middle substituting his own KEM key, say -- breaks the
 * signature. Signatures carry a per-role ML-DSA context string, so a
 * server's signature can never be replayed as a device's or vice versa.
 *
 * The KEM shared secret is never used as an AES key directly; it is expanded
 * by HKDF-SHA256 into one key per direction so the two sides can never reuse
 * an (key, IV) pair against each other -- and separately for the handshake
 * and for DATA, so a sealed CERT or VERIFY can never pass as DATA.
 */
#ifndef PQIOT_H
#define PQIOT_H

#include <stdint.h>
#include <stddef.h>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/wc_mlkem.h>
#include <wolfssl/wolfcrypt/wc_mldsa.h>
#include <wolfssl/wolfcrypt/sha256.h>

#include "pki.h"

/* NIST level 3. Both peers must agree; that is what this constant is for. */
#define PQIOT_MLKEM_LEVEL WC_ML_KEM_768
#define PQIOT_PUBKEY_SZ   WC_ML_KEM_768_PUBLIC_KEY_SIZE  /* 1184 */
#define PQIOT_KEMCT_SZ    WC_ML_KEM_768_CIPHER_TEXT_SIZE /* 1088 */

#define PQIOT_MAGIC0 'P'
#define PQIOT_MAGIC1 'Q'
#define PQIOT_MAGIC2 'I'
#define PQIOT_MAGIC3 'O'
#define PQIOT_VER    2 /* 1 had no authentication */

#define PQIOT_HDR_SZ 8

/* message types */
#define PQIOT_MSG_PUBKEY 0x01
#define PQIOT_MSG_KEMCT  0x02
#define PQIOT_MSG_DATA   0x03
#define PQIOT_MSG_CERT   0x04
#define PQIOT_MSG_VERIFY 0x05

/* Big enough for an ML-DSA-65 certificate (~5.5 KB), the largest thing we
 * ever put on the wire. Bounds every read from the socket. */
#define PQIOT_MAX_BODY 8192

#define PQIOT_SIG_SZ  WC_MLDSA_65_SIG_SIZE /* 3309 */

/* ML-DSA context strings: which role produced a signature. */
#define PQIOT_ROLE_SERVER "PQIOT/2 server"
#define PQIOT_ROLE_DEVICE "PQIOT/2 device"

#define PQIOT_SS_SZ  32 /* ML-KEM shared secret */
#define PQIOT_KEY_SZ 32 /* AES-256 */
#define PQIOT_IV_SZ  12 /* GCM nonce */
#define PQIOT_TAG_SZ 16 /* GCM tag */

/* AEAD framing overhead: IV and tag travel with the cipher text. */
#define PQIOT_AEAD_OVERHEAD (PQIOT_IV_SZ + PQIOT_TAG_SZ)

#define PQIOT_DEFAULT_PORT 4433

/* Keys derived from one KEM shared secret: per direction, and per phase. */
typedef struct {
    uint8_t hs_c2s[PQIOT_KEY_SZ]; /* CERT/VERIFY, client -> server */
    uint8_t hs_s2c[PQIOT_KEY_SZ]; /* CERT/VERIFY, server -> client */
    uint8_t c2s[PQIOT_KEY_SZ];    /* DATA, client -> server */
    uint8_t s2c[PQIOT_KEY_SZ];    /* DATA, server -> client */
} pqiot_keys;

/* All functions return 0 on success and a negative value on failure. */

/* Process-wide CSPRNG, seeded on first use. NULL if seeding failed. */
WC_RNG *pqiot_rng(void);

/* Expand the 32-byte KEM shared secret into the four keys above. */
int pqiot_derive_keys(const uint8_t *ss, size_t ss_len, pqiot_keys *out);

/* AES-256-GCM. `out` needs ptlen + PQIOT_AEAD_OVERHEAD bytes; the IV is
 * generated fresh from the CSPRNG for every call. */
int pqiot_seal(const uint8_t key[PQIOT_KEY_SZ], const uint8_t *pt, size_t ptlen,
               uint8_t *out, size_t outcap, size_t *outlen);

/* Inverse of pqiot_seal. Fails if the tag does not verify. */
int pqiot_open(const uint8_t key[PQIOT_KEY_SZ], const uint8_t *in, size_t inlen,
               uint8_t *pt, size_t ptcap, size_t *ptlen);

/* Framed socket I/O. Both handle short reads/writes. */
int pqiot_send(int fd, uint8_t type, const uint8_t *body, size_t len);
int pqiot_recv(int fd, uint8_t *type, uint8_t *body, size_t cap, size_t *len);

/* Framed I/O with the body sealed/opened under `key` (pqiot_seal/open).
 * recv fails unless the frame is of type `want` and authenticates. */
int pqiot_send_sealed(int fd, const uint8_t key[PQIOT_KEY_SZ], uint8_t type,
                      const uint8_t *pt, size_t ptlen);
int pqiot_recv_sealed(int fd, const uint8_t key[PQIOT_KEY_SZ], uint8_t want,
                      uint8_t *pt, size_t ptcap, size_t *ptlen);

/* Our side of the authentication: a certificate from the demo CA and its
 * ML-DSA-65 signing key. */
typedef struct {
    uint8_t     cert[PQIOT_MAX_BODY]; /* DER, sent as-is in CERT */
    size_t      cert_len;
    wc_MlDsaKey key;
} pqiot_identity;

/* Load a PEM certificate and its PEM private key. */
int pqiot_identity_load(pqiot_identity *id, const char *cert_file,
                        const char *key_file);
void pqiot_identity_free(pqiot_identity *id);

/* Transcript: call once per handshake message, sent or received, in wire
 * order. th must be wc_InitSha256()'d first. */
int pqiot_transcript_add(wc_Sha256 *th, uint8_t type, const uint8_t *body,
                         size_t len);

/* Sign the transcript so far as `role` (PQIOT_ROLE_*). `sig` needs
 * PQIOT_SIG_SZ bytes. */
int pqiot_auth_sign(pqiot_identity *id, wc_Sha256 *th, const char *role,
                    uint8_t *sig, size_t *siglen);

/* Authenticate a peer from its CERT and VERIFY bodies. Succeeds only if the
 * certificate chains to `ca_file`, carries an ML-DSA-65 key, has CN
 * `want_cn` (unless NULL), and `sig` verifies over the transcript as
 * `role`. The peer's CN goes to `cn` for logging. */
int pqiot_auth_verify(const char *ca_file, const uint8_t *cert,
                      size_t cert_len, const char *want_cn, wc_Sha256 *th,
                      const char *role, const uint8_t *sig, size_t siglen,
                      char *cn, size_t cncap);

/* Human-readable name for a message type, for logging. */
const char *pqiot_msg_name(uint8_t type);

#endif /* PQIOT_H */
