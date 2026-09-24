/* PQIOT/1 -- post-quantum secure channel for constrained devices.
 *
 * Wire format, every message:
 *
 *   0      4     5     6         8
 *   +------+-----+-----+---------+------------------+
 *   | PQIO | typ | ver | len(be) | body (len bytes) |
 *   +------+-----+-----+---------+------------------+
 *
 * Handshake:
 *   server -> client  PUBKEY  ML-KEM-768 public key      (1184 B)
 *   client -> server  KEMCT   ML-KEM-768 cipher text     (1088 B)
 *   either direction  DATA    [12B IV][16B tag][ct]
 *
 * The KEM shared secret is never used as an AES key directly; it is expanded
 * by HKDF-SHA256 into one key per direction so the two sides can never reuse
 * an (key, IV) pair against each other.
 */
#ifndef PQIOT_H
#define PQIOT_H

#include <stdint.h>
#include <stddef.h>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/wc_mlkem.h>

/* NIST level 3. Both peers must agree; that is what this constant is for. */
#define PQIOT_MLKEM_LEVEL WC_ML_KEM_768
#define PQIOT_PUBKEY_SZ   WC_ML_KEM_768_PUBLIC_KEY_SIZE  /* 1184 */
#define PQIOT_KEMCT_SZ    WC_ML_KEM_768_CIPHER_TEXT_SIZE /* 1088 */

#define PQIOT_MAGIC0 'P'
#define PQIOT_MAGIC1 'Q'
#define PQIOT_MAGIC2 'I'
#define PQIOT_MAGIC3 'O'
#define PQIOT_VER    1

#define PQIOT_HDR_SZ 8

/* message types */
#define PQIOT_MSG_PUBKEY 0x01
#define PQIOT_MSG_KEMCT  0x02
#define PQIOT_MSG_DATA   0x03

/* Big enough for an ML-KEM-768 public key (1184 B), the largest thing we
 * ever put on the wire. Bounds every read from the socket. */
#define PQIOT_MAX_BODY 2048

#define PQIOT_SS_SZ  32 /* ML-KEM shared secret */
#define PQIOT_KEY_SZ 32 /* AES-256 */
#define PQIOT_IV_SZ  12 /* GCM nonce */
#define PQIOT_TAG_SZ 16 /* GCM tag */

/* AEAD framing overhead: IV and tag travel with the cipher text. */
#define PQIOT_AEAD_OVERHEAD (PQIOT_IV_SZ + PQIOT_TAG_SZ)

#define PQIOT_DEFAULT_PORT 4433

/* Directional key pair derived from one KEM shared secret. */
typedef struct {
    uint8_t c2s[PQIOT_KEY_SZ]; /* client -> server */
    uint8_t s2c[PQIOT_KEY_SZ]; /* server -> client */
} pqiot_keys;

/* All functions return 0 on success and a negative value on failure. */

/* Process-wide CSPRNG, seeded on first use. NULL if seeding failed. */
WC_RNG *pqiot_rng(void);

/* Expand the 32-byte KEM shared secret into the two directional keys. */
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

/* Human-readable name for a message type, for logging. */
const char *pqiot_msg_name(uint8_t type);

#endif /* PQIOT_H */
