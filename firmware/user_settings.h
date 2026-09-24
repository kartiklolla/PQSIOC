/* wolfSSL configuration for the bare-metal firmware (-DWOLFSSL_USER_SETTINGS).
 *
 * Same algorithms as the host build (WOLF_CONF in the Makefile): ML-KEM-768,
 * ML-DSA-65, AES-256-GCM, HKDF-SHA256, X.509 parsing -- minus everything that
 * needs an OS.
 */
#ifndef PQIOT_FW_USER_SETTINGS_H
#define PQIOT_FW_USER_SETTINGS_H

/* ---- platform: no OS, no threads, no files, no sockets ----------------- */
#define SINGLE_THREADED
#define NO_FILESYSTEM
#define NO_WRITEV
#define WOLFSSL_NO_SOCK
#define WOLFSSL_USER_IO          /* we never open a TLS session here anyway */
#define NO_DEV_RANDOM
#define NO_MAIN_DRIVER
#define WOLFSSL_IGNORE_FILE_WARN /* wolfSSL's #include-only .c files */
#define WOLFSSL_GENERAL_ALIGNMENT 4
#define SIZEOF_LONG_LONG 8

/* No TRNG in the simulated SoC: the DRBG is seeded by the firmware
 * (platform.c) from a per-build random seed. See the README. */
#define HAVE_HASHDRBG
#define CUSTOM_RAND_GENERATE_SEED pqiot_fw_seed
#include <stdint.h>
int pqiot_fw_seed(unsigned char *output, unsigned int sz);

/* Keep the big ML-DSA/ML-KEM temporaries on the heap, not the stack. */
#define WOLFSSL_SMALL_STACK

/* ---- algorithms: matches the host build -------------------------------- */
#define WOLFSSL_HAVE_MLKEM
#define WOLFSSL_HAVE_MLDSA
#define WOLFSSL_SHA3
#define WOLFSSL_SHAKE128
#define WOLFSSL_SHAKE256
#define WOLFSSL_SHA384
#define WOLFSSL_SHA512
#define HAVE_AESGCM
#define GCM_TABLE_4BIT
#define WOLFSSL_AES_DIRECT
#define HAVE_HKDF
#define WOLFSSL_ASN_TEMPLATE
#define KEEP_PEER_CERT           /* X509 parsing API used by pqiot_auth_verify */
#define WOLFSSL_SP_MATH_ALL

/* v5.9.2 won't build without ECC (see the Makefile); nothing here uses it,
 * and pqiot_auth_verify refuses any non-ML-DSA-65 key. */
#define HAVE_ECC
#define ECC_TIMING_RESISTANT
#define TFM_TIMING_RESISTANT
#define NO_RSA
#define NO_DH
#define NO_DSA
#define NO_MD4
#define NO_MD5
#define NO_DES3
#define NO_RC4
#define NO_PSK
#define NO_OLD_TLS
#define WOLFSSL_NO_TLS12
#define WOLFSSL_TLS13
#define HAVE_TLS_EXTENSIONS
#define HAVE_SUPPORTED_CURVES
#define NO_SESSION_CACHE
#define NO_ERROR_STRINGS

#endif /* PQIOT_FW_USER_SETTINGS_H */
