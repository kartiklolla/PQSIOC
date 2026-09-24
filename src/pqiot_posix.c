/* POSIX half of the platform layer: the socket hooks behind pqiot_send/recv
 * and loading an identity from PEM files. Bare metal has its own versions
 * (firmware/platform.c); nothing else in src/ touches the OS. */
#include "pqiot.h"

#include <errno.h>
#include <stdio.h>
#include <unistd.h>

#include <wolfssl/wolfcrypt/memory.h>

long pqiot_sys_read(int fd, void *buf, size_t len)
{
    ssize_t n;

    do
        n = read(fd, buf, len);
    while (n < 0 && errno == EINTR);
    return (long)n;
}

long pqiot_sys_write(int fd, const void *buf, size_t len)
{
    ssize_t n;

    do
        n = write(fd, buf, len);
    while (n < 0 && errno == EINTR);
    return (long)n;
}

/* Whole file into buf. Its length, or -1. */
static int read_file(const char *path, uint8_t *buf, size_t cap)
{
    FILE *f = fopen(path, "rb");
    size_t n;

    if (f == NULL)
        return -1;
    n = fread(buf, 1, cap, f);
    /* A file that fills the buffer may have been cut short. */
    if (ferror(f) || n == cap) {
        fclose(f);
        return -1;
    }
    fclose(f);
    return (int)n;
}

int pqiot_identity_load(pqiot_identity *id, const char *cert_file,
                        const char *key_file, const char *ca_file)
{
    static uint8_t cert[16384], key[16384], ca[16384];
    int nc, nk, na, rc = -1;

    if (id == NULL || cert_file == NULL || key_file == NULL || ca_file == NULL)
        return -1;

    nc = read_file(cert_file, cert, sizeof(cert));
    nk = read_file(key_file, key, sizeof(key));
    na = read_file(ca_file, ca, sizeof(ca));
    if (nc > 0 && nk > 0 && na > 0)
        rc = pqiot_identity_parse(id, cert, (size_t)nc, key, (size_t)nk,
                                  ca, (size_t)na);
    wc_ForceZero(key, sizeof(key)); /* held the private key */
    return rc;
}
