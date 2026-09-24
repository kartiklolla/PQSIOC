/* The demo PKI (build/certs, from `make certs`) linked into the image as
 * PEM text; main.c parses it with pqiot_identity_parse. The assembler finds
 * the files through -I (see firmware/Makefile). */
    .section .rodata
#define PEM(sym, file) \
    .balign 4;          \
    .globl sym, sym##_end; \
sym:                    \
    .incbin file;       \
sym##_end:

PEM(fw_ca_pem,     "ca.pem")
PEM(fw_device_pem, "device.pem")
PEM(fw_device_key, "device.key")
/* The networked image is only the device: it must not carry the server's
 * private key. */
#ifndef PQIOT_FW_DEVICE_ONLY
PEM(fw_server_pem, "server.pem")
PEM(fw_server_key, "server.key")
#endif
