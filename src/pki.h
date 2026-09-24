/* The demo PKI both protocols authenticate with (`make certs`): one
 * ML-DSA-65 CA, a server certificate and a device certificate. Paths are
 * relative to the repo root, where the Makefile runs everything. */
#ifndef PKI_H
#define PKI_H

#define PKI_CA_FILE          "build/certs/ca.pem"
#define PKI_SERVER_CERT_FILE "build/certs/server.pem"
#define PKI_SERVER_KEY_FILE  "build/certs/server.key"
#define PKI_DEVICE_CERT_FILE "build/certs/device.pem"
#define PKI_DEVICE_KEY_FILE  "build/certs/device.key"

/* CN/SAN of the server certificate; devices refuse any other name. wolfSSL
 * only checks FQDNs, and .test is reserved (RFC 2606), so this can never be
 * a real host. */
#define PKI_SERVER_NAME "server.pqiot.test"

#endif /* PKI_H */
