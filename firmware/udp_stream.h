/* Reliable byte stream over LiteX UDP (udp_stream.c). */
#ifndef PQIOT_UDP_STREAM_H
#define PQIOT_UDP_STREAM_H

#include <stdint.h>

/* Resolve the peer, then HELLO until it answers. 0 once the bridge is there;
 * after that pqiot_sys_read/write carry the session. */
int udp_stream_open(uint32_t ip, uint16_t local_port, uint16_t peer_port);

#endif /* PQIOT_UDP_STREAM_H */
