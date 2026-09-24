/* Glue between the firmware's scheduler (main.c) and its platform layer
 * (platform.c). */
#ifndef PQIOT_FW_H
#define PQIOT_FW_H

#include <stddef.h>

/* Scheduler: give the CPU to the other coroutine until it blocks or ends. */
void fw_yield(void);
/* Has the other end's coroutine finished? */
int fw_peer_done(void);

/* Pipes: bytes ever sent device->server (dir 0) or server->device (dir 1),
 * and a kill switch that fails every further read/write. */
size_t fw_wire_bytes(int dir);
void fw_wire_abort(void);

#endif /* PQIOT_FW_H */
