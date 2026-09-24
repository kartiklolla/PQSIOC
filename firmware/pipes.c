/* In-memory transport for the all-in-one firmware (main.c): two pipes
 * stand in for the TCP socket. fd 0 is the device's end, fd 1 the server's.
 * A read that finds its pipe empty yields to the other coroutine until
 * bytes arrive. */
#include <stdint.h>
#include <string.h>

#include "pqiot.h" /* pqiot_sys_read/write */
#include "fw.h"

/* ponytail: linear buffers that reset when drained. One session moves
 * ~25 KB each way and each side drains before the other refills, so this
 * never fills; a ring buffer if sessions ever get longer. */
#define PIPE_CAP (64 * 1024)

static struct pipe {
    uint8_t buf[PIPE_CAP];
    size_t  rd, wr;
    size_t  total; /* bytes ever written, for the summary */
} pipes[2];        /* [0]: device -> server, [1]: server -> device */

static int aborted;

size_t fw_wire_bytes(int dir)
{
    return pipes[dir].total;
}

void fw_wire_abort(void)
{
    aborted = 1;
}

long pqiot_sys_write(int fd, const void *buf, size_t len)
{
    struct pipe *p = &pipes[fd == 0 ? 0 : 1];

    if (aborted || (fd != 0 && fd != 1))
        return -1;
    if (p->rd == p->wr)
        p->rd = p->wr = 0;
    if (len > PIPE_CAP - p->wr)
        return -1;
    memcpy(p->buf + p->wr, buf, len);
    p->wr += len;
    p->total += len;
    return (long)len;
}

long pqiot_sys_read(int fd, void *buf, size_t len)
{
    struct pipe *p = &pipes[fd == 0 ? 1 : 0];
    size_t n;

    if (fd != 0 && fd != 1)
        return -1;
    while (p->rd == p->wr) {
        if (aborted)
            return -1;
        if (fw_peer_done())
            return 0; /* peer is gone: end of stream */
        fw_yield();
    }
    n = p->wr - p->rd;
    if (n > len)
        n = len;
    memcpy(buf, p->buf + p->rd, n);
    p->rd += n;
    return (long)n;
}
