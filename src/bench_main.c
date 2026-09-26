/* Native benchmarks (`make bench`):
 *
 *   1. every primitive a session uses (src/bench.c), in nanoseconds;
 *   2. whole PQIOT/2 sessions -- real server and device session code, a
 *      forked process each, over a socketpair -- timed end to end and
 *      counted, so a single failure among N runs shows up.
 *
 *   ./pqiot-bench [primitive-iterations] [sessions]
 */
#include "pqiot.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static uint64_t now_ns(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000u + (uint64_t)ts.tv_nsec;
}

static int cmp_u64(const void *a, const void *b)
{
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;

    return (x > y) - (x < y);
}

/* One session: the server in a child process, the device in this one.
 * The sessions' own logging goes to /dev/null. Nanoseconds, or 0 on
 * failure of either side. */
static uint64_t one_session(pqiot_identity *srv, pqiot_identity *dev)
{
    int sv[2], status, quiet, saved, ok;
    uint64_t t0, t1;
    pid_t pid;

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0)
        return 0;
    fflush(stdout);
    quiet = open("/dev/null", O_WRONLY);
    saved = dup(STDOUT_FILENO);
    dup2(quiet, STDOUT_FILENO);

    t0 = now_ns();
    pid = fork();
    if (pid == 0) {
        close(sv[0]);
        _exit(pqiot_server_session(sv[1], srv) == 0 ? 0 : 1);
    }
    close(sv[1]);
    ok = pid > 0 && pqiot_device_session(sv[0], "sensor=temp value=23.4C", dev) == 0;
    close(sv[0]);
    ok = ok && waitpid(pid, &status, 0) == pid && WIFEXITED(status) &&
         WEXITSTATUS(status) == 0;
    t1 = now_ns();

    fflush(stdout);
    dup2(saved, STDOUT_FILENO);
    close(saved);
    close(quiet);
    return ok ? t1 - t0 : 0;
}

int main(int argc, char **argv)
{
    int iters = argc > 1 ? atoi(argv[1]) : 50;
    int sessions = argc > 2 ? atoi(argv[2]) : 100;
    pqiot_identity srv, dev;
    uint64_t *t;
    int i, fails = 0, n = 0;

    if (pqiot_rng() == NULL ||
        pqiot_identity_load(&srv, PKI_SERVER_CERT_FILE, PKI_SERVER_KEY_FILE,
                            PKI_CA_FILE) != 0 ||
        pqiot_identity_load(&dev, PKI_DEVICE_CERT_FILE, PKI_DEVICE_KEY_FILE,
                            PKI_CA_FILE) != 0) {
        fprintf(stderr, "bench: cannot load identities (make certs)\n");
        return 1;
    }

    printf("== primitives, native, %d iterations each\n", iters);
    if (pqiot_bench(iters, now_ns, "ns", &srv) != 0)
        return 1;

    t = calloc((size_t)sessions, sizeof(*t));
    if (t == NULL)
        return 1;
    for (i = 0; i < sessions; i++) {
        uint64_t d = one_session(&srv, &dev);

        if (d == 0)
            fails++;
        else
            t[n++] = d;
    }
    printf("\n== whole PQIOT/2 sessions (handshake + mutual auth + DATA round trip)\n");
    if (n > 0) {
        qsort(t, (size_t)n, sizeof(*t), cmp_u64);
        printf("  %-44s %9.3f %9.3f %9.3f ms (min median max)\n",
               "session latency, socketpair", t[0] / 1e6, t[n / 2] / 1e6,
               t[n - 1] / 1e6);
    }
    printf("  %-44s %d / %d\n", "sessions succeeded", n, sessions);
    free(t);
    pqiot_identity_free(&srv);
    pqiot_identity_free(&dev);
    return fails == 0 ? 0 : 1;
}
