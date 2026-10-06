/* Tracepoint example trigger: fire the observed syscall on demand.
 *
 * Usage: trigger <ready-path> <ledger-path> <count> <timeout-s>
 *                <pidfile-path>
 *
 * Waits for the parent to publish our TGID to <pidfile-path>
 * (atomically: temporary file plus rename, so a reader never sees
 * a partial write), then waits for the collector to create
 * <ready-path> (proving attach completed before the first
 * syscall), then invokes the getpid syscall directly exactly
 * <count> times, then writes the independent ledger
 * "tgid=<n> count=<n>\n" to <ledger-path>.
 *
 * The TGID arrives through the pidfile because the trigger must
 * never call getpid itself. There is no getpid vDSO entry on
 * x86-64, and since glibc 2.25 there is no PID cache either
 * (getpid(2)), so every libc call traps: any post-attach call
 * would be a 129th observation and break the exact
 * reconciliation. Direct syscall(2) traps are the explicit
 * workload contract: one trap per requested observation,
 * guaranteed.
 *
 * Exit 0 on success, 2 when the barrier times out, 1 on other
 * failures.
 */
#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

static int parse_ulong(const char *text, unsigned long *out) {
    char *end = NULL;
    unsigned long value;

    errno = 0;
    value = strtoul(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0')
        return -1;
    *out = value;
    return 0;
}

static int wait_ready(const char *path, unsigned long timeout_s) {
    struct timespec start, now, nap;
    struct stat ignored;

    nap.tv_sec = 0;
    nap.tv_nsec = 5 * 1000 * 1000;
    if (clock_gettime(CLOCK_MONOTONIC, &start) != 0)
        return -1;
    for (;;) {
        unsigned long elapsed;
        if (stat(path, &ignored) == 0)
            return 0;
        if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
            return -1;
        elapsed = (unsigned long)(now.tv_sec - start.tv_sec);
        if (elapsed >= timeout_s)
            return 1;
        nanosleep(&nap, NULL);
    }
}

static int read_tgid(const char *pidfile, unsigned long timeout_s,
                      unsigned long *tgid) {
    FILE *in;
    char buf[64];
    switch (wait_ready(pidfile, timeout_s)) {
    case 0:
        break;
    case 1:
        fprintf(stderr, "trigger: pidfile timed out\n");
        return 2;
    default:
        fprintf(stderr, "trigger: cannot poll pidfile\n");
        return 1;
    }
    in = fopen(pidfile, "r");
    if (!in || !fgets(buf, sizeof(buf), in)) {
        if (in)
            fclose(in);
        fprintf(stderr, "trigger: cannot read pidfile\n");
        return 1;
    }
    fclose(in);
    buf[strcspn(buf, "\r\n")] = '\0';
    if (parse_ulong(buf, tgid) != 0 || *tgid == 0) {
        fprintf(stderr, "trigger: invalid tgid in pidfile\n");
        return 1;
    }
    return 0;
}

int main(int argc, char **argv) {
    unsigned long count, timeout_s, tgid;
    unsigned long i;
    FILE *ledger;
    int rc;

    if (argc != 6) {
        fprintf(stderr,
                "usage: %s <ready> <ledger> <count> <timeout-s>"
                " <pidfile>\n",
                argv[0]);
        return 1;
    }
    if (parse_ulong(argv[3], &count) != 0 || count == 0 ||
        count > 1000000 || parse_ulong(argv[4], &timeout_s) != 0 ||
        timeout_s == 0 || timeout_s > 3600) {
        fprintf(stderr, "trigger: invalid count or timeout\n");
        return 1;
    }
    rc = read_tgid(argv[5], timeout_s, &tgid);
    if (rc != 0)
        return rc;
    switch (wait_ready(argv[1], timeout_s)) {
    case 0:
        break;
    case 1:
        fprintf(stderr, "trigger: readiness barrier timed out\n");
        return 2;
    default:
        fprintf(stderr, "trigger: cannot poll readiness barrier\n");
        return 1;
    }
    /* Direct traps: exactly count observations, one trap each.
     * No getpid call here by design (see above). */
    for (i = 0; i < count; i++)
        syscall(SYS_getpid);
    ledger = fopen(argv[2], "w");
    if (!ledger) {
        fprintf(stderr, "trigger: cannot write ledger: %s\n",
                strerror(errno));
        return 1;
    }
    fprintf(ledger, "tgid=%lu count=%lu\n", tgid, count);
    if (fclose(ledger) != 0) {
        fprintf(stderr, "trigger: cannot finish ledger: %s\n",
                strerror(errno));
        return 1;
    }
    return 0;
}
