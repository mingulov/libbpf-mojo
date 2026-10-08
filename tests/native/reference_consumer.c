/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */

/* C reference consumer for the tracepoint example.
 *
 * Collects the identical BPF object through the public lmb_* ABI
 * without Mojo. When the Mojo collector and this consumer disagree,
 * the fault lies at the language boundary rather than in the
 * bridge, object, or environment.
 *
 * Usage:
 *   reference_consumer <elf> <tgid> <ns-dev> <ns-ino> <ready>
 *                      <out> <want> <timeout-s>
 *   reference_consumer --eintr <elf> <status> <go> <bye>
 *
 * The collect mode mirrors tracepoint_main argument order and
 * output record. The --eintr mode proves an interrupted poll
 * surfaces EINTR and leaves the session reusable: it opens and
 * loads the object, arms a 1s alarm, blocks in a 30s poll, expects
 * -EINTR, then proves reuse with a non-blocking poll before
 * closing. Signal handlers are unavailable in Mojo without
 * function-pointer FFI, so this one fault lives at the C layer
 * where the EINTR path is implemented.
 *
 * Exit 0 on success (or on the expected fault), 3 on an incomplete
 * window, 77 when the kernel denies the privileged step, 2 on
 * usage errors, 1 on other failures.
 */
#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "libbpf_mojo.h"
#include "event.h"

#define OUT_CAP (LMB_MAX_FRAME_BYTES)

static int parse_u64(const char *text, uint64_t *out) {
    char *end = NULL;
    unsigned long long value;

    errno = 0;
    value = strtoull(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0')
        return -1;
    *out = (uint64_t)value;
    return 0;
}

static uint8_t *read_file(const char *path, uint64_t *len_out) {
    FILE *in;
    long size;
    uint8_t *buf;
    size_t got;

    in = fopen(path, "rb");
    if (!in)
        return NULL;
    if (fseek(in, 0, SEEK_END) != 0 || (size = ftell(in)) < 0) {
        fclose(in);
        return NULL;
    }
    rewind(in);
    buf = malloc((size_t)size > 0 ? (size_t)size : 1);
    if (!buf) {
        fclose(in);
        return NULL;
    }
    got = fread(buf, 1, (size_t)size, in);
    fclose(in);
    if (got != (size_t)size) {
        free(buf);
        return NULL;
    }
    *len_out = (uint64_t)size;
    return buf;
}

static void make_bytes(struct lmb_bytes_v1 *b, const void *ptr,
                       uint32_t len) {
    b->ptr = ptr;
    b->len = len;
    b->_pad = 0;
}

static void make_name(struct lmb_name_v1 *n, const char *text) {
    n->abi_version = LMB_ABI_VERSION;
    n->struct_size = sizeof(*n);
    make_bytes(&n->name, text, (uint32_t)strlen(text));
}

static void put_le64(uint8_t *p, uint64_t v) {
    int i;
    for (i = 0; i < 8; i++)
        p[i] = (uint8_t)(v >> (i * 8));
}

static void put_le32(uint8_t *p, uint32_t v) {
    int i;
    for (i = 0; i < 4; i++)
        p[i] = (uint8_t)(v >> (i * 8));
}

static int write_text(const char *path, const char *text) {
    FILE *out = fopen(path, "w");
    if (!out)
        return -1;
    if (fputs(text, out) == EOF) {
        fclose(out);
        return -1;
    }
    return fclose(out) == 0 ? 0 : -1;
}

/* Classify a setup failure as environment (1, test SKIP) or
 * product (0, test FAIL). EPERM always means the environment
 * denied the operation. EACCES at attach is also environmental:
 * the program already loaded, so the verifier accepted it and
 * only perf/tracefs access can deny the attach. EACCES at load is
 * ambiguous (verifier rejection vs LSM denial) and fails closed:
 * a broken probe must never become a quiet skip. Classification
 * uses the call site plus errno, never a re-read error record, so
 * a stale record cannot mislabel the failure. */
static int privilege_skip(int32_t rc, int at_attach) {
    if (rc == -EPERM)
        return 1;
    if (rc == -EACCES && at_attach)
        return 1;
    return 0;
}

static uint64_t get_le64(const uint8_t *p) {
    uint64_t v = 0;
    int i;
    for (i = 0; i < 8; i++)
        v |= (uint64_t)p[i] << (i * 8);
    return v;
}

static uint32_t get_le32(const uint8_t *p) {
    uint32_t v = 0;
    int i;
    for (i = 0; i < 4; i++)
        v |= (uint32_t)p[i] << (i * 8);
    return v;
}

static uint32_t get_le16(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8);
}

static int collect(const char *elf_path, uint64_t tgid, uint64_t ns_dev,
                   uint64_t ns_ino, const char *ready, const char *out,
                   uint64_t want, uint64_t timeout_s) {
    uint8_t *elf = NULL;
    uint64_t elf_len = 0;
    struct lmb_session *s = NULL;
    struct lmb_options_v1 opts;
    struct lmb_attach_v1 site;
    struct lmb_name_v1 map;
    struct lmb_stats_v1 stats;
    uint8_t dst[OUT_CAP];
    uint32_t written = 0, required = 0;
    uint64_t *seqs;
    uint64_t observed = 0, mismatches = 0;
    uint8_t key[4], value[8], count_raw[8];
    uint32_t need = 0;
    uint64_t counter = 0;
    int32_t rc;
    uint32_t i;
    FILE *report;
    int complete;
    struct timespec start, now;

    if (want == 0 || want > 1000000 || timeout_s == 0 || timeout_s > 3600)
        return 2;
    seqs = malloc(want * sizeof(*seqs));
    if (!seqs) {
        fprintf(stderr, "reference: out of memory\n");
        return 1;
    }
    elf = read_file(elf_path, &elf_len);
    if (!elf) {
        fprintf(stderr, "reference: cannot read object\n");
        free(seqs);
        return 1;
    }
    opts.abi_version = LMB_ABI_VERSION;
    opts.struct_size = sizeof(opts);
    make_bytes(&opts.ring, TP_RING_NAME,
               (uint32_t)strlen(TP_RING_NAME));
    opts.max_raw_bytes = 64;
    opts.stage_slots = 1;
    opts.flags = 0;
    opts._reserved = 0;
    rc = lmb_open(elf, elf_len, &opts, &s);
    free(elf);
    if (rc != 0 || !s) {
        fprintf(stderr, "reference: open failed: %d\n", (int)rc);
        free(seqs);
        return privilege_skip(rc, 0) ? 77 : 1;
    }
    rc = lmb_load(s);
    if (rc != 0) {
        fprintf(stderr, "reference: load failed: %d\n", (int)rc);
        lmb_close(&s);
        free(seqs);
        return privilege_skip(rc, 0) ? 77 : 1;
    }
    make_name(&map, TP_FILTER_MAP);
    put_le32(key, 0);
    put_le64(value, tgid);
    if (lmb_map_write(s, &map, key, 4, value, 8) != 0)
        goto fail;
    put_le32(key, 1);
    put_le64(value, ns_dev);
    if (lmb_map_write(s, &map, key, 4, value, 8) != 0)
        goto fail;
    put_le32(key, 2);
    put_le64(value, ns_ino);
    if (lmb_map_write(s, &map, key, 4, value, 8) != 0)
        goto fail;
    site.abi_version = LMB_ABI_VERSION;
    site.struct_size = sizeof(site);
    make_bytes(&site.program, TP_PROGRAM,
               (uint32_t)strlen(TP_PROGRAM));
    site.kind = LMB_ATTACH_TRACEPOINT;
    site.flags = 0;
    make_bytes(&site.target_a, "syscalls", 8);
    make_bytes(&site.target_b, "sys_enter_getpid", 16);
    rc = lmb_attach(s, &site, 1);
    if (rc != 0) {
        fprintf(stderr, "reference: attach failed: %d\n", (int)rc);
        lmb_close(&s);
        free(seqs);
        return privilege_skip(rc, 1) ? 77 : 1;
    }
    if (write_text(ready, "ready\n") != 0)
        goto fail;
    /* Elapsed-time deadline: the window lasts timeout_s from the
     * first poll, with each wait clamped to the time remaining. */
    if (clock_gettime(CLOCK_MONOTONIC, &start) != 0)
        goto fail;
    for (;;) {
        int64_t elapsed_ms, remain_ms;
        int32_t wait_ms;
        uint64_t seq;
        uint32_t got_tgid, tag;
        if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
            goto fail;
        elapsed_ms = (int64_t)(now.tv_sec - start.tv_sec) * 1000 +
            ((int64_t)now.tv_nsec - (int64_t)start.tv_nsec) / 1000000;
        if (elapsed_ms < 0)
            elapsed_ms = 0;
        if (observed >= want ||
            (uint64_t)elapsed_ms >= timeout_s * 1000)
            break;
        remain_ms = (int64_t)(timeout_s * 1000) - elapsed_ms;
        wait_ms = remain_ms > 1000 ? 1000 : (int32_t)remain_ms;
        rc = lmb_poll(s, dst, OUT_CAP, &written, &required, wait_ms);
        if (rc == -EINTR)
            continue; /* explicit signal retry, not an error */
        if (rc != 0) {
            fprintf(stderr, "reference: poll failed: %d\n", (int)rc);
            goto fail;
        }
        if (written == 0)
            continue;
        if (written != LMB_FRAME_HEADER_SIZE + sizeof(struct tp_event) ||
            get_le32(dst) != sizeof(struct tp_event) ||
            get_le16(dst + 4) != LMB_FRAME_VERSION ||
            get_le16(dst + 6) != 0) {
            mismatches++;
            continue;
        }
        seq = get_le64(dst + LMB_FRAME_HEADER_SIZE);
        got_tgid = get_le32(dst + LMB_FRAME_HEADER_SIZE + 8);
        tag = get_le32(dst + LMB_FRAME_HEADER_SIZE + 12);
        if (got_tgid != (uint32_t)tgid || tag != TP_TAG) {
            mismatches++;
            continue;
        }
        seqs[observed++] = seq;
    }
    make_name(&map, TP_SEQ_MAP);
    put_le32(key, 0);
    if (lmb_map_read(s, &map, key, 4, count_raw, 8, &need) != 0 ||
        need != 0)
        goto fail;
    counter = get_le64(count_raw);
    memset(&stats, 0, sizeof(stats));
    stats.abi_version = LMB_ABI_VERSION;
    stats.struct_size = sizeof(stats);
    if (lmb_stats(s, &stats) != 0)
        goto fail;
    if (lmb_detach(s) != 0)
        goto fail;
    report = fopen(out, "w");
    if (!report)
        goto fail;
    complete = observed == want && mismatches == 0;
    fprintf(report, "observed=%llu\n", (unsigned long long)observed);
    fprintf(report, "want=%llu\n", (unsigned long long)want);
    fputs("seqs=", report);
    for (i = 0; i < observed; i++)
        fprintf(report, "%s%llu", i ? "," : "",
                (unsigned long long)seqs[i]);
    fputc('\n', report);
    fprintf(report, "counter=%llu\n", (unsigned long long)counter);
    fprintf(report, "received=%llu\n",
            (unsigned long long)stats.received);
    fprintf(report, "delivered=%llu\n",
            (unsigned long long)stats.delivered);
    fprintf(report, "malformed=%llu\n",
            (unsigned long long)stats.malformed);
    fprintf(report, "dropped=%llu\n", (unsigned long long)stats.dropped);
    fprintf(report, "mismatches=%llu\n",
            (unsigned long long)mismatches);
    fprintf(report, "complete=%s\n", complete ? "true" : "false");
    if (ferror(report)) {
        fclose(report);
        goto fail;
    }
    if (fclose(report) != 0)
        goto fail;
    free(seqs);
    if (lmb_close(&s) != 0)
        return 1;
    return complete ? 0 : 3;
fail:
    fprintf(stderr, "reference: collection failed\n");
    free(seqs);
    lmb_close(&s);
    return 1;
}

static volatile sig_atomic_t got_alrm = 0;

static void on_alarm(int signo) {
    (void)signo;
    got_alrm = 1;
}

static int wait_file(const char *path, unsigned long timeout_s) {
    unsigned long waited = 0;
    struct stat ignored;
    while (stat(path, &ignored) != 0) {
        if (waited >= timeout_s * 200)
            return -1;
        usleep(5000);
        waited++;
    }
    return 0;
}

/* Publish an early outcome, then park on <bye> like every other
 * path: the parent classifies the written line instead of timing
 * out, and the child stays joinable under the same protocol. */
static int early_outcome(const char *status, const char *bye,
                         const char *text, int code) {
    if (write_text(status, text) != 0)
        return 1;
    if (wait_file(bye, 600) != 0)
        return 1;
    return code;
}

/* EINTR lane: block in poll under a 1s alarm, expect -EINTR, prove
 * the session stays usable, then close cleanly under the fd
 * handshake (status/go/bye files shared with the test driver). */
static int eintr_lane(const char *elf_path, const char *status,
                      const char *go, const char *bye) {
    uint8_t *elf = NULL;
    uint64_t elf_len = 0;
    struct lmb_session *s = NULL;
    struct lmb_options_v1 opts;
    struct sigaction act, old;
    uint8_t dst[OUT_CAP];
    uint32_t written = 0, required = 0;
    int32_t rc, rc2;
    int reusable = 0;

    elf = read_file(elf_path, &elf_len);
    if (!elf)
        return early_outcome(status, bye, "setup=failed read\n", 1);
    if (write_text(status, "ready\n") != 0 || wait_file(go, 600) != 0) {
        /* No outcome to publish (status unwritable) or no parent
         * left to read it (go never arrives): the parent's
         * liveness check turns the bare exit into a fast FAIL. */
        free(elf);
        return 1;
    }
    opts.abi_version = LMB_ABI_VERSION;
    opts.struct_size = sizeof(opts);
    make_bytes(&opts.ring, TP_RING_NAME,
               (uint32_t)strlen(TP_RING_NAME));
    opts.max_raw_bytes = 64;
    opts.stage_slots = 1;
    opts.flags = 0;
    opts._reserved = 0;
    rc = lmb_open(elf, elf_len, &opts, &s);
    free(elf);
    if (rc != 0 || !s) {
        if (privilege_skip(rc, 0))
            return early_outcome(status, bye, "privilege=1\n", 77);
        return early_outcome(status, bye, "setup=failed open\n", 1);
    }
    rc = lmb_load(s);
    if (rc != 0) {
        lmb_close(&s);
        if (privilege_skip(rc, 0))
            return early_outcome(status, bye, "privilege=1\n", 77);
        return early_outcome(status, bye, "setup=failed load\n", 1);
    }
    memset(&act, 0, sizeof(act));
    act.sa_handler = on_alarm;
    sigemptyset(&act.sa_mask);
    if (sigaction(SIGALRM, &act, &old) != 0) {
        lmb_close(&s);
        return early_outcome(status, bye, "setup=failed signal\n", 1);
    }
    alarm(1);
    rc = lmb_poll(s, dst, OUT_CAP, &written, &required, 30000);
    alarm(0);
    sigaction(SIGALRM, &old, NULL);
    if (rc == -EINTR && got_alrm) {
        /* A non-blocking poll must still work: reuse, not death. */
        rc2 = lmb_poll(s, dst, OUT_CAP, &written, &required, 0);
        reusable = rc2 == 0;
    }
    /* Close before reporting, like the Mojo fault modes: the parent
     * samples owned FDs while the session is fully closed but the
     * process is still alive. */
    if (lmb_close(&s) != 0)
        return 1;
    if (write_text(status, rc == -EINTR && reusable
                       ? "eintr=1 reusable=1\n"
                       : "eintr=0 reusable=0\n") != 0)
        return 1;
    if (wait_file(bye, 600) != 0)
        return 1;
    return rc == -EINTR && reusable ? 0 : 1;
}

int main(int argc, char **argv) {
    uint64_t tgid, ns_dev, ns_ino, want, timeout_s;

    if (argc == 6 && strcmp(argv[1], "--eintr") == 0)
        return eintr_lane(argv[2], argv[3], argv[4], argv[5]);
    if (argc != 9) {
        fprintf(stderr,
                "usage: %s <elf> <tgid> <ns-dev> <ns-ino> <ready>"
                " <out> <want> <timeout-s>\n",
                argv[0]);
        return 2;
    }
    if (parse_u64(argv[2], &tgid) != 0 ||
        parse_u64(argv[3], &ns_dev) != 0 ||
        parse_u64(argv[4], &ns_ino) != 0 ||
        parse_u64(argv[7], &want) != 0 ||
        parse_u64(argv[8], &timeout_s) != 0) {
        fprintf(stderr, "reference: invalid number\n");
        return 2;
    }
    if (tgid == 0 || tgid > 0xFFFFFFFFu) {
        fprintf(stderr, "reference: tgid out of u32 range\n");
        return 2;
    }
    return collect(argv[1], tgid, ns_dev, ns_ino, argv[5], argv[6], want,
                   timeout_s);
}
