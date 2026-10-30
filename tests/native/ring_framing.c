/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */

/* Contract tests: framing constants, open validation, lifecycle, stats,
 * and error records. Explicit host mode omits the valid-fixture load
 * and its privilege probe; the default suite retains that case. */
#include "testutil.h"

#ifdef LMB_HOST_GUARD_TEST
#include <stdarg.h>
#include <sys/syscall.h>

/* The dedicated host regression stops an accidental load or privilege
 * probe before kernel execution, including calls from bundled libbpf. */
long __real_syscall(long number, ...);
long __wrap_syscall(long number, ...) {
    if (number == SYS_memfd_create) {
        va_list args;
        va_start(args, number);
        const char *name = va_arg(args, const char *);
        unsigned flags = va_arg(args, unsigned);
        va_end(args);
        return __real_syscall(number, name, flags);
    }
    fprintf(stderr, "HOST GUARD: unexpected syscall %ld; stopped before execution\n",
            number);
    _exit(number == SYS_bpf ? 99 : 98);
}
#endif

static int check_open_reject(const uint8_t *elf, uint64_t elf_len,
                             struct lmb_options_v1 *o, const char *name) {
    struct lmb_session *s = NULL;
    struct lmb_error_v1 err;
    int32_t rc = lmb_open(elf, elf_len, o, &s);
    memset(&err, 0, sizeof(err));
    err.abi_version = LMB_ABI_VERSION;
    err.struct_size = sizeof(err);
    if (rc == 0 || s != NULL) {
        LMB_FAIL(name, "accepted invalid open (rc=%d)", (int)rc);
        if (s)
            lmb_close(&s);
        return 0;
    }
    if (lmb_last_error(&err) != 0 || err.operation != LMB_OP_OPEN ||
        err.domain != LMB_DOMAIN_BRIDGE) {
        LMB_FAIL(name, "wrong error record (op=%u domain=%u)",
                 err.operation, err.domain);
        return 0;
    }
    LMB_OK(name);
    return 1;
}

int main(int argc, char **argv) {
    const char *fixture = lmb_fixture(argc, argv);
    uint8_t *elf = NULL;
    uint64_t elf_len = 0;
    struct lmb_options_v1 o;
    struct lmb_session *s = NULL;
    struct lmb_error_v1 err;
    struct lmb_stats_v1 st;
    int32_t rc;
    char big[300];

    if (lmb_read_file(fixture, &elf, &elf_len) != 0 || elf_len == 0) {
        LMB_FAIL("fixture-load", "cannot read %s", fixture);
        return 1;
    }

    LMB_CHECK(LMB_FRAME_HEADER_SIZE == 8 && LMB_MAX_FRAME_BYTES == 4104 &&
                  LMB_MAX_RAW_BYTES + LMB_FRAME_HEADER_SIZE ==
                      LMB_MAX_FRAME_BYTES,
              "frame-constants", "bad frame constants");
    LMB_CHECK(16 + LMB_FRAME_HEADER_SIZE == 24, "frame-16-24",
              "16-byte payload must frame to 24 bytes");
    LMB_CHECK(LMB_FRAME_VERSION == 1, "frame-version",
              "framing version must be 1");

    /* Initial error record, before any failing call. */
    memset(&err, 0, sizeof(err));
    err.abi_version = LMB_ABI_VERSION;
    err.struct_size = sizeof(err);
    LMB_CHECK(lmb_last_error(&err) == 0 && err.operation == LMB_OP_NONE &&
                  err.domain == LMB_DOMAIN_NONE && err.code == 0 &&
                  err.msg_len == 0,
              "error-initial", "initial record must be all zeros");

    /* Open validation matrix. */
    lmb_make_options(&o, "events", 4096);
    o.abi_version = 0;
    check_open_reject(elf, elf_len, &o, "open-bad-version");
    lmb_make_options(&o, "events", 4096);
    o.struct_size = sizeof(o) - 1;
    check_open_reject(elf, elf_len, &o, "open-short-struct");
    memset(big, 'x', sizeof(big) - 1);
    big[sizeof(big) - 1] = '\0';
    lmb_make_options(&o, "events", 4096);
    o.ring.ptr = (const uint8_t *)big;
    o.ring.len = 257;
    check_open_reject(elf, elf_len, &o, "open-ring-too-long");
    lmb_make_options(&o, "events", 4096);
    o.ring.ptr = (const uint8_t *)"ev\0il";
    o.ring.len = 5;
    check_open_reject(elf, elf_len, &o, "open-ring-nul");
    lmb_make_options(&o, "events", 4096);
    o.ring._pad = 1;
    check_open_reject(elf, elf_len, &o, "open-ring-pad");
    lmb_make_options(&o, "events", 4096);
    o.ring.ptr = (const uint8_t *)"\xff\xfe";
    o.ring.len = 2;
    check_open_reject(elf, elf_len, &o, "open-ring-utf8-lonely");
    lmb_make_options(&o, "events", 4096);
    o.ring.ptr = (const uint8_t *)"\xe2\x82";
    o.ring.len = 2;
    check_open_reject(elf, elf_len, &o, "open-ring-utf8-truncated");
    lmb_make_options(&o, "events", 4096);
    o.ring.ptr = (const uint8_t *)"\xc0\xaf";
    o.ring.len = 2;
    check_open_reject(elf, elf_len, &o, "open-ring-utf8-overlong");
    lmb_make_options(&o, "events", 4096);
    o.ring.ptr = (const uint8_t *)"\xed\xa0\x80";
    o.ring.len = 3;
    check_open_reject(elf, elf_len, &o, "open-ring-utf8-surrogate");
    /* Valid non-ASCII UTF-8 passes validation (open copies blindly;
     * resolving the name is load's job, not open's). */
    lmb_make_options(&o, "events", 4096);
    o.ring.ptr = (const uint8_t *)"a\xc3\xa9"
                                        "b";
    o.ring.len = 4;
    s = NULL;
    rc = lmb_open(elf, elf_len, &o, &s);
    LMB_CHECK(rc == 0 && s != NULL, "open-ring-utf8-ok",
              "valid UTF-8 name must pass validation");
    lmb_close(&s);
    lmb_make_options(&o, "events", 0);
    check_open_reject(elf, elf_len, &o, "open-max-raw-zero");
    lmb_make_options(&o, "events", 4097);
    check_open_reject(elf, elf_len, &o, "open-max-raw-huge");
    lmb_make_options(&o, "events", 4096);
    o.stage_slots = 0;
    check_open_reject(elf, elf_len, &o, "open-stage-zero");
    lmb_make_options(&o, "events", 4096);
    o.stage_slots = 2;
    check_open_reject(elf, elf_len, &o, "open-stage-two");
    lmb_make_options(&o, "events", 4096);
    o.flags = 1;
    check_open_reject(elf, elf_len, &o, "open-flags");
    lmb_make_options(&o, "events", 4096);
    rc = lmb_open(elf, elf_len, &o, NULL);
    LMB_CHECK(rc != 0, "open-null-out", "null out must fail, got %d",
              (int)rc);
    rc = lmb_open(NULL, 100, &o, &s);
    LMB_CHECK(rc != 0 && s == NULL, "open-null-elf",
              "null bytes must fail");
    rc = lmb_open(elf, 0, &o, &s);
    LMB_CHECK(rc != 0 && s == NULL, "open-zero-bytes",
              "zero length must fail");
    /* An unallocatable length fails closed with ENOMEM and clears
     * the output; the copy is never attempted. */
    lmb_make_options(&o, "events", 4096);
    s = NULL;
    rc = lmb_open(elf, UINT64_MAX, &o, &s);
    LMB_CHECK(rc == -ENOMEM && s == NULL &&
                  lmb_error_is(LMB_OP_OPEN, LMB_DOMAIN_POSIX),
              "open-huge-enomem", "giant length must fail ENOMEM");

    /* Allocation bound: the admitted ELF size is a contract; over-cap
     * input fails closed with ENOMEM before any allocation. */
    LMB_CHECK(LMB_MAX_ELF_BYTES == 16777216, "open-elf-cap-value",
              "ELF cap must be 16 MiB");
    {
        uint64_t over = (uint64_t)LMB_MAX_ELF_BYTES + 1;
        uint8_t *big = calloc(1, (size_t)over);
        lmb_make_options(&o, "events", 4096);
        s = NULL;
        if (!big) {
            LMB_FAIL("open-elf-over-cap", "cannot allocate test buffer");
        } else {
            memcpy(big, elf, (size_t)elf_len);
            rc = lmb_open(big, over, &o, &s);
            if (rc == 0 && s)
                lmb_close(&s);
            LMB_CHECK(rc == -ENOMEM && s == NULL &&
                          lmb_error_is(LMB_OP_OPEN, LMB_DOMAIN_POSIX),
                      "open-elf-over-cap",
                      "over-cap ELF must fail ENOMEM, got %d", (int)rc);
            free(big);
        }
    }
    {
        /* Exactly at the bound, open proceeds: a valid prefix with
         * zero padding opens and closes normally. */
        uint64_t at = (uint64_t)LMB_MAX_ELF_BYTES;
        uint8_t *big = calloc(1, (size_t)at);
        lmb_make_options(&o, "events", 4096);
        if (!big) {
            LMB_FAIL("open-elf-at-cap", "cannot allocate test buffer");
        } else {
            memcpy(big, elf, (size_t)elf_len);
            s = NULL;
            rc = lmb_open(big, at, &o, &s);
            LMB_CHECK(rc == 0 && s != NULL, "open-elf-at-cap",
                      "at-cap ELF must proceed, got %d", (int)rc);
            if (s)
                lmb_close(&s);
            free(big);
        }
    }
    /* Output aliasing: the out cell must not overlap any input, and a
     * rejected call leaves every input byte untouched. */
    {
        struct lmb_options_v1 pristine;
        uint8_t *elf_copy = malloc(elf_len ? (size_t)elf_len : 1);
        char ringbuf[32];
        struct lmb_session *leaked;
        lmb_make_options(&o, "events", 4096);
        pristine = o;
        memset(ringbuf, 0xA5, sizeof(ringbuf));
        memcpy(ringbuf, "events", 6);
        if (!elf_copy) {
            LMB_FAIL("open-alias", "cannot allocate test buffer");
        } else {
            int ring_tail_clean;
            memcpy(elf_copy, elf, (size_t)elf_len);
            rc = lmb_open(elf_copy, elf_len, &o,
                          (struct lmb_session **)&o);
            LMB_CHECK(rc == -EINVAL && !memcmp(&o, &pristine, sizeof(o)),
                      "open-alias-out-opts",
                      "out/opts overlap must fail without clobbering");
            lmb_make_options(&o, "events", 4096);
            rc = lmb_open(elf_copy, elf_len, &o,
                          (struct lmb_session **)(elf_copy + elf_len - 8));
            if (rc == 0) {
                memcpy(&leaked, elf_copy + elf_len - 8, sizeof(leaked));
                if (leaked)
                    lmb_close(&leaked);
            }
            LMB_CHECK(rc == -EINVAL &&
                          !memcmp(elf_copy, elf, (size_t)elf_len),
                      "open-alias-out-elf",
                      "out/elf overlap must fail without clobbering");
            memcpy(elf_copy, elf, (size_t)elf_len);
            lmb_make_options(&o, "events", 4096);
            o.ring.ptr = (const uint8_t *)ringbuf;
            o.ring.len = 6;
            rc = lmb_open(elf_copy, elf_len, &o,
                          (struct lmb_session **)(ringbuf + 2));
            ring_tail_clean = ringbuf[6] == (char)0xA5 &&
                              ringbuf[9] == (char)0xA5;
            LMB_CHECK(rc == -EINVAL && ring_tail_clean &&
                          !memcmp(ringbuf, "events", 6),
                      "open-alias-out-ring",
                      "out/ring overlap must fail without clobbering");
            free(elf_copy);
        }
    }

    /* Error content after a usage failure. */
    lmb_make_options(&o, "events", 4096);
    o.abi_version = 0;
    s = NULL;
    lmb_open(elf, elf_len, &o, &s);
    memset(&err, 0, sizeof(err));
    err.abi_version = LMB_ABI_VERSION;
    err.struct_size = sizeof(err);
    LMB_CHECK(lmb_last_error(&err) == 0 && err.operation == LMB_OP_OPEN &&
                  err.domain == LMB_DOMAIN_BRIDGE && err.msg_len > 0 &&
                  err.msg_len <= LMB_MAX_MSG_LEN &&
                  err.message[err.msg_len] == 0,
              "error-content", "usage error must carry a message");

    /* A short record must not leave bytes from a longer predecessor:
     * the full message tail stays zeroed. */
    lmb_make_options(&o, "events", 4096);
    s = NULL;
    rc = lmb_open(elf, elf_len, &o, (struct lmb_session **)&o);
    LMB_CHECK(rc == -EINVAL, "error-tail-long",
              "alias open must fail, got %d", (int)rc);
    memset(&st, 0, sizeof(st));
    st.abi_version = LMB_ABI_VERSION;
    st.struct_size = sizeof(st);
    rc = lmb_stats(NULL, &st);
    LMB_CHECK(rc == -EINVAL, "error-tail-short",
              "null stats must fail, got %d", (int)rc);
    memset(&err, 0, sizeof(err));
    err.abi_version = LMB_ABI_VERSION;
    err.struct_size = sizeof(err);
    {
        int tail_clean = 1;
        uint32_t i;
        LMB_CHECK(lmb_last_error(&err) == 0 &&
                      err.operation == LMB_OP_STATS && err.msg_len < 29,
                  "error-tail-order", "short record must follow long one");
        for (i = err.msg_len; i < sizeof(err.message); i++)
            if (err.message[i] != 0)
                tail_clean = 0;
        LMB_CHECK(tail_clean, "error-tail-zero",
                  "message tail must be zeroed");
    }
    /* Restore the OP_OPEN record the preservation check below needs. */
    lmb_make_options(&o, "events", 4096);
    o.abi_version = 0;
    s = NULL;
    lmb_open(elf, elf_len, &o, &s);

    /* Inspection failure preserves the stored record. */
    memset(&st, 0, sizeof(st));
    st.abi_version = 0;
    st.struct_size = sizeof(st);
    LMB_CHECK(lmb_stats(s, &st) != 0, "stats-bad-out",
              "bad stats header must fail");
    memset(&err, 0, sizeof(err));
    err.abi_version = LMB_ABI_VERSION;
    err.struct_size = sizeof(err);
    LMB_CHECK(lmb_last_error(&err) == 0 && err.operation == LMB_OP_OPEN,
              "error-preserved", "failed inspection must preserve record");

    /* Lifecycle on a valid open. */
    lmb_make_options(&o, "events", 4096);
    s = NULL;
    rc = lmb_open(elf, elf_len, &o, &s);
    LMB_CHECK(rc == 0 && s != NULL, "open-ok",
              "valid open must succeed, got %d", (int)rc);
    if (rc == 0 && s != NULL) {
        memset(&st, 0, sizeof(st));
        st.abi_version = LMB_ABI_VERSION;
        st.struct_size = sizeof(st);
        LMB_CHECK(lmb_stats(s, &st) == 0 && st.received == 0 &&
                      st.delivered == 0 && st.staged == 0 &&
                      st.malformed == 0 && st.dropped == 0,
                  "stats-zero", "fresh session counters must be zero");
        LMB_CHECK(lmb_poll(s, NULL, 0, NULL, NULL, 0) != 0,
                  "poll-unloaded", "poll before load must fail");
        LMB_CHECK(lmb_attach(s, NULL, 0) != 0, "attach-unloaded",
                  "attach before load must fail");
        LMB_CHECK(lmb_detach(s) == 0, "detach-unloaded",
                  "detach without links must succeed");
        LMB_CHECK(lmb_close(&s) == 0 && s == NULL, "close-ok",
                  "close must null the handle");
    }
    /* Unparseable bytes fail in the libbpf domain with or without
     * privileges: the parse error precedes any kernel call. */
    {
        static const uint8_t garbage[64];
        struct lmb_session *g = NULL;
        lmb_make_options(&o, "events", 4096);
        rc = lmb_open(garbage, sizeof(garbage), &o, &g);
        if (rc == 0 && g != NULL) {
            rc = lmb_load(g);
            memset(&err, 0, sizeof(err));
            err.abi_version = LMB_ABI_VERSION;
            err.struct_size = sizeof(err);
            LMB_CHECK(rc != 0 && lmb_last_error(&err) == 0 &&
                          err.operation == LMB_OP_LOAD &&
                          err.domain == LMB_DOMAIN_LIBBPF,
                      "load-garbage", "garbage ELF must fail in libbpf");
            lmb_close(&g);
        } else {
            LMB_FAIL("load-garbage", "open of garbage must succeed");
            if (g)
                lmb_close(&g);
        }
    }
    /* Repeated open/close and load-failure/close cycles must not
     * accumulate file descriptors. Allocation leaks are covered by
     * the sanitizer build's leak checker. */
    {
        static const uint8_t garbage[64];
        long before = lmb_count_fds();
        long after = -2;
        int n;
        int ok = before >= 0 ? 1 : 0;
        for (n = 0; n < 200 && ok; n++) {
            struct lmb_session *c = NULL;
            lmb_make_options(&o, "events", 4096);
            if (lmb_open(elf, elf_len, &o, &c) != 0 || !c ||
                lmb_close(&c) != 0 || c != NULL)
                ok = 0;
        }
        after = lmb_count_fds();
        LMB_CHECK(ok && before == after, "cycle-open-close",
                  "200 open/close cycles must hold fds steady");
        before = lmb_count_fds();
        after = -2;
        ok = before >= 0 ? 1 : 0;
        for (n = 0; n < 50 && ok; n++) {
            struct lmb_session *c = NULL;
            lmb_make_options(&o, "events", 4096);
            if (lmb_open(garbage, sizeof(garbage), &o, &c) != 0 ||
                !c || lmb_load(c) == 0 || lmb_close(&c) != 0 ||
                c != NULL)
                ok = 0;
        }
        after = lmb_count_fds();
        LMB_CHECK(ok && before == after, "cycle-load-fail-close",
                  "50 load-failure cycles must hold fds steady");
    }
    /* Dual-mode load: privileged loads latch no native error;
     * unprivileged refusals latch the native code. A load failure
     * with privileges present is a real defect. */
    if (getenv("LMB_HOST_ONLY") && !strcmp(getenv("LMB_HOST_ONLY"), "1")) {
        puts("NOT_RUN ring_framing.load-dual: host-only scope; no load or privilege probe");
    } else {
        struct lmb_session *d = NULL;
        lmb_make_options(&o, "events", 4096);
        if (lmb_open(elf, elf_len, &o, &d) == 0 && d != NULL) {
            int32_t lrc = lmb_load(d);
            if (lrc == 0) {
                memset(&st, 0, sizeof(st));
                st.abi_version = LMB_ABI_VERSION;
                st.struct_size = sizeof(st);
                LMB_CHECK(lmb_stats(d, &st) == 0 &&
                              st.last_error == 0,
                          "load-clean-no-latch",
                          "clean load must latch no error");
            } else if (!lmb_has_collection_privilege()) {
                memset(&st, 0, sizeof(st));
                st.abi_version = LMB_ABI_VERSION;
                st.struct_size = sizeof(st);
                LMB_CHECK(lmb_stats(d, &st) == 0 &&
                              st.last_error != 0 &&
                              lmb_error_is(LMB_OP_LOAD,
                                           LMB_DOMAIN_LIBBPF),
                          "load-denied-latches",
                          "denied load must latch native code");
            } else {
                LMB_FAIL("load-dual",
                         "load failed despite privileges");
            }
            lmb_close(&d);
        } else {
            LMB_FAIL("load-dual", "open for dual load must succeed");
        }
    }
    /* Output aliasing is refused before any state changes, even on an
     * unloaded session: required keeps its entry value. */
    {
        struct lmb_session *d = NULL;
        struct lmb_name_v1 nm;
        union {
            uint32_t cell;
            uint8_t bytes[4];
        } keyu;
        uint8_t dstbuf[8] = {0};
        lmb_make_options(&o, "events", 4096);
        lmb_make_name(&nm, "test_hash");
        if (lmb_open(elf, elf_len, &o, &d) == 0 && d != NULL) {
            keyu.cell = 0xDEAD;
            LMB_CHECK(lmb_map_read(d, &nm, keyu.bytes, sizeof(keyu),
                                   dstbuf, sizeof(dstbuf),
                                   &keyu.cell) == -EINVAL &&
                          keyu.cell == 0xDEAD &&
                          lmb_error_is(LMB_OP_MAP_READ,
                                       LMB_DOMAIN_BRIDGE),
                      "map-read-alias",
                      "aliased required must fail untouched");
            lmb_close(&d);
        } else {
            LMB_FAIL("map-read-alias", "open must succeed");
        }
    }
    LMB_CHECK(lmb_close(&s) == 0, "close-null-pointee",
              "close must tolerate a null pointee");
    LMB_CHECK(lmb_close(NULL) == 0, "close-null-handle",
              "close must tolerate a null handle");
    LMB_CHECK(lmb_stats(NULL, &st) != 0, "stats-null-session",
              "null session must fail");

    free(elf);
    return lmb_failures ? 1 : 0;
}
