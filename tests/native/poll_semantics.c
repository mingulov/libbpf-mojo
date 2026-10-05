/* Poll and framing behavior against a live ring buffer. Requires
 * collection privileges; reports SKIP when the kernel refuses with
 * EPERM/EACCES. Uses real syscalls (not vDSO) to trigger events. */
#include <signal.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "testutil.h"

#define TAG 0xA02u

static void lmb_alrm(int sig) {
    (void)sig;
}

static int parse_frames(const uint8_t *buf, uint32_t len, uint32_t pid,
                        int *frames_out) {
    uint32_t off = 0;
    int frames = 0;
    while (off < len) {
        uint32_t plen;
        uint16_t ver, rsv;
        if (len - off < LMB_FRAME_HEADER_SIZE)
            return -1;
        plen = lmb_le32(buf + off);
        ver = lmb_le16(buf + off + 4);
        rsv = lmb_le16(buf + off + 6);
        if (ver != LMB_FRAME_VERSION || rsv != 0 || plen != 16)
            return -2;
        if (len - off - LMB_FRAME_HEADER_SIZE < plen)
            return -3;
        if (lmb_le32(buf + off + 8) != pid)
            return -4;
        if (lmb_le32(buf + off + 12) != TAG)
            return -5;
        off += LMB_FRAME_HEADER_SIZE + plen;
        frames++;
    }
    *frames_out = frames;
    return 0;
}

int main(int argc, char **argv) {
    const char *fixture = lmb_fixture(argc, argv);
    uint8_t *elf = NULL;
    uint64_t elf_len = 0;
    struct lmb_options_v1 o;
    struct lmb_attach_v1 site;
    struct lmb_name_v1 map;
    struct lmb_session *s = NULL;
    struct lmb_stats_v1 st;
    uint8_t dst[8192];
    uint32_t written = 0, required = 0;
    uint32_t pid = (uint32_t)getpid();
    uint64_t pid64 = pid;
    uint32_t zero = 0;
    int frames = 0;
    int i;

    if (lmb_read_file(fixture, &elf, &elf_len) != 0 || elf_len == 0) {
        LMB_FAIL("fixture-load", "cannot read %s", fixture);
        return 1;
    }
    lmb_make_options(&o, "events", 4096);
    if (lmb_open(elf, elf_len, &o, &s) != 0 || !s) {
        LMB_FAIL("setup-open", "open must succeed");
        free(elf);
        return 1;
    }
    if (lmb_load(s) != 0) {
        int eligible = lmb_has_collection_privilege();
        lmb_close(&s);
        free(elf);
        if (!eligible)
            LMB_SKIP("missing collection privileges");
        LMB_FAIL("setup-load", "load failed despite privileges");
        return 1;
    }
    /* Deliver only our own PID from the BPF side. BPF observes the
     * initial PID namespace, so the filter also carries our namespace
     * identity for bpf_get_ns_current_pid_tgid. */
    {
        struct stat nsst;
        uint32_t key = 0;
        uint64_t dev, ino;
        if (stat("/proc/self/ns/pid", &nsst) != 0) {
            lmb_close(&s);
            free(elf);
            LMB_SKIP("cannot stat pid namespace identity");
        }
        dev = (uint64_t)nsst.st_dev;
        ino = (uint64_t)nsst.st_ino;
        lmb_make_name(&map, "filter");
        if (lmb_map_write(s, &map, (const uint8_t *)&zero, 4,
                          (const uint8_t *)&pid64, 8) != 0) {
            LMB_FAIL("setup-filter", "cannot write pid filter");
            lmb_close(&s);
            free(elf);
            return 1;
        }
        key = 1;
        if (lmb_map_write(s, &map, (const uint8_t *)&key, 4,
                          (const uint8_t *)&dev, 8) != 0) {
            LMB_FAIL("setup-filter-ns", "cannot write ns dev filter");
            lmb_close(&s);
            free(elf);
            return 1;
        }
        key = 2;
        if (lmb_map_write(s, &map, (const uint8_t *)&key, 4,
                          (const uint8_t *)&ino, 8) != 0) {
            LMB_FAIL("setup-filter-ns", "cannot write ns ino filter");
            lmb_close(&s);
            free(elf);
            return 1;
        }
    }
    lmb_make_attach(&site, "on_getpid", LMB_ATTACH_TRACEPOINT, "syscalls",
                    "sys_enter_getpid");
    if (lmb_attach(s, &site, 1) != 0) {
        int eligible = lmb_has_collection_privilege();
        lmb_close(&s);
        free(elf);
        if (!eligible)
            LMB_SKIP("missing collection privileges");
        LMB_FAIL("setup-attach", "attach failed despite privileges");
        return 1;
    }

    written = 0xDEAD;
    required = 0xDEAD;
    LMB_CHECK(lmb_poll(s, dst, sizeof(dst), &written, &required, 50) == 0 &&
                  written == 0 && required == 0,
              "timeout-empty", "quiet poll must yield 0/0 (w=%u r=%u)",
              written, required);

    for (i = 0; i < 3; i++)
        syscall(SYS_getpid);
    /* One frame per poll: drain the three records one at a time. */
    {
        int total = 0, got = 0, ok = 1;
        uint32_t wsum = 0;
        for (i = 0; i < 3; i++) {
            written = 0;
            required = 0;
            if (lmb_poll(s, dst, sizeof(dst), &written, &required,
                         2000) != 0 ||
                parse_frames(dst, written, pid, &got) != 0 || got != 1) {
                ok = 0;
                break;
            }
            total += got;
            wsum += written;
        }
        frames = total;
        written = wsum;
        LMB_CHECK(ok && total == 3, "three-events",
                  "want 3 framed events (w=%u frames=%d)", written,
                  frames);
    }

    syscall(SYS_getpid);
    written = 0xDEAD;
    required = 0;
    LMB_CHECK(lmb_poll(s, dst, 10, &written, &required, 2000) == -ENOSPC &&
                  written == 0 && required == 24,
              "enospc-retain", "short poll must keep required=24 (w=%u r=%u)",
              written, required);

    memset(&st, 0, sizeof(st));
    st.abi_version = LMB_ABI_VERSION;
    st.struct_size = sizeof(st);
    LMB_CHECK(lmb_stats(s, &st) == 0 && st.staged == 1, "staged-one",
              "retained record must show staged=1");

    written = 0;
    required = 0xDEAD;
    LMB_CHECK(lmb_poll(s, dst, 24, &written, &required, 0) == 0 &&
                  written == 24 && required == 0 &&
                  parse_frames(dst, written, pid, &frames) == 0 &&
                  frames == 1,
              "retry-once", "retry must deliver exactly once (w=%u)",
              written);

    written = 0xDEAD;
    required = 0xDEAD;
    LMB_CHECK(lmb_poll(s, dst, sizeof(dst), &written, &required, 0) == 0 &&
                  written == 0 && required == 0,
              "drained", "drained ring must yield 0/0");

    memset(&st, 0, sizeof(st));
    st.abi_version = LMB_ABI_VERSION;
    st.struct_size = sizeof(st);
    LMB_CHECK(
        lmb_stats(s, &st) == 0 && st.staged == 0 && st.malformed == 0 &&
            st.dropped == 0 && st.delivered == 4 &&
            st.last_error == 0 &&
            st.received == st.delivered + st.staged + st.malformed +
                                st.dropped,
        "conservation", "received must reconcile (r=%llu d=%llu)",
        (unsigned long long)st.received,
        (unsigned long long)st.delivered);

    /* Producer health: four matched attempts, no failed
     * submissions, and runs covering at least the attempts. */
    {
        struct lmb_name_v1 statmap;
        uint32_t skey = 0;
        uint64_t runs = 0, attempts = 0, failed = 0;
        uint32_t sreq = 0;
        int sok = 1;
        lmb_make_name(&statmap, "test_stats");
        if (lmb_map_read(s, &statmap, (const uint8_t *)&skey, 4,
                         (uint8_t *)&runs, 8, &sreq) != 0)
            sok = 0;
        skey = 1;
        if (lmb_map_read(s, &statmap, (const uint8_t *)&skey, 4,
                         (uint8_t *)&attempts, 8, &sreq) != 0)
            sok = 0;
        skey = 2;
        if (lmb_map_read(s, &statmap, (const uint8_t *)&skey, 4,
                         (uint8_t *)&failed, 8, &sreq) != 0)
            sok = 0;
        LMB_CHECK(sok && attempts == 4 && failed == 0 &&
                      runs >= attempts &&
                      attempts - failed == st.delivered,
                  "producer-health",
                  "producer must show 4 attempts, 0 failed");
    }

    /* A foreign PID's syscalls must not produce events. */
    {
        pid_t child = fork();
        if (child < 0) {
            LMB_FAIL("foreign-pid-quiet", "fork failed");
        } else if (child == 0) {
            int k;
            for (k = 0; k < 5; k++)
                syscall(SYS_getpid);
            _exit(0);
        } else {
            int status = 0;
            waitpid(child, &status, 0);
            written = 0xDEAD;
            required = 0xDEAD;
            LMB_CHECK(lmb_poll(s, dst, sizeof(dst), &written,
                               &required, 200) == 0 &&
                          written == 0 && required == 0,
                      "foreign-pid-quiet",
                      "foreign pid must yield no events");
        }
    }

    LMB_CHECK(lmb_detach(s) == 0, "detach-ok", "detach must succeed");
    /* Detach destroys the link: our own syscalls go quiet. */
    syscall(SYS_getpid);
    syscall(SYS_getpid);
    written = 0xDEAD;
    required = 0xDEAD;
    LMB_CHECK(lmb_poll(s, dst, sizeof(dst), &written, &required, 200) ==
                  0 &&
                  written == 0 && required == 0,
              "detached-quiet", "detached link must deliver nothing");
    LMB_CHECK(lmb_attach(s, &site, 1) == 0, "reattach-ok",
              "attach after detach must succeed");
    syscall(SYS_getpid);
    written = 0;
    LMB_CHECK(lmb_poll(s, dst, sizeof(dst), &written, &required, 2000) ==
                  0 &&
                  parse_frames(dst, written, pid, &frames) == 0 &&
                  frames == 1,
              "reattached-event", "reattached session must deliver");

    /* A signal during a bounded wait must interrupt with EINTR and
     * copy nothing. Drain first so the wait really blocks; a helper
     * child delivers the signal mid-wait, with retries in case a
     * signal lands before the wait starts. */
    {
        struct sigaction sa;
        int32_t erc = 0;
        int drained, attempt;
        memset(&sa, 0, sizeof(sa));
        sa.sa_handler = lmb_alrm;
        sigemptyset(&sa.sa_mask);
        sa.sa_flags = 0;
        LMB_CHECK(sigaction(SIGALRM, &sa, NULL) == 0, "eintr-setup",
                  "sigaction must succeed");
        for (drained = 0; drained < 10; drained++) {
            written = 0;
            required = 0;
            if (lmb_poll(s, dst, sizeof(dst), &written, &required, 0) !=
                0)
                break;
            if (written == 0)
                break;
        }
        for (attempt = 0; attempt < 3; attempt++) {
            pid_t killer = fork();
            int status = 0;
            if (killer < 0) {
                erc = -EIO;
                break;
            }
            if (killer == 0) {
                struct timespec half = {0, 500000000L};
                pid_t parent = getppid();
                nanosleep(&half, NULL);
                kill(parent, SIGALRM);
                _exit(0);
            }
            written = 0xDEAD;
            required = 0xDEAD;
            erc = lmb_poll(s, dst, sizeof(dst), &written, &required,
                           10000);
            waitpid(killer, &status, 0);
            if (erc == -EINTR && written == 0 && required == 0)
                break;
        }
        LMB_CHECK(erc == -EINTR && written == 0 && required == 0,
                  "eintr", "interrupted wait must report EINTR (rc=%d)",
                  (int)erc);
    }
    /* Skip loop: with an 8-byte raw cap the 16-byte record is
     * malformed and the 8-byte record stages. One poll must skip
     * the former and deliver the latter however the kernel orders
     * the two programs. */
    {
        struct lmb_options_v1 o2;
        struct lmb_attach_v1 both[2];
        struct lmb_session *s2 = NULL;
        struct lmb_stats_v1 st2;
        struct lmb_name_v1 statmap;
        uint32_t skey = 1;
        uint64_t attempts = 0;
        uint32_t sreq = 0;
        lmb_make_options(&o2, "events", 8);
        if (lmb_open(elf, elf_len, &o2, &s2) != 0 || !s2) {
            LMB_FAIL("mixed-open", "second session must open");
        } else if (lmb_load(s2) != 0) {
            LMB_FAIL("mixed-load", "second session must load");
            lmb_close(&s2);
        } else {
            uint32_t zk = 0, ok1 = 1, ok2 = 2;
            uint64_t pid64b = pid;
            struct stat nsb;
            uint64_t devb, inob;
            lmb_make_name(&map, "filter");
            if (stat("/proc/self/ns/pid", &nsb) != 0) {
                LMB_FAIL("mixed-open", "cannot stat pid namespace");
                lmb_close(&s2);
                s2 = NULL;
            } else {
                devb = (uint64_t)nsb.st_dev;
                inob = (uint64_t)nsb.st_ino;
            }
            if (s2 == NULL) {
                /* setup failed; skip the mixed phase */
            } else {
                lmb_map_write(s2, &map, (const uint8_t *)&zk, 4,
                              (const uint8_t *)&pid64b, 8);
                lmb_map_write(s2, &map, (const uint8_t *)&ok1, 4,
                              (const uint8_t *)&devb, 8);
                lmb_map_write(s2, &map, (const uint8_t *)&ok2, 4,
                              (const uint8_t *)&inob, 8);
                lmb_make_attach(&both[0], "on_getpid",
                                LMB_ATTACH_TRACEPOINT, "syscalls",
                                "sys_enter_getpid");
                lmb_make_attach(&both[1], "on_getpid_small",
                                LMB_ATTACH_TRACEPOINT, "syscalls",
                                "sys_enter_getpid");
                LMB_CHECK(lmb_attach(s2, both, 2) == 0, "mixed-attach",
                          "two-program transaction must attach");
                syscall(SYS_getpid);
                written = 0;
                required = 0xDEAD;
                LMB_CHECK(lmb_poll(s2, dst, sizeof(dst), &written,
                                   &required, 2000) == 0 &&
                              written == 16 && required == 0 &&
                              lmb_le32(dst) == 8 &&
                              lmb_le16(dst + 4) == LMB_FRAME_VERSION &&
                              lmb_le16(dst + 6) == 0 &&
                              lmb_le32(dst + 8) == pid &&
                              lmb_le32(dst + 12) == 0xA03u,
                          "mixed-skip-small",
                          "first poll must deliver the small frame");
                written = 0xDEAD;
                required = 0xDEAD;
                LMB_CHECK(lmb_poll(s2, dst, sizeof(dst), &written,
                                   &required, 0) == 0 &&
                              written == 0 && required == 0,
                          "mixed-skip-drained",
                          "second poll must yield 0/0");
                memset(&st2, 0, sizeof(st2));
                st2.abi_version = LMB_ABI_VERSION;
                st2.struct_size = sizeof(st2);
                lmb_make_name(&statmap, "test_stats");
                if (lmb_map_read(s2, &statmap, (const uint8_t *)&skey, 4,
                                 (uint8_t *)&attempts, 8, &sreq) != 0)
                    attempts = 0;
                LMB_CHECK(lmb_stats(s2, &st2) == 0 &&
                              st2.received == 2 && st2.delivered == 1 &&
                              st2.staged == 0 && st2.malformed == 1 &&
                              st2.dropped == 0 && attempts == 2,
                          "mixed-skip-counts",
                          "skip must reconcile 2/1/1 (r=%llu)",
                          (unsigned long long)st2.received);
                LMB_CHECK(lmb_detach(s2) == 0 && lmb_close(&s2) == 0 &&
                              s2 == NULL,
                          "mixed-teardown", "second session must close");
            }
        }
    }
    LMB_CHECK(lmb_detach(s) == 0 && lmb_close(&s) == 0 && s == NULL,
              "teardown-ok", "teardown must succeed");

    free(elf);
    return lmb_failures ? 1 : 0;
}
