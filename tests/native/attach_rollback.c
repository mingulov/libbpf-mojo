/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */

/* Attach transactionality: all sites attach or none do. Requires
 * collection privileges; reports SKIP when the kernel refuses.
 * Rollback is proven behaviorally (a failed transaction leaves the
 * session reusable) plus ASan leak coverage of the failure path. */
#include "testutil.h"

int main(int argc, char **argv) {
    const char *fixture = lmb_fixture(argc, argv);
    uint8_t *elf = NULL;
    uint64_t elf_len = 0;
    struct lmb_options_v1 o;
    struct lmb_attach_v1 good, bad, mixed[2];
    struct lmb_session *s = NULL;

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

    lmb_make_attach(&good, "on_getpid", LMB_ATTACH_TRACEPOINT, "syscalls",
                    "sys_enter_getpid");
    lmb_make_attach(&bad, "no_such_program", LMB_ATTACH_TRACEPOINT,
                    "syscalls", "sys_enter_getpid");

    LMB_CHECK(lmb_attach(s, &bad, 1) != 0 &&
                  lmb_error_is(LMB_OP_ATTACH, LMB_DOMAIN_BRIDGE),
              "unknown-program", "unknown program must fail closed");
    LMB_CHECK(lmb_attach(s, &good, 1) == 0, "usable-after-failure",
              "session must stay usable after failed attach");
    LMB_CHECK(lmb_detach(s) == 0, "detach-after-failure",
              "detach must succeed");

    /* Failed transactions must not leak descriptors: the created
     * link is destroyed, not orphaned. */
    {
        long before = lmb_count_fds();
        int mrc;
        mixed[0] = good;
        mixed[1] = bad;
        mrc = lmb_attach(s, mixed, 2);
        LMB_CHECK(mrc != 0 && before >= 0 &&
                      lmb_count_fds() == before,
                  "mixed-fails",
                  "mixed valid/bogus transaction must fail clean");
    }
    LMB_CHECK(lmb_attach(s, &good, 1) == 0, "rollback-clean",
              "failed transaction must leave no partial links");
    LMB_CHECK(lmb_attach(s, &good, 1) != 0, "double-attach",
              "second attach without detach must fail");
    LMB_CHECK(lmb_detach(s) == 0, "detach-ok", "detach must succeed");

    good.kind = 99;
    LMB_CHECK(lmb_attach(s, &good, 1) != 0 &&
                  lmb_error_is(LMB_OP_ATTACH, LMB_DOMAIN_BRIDGE),
              "bad-kind", "unknown kind must fail before libbpf");
    lmb_make_attach(&good, "on_getpid", LMB_ATTACH_TRACEPOINT, "syscalls",
                    "sys_enter_getpid");
    good.abi_version = 0;
    LMB_CHECK(lmb_attach(s, &good, 1) != 0 &&
                  lmb_error_is(LMB_OP_ATTACH, LMB_DOMAIN_BRIDGE),
              "bad-site-version", "bad site header must fail");

    /* The fixture program is a tracepoint, not fentry: attaching it as
     * tracing must fail target verification. A positive tracing attach
     * needs BTF-backed fixtures and is covered when those exist. */
    lmb_make_attach(&good, "on_getpid", LMB_ATTACH_TRACING, "anything", "");
    LMB_CHECK(lmb_attach(s, &good, 1) != 0, "tracing-mismatch",
              "tracing attach must verify the ELF target");
    LMB_CHECK(lmb_detach(s) == 0 && lmb_detach(s) == 0,
              "detach-idempotent", "detach must be idempotent");

    /* A load that fails after map creation (unknown ring name) must
     * roll back without leaking descriptors. */
    {
        struct lmb_options_v1 ob;
        struct lmb_session *d = NULL;
        long before = lmb_count_fds();
        lmb_make_options(&ob, "no_such_ring", 4096);
        LMB_CHECK(lmb_open(elf, elf_len, &ob, &d) == 0 && d != NULL,
                  "load-bad-ring-open", "open must succeed");
        if (d != NULL) {
            LMB_CHECK(lmb_load(d) == -ENOENT &&
                          lmb_error_is(LMB_OP_LOAD,
                                       LMB_DOMAIN_BRIDGE),
                      "load-bad-ring",
                      "unknown ring must fail bridge ENOENT");
            LMB_CHECK(lmb_close(&d) == 0 && d == NULL &&
                          before >= 0 && lmb_count_fds() == before,
                      "load-bad-ring-clean",
                      "failed load must hold fds steady");
        }
    }

    /* The fixture carries pinning metadata; the bridge disables it.
     * When bpffs is visible, no pin may escape the load above. */
    {
        DIR *bpffs = opendir("/sys/fs/bpf");
        if (!bpffs) {
            printf("note no-bpffs: pin escape unscannable\n");
        } else {
            struct dirent *ent;
            int escaped = 0;
            while ((ent = readdir(bpffs)) != NULL) {
                if (strstr(ent->d_name, "test_pinned") ||
                    strstr(ent->d_name, "libbpf_mojo"))
                    escaped = 1;
            }
            closedir(bpffs);
            LMB_CHECK(!escaped, "no-pins",
                      "load must leave no filesystem pins");
        }
    }
    LMB_CHECK(lmb_close(&s) == 0 && s == NULL, "close-ok",
              "close must succeed");

    free(elf);
    return lmb_failures ? 1 : 0;
}
