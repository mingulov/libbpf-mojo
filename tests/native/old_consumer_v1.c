/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */

/* Old-header consumer fixture: exercises all eleven v1 operations
 * through the frozen header only, linked against the candidate
 * shared library. Including abi_v1_frozen.h (and never the live
 * header) proves an old consumer compiles against the frozen
 * contract; every call below runs unprivileged and must behave
 * exactly as docs/abi-v1.md specifies. */
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "abi_v1_frozen.h"

static int failures = 0;

#define OK(name) printf("ok %s\n", (name))
#define FAIL(name, ...)                                \
    do {                                               \
        printf("FAIL %s: ", (name));                   \
        printf(__VA_ARGS__);                           \
        printf("\n");                                  \
        failures++;                                    \
    } while (0)
#define CHECK(cond, name, ...)                         \
    do {                                               \
        if (cond)                                      \
            OK(name);                                  \
        else                                           \
            FAIL(name, __VA_ARGS__);                   \
    } while (0)

static void make_options(struct lmb_options_v1 *o) {
    static const char ring[] = "events";
    memset(o, 0, sizeof(*o));
    o->abi_version = LMB_ABI_VERSION;
    o->struct_size = sizeof(*o);
    o->ring.ptr = (const uint8_t *)ring;
    o->ring.len = sizeof(ring) - 1;
    o->max_raw_bytes = 4096;
    o->stage_slots = 1;
}

static void make_name(struct lmb_name_v1 *n, const char *s) {
    memset(n, 0, sizeof(*n));
    n->abi_version = LMB_ABI_VERSION;
    n->struct_size = sizeof(*n);
    n->name.ptr = (const uint8_t *)s;
    n->name.len = (uint32_t)strlen(s);
}

static int last_is(uint32_t op, uint32_t domain) {
    struct lmb_error_v1 err;
    memset(&err, 0, sizeof(err));
    err.abi_version = LMB_ABI_VERSION;
    err.struct_size = sizeof(err);
    return lmb_last_error(&err) == 0 && err.operation == op &&
           err.domain == domain;
}

int main(void) {
    /* Deliberately not an ELF object: v1 open copies bytes without
     * parsing (succeeds), load parses (fails unprivileged). */
    static const uint8_t garbage[64] = "not an ELF object at all";
    struct lmb_options_v1 o;
    struct lmb_name_v1 name;
    struct lmb_session *s = NULL;
    struct lmb_session *sentinel =
        (struct lmb_session *)(uintptr_t)0xDEAD;
    struct lmb_error_v1 err, again;
    struct lmb_stats_v1 st;
    struct lmb_map_info_v1 info;
    struct lmb_attach_v1 site;
    uint8_t dst[32];
    uint8_t key[4] = {7, 0, 0, 0};
    uint8_t value[8] = {0};
    uint32_t written = 0xBEEF;
    uint32_t required = 0xBEEF;

    CHECK(sizeof(struct lmb_options_v1) == 40 &&
              sizeof(struct lmb_attach_v1) == 64 &&
              sizeof(struct lmb_name_v1) == 24 &&
              sizeof(struct lmb_map_info_v1) == 40 &&
              sizeof(struct lmb_stats_v1) == 56 &&
              sizeof(struct lmb_error_v1) == 1048,
          "frozen-sizes", "frozen header sizes must match the contract");

    /* Failed open clears its output handle (abi-v1). */
    make_options(&o);
    o.abi_version = 99;
    s = sentinel;
    CHECK(lmb_open(garbage, sizeof(garbage), &o, &s) == -EINVAL &&
              s == NULL,
          "open-bad-version", "bad version must fail cleared");
    CHECK(last_is(LMB_OP_OPEN, LMB_DOMAIN_BRIDGE), "open-record",
          "failed open must report bridge usage");

    /* Null output handle fails without clearing anything. */
    make_options(&o);
    CHECK(lmb_open(garbage, sizeof(garbage), &o, NULL) == -EINVAL,
          "open-null-out", "null out handle must fail");

    /* Garbage bytes open (copy only) and fail only at load. */
    make_options(&o);
    s = NULL;
    CHECK(lmb_open(garbage, sizeof(garbage), &o, &s) == 0 && s != NULL,
          "open-garbage", "open must copy without parsing");
    CHECK(lmb_load(s) != 0, "load-garbage",
          "load must reject garbage ELF");
    CHECK(last_is(LMB_OP_LOAD, LMB_DOMAIN_LIBBPF), "load-record",
          "parse failure must report libbpf domain");

    /* Validation paths need no loaded object. */
    CHECK(lmb_load(NULL) == -EINVAL, "load-null",
          "null session must fail closed");
    memset(&site, 0, sizeof(site));
    site.abi_version = LMB_ABI_VERSION;
    site.struct_size = sizeof(site);
    CHECK(lmb_attach(NULL, &site, 1) == -EINVAL, "attach-null",
          "null session must fail closed");
    CHECK(lmb_attach(s, &site, 1) == -EINVAL, "attach-unloaded",
          "unloaded session must fail closed");
    written = 0xBEEF;
    required = 0xBEEF;
    CHECK(lmb_poll(NULL, dst, sizeof(dst), &written, &required, 0) ==
                  -EINVAL &&
              written == 0xBEEF && required == 0xBEEF,
          "poll-null-untouched", "null session must leave outs alone");
    CHECK(lmb_poll(s, dst, sizeof(dst), &written, &required, 0) ==
          -EINVAL, "poll-unloaded", "unloaded session must fail closed");

    /* Map validation on an unloaded session. */
    make_name(&name, "stat");
    memset(&info, 0, sizeof(info));
    info.abi_version = LMB_ABI_VERSION;
    info.struct_size = sizeof(info);
    CHECK(lmb_map_info(s, &name, &info) == -EINVAL, "map-info-unloaded",
          "map info needs a loaded session");
    required = 123;
    CHECK(lmb_map_read(s, &name, key, sizeof(key), value, sizeof(value),
                       &required) == -EINVAL,
          "map-read-unloaded", "map read needs a loaded session");
    CHECK(lmb_map_write(s, &name, key, sizeof(key), value,
                        sizeof(value)) == -EINVAL,
          "map-write-unloaded", "map write needs a loaded session");

    /* Stats and inspection behavior. */
    memset(&st, 0, sizeof(st));
    st.abi_version = LMB_ABI_VERSION;
    st.struct_size = sizeof(st);
    CHECK(lmb_stats(s, &st) == 0 && st.received == 0 &&
              st.delivered == 0 && st.staged == 0 &&
              st.malformed == 0 && st.dropped == 0,
          "stats-zeros", "fresh session counters must be zero");
    st.struct_size = 1;
    CHECK(lmb_stats(s, &st) == -EINVAL, "stats-short",
          "short struct must fail");
    memset(&err, 0, sizeof(err));
    err.abi_version = LMB_ABI_VERSION;
    err.struct_size = sizeof(err);
    CHECK(lmb_last_error(&err) == 0, "last-error-ok",
          "inspection must succeed");
    err.struct_size = 1;
    CHECK(lmb_last_error(&err) == -EINVAL, "last-error-short",
          "short inspection struct must fail");
    memset(&again, 0, sizeof(again));
    again.abi_version = LMB_ABI_VERSION;
    again.struct_size = sizeof(again);
    CHECK(lmb_last_error(&again) == 0 &&
              again.operation == err.operation &&
              again.domain == err.domain && again.code == err.code &&
              again.msg_len == err.msg_len,
          "last-error-preserved",
          "failed inspection must preserve the record");

    /* Detach with no links succeeds; close releases everything. */
    CHECK(lmb_detach(s) == 0, "detach-fresh",
          "detach with no links must succeed");
    CHECK(lmb_detach(NULL) == -EINVAL, "detach-null",
          "null session must fail closed");
    CHECK(lmb_close(&s) == 0 && s == NULL, "close-ok",
          "close must null the handle");
    CHECK(lmb_close(&s) == 0, "close-null-pointee",
          "double close must succeed");

    return failures ? 1 : 0;
}
