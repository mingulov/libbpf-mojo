/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include "generic_internal.h"
#include "generic_events_host.h"

static void refused(struct lmb_object *object, const struct lmb_attach_options_v1 *opts, int code) {
    uint64_t calls = lmb_events_call_count(GE_ATTACH);
    unsigned refs = object ? object->refs : 0;
    struct lmb_link *link = (void *)1;
    CHECK(lmb_object_attach_v1(object, opts, &link) == code && !link);
    CHECK(lmb_events_call_count(GE_ATTACH) == calls);
    CHECK(!object || object->refs == refs);
    ge_diagnostic(10, 4, code);
}
static void validation(const char *fixture, const char *tracing) {
    struct lmb_object *object = ge_object(fixture, 0);
    struct lmb_attach_options_v1 opts = ge_attach_options(), bad;
    refused(object, &opts, -EINVAL); refused(NULL, &opts, -EINVAL); refused(object, NULL, -EINVAL);
    CHECK(lmb_object_attach_v1(object, &opts, NULL) == -EINVAL);
    CHECK(lmb_object_load_v1(object) == 0);
    for (unsigned i = 0; i < 18; i++) {
        bad = opts;
        switch(i) {
        case 0: bad.abi_version = 2; break;
        case 1: bad.struct_size--; break;
        case 2: bad.struct_size++; break;
        case 3: bad.family = 2; break;
        case 4: bad.flags = 1; break;
        case 5: bad._reserved = 1; break;
        case 6: bad.program.len = 0; break;
        case 7: bad.program.ptr = NULL; break;
        case 8: bad.program.len = 257; break;
        case 9: bad.program.ptr = (void *)(UINTPTR_MAX - 2); break;
        case 10: bad.target_a.len = 0; break;
        case 11: bad.target_b.ptr = NULL; break;
        case 12: bad.program.ptr = (const uint8_t *)"a\0b"; bad.program.len = 3; break;
        case 13: bad.target_a.ptr = (const uint8_t *)"\xc0\xaf"; bad.target_a.len = 2; break;
        case 14: bad.target_b.ptr = (const uint8_t *)"\xed\xa0\x80"; bad.target_b.len = 3; break;
        case 15: bad.program.ptr = (const uint8_t *)"\xf4\x90\x80\x80"; bad.program.len = 4; break;
        case 16: bad.target_a.ptr = (const uint8_t *)"\x80"; bad.target_a.len = 1; break;
        case 17: bad.target_b.ptr = (const uint8_t *)"\xe2\x82"; bad.target_b.len = 2; break;
        }
        refused(object, &bad, -EINVAL);
    }
    bad = opts; bad.program.ptr = (const uint8_t *)"missing"; bad.program.len = 7;
    refused(object, &bad, -ENOENT);
    bad = opts;
    struct lmb_link **alias = (void *)&bad._reserved;
    CHECK(lmb_object_attach_v1(object, &bad, alias) == -EINVAL && !*alias);
    uint8_t name[16] = "on_getpid"; bad = opts; bad.program.ptr = name;
    alias = (void *)name;
    CHECK(lmb_object_attach_v1(object, &bad, alias) == -EINVAL);
    ge_program_fd(-1); refused(object, &opts, -EINVAL); ge_program_fd(12345);
    /* Explicit target names need not equal the ELF section suffix. The
     * seam also proves the foreign call sees copied target strings. */
    char category[] = "alternate", event[] = "different";
    bad = opts; bad.target_a.ptr = (void *)category; bad.target_a.len = strlen(category);
    bad.target_b.ptr = (void *)event; bad.target_b.len = strlen(event);
    ge_attach_targets(category, event, category, event);
    struct lmb_link *link = NULL;
    CHECK(lmb_object_attach_v1(object, &bad, &link) == 0 && link);
    memset(category, 0xcc, sizeof(category)); memset(event, 0xcc, sizeof(event));
    CHECK(lmb_link_close_v1(&link) == 0);
    ge_attach_targets("syscalls", "sys_enter_getpid", opts.target_a.ptr, opts.target_b.ptr);
    CHECK(lmb_object_close_v1(&object) == 0);
    object = ge_object(tracing, 1);
    bad = opts; bad.program.ptr = (const uint8_t *)"missing"; bad.program.len = 7;
    refused(object, &bad, -ENOENT);
    bad.program.ptr = (const uint8_t *)"traced"; bad.program.len = 6;
    refused(object, &bad, -EOPNOTSUPP);
    bad.program.ptr = (const uint8_t *)"first"; bad.program.len = 5;
    refused(object, &bad, -EOPNOTSUPP);
    CHECK(lmb_object_close_v1(&object) == 0);
    puts("attach validation: strict spans, tracepoint-only, load/type/FD and aliases checked");
}
static void ownership(const char *fixture) {
    struct lmb_object *object = ge_object(fixture, 1);
    struct lmb_attach_options_v1 opts = ge_attach_options();
    struct lmb_buffer_options_v1 ropts = ge_buffer_options();
    struct lmb_link *a = NULL, *b = NULL;
    struct lmb_buffer *ring = NULL;
    CHECK(lmb_object_attach_v1(object, &opts, &a) == 0 && a);
    CHECK(object->refs == 2 && a->parent == object);
    CHECK(lmb_object_close_v1(&object) == -EBUSY && object);
    unsigned refs = object->refs;
    ge_alloc_fault(1);
    CHECK(lmb_object_attach_v1(object, &opts, &b) == -ENOMEM && !b);
    CHECK(ge_alloc_finish() == 1 && object->refs == refs); ge_diagnostic(10, 1, -ENOMEM);
    object->refs = UINT_MAX;
    uint64_t native = lmb_events_call_count(GE_ATTACH);
    CHECK(lmb_object_attach_v1(object, &opts, &b) == -EOVERFLOW && !b);
    CHECK(object->refs == UINT_MAX && lmb_events_call_count(GE_ATTACH) == native);
    ge_diagnostic(10, 4, -EOVERFLOW); object->refs = refs;
    for (int null_result = 0; null_result < 2; null_result++) {
        ge_attach_fault(-EACCES, null_result);
        CHECK(lmb_object_attach_v1(object, &opts, &b) == -EACCES && !b);
        CHECK(object->refs == refs); ge_diagnostic(10, 2, -EACCES);
    }
    ge_attach_fault(0, 0);
    CHECK(lmb_object_attach_v1(object, &opts, &b) == 0 && b);
    CHECK(lmb_buffer_open_v1(object, &ropts, &ring) == 0 && ring);
    CHECK(lmb_object_ref_v1(object) == 0); /* A retained view. */
    struct lmb_object *view = object;
    uint64_t before = lmb_events_close_count();
    lmb_object_release_v1(&object); CHECK(!object && view->refs == 4);
    CHECK(lmb_link_close_v1(&a) == 0 && !a);
    CHECK(view->refs == 3 && lmb_events_close_count() == before);
    ge_destroy_fault(-EIO);
    CHECK(lmb_link_close_v1(&b) == -EIO && !b); ge_diagnostic(11, 2, -EIO);
    CHECK(view->refs == 2 && lmb_events_close_count() == before);
    ge_destroy_fault(0);
    CHECK(lmb_buffer_close_v1(&ring) == 0 && !ring);
    CHECK(view->refs == 1 && lmb_events_close_count() == before);
    lmb_object_unref_v1(view); CHECK(lmb_events_close_count() == before + 1);
    CHECK(lmb_link_close_v1(&a) == 0); ge_diagnostic(0, 0, 0);
    CHECK(lmb_link_close_v1(NULL) == -EINVAL); ge_diagnostic(11, 4, -EINVAL);
    /* Cancellation after successful link creation and later setup refusal. */
    object = ge_object(fixture, 1);
    CHECK(lmb_object_attach_v1(object, &opts, &a) == 0);
    ropts.flags = 1; CHECK(lmb_buffer_open_v1(object, &ropts, &ring) == -EINVAL && !ring);
    CHECK(object->refs == 2); CHECK(lmb_link_close_v1(&a) == 0);
    CHECK(lmb_object_close_v1(&object) == 0);
    puts("attach ownership: overflow/allocation/native rollback, sibling retention, parent release and cancellation checked");
}
int main(int argc, char **argv) {
    if (argc != 3) return 2;
    unsigned fds = ge_fd_count(); ge_begin(argv[1]);
    validation(argv[1], argv[2]); ownership(argv[1]);
    for (unsigned i = 0; i < 100; i++) {
        struct lmb_object *object = ge_object(argv[1], 1);
        struct lmb_attach_options_v1 opts = ge_attach_options(); struct lmb_link *link = NULL;
        ge_attach_fault(-EIO, i % 2);
        CHECK(lmb_object_attach_v1(object, &opts, &link) == -EIO && !link && object->refs == 1);
        CHECK(lmb_object_close_v1(&object) == 0);
    }
    ge_attach_fault(0, 0);
    int result = ge_end("generic attach"); int stable = ge_fd_count() == fds; CHECK(stable);
    return result || !stable;
}
