/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <bpf/libbpf.h>
#include "generic_internal.h"
#include "internal.h"

static int32_t fail(uint32_t op, uint32_t domain, int32_t code, const char *text) {
    lmb_generic_record(op, domain, code, text); return code;
}
static int text_valid(struct lmb_span_v1 span) {
    if (span.len > 256 || !lmb_generic_check_span(span.ptr, span.len)) return 0;
    struct lmb_bytes_v1 bytes = {span.ptr, (uint32_t)span.len, 0};
    return lmb_check_bytes(&bytes, 256, 1);
}
static void text_copy(char dst[257], struct lmb_span_v1 span) {
    memcpy(dst, span.ptr, (size_t)span.len); dst[span.len] = 0;
}

int32_t lmb_object_attach_v1(struct lmb_object *object,
        const struct lmb_attach_options_v1 *opts, struct lmb_link **out) {
    const uint32_t op = LMB_GENERIC_OP_ATTACH;
    char name[257], category[257], event[257];
    if (!out || !lmb_generic_check_span(out, sizeof(*out)))
        return fail(op, LMB_GENERIC_DOMAIN_BRIDGE, -EINVAL, "invalid link output");
    *out = NULL;
    if (!opts || !lmb_generic_check_span(opts, sizeof(*opts)) ||
        !lmb_check_header(opts->abi_version, opts->struct_size, sizeof(*opts)))
        return fail(op, LMB_GENERIC_DOMAIN_BRIDGE, -EINVAL, "invalid attach options header");
    if (!text_valid(opts->program) || !text_valid(opts->target_a) || !text_valid(opts->target_b) ||
        opts->family != LMB_ATTACH_FAMILY_TRACEPOINT || opts->flags || opts->_reserved)
        return fail(op, LMB_GENERIC_DOMAIN_BRIDGE, -EINVAL, "invalid attach names, family or flags");
    if (lmb_generic_ranges_overlap(out, sizeof(*out), opts, sizeof(*opts)) ||
        lmb_generic_ranges_overlap(out, sizeof(*out), opts->program.ptr, opts->program.len) ||
        lmb_generic_ranges_overlap(out, sizeof(*out), opts->target_a.ptr, opts->target_a.len) ||
        lmb_generic_ranges_overlap(out, sizeof(*out), opts->target_b.ptr, opts->target_b.len))
        return fail(op, LMB_GENERIC_DOMAIN_BRIDGE, -EINVAL, "link output aliases attach input");
    if (!lmb_object_need_loaded(object, op)) return -EINVAL;
    text_copy(name, opts->program); text_copy(category, opts->target_a); text_copy(event, opts->target_b);
    struct bpf_program *program = bpf_object__find_program_by_name(object->obj, name);
    if (!program) return fail(op, LMB_GENERIC_DOMAIN_BRIDGE, -ENOENT, "program not found");
    if (bpf_program__type(program) != BPF_PROG_TYPE_TRACEPOINT)
        return fail(op, LMB_GENERIC_DOMAIN_BRIDGE, -EOPNOTSUPP, "program is not a tracepoint");
    if (bpf_program__fd(program) < 0)
        return fail(op, LMB_GENERIC_DOMAIN_BRIDGE, -EINVAL, "tracepoint has no loaded FD");
    struct lmb_link *child = calloc(1, sizeof(*child));
    if (!child) return fail(op, LMB_GENERIC_DOMAIN_POSIX, -ENOMEM, "link allocation failed");
    int32_t code = lmb_object_ref_v1(object);
    if (code) { free(child); return fail(op, LMB_GENERIC_DOMAIN_BRIDGE, code, "link owner reference failed"); }
    child->parent = object;
    child->link = bpf_program__attach_tracepoint(program, category, event);
    code = (int32_t)libbpf_get_error(child->link);
    if (code) {
        free(child); lmb_object_unref_v1(object);
        return fail(op, LMB_GENERIC_DOMAIN_LIBBPF, code, "tracepoint attachment failed");
    }
    *out = child; lmb_generic_clear(); return 0;
}

int32_t lmb_link_close_v1(struct lmb_link **cell) {
    const uint32_t op = LMB_GENERIC_OP_LINK_CLOSE;
    if (!cell || !lmb_generic_check_span(cell, sizeof(*cell)))
        return fail(op, LMB_GENERIC_DOMAIN_BRIDGE, -EINVAL, "invalid link cell");
    if (*cell) {
        struct lmb_link *child = *cell;
        struct lmb_object *parent = child->parent;
        int32_t code = bpf_link__destroy(child->link);
        *cell = NULL; free(child); lmb_object_unref_v1(parent);
        if (code) return fail(op, LMB_GENERIC_DOMAIN_LIBBPF, code, "link destruction failed");
    }
    lmb_generic_clear(); return 0;
}
