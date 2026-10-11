/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "generic_internal.h"

static int32_t fail(uint32_t domain, int32_t code, const char *message) {
    lmb_generic_record(LMB_GENERIC_OP_TEST_RUN, domain, code, message);
    return code;
}

int32_t lmb_program_test_run_v1(struct lmb_object *object,
    const struct lmb_name_v1 *name,
    const struct lmb_program_test_options_v1 *options,
    struct lmb_program_test_result_v1 *out) {
    struct lmb_program_test_options_v1 input;
    struct lmb_program_test_result_v1 completed;
    struct bpf_test_run_opts native;
    struct bpf_program *program;
    char text[257];
    uint8_t *data_in = NULL, *ctx_in = NULL, *data_out = NULL, *ctx_out = NULL;
    int32_t code;
    int fd;

    if (!options || !out || !name ||
        !lmb_generic_check_span(options, sizeof(*options)) ||
        !lmb_generic_check_span(out, sizeof(*out)) ||
        !lmb_generic_check_span(name, sizeof(*name)))
        return fail(LMB_GENERIC_DOMAIN_BRIDGE, -EINVAL, "invalid test-run arguments");
    if (options->abi_version != LMB_GENERIC_ABI_VERSION || options->struct_size != sizeof(*options) ||
        out->abi_version != LMB_GENERIC_ABI_VERSION || out->struct_size != sizeof(*out))
        return fail(LMB_GENERIC_DOMAIN_BRIDGE, -EINVAL, "invalid test-run header");
    input = *options;
    if (!lmb_generic_check_name(name) ||
        input.data_in.len > LMB_GENERIC_MAX_TEST_BYTES ||
        input.ctx_in.len > LMB_GENERIC_MAX_TEST_BYTES ||
        input.data_out.len > LMB_GENERIC_MAX_TEST_BYTES ||
        input.ctx_out.len > LMB_GENERIC_MAX_TEST_BYTES ||
        !lmb_generic_check_span(input.data_in.ptr, input.data_in.len) ||
        !lmb_generic_check_span(input.ctx_in.ptr, input.ctx_in.len) ||
        !lmb_generic_check_span(input.data_out.ptr, input.data_out.len) ||
        !lmb_generic_check_span(input.ctx_out.ptr, input.ctx_out.len))
        return fail(LMB_GENERIC_DOMAIN_BRIDGE, -EINVAL, "invalid test-run span or name");
    if (input.flags || input.repeat == 0 || input.repeat > INT_MAX)
        return fail(LMB_GENERIC_DOMAIN_BRIDGE, -EINVAL, "unsupported test-run flags or repeat");
    if (lmb_generic_ranges_overlap(input.data_out.ptr, input.data_out.len,
                                   input.ctx_out.ptr, input.ctx_out.len) ||
        lmb_generic_ranges_overlap(input.data_out.ptr, input.data_out.len, out, sizeof(*out)) ||
        lmb_generic_ranges_overlap(input.ctx_out.ptr, input.ctx_out.len, out, sizeof(*out)))
        return fail(LMB_GENERIC_DOMAIN_BRIDGE, -EINVAL, "test-run outputs overlap");
    memcpy(text, name->name.ptr, name->name.len);
    text[name->name.len] = 0;
    if (!lmb_object_need_loaded(object, LMB_GENERIC_OP_TEST_RUN)) return -EINVAL;
    program = bpf_object__find_program_by_name(object->obj, text);
    if (!program) return fail(LMB_GENERIC_DOMAIN_BRIDGE, -ENOENT, "program not found");
    if (bpf_program__type(program) != BPF_PROG_TYPE_XDP)
        return fail(LMB_GENERIC_DOMAIN_BRIDGE, -EOPNOTSUPP, "unsupported test-run program type");
    fd = bpf_program__fd(program);
    if (fd < 0) return fail(LMB_GENERIC_DOMAIN_LIBBPF, fd, "program FD is unavailable");

    /* Capture both inputs before any caller-visible commit. Options and
     * name values above are already local, so outputs may alias them. */
    if (input.data_in.len) {
        data_in = malloc((size_t)input.data_in.len);
        if (!data_in) goto no_memory;
        memcpy(data_in, input.data_in.ptr, (size_t)input.data_in.len);
    }
    if (input.ctx_in.len) {
        ctx_in = malloc((size_t)input.ctx_in.len);
        if (!ctx_in) goto no_memory;
        memcpy(ctx_in, input.ctx_in.ptr, (size_t)input.ctx_in.len);
    }
    if (input.data_out.len) {
        data_out = malloc((size_t)input.data_out.len);
        if (!data_out) goto no_memory;
    }
    if (input.ctx_out.len) {
        ctx_out = malloc((size_t)input.ctx_out.len);
        if (!ctx_out) goto no_memory;
    }
    memset(&native, 0, sizeof(native));
    native.sz = sizeof(native);
    native.data_in = data_in; native.ctx_in = ctx_in;
    native.data_out = data_out; native.ctx_out = ctx_out;
    native.data_size_in = (uint32_t)input.data_in.len;
    native.ctx_size_in = (uint32_t)input.ctx_in.len;
    native.data_size_out = (uint32_t)input.data_out.len;
    native.ctx_size_out = (uint32_t)input.ctx_out.len;
    native.repeat = (int)input.repeat;
    code = bpf_prog_test_run_opts(fd, &native);
    if (code) {
        code = fail(LMB_GENERIC_DOMAIN_KERNEL, code, "program test-run failed");
        goto done;
    }
    if ((input.data_out.len && native.data_size_out > input.data_out.len) ||
        (input.ctx_out.len && native.ctx_size_out > input.ctx_out.len)) {
        code = fail(LMB_GENERIC_DOMAIN_BRIDGE, -EOVERFLOW, "test-run actual exceeds output capacity");
        goto done;
    }
    memset(&completed, 0, sizeof(completed));
    completed.abi_version = LMB_GENERIC_ABI_VERSION;
    completed.struct_size = sizeof(completed);
    completed.retval = native.retval;
    completed.data_actual = native.data_size_out;
    completed.ctx_actual = native.ctx_size_out;
    completed.duration_ns = native.duration;
    if (input.data_out.len && native.data_size_out)
        memcpy(input.data_out.ptr, data_out, native.data_size_out);
    if (input.ctx_out.len && native.ctx_size_out)
        memcpy(input.ctx_out.ptr, ctx_out, native.ctx_size_out);
    *out = completed;
    lmb_generic_clear();
    goto done;

no_memory:
    code = fail(LMB_GENERIC_DOMAIN_POSIX, -ENOMEM, "allocation failed");
done:
    free(ctx_out); free(data_out); free(ctx_in); free(data_in);
    return code;
}
