/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* Real ELF/program lookup and pinned libbpf test-run forwarding. Only
 * loaded state, FD access and the guarded syscall response are doubles. */
#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <linux/bpf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "libbpf_mojo_generic.h"

#ifdef LMB_TESTRUN_RED_BASELINE
#pragma weak lmb_program_test_run_v1
#endif

static unsigned checks, failures, bpf_calls, native_calls, fd_queries, closes;
static int load_result, synthetic_fd = 0x1bad;
static int allocation_window, allocation_fault;
static unsigned allocation_calls, allocation_failures, allocation_live;
static void *owned_allocations[16];
#define CHECK(c) do { checks++; if (!(c)) { failures++; \
    fprintf(stderr, "FAIL line %u: %s\n", __LINE__, #c); } } while (0)

static struct {
    int armed, error;
    struct lmb_program_test_options_v1 caller;
    struct lmb_program_test_result_v1 *result;
    uint32_t data_actual, ctx_actual, retval, duration;
    unsigned repeat;
} script;

static int overlap(const void *a, size_t an, const void *b, size_t bn) {
    uintptr_t ap = (uintptr_t)a, bp = (uintptr_t)b;
    return an && bn && (ap <= bp ? bp - ap < an : ap - bp < bn);
}
static int is_owned(const void *pointer) {
    for (unsigned i = 0; i < 16; i++) if (owned_allocations[i] == pointer) return pointer != NULL;
    return 0;
}
static void scratch(const void *pointer, size_t length) {
    if (!length) { CHECK(pointer == NULL); return; }
    CHECK(pointer != NULL && is_owned(pointer));
    CHECK(!overlap(pointer, length, script.caller.data_in.ptr, script.caller.data_in.len));
    CHECK(!overlap(pointer, length, script.caller.ctx_in.ptr, script.caller.ctx_in.len));
    CHECK(!overlap(pointer, length, script.caller.data_out.ptr, script.caller.data_out.len));
    CHECK(!overlap(pointer, length, script.caller.ctx_out.ptr, script.caller.ctx_out.len));
    CHECK(!overlap(pointer, length, script.result, sizeof(*script.result)));
}
static uint8_t pattern(int context, size_t index) {
    return (uint8_t)(context ? 0x9d - index * 7 : 0x5b + index * 3);
}

long lmb_test_bpf_dispatch(int command, void *raw_attr, unsigned int size) {
    union bpf_attr *attr = raw_attr;
    if (!script.armed || !attr || command != BPF_PROG_TEST_RUN) {
        fputs("HOST GUARD: unscripted BPF request stopped before execution\n", stderr);
        _exit(99);
    }
    script.armed = 0; bpf_calls++;
    CHECK(size == offsetof(union bpf_attr, test) + sizeof(attr->test));
    CHECK(attr->test.prog_fd == (uint32_t)synthetic_fd);
    CHECK(attr->test.repeat == script.repeat);
    CHECK(attr->test.flags == 0 && attr->test.cpu == 0 && attr->test.batch_size == 0);
    CHECK(attr->test.retval == 0 && attr->test.duration == 0);
    CHECK(attr->test.data_size_in == script.caller.data_in.len);
    CHECK(attr->test.ctx_size_in == script.caller.ctx_in.len);
    CHECK(attr->test.data_size_out == script.caller.data_out.len);
    CHECK(attr->test.ctx_size_out == script.caller.ctx_out.len);
    const uint8_t *data_in = (const void *)(uintptr_t)attr->test.data_in;
    const uint8_t *ctx_in = (const void *)(uintptr_t)attr->test.ctx_in;
    uint8_t *data_out = (void *)(uintptr_t)attr->test.data_out;
    uint8_t *ctx_out = (void *)(uintptr_t)attr->test.ctx_out;
    scratch(data_in, attr->test.data_size_in); scratch(ctx_in, attr->test.ctx_size_in);
    scratch(data_out, attr->test.data_size_out); scratch(ctx_out, attr->test.ctx_size_out);
    CHECK(!overlap(data_in, attr->test.data_size_in, ctx_in, attr->test.ctx_size_in));
    CHECK(!overlap(data_out, attr->test.data_size_out, ctx_out, attr->test.ctx_size_out));
    if (attr->test.data_size_in)
        CHECK(!memcmp(data_in, script.caller.data_in.ptr, attr->test.data_size_in));
    if (attr->test.ctx_size_in)
        CHECK(!memcmp(ctx_in, script.caller.ctx_in.ptr, attr->test.ctx_size_in));
    size_t count = script.data_actual < attr->test.data_size_out ?
        script.data_actual : attr->test.data_size_out;
    for (size_t i = 0; i < count; i++) data_out[i] = pattern(0, i);
    count = script.ctx_actual < attr->test.ctx_size_out ? script.ctx_actual : attr->test.ctx_size_out;
    for (size_t i = 0; i < count; i++) ctx_out[i] = pattern(1, i);
    /* The real libbpf wrapper copies these fields back even on failure. */
    attr->test.data_size_out = script.data_actual;
    attr->test.ctx_size_out = script.ctx_actual;
    attr->test.retval = script.retval;
    attr->test.duration = script.duration;
    if (script.error) { errno = -script.error; return -1; }
    return 0;
}

int __wrap_bpf_object__load(struct bpf_object *object) {
    CHECK(object != NULL); return load_result;
}
int __real_bpf_program__fd(const struct bpf_program *program);
int __wrap_bpf_program__fd(const struct bpf_program *program) {
    CHECK(program != NULL && __real_bpf_program__fd(program) == -ENOENT);
    CHECK(!strcmp(bpf_program__name(program), "packet_control"));
    fd_queries++; return synthetic_fd;
}
void __real_bpf_object__close(struct bpf_object *object);
void __wrap_bpf_object__close(struct bpf_object *object) {
    if (object) {
        struct bpf_program *program;
        bpf_object__for_each_program(program, object)
            CHECK(__real_bpf_program__fd(program) == -ENOENT);
        closes++;
    }
    __real_bpf_object__close(object);
}
/* Observe the complete native record, then call its real pinned routine.
 * Only this test target wraps the function; no production observer exists. */
int __real_bpf_prog_test_run_opts(int fd, struct bpf_test_run_opts *options);
int __wrap_bpf_prog_test_run_opts(int fd, struct bpf_test_run_opts *options) {
    struct bpf_test_run_opts expected;
    memset(&expected, 0, sizeof(expected));
    native_calls++;
    CHECK(script.armed && options != NULL && fd == synthetic_fd);
    CHECK(options->sz == sizeof(*options));
    expected.sz = sizeof(expected);
    expected.data_in = script.caller.data_in.len ? options->data_in : NULL;
    expected.ctx_in = script.caller.ctx_in.len ? options->ctx_in : NULL;
    expected.data_out = script.caller.data_out.len ? options->data_out : NULL;
    expected.ctx_out = script.caller.ctx_out.len ? options->ctx_out : NULL;
    expected.data_size_in = (uint32_t)script.caller.data_in.len;
    expected.ctx_size_in = (uint32_t)script.caller.ctx_in.len;
    expected.data_size_out = (uint32_t)script.caller.data_out.len;
    expected.ctx_size_out = (uint32_t)script.caller.ctx_out.len;
    expected.repeat = (int)script.repeat;
    CHECK(!memcmp(options, &expected, sizeof(expected)));
    int result = __real_bpf_prog_test_run_opts(fd, options);
    errno = ENOTTY; /* Signed return must survive conflicting ambient errno. */
    return result;
}

void *__real_malloc(size_t size);
void *__wrap_malloc(size_t size) {
    if (!allocation_window) return __real_malloc(size);
    allocation_calls++;
    if (allocation_fault > 0 && allocation_calls == (unsigned)allocation_fault) {
        allocation_failures++; errno = ENOMEM; return NULL;
    }
    void *memory = __real_malloc(size);
    if (memory) {
        unsigned i;
        for (i = 0; i < 16 && owned_allocations[i]; i++);
        CHECK(i < 16);
        if (i < 16) { owned_allocations[i] = memory; allocation_live++; }
    }
    return memory;
}
void __real_free(void *pointer);
void __wrap_free(void *pointer) {
    if (pointer) for (unsigned i = 0; i < 16; i++) {
        if (owned_allocations[i] == pointer) {
            owned_allocations[i] = NULL; allocation_live--; break;
        }
    }
    __real_free(pointer);
}
static void start_allocations(int fault) {
    CHECK(allocation_live == 0);
    allocation_calls = 0; allocation_fault = fault; allocation_window = 1;
}
static unsigned finish_allocations(void) {
    allocation_window = 0; allocation_fault = 0;
    CHECK(allocation_live == 0);
    return allocation_calls;
}

static struct lmb_name_v1 name_of(const char *text) {
    struct lmb_name_v1 name = {1, sizeof(name),
        {(const uint8_t *)text, (uint32_t)strlen(text), 0}};
    return name;
}
static struct lmb_program_test_options_v1 options_of(void) {
    struct lmb_program_test_options_v1 options = {0};
    options.abi_version = 1; options.struct_size = sizeof(options); options.repeat = 1;
    return options;
}
static void result_header(struct lmb_program_test_result_v1 *result) {
    memset(result, 0xaa, sizeof(*result));
    result->abi_version = 1; result->struct_size = sizeof(*result);
}
static void diagnostic(uint32_t domain, int32_t code) {
    struct lmb_generic_error_v1 error = {0};
    error.abi_version = 1; error.struct_size = sizeof(error);
    CHECK(lmb_generic_last_error_v1(&error) == 0);
    CHECK(error.operation == LMB_GENERIC_OP_TEST_RUN && error.domain == domain && error.code == code);
    CHECK(error.msg_len > 0 && error.msg_len <= 1023 && !error.message[error.msg_len]);
    for (size_t i = error.msg_len; i < sizeof(error.message); i++) CHECK(error.message[i] == 0);
}
static void clear_diagnostic(void) {
    struct lmb_generic_error_v1 error = {0};
    error.abi_version = 1; error.struct_size = sizeof(error);
    CHECK(lmb_generic_last_error_v1(&error) == 0);
    CHECK(error.operation == 0 && error.domain == 0 && error.code == 0);
}
static unsigned fd_count(void) {
    DIR *directory = opendir("/proc/self/fd");
    if (!directory) { perror("opendir fd"); exit(1); }
    unsigned count = 0; struct dirent *entry;
    while ((entry = readdir(directory))) if (entry->d_name[0] != '.') count++;
    closedir(directory); return count;
}
static struct lmb_object *open_fixture(const uint8_t *elf, size_t size, int loaded) {
    struct lmb_object_options_v1 options = {0};
    struct lmb_object *object = NULL;
    options.abi_version = 1; options.struct_size = sizeof(options);
    CHECK(lmb_object_open_v1(elf, size, &options, &object) == 0 && object);
    if (!object) exit(1);
    if (loaded) CHECK(lmb_object_load_v1(object) == load_result);
    return object;
}
static uint8_t *read_fixture(const char *path, size_t *size) {
    FILE *file = fopen(path, "rb");
    if (!file) { perror("fixture"); exit(1); }
    CHECK(fseek(file, 0, SEEK_END) == 0);
    long length = ftell(file); CHECK(length > 0); rewind(file);
    if (length <= 0) exit(1);
    uint8_t *elf = malloc((size_t)length); CHECK(elf != NULL);
    if (!elf) exit(1);
    CHECK(fread(elf, 1, (size_t)length, file) == (size_t)length && fclose(file) == 0);
    *size = (size_t)length; return elf;
}
static void unchanged(const uint8_t *memory, size_t length, uint8_t byte) {
    int intact = 1;
    for (size_t i = 0; i < length; i++) if (memory[i] != byte) { intact = 0; break; }
    CHECK(intact);
}
static void invalid(struct lmb_object *object, const struct lmb_name_v1 *name,
    const struct lmb_program_test_options_v1 *options, struct lmb_program_test_result_v1 *result,
    uint8_t *watched, size_t watched_size, int32_t code, uint32_t domain, unsigned fd_gets) {
    struct lmb_program_test_result_v1 before;
    int valid_result = result && (uintptr_t)result <= UINTPTR_MAX - sizeof(*result);
    if (valid_result) memcpy(&before, result, sizeof(before));
    uint8_t *bytes = watched_size ? malloc(watched_size) : NULL;
    if (watched_size) { CHECK(bytes != NULL); if (!bytes) exit(1); memcpy(bytes, watched, watched_size); }
    unsigned calls = bpf_calls, native = native_calls, fds = fd_queries;
    start_allocations(0);
    CHECK(lmb_program_test_run_v1(object, name, options, result) == code);
    CHECK(finish_allocations() == 0);
    CHECK(bpf_calls == calls && native_calls == native && fd_queries == fds + fd_gets);
    if (valid_result) CHECK(!memcmp(result, &before, sizeof(before)));
    if (watched_size) CHECK(!memcmp(bytes, watched, watched_size));
    free(bytes); diagnostic(domain, code);
}

static void validation(struct lmb_object *object, struct lmb_object *unloaded,
                       struct lmb_object *tracepoint) {
    struct lmb_name_v1 name = name_of("packet_control"), bad, missing = name_of("missing_program");
    struct lmb_name_v1 trace = name_of("on_getpid");
    struct lmb_program_test_options_v1 options = options_of(), broken;
    struct lmb_program_test_result_v1 result;
    uint8_t arena[256]; memset(arena, 0xa5, sizeof(arena)); result_header(&result);
    options.data_in.ptr = arena; options.data_in.len = 61;
    options.ctx_in.ptr = arena + 64; options.ctx_in.len = 24;
    options.data_out.ptr = arena + 96; options.data_out.len = 97;
    options.ctx_out.ptr = arena + 200; options.ctx_out.len = 40;
#define INVALID(obj, nm, op, res, rc) invalid(obj, nm, op, res, arena, sizeof(arena), rc, LMB_GENERIC_DOMAIN_BRIDGE, 0)
    INVALID(NULL, &name, &options, &result, -EINVAL);
    INVALID(object, NULL, &options, &result, -EINVAL);
    INVALID(object, &name, NULL, &result, -EINVAL);
    INVALID(object, &name, &options, NULL, -EINVAL);
    INVALID(unloaded, &name, &options, &result, -EINVAL);
    INVALID(object, &name, (const void *)(UINTPTR_MAX - 7), &result, -EINVAL);
    INVALID(object, (const void *)(UINTPTR_MAX - 7), &options, &result, -EINVAL);
    INVALID(object, &name, &options, (void *)(UINTPTR_MAX - 7), -EINVAL);
    broken = options; broken.abi_version = 99;
    INVALID(object, &missing, &broken, &result, -EINVAL);
    for (int delta = -1; delta <= 1; delta += 2) {
        broken = options; broken.struct_size = sizeof(broken) + delta;
        INVALID(object, &name, &broken, &result, -EINVAL);
        result.struct_size = sizeof(result) + delta;
        INVALID(object, &name, &options, &result, -EINVAL); result_header(&result);
        bad = name; bad.struct_size = sizeof(bad) + delta;
        INVALID(object, &bad, &options, &result, -EINVAL);
    }
    result.abi_version = 0; INVALID(object, &name, &options, &result, -EINVAL); result_header(&result);
    bad = name; bad.abi_version = 0; INVALID(object, &bad, &options, &result, -EINVAL);
    bad = name; bad.name._pad = 1; INVALID(object, &bad, &options, &result, -EINVAL);
    const char *names[] = {"", "a\0b", "\xff", "\xc0\xaf", "\xed\xa0\x80", "\xe2\x82"};
    const unsigned sizes[] = {0, 3, 1, 2, 3, 2};
    for (unsigned i = 0; i < sizeof(sizes)/sizeof(*sizes); i++) {
        bad = name; bad.name.ptr = (const void *)names[i]; bad.name.len = sizes[i];
        INVALID(object, &bad, &options, &result, -EINVAL);
    }
    bad = name; bad.name.len = 257; INVALID(object, &bad, &options, &result, -EINVAL);
    bad = name; bad.name.ptr = NULL; INVALID(object, &bad, &options, &result, -EINVAL);
    bad = name; bad.name.ptr = (const void *)(UINTPTR_MAX - 1); bad.name.len = 4;
    INVALID(object, &bad, &options, &result, -EINVAL);
    for (unsigned span = 0; span < 4; span++) {
        broken = options;
        if (span == 0) broken.data_in.ptr = NULL;
        if (span == 1) broken.ctx_in.ptr = NULL;
        if (span == 2) broken.data_out.ptr = NULL;
        if (span == 3) broken.ctx_out.ptr = NULL;
        INVALID(object, &name, &broken, &result, -EINVAL);
        if (span == 0) broken.data_in.ptr = (const void *)(UINTPTR_MAX - 1);
        if (span == 1) broken.ctx_in.ptr = (const void *)(UINTPTR_MAX - 1);
        if (span == 2) broken.data_out.ptr = (void *)(UINTPTR_MAX - 1);
        if (span == 3) broken.ctx_out.ptr = (void *)(UINTPTR_MAX - 1);
        INVALID(object, &name, &broken, &result, -EINVAL);
        broken = options;
        if (span == 0) broken.data_in.len = 1048577;
        if (span == 1) broken.ctx_in.len = 1048577;
        if (span == 2) broken.data_out.len = 1048577;
        if (span == 3) broken.ctx_out.len = 1048577;
        INVALID(object, &name, &broken, &result, -EINVAL);
        if (span == 0) broken.data_in.len = UINT64_MAX;
        if (span == 1) broken.ctx_in.len = UINT64_MAX;
        if (span == 2) broken.data_out.len = UINT64_MAX;
        if (span == 3) broken.ctx_out.len = UINT64_MAX;
        INVALID(object, &name, &broken, &result, -EINVAL);
    }
    const uint64_t repeats[] = {0, UINT64_C(2147483648), UINT64_MAX};
    for (unsigned i = 0; i < sizeof(repeats)/sizeof(*repeats); i++) {
        broken = options; broken.repeat = repeats[i];
        INVALID(object, &name, &broken, &result, -EINVAL);
    }
    const uint64_t flags[] = {1, 2, 4, UINT64_C(1) << 63, UINT64_MAX};
    for (unsigned i = 0; i < sizeof(flags)/sizeof(*flags); i++) {
        broken = options; broken.flags = flags[i];
        INVALID(object, &name, &broken, &result, -EINVAL);
    }
    broken = options; broken.ctx_out.ptr = arena + 192;
    INVALID(object, &name, &broken, &result, -EINVAL);
    broken = options; broken.ctx_out.ptr = broken.data_out.ptr;
    INVALID(object, &name, &broken, &result, -EINVAL);
    broken = options; broken.data_out.ptr = (void *)&result; broken.data_out.len = sizeof(result);
    INVALID(object, &name, &broken, &result, -EINVAL);
    broken = options; broken.ctx_out.ptr = (uint8_t *)&result + sizeof(result) - 1; broken.ctx_out.len = 1;
    INVALID(object, &name, &broken, &result, -EINVAL);
    INVALID(object, &missing, &options, &result, -ENOENT);
    INVALID(tracepoint, &trace, &options, &result, -EOPNOTSUPP);
    broken = options; broken.data_in.ptr = NULL;
    INVALID(tracepoint, &trace, &broken, &result, -EINVAL);
    INVALID(tracepoint, &missing, &broken, &result, -EINVAL);
    INVALID(tracepoint, &missing, &options, &result, -ENOENT);
    broken = options; broken.data_out.ptr = (void *)&result;
    INVALID(tracepoint, &trace, &broken, &result, -EINVAL);
    synthetic_fd = -EBADF;
    invalid(object, &name, &options, &result, arena, sizeof(arena), -EBADF, LMB_GENERIC_DOMAIN_LIBBPF, 1);
    synthetic_fd = -ENOENT;
    invalid(object, &name, &options, &result, arena, sizeof(arena), -ENOENT, LMB_GENERIC_DOMAIN_LIBBPF, 1);
    synthetic_fd = -1;
    invalid(object, &name, &options, &result, arena, sizeof(arena), -1, LMB_GENERIC_DOMAIN_LIBBPF, 1);
    synthetic_fd = 0x1bad;
    unchanged(arena, sizeof(arena), 0xa5);
#undef INVALID
    puts("test-run validation: headers/spans/name/repeat/flags/overlap/state/type/FD checked without execution");
}

static unsigned run(struct lmb_object *object, const struct lmb_name_v1 *name,
    const struct lmb_program_test_options_v1 *options, struct lmb_program_test_result_v1 *result,
    uint32_t data_actual, uint32_t ctx_actual, uint32_t retval, uint32_t duration,
    int native_error, int expected_error) {
    struct lmb_program_test_options_v1 saved = *options;
    struct lmb_program_test_result_v1 before = *result;
    uint8_t *data_before = saved.data_out.len ? malloc(saved.data_out.len) : NULL;
    uint8_t *ctx_before = saved.ctx_out.len ? malloc(saved.ctx_out.len) : NULL;
    if (saved.data_out.len) { CHECK(data_before != NULL); if (!data_before) exit(1); memcpy(data_before, saved.data_out.ptr, saved.data_out.len); }
    if (saved.ctx_out.len) { CHECK(ctx_before != NULL); if (!ctx_before) exit(1); memcpy(ctx_before, saved.ctx_out.ptr, saved.ctx_out.len); }
    CHECK(!script.armed);
    script.armed = 1; script.error = native_error; script.caller = saved;
    script.result = result; script.data_actual = data_actual; script.ctx_actual = ctx_actual;
    script.retval = retval; script.duration = duration; script.repeat = (unsigned)saved.repeat;
    unsigned syscalls = bpf_calls, native = native_calls, fds = fd_queries;
    start_allocations(0);
    CHECK(lmb_program_test_run_v1(object, name, options, result) == expected_error);
    unsigned allocations = finish_allocations();
    CHECK(!script.armed && bpf_calls == syscalls + 1 && native_calls == native + 1 && fd_queries == fds + 1);
    if (expected_error) {
        CHECK(!memcmp(result, &before, sizeof(before)));
        if (saved.data_out.len) CHECK(!memcmp(saved.data_out.ptr, data_before, saved.data_out.len));
        if (saved.ctx_out.len) CHECK(!memcmp(saved.ctx_out.ptr, ctx_before, saved.ctx_out.len));
        diagnostic(native_error ? LMB_GENERIC_DOMAIN_KERNEL : LMB_GENERIC_DOMAIN_BRIDGE, expected_error);
    } else {
        CHECK(result->abi_version == 1 && result->struct_size == sizeof(*result) && result->_pad == 0);
        CHECK(result->retval == retval && result->duration_ns == duration);
        CHECK(result->data_actual == data_actual && result->ctx_actual == ctx_actual);
        if (saved.data_out.len) {
            CHECK(data_actual <= saved.data_out.len);
            if (data_actual <= saved.data_out.len) {
                for (size_t i = 0; i < data_actual; i++) CHECK(saved.data_out.ptr[i] == pattern(0, i));
                CHECK(!memcmp(saved.data_out.ptr + data_actual, data_before + data_actual, saved.data_out.len - data_actual));
            }
        }
        if (saved.ctx_out.len) {
            CHECK(ctx_actual <= saved.ctx_out.len);
            if (ctx_actual <= saved.ctx_out.len) {
                for (size_t i = 0; i < ctx_actual; i++) CHECK(saved.ctx_out.ptr[i] == pattern(1, i));
                CHECK(!memcmp(saved.ctx_out.ptr + ctx_actual, ctx_before + ctx_actual, saved.ctx_out.len - ctx_actual));
            }
        }
        clear_diagnostic();
    }
    free(data_before); free(ctx_before); return allocations;
}

enum aliases { DATA_ALIAS = 1, CTX_ALIAS = 2, CROSS_OUTPUTS = 4, CROSS_INPUTS = 8,
               RESULT_DATA = 16, RESULT_CTX = 32, ADJACENT = 64, OPTIONS_OUTPUT = 128,
               NAME_OUTPUT = 256, NAME_RESULT = 512 };
static unsigned ordinary(struct lmb_object *object, unsigned mode, int omission,
                          int error, uint32_t data_actual, uint32_t ctx_actual) {
    struct { struct lmb_program_test_options_v1 options; uint8_t spill[40]; } control;
    struct { struct lmb_name_v1 name; uint8_t text[104]; } named;
    struct { struct lmb_program_test_result_v1 result; uint8_t spill[21]; } result_input;
    struct { uint8_t pre[16]; struct lmb_program_test_result_v1 result;
             uint8_t data[97], ctx[40], post[16]; } adjacent;
    struct { uint8_t pre[16], bytes[128], post[16]; } data, ctx;
    struct lmb_program_test_options_v1 *options = &control.options;
    struct lmb_program_test_result_v1 *result = &result_input.result;
    struct lmb_name_v1 name = name_of("packet_control"), *program = &name;
    uint8_t packet[61], context[24], spill_before[21];
    memset(&control, 0xa5, sizeof(control)); memset(&named, 0xa5, sizeof(named));
    memset(&result_input, 0xa5, sizeof(result_input)); memset(&adjacent, 0xa5, sizeof(adjacent));
    memset(&data, 0xa5, sizeof(data)); memset(&ctx, 0xa5, sizeof(ctx));
    for (size_t i = 0; i < sizeof(packet); i++) packet[i] = (uint8_t)(0x11 + i * 7);
    for (size_t i = 0; i < sizeof(context); i++) context[i] = (uint8_t)(0xf1 - i * 5);
    *options = options_of(); result_header(result);
    options->data_in.ptr = packet; options->data_in.len = sizeof(packet);
    options->ctx_in.ptr = context; options->ctx_in.len = sizeof(context);
    options->data_out.ptr = data.bytes; options->data_out.len = 97;
    options->ctx_out.ptr = ctx.bytes; options->ctx_out.len = 40;
    if (mode & ADJACENT) {
        result = &adjacent.result; result_header(result);
        options->data_out.ptr = adjacent.data; options->ctx_out.ptr = adjacent.ctx;
        CHECK(adjacent.data == (uint8_t *)result + sizeof(*result));
        CHECK(adjacent.ctx == adjacent.data + 97);
    }
    if (mode & DATA_ALIAS) {
        memcpy(data.bytes, packet, sizeof(packet)); options->data_in.ptr = data.bytes;
    }
    if (mode & CTX_ALIAS) {
        memcpy(ctx.bytes, context, sizeof(context)); options->ctx_in.ptr = ctx.bytes;
    }
    if (mode & CROSS_OUTPUTS) {
        memcpy(ctx.bytes, packet, sizeof(packet)); memcpy(data.bytes, context, sizeof(context));
        options->data_in.ptr = ctx.bytes; options->ctx_in.ptr = data.bytes;
    }
    if (mode & CROSS_INPUTS) options->ctx_in.ptr = packet + 13;
    if (mode & RESULT_DATA) options->data_in.ptr = (const void *)&result_input;
    if (mode & RESULT_CTX) options->ctx_in.ptr = (const uint8_t *)result + 16;
    if (mode & OPTIONS_OUTPUT) {
        options->data_out.ptr = (void *)&control;
        data_actual = 73; /* Copyback overwrites ctx pointer/length and repeat. */
    }
    if (mode & NAME_OUTPUT) {
        named.name = name; memcpy(named.text, "packet_control", 14);
        named.name.name.ptr = named.text;
        program = &named.name; options->data_out.ptr = (void *)&named;
    }
    if (mode & NAME_RESULT) {
        memcpy((uint8_t *)result + 16, "packet_control", 14);
        name.name.ptr = (uint8_t *)result + 16;
    }
    memcpy(spill_before, result_input.spill, sizeof(spill_before));
    if (omission & 1) { options->data_out.ptr = (void *)UINTPTR_MAX; options->data_out.len = 0; }
    if (omission & 2) { options->ctx_out.ptr = (void *)UINTPTR_MAX; options->ctx_out.len = 0; }
    int expected = error ? error :
        ((options->data_out.len && data_actual > options->data_out.len) ||
         (options->ctx_out.len && ctx_actual > options->ctx_out.len)) ? -EOVERFLOW : 0;
    unsigned allocations = run(object, program, options, result, data_actual, ctx_actual,
                               2, 123, error, expected);
    unchanged(data.pre, 16, 0xa5); unchanged(data.post, 16, 0xa5);
    unchanged(ctx.pre, 16, 0xa5); unchanged(ctx.post, 16, 0xa5);
    unchanged(adjacent.pre, 16, 0xa5); unchanged(adjacent.post, 16, 0xa5);
    CHECK(!memcmp(result_input.spill, spill_before, sizeof(spill_before)));
    if (omission & 1) unchanged(data.bytes, sizeof(data.bytes), 0xa5);
    if (omission & 2) unchanged(ctx.bytes, sizeof(ctx.bytes), 0xa5);
    return allocations;
}

static void boundaries(struct lmb_object *object) {
    struct lmb_name_v1 name = name_of("packet_control");
    struct lmb_program_test_result_v1 result;
    uint8_t input[61], context[24], data[97], ctx[97];
    memset(input, 0x16, sizeof(input)); memset(context, 0x24, sizeof(context));
    struct lmb_program_test_options_v1 options = options_of();
    options.data_in.ptr = input; options.data_in.len = sizeof(input);
    options.ctx_in.ptr = context; options.ctx_in.len = sizeof(context);
    options.data_out.ptr = data; options.data_out.len = 40;
    options.ctx_out.ptr = ctx; options.ctx_out.len = 97;
    memset(data, 0xa5, sizeof(data)); memset(ctx, 0xa5, sizeof(ctx)); result_header(&result);
    run(object, &name, &options, &result, 37, 16, UINT32_C(0xfedcba98), UINT32_C(0x89abcdef), 0, 0);
    options.repeat = INT_MAX; result_header(&result);
    run(object, &name, &options, &result, 0, 0, 0, 0, 0, 0);
    options.repeat = 1;
    for (unsigned empty = 1; empty <= 3; empty++) {
        options.data_in.ptr = empty & 1 ? (void *)UINTPTR_MAX : input;
        options.data_in.len = empty & 1 ? 0 : sizeof(input);
        options.ctx_in.ptr = empty & 2 ? (void *)UINTPTR_MAX : context;
        options.ctx_in.len = empty & 2 ? 0 : sizeof(context);
        result_header(&result); run(object, &name, &options, &result, 37, 16, 2, 123, 0, 0);
    }
    options = options_of();
    options.data_in.ptr = (void *)UINTPTR_MAX; options.ctx_in.ptr = (void *)UINTPTR_MAX;
    options.data_out.ptr = (void *)UINTPTR_MAX; options.ctx_out.ptr = (void *)UINTPTR_MAX;
    result_header(&result); run(object, &name, &options, &result, UINT32_MAX, 65537, 2, 123, 0, 0);
    CHECK(allocation_calls == 0);
    /* Every span independently accepts its exact maximum. These are
     * forwarding tests, not kernel-valid packet/context claims. */
    const size_t maximum = 1048576;
    uint8_t *large = malloc(maximum + 32); CHECK(large != NULL); if (!large) exit(1);
    for (unsigned span = 0; span < 4; span++) {
        memset(large, 0xa5, maximum + 32);
        memset(data, 0xa5, sizeof(data)); memset(ctx, 0xa5, sizeof(ctx));
        options = options_of();
        options.data_in.ptr = input; options.data_in.len = 61;
        options.ctx_in.ptr = context; options.ctx_in.len = 24;
        options.data_out.ptr = data; options.data_out.len = 97;
        options.ctx_out.ptr = ctx; options.ctx_out.len = 40;
        if (span == 0) { options.data_in.ptr = large + 16; options.data_in.len = maximum; }
        if (span == 1) { options.ctx_in.ptr = large + 16; options.ctx_in.len = maximum; }
        if (span == 2) { options.data_out.ptr = large + 16; options.data_out.len = maximum; }
        if (span == 3) { options.ctx_out.ptr = large + 16; options.ctx_out.len = maximum; }
        result_header(&result); run(object, &name, &options, &result, 37, 16, 2, 123, 0, 0);
        unchanged(large, 16, 0xa5); unchanged(large + maximum + 16, 16, 0xa5);
    }
    free(large);
    puts("test-run boundaries: four independent maxima, reversed capacities, high-bit values, INT_MAX repeat, ignored zero pointers");
}

static uint8_t *page_end(size_t length, size_t *mapping_size) {
    long page = sysconf(_SC_PAGESIZE); CHECK(page > 0 && length < (size_t)page);
    *mapping_size = (size_t)page * 2;
    uint8_t *mapping = mmap(NULL, *mapping_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(mapping != MAP_FAILED); if (mapping == MAP_FAILED) exit(1);
    CHECK(mprotect(mapping + page, (size_t)page, PROT_NONE) == 0);
    memset(mapping, 0xa5, (size_t)page); return mapping + page - length;
}
static void protected_extents(struct lmb_object *object) {
    struct lmb_name_v1 name = name_of("packet_control");
    struct lmb_program_test_options_v1 options = options_of();
    struct lmb_program_test_result_v1 result;
    size_t sizes[4]; uint8_t *ends[4];
    const size_t lengths[] = {61, 24, 97, 40};
    for (unsigned i = 0; i < 4; i++) ends[i] = page_end(lengths[i], &sizes[i]);
    options.data_in.ptr = ends[0]; options.data_in.len = 61;
    options.ctx_in.ptr = ends[1]; options.ctx_in.len = 24;
    options.data_out.ptr = ends[2]; options.data_out.len = 97;
    options.ctx_out.ptr = ends[3]; options.ctx_out.len = 40;
    result_header(&result); run(object, &name, &options, &result, 37, 16, 2, 123, 0, 0);
    result_header(&result); run(object, &name, &options, &result, 97, 40, 2, 123, 0, 0);
    result_header(&result); run(object, &name, &options, &result, 98, 41, 2, 123, 0, -EOVERFLOW);
    for (unsigned i = 0; i < 4; i++) {
        unchanged(ends[i] - 16, 16, 0xa5);
        CHECK(munmap(ends[i] + lengths[i] - sizes[i] / 2, sizes[i]) == 0);
    }
    puts("test-run protected extents: all four spans end at an inaccessible page");
}

static void allocation_cleanup(struct lmb_object *object, unsigned steps) {
    struct lmb_name_v1 name = name_of("packet_control");
    uint8_t input[61], context[24], data[97], ctx[40];
    memset(input, 0x16, sizeof(input)); memset(context, 0x24, sizeof(context));
    struct lmb_program_test_options_v1 options = options_of();
    struct lmb_program_test_result_v1 result, before;
    options.data_in.ptr = input; options.data_in.len = sizeof(input);
    options.ctx_in.ptr = context; options.ctx_in.len = sizeof(context);
    options.data_out.ptr = data; options.data_out.len = sizeof(data);
    options.ctx_out.ptr = ctx; options.ctx_out.len = sizeof(ctx);
    CHECK(steps > 0 && steps <= 16);
    for (unsigned fail_at = 1; fail_at <= steps; fail_at++) {
        memset(data, 0xa5, sizeof(data)); memset(ctx, 0xa5, sizeof(ctx)); result_header(&result); before = result;
        unsigned calls = bpf_calls, native = native_calls, faults = allocation_failures;
        start_allocations((int)fail_at);
        CHECK(lmb_program_test_run_v1(object, &name, &options, &result) == -ENOMEM);
        CHECK(finish_allocations() == fail_at && allocation_failures == faults + 1);
        CHECK(bpf_calls == calls && native_calls == native && !script.armed);
        CHECK(!memcmp(&before, &result, sizeof(result)));
        unchanged(data, sizeof(data), 0xa5); unchanged(ctx, sizeof(ctx), 0xa5);
        diagnostic(LMB_GENERIC_DOMAIN_POSIX, -ENOMEM);
        /* Allocation faults do not poison the loaded owner or retain scratch. */
        run(object, &name, &options, &result, 37, 16, 2, 123, 0, 0);
    }
    printf("test-run allocation cleanup: %u observed owned allocation boundaries failed and recovered\n", steps);
}

static void guard_controls(const char *executable) {
    const char *modes[] = {"--guard-positive", "--guard-trap", "--guard-unknown"};
    const int exits[] = {0, 99, 98};
    for (unsigned i = 0; i < 3; i++) {
        pid_t child = fork(); CHECK(child >= 0);
        if (!child) { execl(executable, executable, modes[i], (char *)NULL); _exit(97); }
        int status = 0; CHECK(waitpid(child, &status, 0) == child);
        CHECK(WIFEXITED(status) && WEXITSTATUS(status) == exits[i]);
    }
}

int main(int argc, char **argv) {
#ifdef LMB_TESTRUN_RED_BASELINE
    if (!lmb_program_test_run_v1) {
        fputs("FAIL missing implementation: lmb_program_test_run_v1\n", stderr); return 1;
    }
#endif
    if (argc == 2 && !strcmp(argv[1], "--guard-trap")) {
        union bpf_attr attr = {0};
        syscall(SYS_bpf, BPF_MAP_CREATE, &attr, (unsigned)sizeof(attr)); return 1;
    }
    if (argc == 2 && !strcmp(argv[1], "--guard-unknown")) { syscall(SYS_getppid); return 1; }
    if (argc == 2 && !strcmp(argv[1], "--guard-positive")) {
        CHECK(syscall(SYS_getpid) == getpid());
        int fd = (int)syscall(SYS_memfd_create, "testrun-guard-positive", 0U);
        CHECK(fd >= 0); if (fd >= 0) CHECK(close(fd) == 0);
        puts("guard positive: real non-BPF calls completed"); return failures ? 1 : 0;
    }
    if (argc == 2 && !strcmp(argv[1], "--leak-control")) {
        void *memory = malloc(17); if (!memory) return 2;
        memset(memory, 0x17, 17); return 0; /* Deliberate unreachable leak. */
    }
    if (argc != 3) { fputs("usage: generic_testrun <xdp-fixture> <tracepoint-fixture>\n", stderr); return 2; }
    guard_controls(argv[0]);
    size_t xdp_size, trace_size;
    uint8_t *xdp_elf = read_fixture(argv[1], &xdp_size), *trace_elf = read_fixture(argv[2], &trace_size);
    unsigned initial_fds = fd_count();
    struct lmb_object *unloaded = open_fixture(xdp_elf, xdp_size, 0);
    struct lmb_object *object = open_fixture(xdp_elf, xdp_size, 1);
    struct lmb_object *tracepoint = open_fixture(trace_elf, trace_size, 1);
    validation(object, unloaded, tracepoint);
    unsigned allocations = ordinary(object, 0, 0, 0, 37, 16);
    const unsigned modes[] = {DATA_ALIAS, CTX_ALIAS, DATA_ALIAS | CTX_ALIAS, CROSS_OUTPUTS,
        CROSS_INPUTS, RESULT_DATA, RESULT_CTX, RESULT_DATA | RESULT_CTX,
        ADJACENT, OPTIONS_OUTPUT, NAME_OUTPUT, NAME_RESULT};
    for (unsigned i = 0; i < sizeof(modes)/sizeof(*modes); i++) ordinary(object, modes[i], 0, 0, 37, 16);
    ordinary(object, 0, 1, 0, 37, 16); ordinary(object, 0, 2, 0, 37, 16);
    ordinary(object, 0, 2, 0, 37, 0);
    ordinary(object, 0, 3, 0, UINT32_MAX, UINT32_MAX);
    ordinary(object, 0, 0, 0, 0, 0);
    const int errors[] = {-ENOSPC, -EINTR, -EOPNOTSUPP, -EINVAL, -EIO};
    for (unsigned i = 0; i < sizeof(errors)/sizeof(*errors); i++) {
        ordinary(object, 0, 0, errors[i], 37, 16);
        ordinary(object, DATA_ALIAS | CTX_ALIAS, 0, errors[i], 37, 16);
    }
    /* Packet finish and later context finish can fail after partial writes. */
    ordinary(object, 0, 0, -ENOSPC, 98, 16);
    ordinary(object, 0, 0, -ENOSPC, 37, 41);
    ordinary(object, 0, 0, 0, 98, 16); ordinary(object, 0, 0, 0, 37, 41);
    ordinary(object, 0, 1, 0, UINT32_MAX, 16);
    ordinary(object, 0, 2, 0, 37, UINT32_MAX);
    boundaries(object); protected_extents(object); allocation_cleanup(object, allocations);
    unsigned before_closes = closes;
    CHECK(lmb_object_close_v1(&object) == 0 && !object);
    CHECK(lmb_object_close_v1(&unloaded) == 0 && !unloaded);
    CHECK(lmb_object_close_v1(&tracepoint) == 0 && !tracepoint);
    CHECK(closes == before_closes + 3 && fd_count() == initial_fds);
    load_result = -EIO; object = open_fixture(xdp_elf, xdp_size, 1);
    struct lmb_name_v1 name = name_of("packet_control");
    struct lmb_program_test_options_v1 options = options_of();
    struct lmb_program_test_result_v1 result; result_header(&result);
    invalid(object, &name, &options, &result, NULL, 0, -EINVAL, LMB_GENERIC_DOMAIN_BRIDGE, 0);
    CHECK(lmb_object_close_v1(&object) == 0 && !object && fd_count() == initial_fds);
    free(xdp_elf); free(trace_elf);
    CHECK(!script.armed && allocation_live == 0 && native_calls == bpf_calls);
    printf("generic test-run: %u checks, %u failures; %u real libbpf calls / %u scripted BPF requests, zero executed BPF calls\n",
           checks, failures, native_calls, bpf_calls);
    puts("NOT_RUN generic_testrun.kernel-runtime: host adapter evidence only");
    return failures ? 1 : 0;
}
