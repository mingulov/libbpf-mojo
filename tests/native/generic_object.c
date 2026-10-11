/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* Real libbpf parsing/metadata/ownership, with the load boundary stopped
 * before kernel work. These tests never qualify a successful load. */
#include <dirent.h>
#include <errno.h>
#include <linux/bpf.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "libbpf_mojo_generic.h"

#ifdef LMB_OBJECT_RED_BASELINE
#pragma weak lmb_object_open_v1
#pragma weak lmb_object_configure_program_v1
#pragma weak lmb_object_load_v1
#pragma weak lmb_object_program_info_v1
#pragma weak lmb_object_map_info_v1
#pragma weak lmb_object_close_v1
#pragma weak lmb_object_release_v1
#pragma weak lmb_generic_last_error_v1
#pragma weak lmb_object_ref_v1
#pragma weak lmb_object_unref_v1
#pragma weak lmb_object_gen_v1
#pragma weak lmb_object_gen_check_v1
#endif

static unsigned checks, failures, native_closes, load_calls, bpf_calls;
static long allocation_fault = -1, allocation_index;
static unsigned allocation_hit;
static const uint8_t *borrowed_elf, *borrowed_name, *borrowed_btf, *borrowed_target;
#define CHECK(c) do { checks++; if (!(c)) { failures++; \
    fprintf(stderr, "FAIL line %u: %s\n", __LINE__, #c); } } while (0)

enum load_case {
    LOAD_LEGACY_FAILURE, LOAD_MIXED, LOAD_BEFORE_PROGRAMS, LOAD_AFTER_PROGRAMS,
    LOAD_RETRY_SUCCESS, LOAD_RETRY_FAILURE, LOAD_UNKNOWN_BUFFER,
    LOAD_RECORD_RETRY_SUCCESS
};
static enum load_case load_case;
static struct lmb_object *nested_object;
static const struct bpf_insn *expected_insns;
static size_t expected_insn_count;
static char *expected_log_buffer;
static size_t expected_log_size;
static unsigned expected_log_level, scripted_at, scripted_count;
static int record_retry;
static int scripted_results[2];
static const char *scripted_log;
static unsigned mock_program_requests, mock_memcg_probes, allow_memcg_probe;
static const char first_success[] = "first verified successfully\n";
static const char first_failure[] = "first verifier failure\n";
static const char second_failure[] = "second verifier failure\n";
static const char second_success[] = "second verified successfully\n";

static void program_attempt(struct bpf_program *prog, const char *log,
                            int terminal, int retry, char *alternate_buffer,
                            size_t alternate_size) {
    struct bpf_prog_load_opts opts = {0};
    uint32_t function_info[4] = {0};
    size_t size = 0;
    const char *buffer = bpf_program__log_buf(prog, &size);
    opts.sz = sizeof(opts);
    opts.log_buf = alternate_buffer ? alternate_buffer : (char *)buffer;
    opts.log_size = (uint32_t)(alternate_buffer ? alternate_size : size);
    opts.log_level = alternate_buffer ? 1 : bpf_program__log_level(prog);
    opts.attempts = 3;
    if (retry == 2) {
        opts.func_info = function_info;
        opts.func_info_cnt = 1;
        opts.func_info_rec_size = sizeof(function_info);
    }
    expected_insns = bpf_program__insns(prog);
    expected_insn_count = bpf_program__insn_cnt(prog);
    expected_log_buffer = opts.log_level ? opts.log_buf : NULL;
    expected_log_size = opts.log_level ? opts.log_size : 0;
    expected_log_level = opts.log_level;
    scripted_log = log;
    scripted_at = 0;
    scripted_count = retry ? 2 : 1;
    scripted_results[0] = retry == 2 ? -E2BIG : retry ? -EAGAIN : terminal;
    scripted_results[1] = terminal;
    record_retry = retry == 2;
    /* A positive scripted result is never assigned to a program FD and
     * represents no kernel object. The real pinned API handles retries. */
    errno = ENOTTY;
    int code = bpf_prog_load(bpf_program__type(prog), NULL, "GPL",
                            expected_insns, expected_insn_count, &opts);
    CHECK(code == terminal);
    CHECK(errno == (terminal < 0 ? -terminal : retry == 2 ? E2BIG : retry ? EAGAIN : ENOTTY));
    CHECK(scripted_at == scripted_count);
    CHECK(opts.log_buf == (alternate_buffer ? alternate_buffer : (char *)buffer) &&
          opts.log_size == (alternate_buffer ? alternate_size : size));
    CHECK(!record_retry || (opts.func_info == function_info &&
                           opts.func_info_rec_size == sizeof(function_info)));
    expected_insns = NULL;
}

void *__real_malloc(size_t n);
void *__real_calloc(size_t count, size_t n);
static int allocation_fails(void) {
    if (allocation_fault < 0 || allocation_index++ != allocation_fault) return 0;
    allocation_hit = 1; errno = ENOMEM; return 1;
}
void *__wrap_malloc(size_t n) { return allocation_fails() ? NULL : __real_malloc(n); }
void *__wrap_calloc(size_t count, size_t n) {
    return allocation_fails() ? NULL : __real_calloc(count, n);
}

struct bpf_object *__real_bpf_object__open_mem(const void *bytes, size_t size,
    const struct bpf_object_open_opts *opts);
struct bpf_object *__wrap_bpf_object__open_mem(const void *bytes, size_t size,
    const struct bpf_object_open_opts *opts) {
    if (borrowed_elf) {
        CHECK(bytes != borrowed_elf);
        CHECK(opts && opts->sz == sizeof(*opts));
        CHECK(opts->object_name != (const char *)borrowed_name && !strcmp(opts->object_name, "copied"));
        CHECK(opts->btf_custom_path != (const char *)borrowed_btf && !strcmp(opts->btf_custom_path, (const char *)borrowed_btf));
        CHECK(opts->bpf_token_path && !opts->bpf_token_path[0]);
        CHECK(!opts->kernel_log_buf && !opts->kernel_log_size && !opts->kconfig && !opts->relaxed_maps);
    }
    return __real_bpf_object__open_mem(bytes, size, opts);
}

int __wrap_bpf_program__set_attach_target(struct bpf_program *program,
                                         int fd, const char *target) {
    CHECK(program && fd == 0 && target != (const char *)borrowed_target);
    CHECK(!strcmp(target, "do_sys_open"));
    return -2041;
}

void __real_bpf_object__close(struct bpf_object *obj);
void __wrap_bpf_object__close(struct bpf_object *obj) {
    if (obj) native_closes++;
    __real_bpf_object__close(obj);
}

int __wrap_bpf_object__load(struct bpf_object *obj) {
    struct bpf_program *prog;
    load_calls++;
    if (nested_object) {
        struct lmb_object *nested = nested_object;
        nested_object = NULL;
        unsigned before = load_calls;
        CHECK(lmb_object_load_v1(nested) == -EINVAL);
        CHECK(load_calls == before);
    }
    if (load_case == LOAD_BEFORE_PROGRAMS) return -ENOMEM;
    if (load_case != LOAD_LEGACY_FAILURE) {
        struct bpf_program *first = bpf_object__find_program_by_name(obj, "first");
        struct bpf_program *second = bpf_object__find_program_by_name(obj, "second");
        CHECK(first && second);
        if (!first || !second) abort();
        if (load_case == LOAD_RETRY_FAILURE) {
            program_attempt(first, first_failure, -133, 1, NULL, 0);
            return -133;
        }
        if (load_case == LOAD_UNKNOWN_BUFFER) {
            char unrelated[128] = {0};
            program_attempt(first, first_failure, -133, 0,
                            unrelated, sizeof(unrelated));
            return -133;
        }
        program_attempt(first, first_success, 42,
                        load_case == LOAD_RECORD_RETRY_SUCCESS ? 2 :
                        load_case == LOAD_RETRY_SUCCESS, NULL, 0);
        program_attempt(second, load_case == LOAD_AFTER_PROGRAMS ? second_success : second_failure,
                        load_case == LOAD_AFTER_PROGRAMS ? 43 : -133, 0, NULL, 0);
        return load_case == LOAD_AFTER_PROGRAMS ? -EIO : -133;
    }
    bpf_object__for_each_program(prog, obj) {
        size_t size = 0;
        const char *buffer = bpf_program__log_buf(prog, &size);
        if (buffer && size) {
            const char log[] = "controlled load failure\n";
            size_t n = sizeof(log) < size ? sizeof(log) : size;
            memcpy((char *)buffer, log, n);
        }
    }
    return -133;
}

/* Fail closed if host-only coverage accidentally reaches a BPF syscall. */
long __real_syscall(long number, ...);
long __wrap_syscall(long number, ...) {
    if (number == SYS_bpf) {
        va_list args;
        va_start(args, number);
        int command = va_arg(args, int);
        union bpf_attr *attr = va_arg(args, union bpf_attr *);
        unsigned size = va_arg(args, unsigned);
        va_end(args);
        /* Initialize libbpf's test-local memlock setting without touching
         * RLIMIT_MEMLOCK. Its one feature probe is denied here, before any
         * syscall. Every subsequent permitted request must match the
         * explicit program script; unexpected requests remain fatal. */
        if (allow_memcg_probe && command == BPF_PROG_LOAD && attr &&
            attr->insn_cnt == 2 && !attr->log_buf && !attr->log_size) {
            const struct bpf_insn *insns = (const void *)(uintptr_t)attr->insns;
            CHECK(insns[0].code == (BPF_JMP | BPF_CALL) &&
                  insns[0].imm == BPF_FUNC_ktime_get_coarse_ns &&
                  insns[1].code == (BPF_JMP | BPF_EXIT));
            mock_memcg_probes++; allow_memcg_probe = 0;
            errno = EPERM;
            return -1;
        }
        if (expected_insns && command == BPF_PROG_LOAD && attr &&
            attr->insns == (uintptr_t)expected_insns &&
            scripted_at < scripted_count) {
            CHECK(size >= offsetof(union bpf_attr, log_size) + sizeof(attr->log_size));
            CHECK(attr->insn_cnt == expected_insn_count);
            CHECK(attr->log_buf == (uintptr_t)expected_log_buffer &&
                  attr->log_size == expected_log_size && attr->log_level == expected_log_level);
            if (record_retry) {
                CHECK(attr->func_info_cnt == 1 && attr->func_info_rec_size == 16);
                if (scripted_at == 0) attr->func_info_rec_size = 8;
            }
            if (expected_log_buffer && expected_log_size) {
                size_t bytes = strlen(scripted_log) + 1;
                if (bytes > expected_log_size) bytes = expected_log_size;
                memcpy(expected_log_buffer, scripted_log, bytes);
                attr->log_true_size = (uint32_t)strlen(scripted_log) + 1;
            }
            mock_program_requests++;
            int result = scripted_results[scripted_at++];
            if (result >= 0) return result;
            errno = -result;
            return -1;
        }
    }
    if (number == SYS_memfd_create) {
        va_list args;
        va_start(args, number);
        const char *text = va_arg(args, const char *);
        unsigned flags = va_arg(args, unsigned);
        va_end(args);
        return __real_syscall(number, text, flags);
    }
    if (number == SYS_bpf) {
        bpf_calls++;
        fprintf(stderr, "FAIL unscripted BPF request: scenario=%u request=%u/%u feature_probe=%u\n",
                load_case, scripted_at, scripted_count, allow_memcg_probe);
    }
    fprintf(stderr, "FAIL unexpected syscall %ld\n", number);
    abort();
}

static struct lmb_object_options_v1 options(void) {
    struct lmb_object_options_v1 o = {0};
    o.abi_version = 1;
    o.struct_size = sizeof(o);
    return o;
}

static struct lmb_name_v1 name(const char *text) {
    struct lmb_name_v1 n = {0};
    n.abi_version = 1;
    n.struct_size = sizeof(n);
    n.name.ptr = (const uint8_t *)text;
    n.name.len = (uint32_t)strlen(text);
    return n;
}

static struct lmb_program_options_v1 config(const char *text) {
    struct lmb_program_options_v1 o = {0};
    o.abi_version = 1;
    o.struct_size = sizeof(o);
    o.program.ptr = (const uint8_t *)text;
    o.program.len = strlen(text);
    return o;
}

static struct lmb_program_info_v1 info(void) {
    struct lmb_program_info_v1 o;
    memset(&o, 0xA5, sizeof(o));
    o.abi_version = 1;
    o.struct_size = sizeof(o);
    o.log.ptr = NULL;
    o.log.len = 0;
    return o;
}

static void error_is(uint32_t op, uint32_t domain, int32_t code) {
    struct lmb_generic_error_v1 e = {1, sizeof(e), 0, 0, 0, 0, {0}};
    CHECK(lmb_generic_last_error_v1(&e) == 0);
    CHECK(e.operation == op && e.domain == domain && e.code == code);
    unsigned zero_tail = 1;
    for (unsigned i = e.msg_len; i < sizeof(e.message); i++)
        if (e.message[i] != 0) zero_tail = 0;
    CHECK(zero_tail);
}

static long fds(void) {
    DIR *d = opendir("/proc/self/fd");
    struct dirent *entry;
    long n = 0;
    if (!d) return -1;
    while ((entry = readdir(d))) if (entry->d_name[0] != '.') n++;
    closedir(d);
    return n;
}

static uint8_t *read_file(const char *path, size_t *size) {
    FILE *f = fopen(path, "rb");
    long length;
    uint8_t *data;
    if (!f || fseek(f, 0, SEEK_END) || (length = ftell(f)) <= 0 ||
        fseek(f, 0, SEEK_SET)) abort();
    *size = (size_t)length;
    data = malloc(*size);
    if (!data || fread(data, 1, *size, f) != *size) abort();
    fclose(f);
    return data;
}

static struct lmb_object *open_object(const uint8_t *elf, size_t size,
                                     struct lmb_object_options_v1 *o) {
    struct lmb_object *obj = NULL;
    CHECK(lmb_object_open_v1(elf, size, o, &obj) == 0 && obj);
    if (!obj) abort();
    return obj;
}

static void open_validation(const uint8_t *elf, size_t size,
                            const char *valid_btf) {
    struct lmb_object_options_v1 o;
    struct lmb_object *obj;
    static const uint8_t invalid_utf8[] = {0xC0, 0xAF};
    static const uint8_t nulpath[] = {'a', 0, 'b'};
    const uint8_t garbage[] = "not an ELF";
    for (unsigned row = 0; row < 12; row++) {
        o = options();
        switch (row) {
        case 0: o.abi_version = 2; break;
        case 1: o.struct_size--; break;
        case 2: o.struct_size++; break;
        case 3: o.flags = 1; break;
        case 4: o._reserved = 1; break;
        case 5: o.log_level = 3; break;
        case 6: o.log_capacity = 1048577; break;
        case 7: o.name.len = 257; break;
        case 8: o.name.ptr = invalid_utf8; o.name.len = 2; break;
        case 9: o.custom_btf.ptr = nulpath; o.custom_btf.len = 3; break;
        case 10: o.custom_btf.len = 4097; break;
        case 11: o.name.len = 1; break;
        }
        obj = (struct lmb_object *)(uintptr_t)1;
        CHECK(lmb_object_open_v1(elf, size, &o, &obj) == -EINVAL && !obj);
        error_is(1, 4, -EINVAL);
    }
    o = options();
    CHECK(lmb_object_open_v1(elf, size, &o, NULL) == -EINVAL);
    CHECK(lmb_object_open_v1(NULL, size, &o, &obj) == -EINVAL && !obj);
    CHECK(lmb_object_open_v1(elf, 0, &o, &obj) == -EINVAL && !obj);
    CHECK(lmb_object_open_v1(elf, size, NULL, &obj) == -EINVAL && !obj);
    CHECK(lmb_object_open_v1(garbage, sizeof(garbage), &o, &obj) < 0 && !obj);
    {
        long native;
        struct bpf_object *oracle = bpf_object__open_mem(garbage, sizeof(garbage), NULL);
        native = libbpf_get_error(oracle);
        error_is(1, 2, (int32_t)native);
        if (!native) bpf_object__close(oracle);
    }
    o = options();
    o.custom_btf.ptr = (const uint8_t *)"/nonexistent-lmb-generic-btf";
    o.custom_btf.len = strlen((const char *)o.custom_btf.ptr);
    CHECK(lmb_object_open_v1(elf, size, &o, &obj) == -ENOENT && !obj);
    error_is(1, 2, -ENOENT);
    o.custom_btf.ptr = (const uint8_t *)valid_btf;
    o.custom_btf.len = strlen(valid_btf);
    obj = open_object(elf, size, &o);
    CHECK(lmb_object_close_v1(&obj) == 0 && !obj);
    o.custom_btf.ptr = (const uint8_t *)"/dev/null";
    o.custom_btf.len = 9;
    CHECK(lmb_object_open_v1(elf, size, &o, &obj) < 0 && !obj);
    {
        struct lmb_generic_error_v1 before = {1, sizeof(before), 0, 0, 0, 0, {0}};
        struct lmb_generic_error_v1 after;
        CHECK(lmb_generic_last_error_v1(&before) == 0);
        CHECK(before.operation == 1 && before.domain == 2 && before.code < 0);
        after = before;
        after.struct_size--;
        CHECK(lmb_generic_last_error_v1(&after) == -EINVAL);
        after.abi_version = 1;
        after.struct_size = sizeof(after);
        CHECK(lmb_generic_last_error_v1(&after) == 0 && !memcmp(&before, &after, sizeof(after)));
    }
}

static void metadata_config(const uint8_t *elf, size_t size) {
    struct lmb_object_options_v1 o = options();
    struct lmb_object *obj = open_object(elf, size, &o);
    struct lmb_name_v1 n = name("first");
    struct lmb_program_info_v1 p = info(), before;
    struct lmb_program_options_v1 c = config("first");
    struct lmb_map_info_v1 m = {1, sizeof(m), 0, 0, 0, 0, 0, 0, 0, 0}, mbefore = m;
    uint8_t log[16];
    memset(log, 0xCC, sizeof(log));
    p.log.ptr = log + 1; p.log.len = 14;
    CHECK(lmb_object_program_info_v1(obj, &n, &p) == 0);
    CHECK(p.prog_type == BPF_PROG_TYPE_SOCKET_FILTER && p.insn_count > 0);
    CHECK(p.autoload == 1 && p.generation == 0 && p.log_actual == 0 && !p.log_truncated);
    CHECK(!p._pad0 && !p._reserved && p.log.ptr == log + 1 && p.log.len == 14);
    for (unsigned i = 0; i < sizeof(log); i++) CHECK(log[i] == 0xCC);
    c.autoload = 2;
    CHECK(lmb_object_configure_program_v1(obj, &c) == 0);
    p = info(); CHECK(lmb_object_program_info_v1(obj, &n, &p) == 0);
    CHECK(p.autoload == 0 && p.generation == 1);
    c.autoload = 1;
    CHECK(lmb_object_configure_program_v1(obj, &c) == 0);
    p = info(); CHECK(lmb_object_program_info_v1(obj, &n, &p) == 0);
    CHECK(p.autoload == 1 && p.generation == 2);
    for (unsigned row = 0; row < 6; row++) {
        c = config("first");
        switch (row) {
        case 0: c.abi_version++; break;
        case 1: c.struct_size--; break;
        case 2: c.flags = 1; break;
        case 3: c.autoload = 3; break;
        case 4: c.program.len = 0; break;
        case 5: c.attach_target.ptr = (const uint8_t *)"target"; c.attach_target.len = 6; c.autoload = 2; break;
        }
        CHECK(lmb_object_configure_program_v1(obj, &c) == -EINVAL);
        p = info(); CHECK(lmb_object_program_info_v1(obj, &n, &p) == 0);
        CHECK(p.autoload == 1 && p.generation == 2);
    }
    c = config("missing");
    CHECK(lmb_object_configure_program_v1(obj, &c) == -ENOENT);
    n = name("counter");
    CHECK(lmb_object_map_info_v1(obj, &n, &m) == -EINVAL && !memcmp(&m, &mbefore, sizeof(m)));
    n = name("first");
    for (unsigned row = 0; row < 6; row++) {
        p = info();
        switch (row) {
        case 0: p.abi_version++; break;
        case 1: p.struct_size++; break;
        case 2: p.log.len = 1; break;
        case 3: p.log.ptr = (uint8_t *)&p; p.log.len = sizeof(p); break;
        case 4: n.name._pad = 1; break;
        case 5: n.name.ptr = (const uint8_t *)"missing"; n.name.len = 7; break;
        }
        before = p;
        CHECK(lmb_object_program_info_v1(obj, &n, &p) == (row == 5 ? -ENOENT : -EINVAL));
        CHECK(!memcmp(&before, &p, sizeof(p)));
        n = name("first");
    }
    CHECK(lmb_object_close_v1(&obj) == 0 && !obj);
}

static void lifetime(const uint8_t *elf, size_t size) {
    struct lmb_object_options_v1 o = options();
    struct lmb_object *obj = open_object(elf, size, &o), *view = obj;
    struct lmb_name_v1 n = name("first");
    struct lmb_program_info_v1 p = info();
    struct lmb_program_options_v1 c = config("first");
    uint64_t gen = UINT64_MAX;
    unsigned closes = native_closes;
    CHECK(lmb_object_gen_v1(obj, &gen) == 0 && gen == 0);
    CHECK(lmb_object_ref_v1(obj) == 0);
    CHECK(lmb_object_ref_v1(obj) == 0);
    CHECK(lmb_object_close_v1(&obj) == -EBUSY && obj == view);
    error_is(6, 4, -EBUSY);
    CHECK(lmb_object_gen_check_v1(obj, gen) == 0);
    CHECK(lmb_object_configure_program_v1(obj, &c) == 0);
    CHECK(lmb_object_gen_check_v1(view, gen) == -ESTALE);
    error_is(17, 4, -ESTALE);
    lmb_object_release_v1(&obj);
    CHECK(!obj && native_closes == closes);
    error_is(17, 4, -ESTALE);
    CHECK(lmb_object_program_info_v1(view, &n, &p) == 0 && p.generation == 1);
    lmb_object_unref_v1(view);
    CHECK(native_closes == closes);
    lmb_object_unref_v1(view);
    CHECK(native_closes == closes + 1);
    obj = open_object(elf, size, &o);
    CHECK(lmb_object_ref_v1(obj) == 0);
    lmb_object_unref_v1(obj);
    CHECK(lmb_object_close_v1(&obj) == 0 && !obj);
    CHECK(lmb_object_close_v1(&obj) == 0);
    CHECK(lmb_object_close_v1(NULL) == -EINVAL);
    lmb_object_release_v1(&obj);
    lmb_object_release_v1(NULL);
    lmb_object_unref_v1(NULL);
    CHECK(lmb_object_ref_v1(NULL) == -EINVAL);
    CHECK(lmb_object_gen_v1(NULL, &gen) == -EINVAL && gen == 0);
    CHECK(lmb_object_gen_check_v1(NULL, 0) == -EINVAL);
}

static void load_failure(const uint8_t *elf, size_t size) {
    struct lmb_object_options_v1 o = options();
    struct lmb_object *obj;
    struct lmb_name_v1 n = name("first");
    struct lmb_program_info_v1 p = info();
    uint8_t log[6];
    o.log_level = 2; o.log_capacity = 128;
    obj = open_object(elf, size, &o);
    CHECK(lmb_object_load_v1(obj) == -133);
    error_is(3, 2, -133);
    memset(log, 0xCC, sizeof(log));
    p.log.ptr = log + 1; p.log.len = 4;
    CHECK(lmb_object_program_info_v1(obj, &n, &p) == 0);
    CHECK(p.log_actual == 24 && p.log_truncated == 1);
    CHECK(log[0] == 0xCC && log[5] == 0xCC && !memcmp(log + 1, "cont", 4));
    CHECK(lmb_object_load_v1(obj) == -EINVAL);
    CHECK(lmb_object_close_v1(&obj) == 0 && !obj);
    CHECK(lmb_object_load_v1(NULL) == -EINVAL);
}

static void expect_program_log(struct lmb_object *obj, const char *program,
                               const char *expected, size_t retained) {
    struct lmb_name_v1 n = name(program);
    struct lmb_program_info_v1 p = info();
    uint8_t log[130];
    memset(log, 0xCC, sizeof(log));
    p.log.ptr = log + 1; p.log.len = sizeof(log) - 2;
    CHECK(lmb_object_program_info_v1(obj, &n, &p) == 0);
    CHECK(p.log_actual == retained && p.log_truncated == 0);
    CHECK(log[0] == 0xCC && log[sizeof(log) - 1] == 0xCC);
    CHECK(!retained || !memcmp(log + 1, expected, retained));
    CHECK(log[retained + 1] == 0xCC);
    memset(log, 0xCC, sizeof(log));
    p = info(); p.log.ptr = log + 1; p.log.len = 4;
    CHECK(lmb_object_program_info_v1(obj, &n, &p) == 0);
    CHECK(p.log_actual == retained && p.log_truncated == (retained > 4));
    CHECK(log[0] == 0xCC && log[5] == 0xCC);
    CHECK(!retained || !memcmp(log + 1, expected, retained < 4 ? retained : 4));
}

static void logging_modes(const uint8_t *elf, size_t size) {
    /* The real pinned bpf_prog_load still executes inside the observer;
     * only its syscall requests receive scripted results. No BPF syscall
     * executes and the aggregate object load always returns a failure. */
    for (unsigned mode = 0; mode < 3; mode++) {
        for (enum load_case scenario = LOAD_MIXED; scenario <= LOAD_RECORD_RETRY_SUCCESS; scenario++) {
            struct lmb_object_options_v1 o = options();
            o.log_level = mode; o.log_capacity = 128;
            struct lmb_object *obj = open_object(elf, size, &o);
            load_case = scenario;
            int expected_code = scenario == LOAD_BEFORE_PROGRAMS ? -ENOMEM :
                                scenario == LOAD_AFTER_PROGRAMS ? -EIO : -133;
            CHECK(lmb_object_load_v1(obj) == expected_code);
            error_is(3, 2, expected_code);
            int first_attempted = scenario != LOAD_BEFORE_PROGRAMS && scenario != LOAD_UNKNOWN_BUFFER;
            int first_failed = scenario == LOAD_RETRY_FAILURE;
            int second_attempted = first_attempted && !first_failed;
            int second_failed = second_attempted && scenario != LOAD_AFTER_PROGRAMS;
            const char *first_log = first_failed ? first_failure : first_success;
            const char *second_log = second_failed ? second_failure : second_success;
            size_t first_bytes = first_attempted && (mode == 2 || (mode == 1 && first_failed)) ? strlen(first_log) : 0;
            size_t second_bytes = second_attempted && (mode == 2 || (mode == 1 && second_failed)) ? strlen(second_log) : 0;
            expect_program_log(obj, "first", first_log, first_bytes);
            expect_program_log(obj, "second", second_log, second_bytes);
            CHECK(lmb_object_load_v1(obj) == -EINVAL);
            CHECK(lmb_object_close_v1(&obj) == 0 && !obj);
            printf("log mode=%u scenario=%u: expected first=%zu second=%zu aggregate=%d\n",
                   mode, scenario, first_bytes, second_bytes, expected_code);
        }
        for (unsigned cap = 0; cap <= 8; cap += 8) {
            struct lmb_object_options_v1 o = options();
            o.log_level = mode; o.log_capacity = cap;
            struct lmb_object *obj = open_object(elf, size, &o);
            load_case = LOAD_MIXED;
            CHECK(lmb_object_load_v1(obj) == -133);
            error_is(3, 2, -133);
            expect_program_log(obj, "first", first_success, mode == 2 ? cap : 0);
            expect_program_log(obj, "second", second_failure, mode ? cap : 0);
            CHECK(lmb_object_close_v1(&obj) == 0);
        }
        struct lmb_object_options_v1 o = options();
        o.log_level = mode; o.log_capacity = 128;
        struct lmb_object *outer = open_object(elf, size, &o);
        struct lmb_object *nested = open_object(elf, size, &o);
        nested_object = nested; load_case = LOAD_MIXED;
        CHECK(lmb_object_load_v1(outer) == -133);
        error_is(3, 2, -133);
        expect_program_log(outer, "first", first_success, mode == 2 ? strlen(first_success) : 0);
        expect_program_log(outer, "second", second_failure, mode ? strlen(second_failure) : 0);
        CHECK(lmb_object_close_v1(&outer) == 0);
        /* A nested refusal must leave the owner open for configuration
         * and a later ordinary attempt after TLS restoration. */
        struct lmb_program_options_v1 c = config("first");
        CHECK(lmb_object_configure_program_v1(nested, &c) == 0);
        load_case = LOAD_BEFORE_PROGRAMS;
        CHECK(lmb_object_load_v1(nested) == -ENOMEM);
        error_is(3, 2, -ENOMEM);
        CHECK(lmb_object_close_v1(&nested) == 0);
    }
    load_case = LOAD_LEGACY_FAILURE;
}

static void copied_and_allocation_failures(const uint8_t *elf, size_t size,
                                          const char *btf_path) {
    struct lmb_object_options_v1 o = options();
    struct lmb_object *obj;
    struct lmb_name_v1 n = name("first");
    struct lmb_program_info_v1 p = info();
    uint8_t *copy = malloc(size);
    char object_name[] = "copied";
    char *path = malloc(strlen(btf_path) + 1);
    CHECK(copy && path);
    if (!copy || !path) abort();
    memcpy(copy, elf, size); strcpy(path, btf_path);
    o.name.ptr = (const uint8_t *)object_name; o.name.len = 6;
    o.custom_btf.ptr = (const uint8_t *)path; o.custom_btf.len = strlen(path);
    borrowed_elf = copy; borrowed_name = (const uint8_t *)object_name;
    borrowed_btf = (const uint8_t *)path;
    obj = open_object(copy, size, &o);
    borrowed_elf = borrowed_name = borrowed_btf = NULL;
    memset(copy, 0, size); memset(object_name, 0, sizeof(object_name));
    memset(path, 0, strlen(path)); free(path); free(copy); memset(&o, 0, sizeof(o));
    CHECK(lmb_object_program_info_v1(obj, &n, &p) == 0 && p.insn_count > 0);
    CHECK(lmb_object_close_v1(&obj) == 0);

    o = options(); o.name.ptr = (const uint8_t *)"alloc"; o.name.len = 5;
    o.log_level = 2; o.log_capacity = 128;
    long baseline = fds();
    long faults = 0;
    for (long at = 0; at < 256; at++) {
        allocation_fault = at; allocation_index = 0; allocation_hit = 0;
        obj = NULL;
        int32_t rc = lmb_object_open_v1(elf, size, &o, &obj);
        allocation_fault = -1;
        if (allocation_hit) {
            faults++;
            CHECK(rc < 0 && !obj);
            struct lmb_generic_error_v1 error = {1, sizeof(error), 0, 0, 0, 0, {0}};
            CHECK(lmb_generic_last_error_v1(&error) == 0 && error.code == rc);
            CHECK(error.domain == 1 || error.domain == 2);
        } else {
            CHECK(rc == 0 && obj);
            CHECK(lmb_object_close_v1(&obj) == 0);
            break;
        }
        CHECK(fds() == baseline);
    }
    CHECK(faults >= 7 && faults < 256);
    printf("allocation failure boundaries: %ld\n", faults);
}

static void diagnostics_independent(void) {
    struct lmb_object *obj = NULL;
    struct lmb_object_options_v1 o = options();
    struct lmb_generic_error_v1 before = {1, sizeof(before), 0, 0, 0, 0, {0}}, after;
    struct lmb_error_v1 old = {1, sizeof(old), 0, 0, 0, 0, {0}}, saved;
    struct lmb_options_v1 invalid = {0};
    struct lmb_session *session = NULL;
    CHECK(lmb_open(NULL, 0, &invalid, &session) == -EINVAL);
    CHECK(lmb_last_error(&old) == 0); saved = old;
    CHECK(lmb_object_open_v1(NULL, 0, &o, &obj) == -EINVAL);
    CHECK(lmb_generic_last_error_v1(&before) == 0);
    CHECK(lmb_open(NULL, 0, &invalid, &session) == -EINVAL);
    after = before;
    CHECK(lmb_generic_last_error_v1(&after) == 0 && !memcmp(&before, &after, sizeof(after)));
    CHECK(lmb_object_close_v1(&obj) == 0);
    after.abi_version = 1; after.struct_size = sizeof(after);
    CHECK(lmb_generic_last_error_v1(&after) == 0);
    const struct lmb_generic_error_v1 zero = {0};
    CHECK(!memcmp(&after, &zero, sizeof(after)));
    old.abi_version = 1; old.struct_size = sizeof(old);
    CHECK(lmb_last_error(&old) == 0 && !memcmp(&old, &saved, sizeof(old)));
}

int main(int argc, char **argv) {
#ifdef LMB_OBJECT_RED_BASELINE
    if (!lmb_object_open_v1 || !lmb_object_ref_v1) {
        fprintf(stderr, "FAIL generic object implementation absent\n");
        return 1;
    }
#endif
    if (argc != 4) return 2;
    size_t size, nomap_size, tracing_size;
    uint8_t *elf = read_file(argv[1], &size);
    uint8_t *nomap = read_file(argv[2], &nomap_size);
    uint8_t *tracing = read_file(argv[3], &tracing_size);
    long baseline = fds();
    open_validation(elf, size, argv[1]);
    metadata_config(elf, size);
    metadata_config(nomap, nomap_size);
    lifetime(elf, size);
    load_failure(elf, size);
    {
        /* bpf_prog_load checks attempts only after bump_rlimit_memlock.
         * Disabling that automatic bump and intercepting its feature probe
         * prevents host limit changes as well as BPF syscalls. */
        struct bpf_prog_load_opts opts = {0};
        opts.sz = sizeof(opts); opts.attempts = -1;
        CHECK(libbpf_set_memlock_rlim(0) == 0);
        allow_memcg_probe = 1;
        CHECK(bpf_prog_load(BPF_PROG_TYPE_SOCKET_FILTER, NULL, "GPL", NULL, 0, &opts) == -EINVAL);
        CHECK(mock_memcg_probes == 1 && !allow_memcg_probe);
    }
    logging_modes(elf, size);
    copied_and_allocation_failures(elf, size, argv[1]);
    diagnostics_independent();
    {
        struct lmb_object_options_v1 o = options();
        struct lmb_object *obj = open_object(tracing, tracing_size, &o);
        struct lmb_program_options_v1 c = config("traced");
        c.attach_target.ptr = (const uint8_t *)"wrong_target"; c.attach_target.len = 12;
        CHECK(lmb_object_configure_program_v1(obj, &c) == -EINVAL);
        c.attach_target.ptr = (const uint8_t *)"do_sys_open"; c.attach_target.len = 11;
        c.autoload = 2; borrowed_target = c.attach_target.ptr;
        CHECK(lmb_object_configure_program_v1(obj, &c) == -2041);
        error_is(2, 2, -2041);
        struct lmb_name_v1 n = name("traced");
        struct lmb_program_info_v1 p = info();
        CHECK(lmb_object_program_info_v1(obj, &n, &p) == 0 && p.generation == 0 && p.autoload == 1);
        CHECK(lmb_object_close_v1(&obj) == 0);
    }
    for (unsigned i = 0; i < 128; i++) {
        struct lmb_object_options_v1 o = options();
        struct lmb_object *obj = open_object(elf, size, &o);
        struct lmb_object *view = obj;
        CHECK(lmb_object_ref_v1(obj) == 0);
        lmb_object_release_v1(&obj);
        lmb_object_unref_v1(view);
    }
    CHECK(fds() == baseline);
    CHECK(load_calls == 34 && bpf_calls == 0 && mock_program_requests == 57);
    free(elf); free(nomap); free(tracing);
    printf("generic object: %u checks, %u failures; host BPF calls=%u; intercepted program requests=%u, feature probes=%u\n",
           checks, failures, bpf_calls, mock_program_requests, mock_memcg_probes);
    return failures ? 1 : 0;
}
