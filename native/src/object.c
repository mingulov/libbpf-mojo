/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
#include <errno.h>
#include <limits.h>
#include <linux/bpf.h>
#include <stdlib.h>
#include <string.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>
#include "internal.h"
#include "generic_internal.h"

static _Thread_local struct lmb_generic_error_v1 generic_error;

void lmb_generic_clear(void) {
    memset(&generic_error, 0, sizeof(generic_error));
}

void lmb_generic_record(uint32_t op, uint32_t domain, int32_t code,
                        const char *message) {
    size_t n = 0;
    lmb_generic_clear();
    generic_error.abi_version = 1;
    generic_error.struct_size = sizeof(generic_error);
    generic_error.operation = op;
    generic_error.domain = domain;
    generic_error.code = code;
    while (n < LMB_GENERIC_MAX_MSG_LEN && message[n]) {
        unsigned char c = (unsigned char)message[n];
        generic_error.message[n] = c >= 32 && c <= 126 ? c : '?';
        n++;
    }
    generic_error.msg_len = (uint32_t)n;
}

static int32_t fail(uint32_t op, uint32_t domain, int32_t code,
                    const char *message) {
    lmb_generic_record(op, domain, code, message);
    return code;
}

int32_t lmb_generic_last_error_v1(struct lmb_generic_error_v1 *out) {
    if (!out || !lmb_check_header(out->abi_version, out->struct_size, sizeof(*out)))
        return -EINVAL;
    memcpy(out, &generic_error, sizeof(*out));
    return 0;
}

int lmb_generic_check_span(const void *ptr, uint64_t len) {
    return len == 0 || (ptr && len <= SIZE_MAX &&
        len <= UINTPTR_MAX - (uintptr_t)ptr);
}

int lmb_generic_ranges_overlap(const void *a, uint64_t an,
                               const void *b, uint64_t bn) {
    uintptr_t ap = (uintptr_t)a, bp = (uintptr_t)b;
    if (!an || !bn) return 0;
    if (!lmb_generic_check_span(a, an) || !lmb_generic_check_span(b, bn)) return 1;
    return ap <= bp ? bp - ap < an : ap - bp < bn;
}

static int text_span(const struct lmb_span_v1 *span, int required) {
    struct lmb_bytes_v1 bytes;
    if (span->len > 256 || !lmb_generic_check_span(span->ptr, span->len)) return 0;
    bytes.ptr = span->ptr; bytes.len = (uint32_t)span->len; bytes._pad = 0;
    return lmb_check_bytes(&bytes, 256, required);
}

int lmb_generic_check_name(const struct lmb_name_v1 *name) {
    return name && lmb_check_header(name->abi_version, name->struct_size, sizeof(*name)) &&
        lmb_generic_check_span(name->name.ptr, name->name.len) &&
        lmb_check_bytes(&name->name, 256, 1);
}

static char *copy_span(const uint8_t *bytes, size_t len) {
    char *text;
    if (!len) return NULL;
    text = malloc(len + 1);
    if (text) { memcpy(text, bytes, len); text[len] = 0; }
    return text;
}

static void name_text(const struct lmb_name_v1 *name, char text[257]) {
    memcpy(text, name->name.ptr, name->name.len);
    text[name->name.len] = 0;
}

static void destroy(struct lmb_object *obj) {
    if (obj->obj) bpf_object__close(obj->obj);
    for (size_t i = 0; i < obj->program_count; i++) {
        free(obj->programs[i].attach_target);
        free(obj->programs[i].log);
    }
    free(obj->programs); free(obj->custom_btf); free(obj->name);
    free(obj->elf); free(obj);
}

unsigned lmb_object_live_children(const struct lmb_object *obj) {
    return obj ? obj->refs - obj->external : 0;
}

int lmb_object_need_loaded(const struct lmb_object *obj, uint32_t op) {
    if (obj && obj->loaded) return 1;
    fail(op, LMB_GENERIC_DOMAIN_BRIDGE, -EINVAL, "object is not loaded");
    return 0;
}

int32_t lmb_object_open_v1(const uint8_t *elf, uint64_t elf_bytes,
    const struct lmb_object_options_v1 *opts, struct lmb_object **out) {
    const uint32_t op = LMB_GENERIC_OP_OBJECT_OPEN;
    struct lmb_object *obj;
    struct bpf_program *program;
    struct bpf_map *map;
    struct bpf_object_open_opts native = {0};
    int32_t code;
    if (!out) return fail(op, 4, -EINVAL, "null output handle");
    *out = NULL;
    if (!opts || !lmb_check_header(opts->abi_version, opts->struct_size, sizeof(*opts)))
        return fail(op, 4, -EINVAL, "invalid options header");
    if (!elf_bytes || !lmb_generic_check_span(elf, elf_bytes) ||
        !text_span(&opts->name, 0) || opts->custom_btf.len > 4096 ||
        !lmb_generic_check_span(opts->custom_btf.ptr, opts->custom_btf.len) ||
        (opts->custom_btf.len && memchr(opts->custom_btf.ptr, 0, (size_t)opts->custom_btf.len)))
        return fail(op, 4, -EINVAL, "invalid input span");
    if (opts->log_level > 2 || opts->flags || opts->_reserved || opts->log_capacity > 1048576)
        return fail(op, 4, -EINVAL, "unsupported object options");
    if (lmb_generic_ranges_overlap(out, sizeof(*out), opts, sizeof(*opts)) ||
        lmb_generic_ranges_overlap(out, sizeof(*out), elf, elf_bytes) ||
        lmb_generic_ranges_overlap(out, sizeof(*out), opts->name.ptr, opts->name.len) ||
        lmb_generic_ranges_overlap(out, sizeof(*out), opts->custom_btf.ptr, opts->custom_btf.len))
        return fail(op, 4, -EINVAL, "output aliases input");
    obj = calloc(1, sizeof(*obj));
    if (!obj) return fail(op, 1, -ENOMEM, "allocation failed");
    obj->elf_len = (size_t)elf_bytes;
    obj->elf = malloc(obj->elf_len);
    obj->name = copy_span(opts->name.ptr, (size_t)opts->name.len);
    obj->custom_btf = copy_span(opts->custom_btf.ptr, (size_t)opts->custom_btf.len);
    if (!obj->elf || (opts->name.len && !obj->name) ||
        (opts->custom_btf.len && !obj->custom_btf)) {
        code = -ENOMEM; goto allocation_failed;
    }
    memcpy(obj->elf, elf, obj->elf_len);
    obj->log_level = opts->log_level;
    obj->log_capacity = (size_t)opts->log_capacity;
    libbpf_set_print(NULL);
    if (obj->custom_btf) {
        struct btf *btf = btf__parse(obj->custom_btf, NULL);
        code = (int32_t)libbpf_get_error(btf);
        if (code) goto native_failed;
        btf__free(btf);
    }
    native.sz = sizeof(native);
    native.object_name = obj->name;
    native.btf_custom_path = obj->custom_btf;
    native.kernel_log_level = obj->log_level ? 1 : 0;
    native.bpf_token_path = "";
    obj->obj = bpf_object__open_mem(obj->elf, obj->elf_len, &native);
    code = (int32_t)libbpf_get_error(obj->obj);
    if (code) { obj->obj = NULL; goto native_failed; }
    bpf_object__for_each_map(map, obj->obj) {
        code = bpf_map__set_pin_path(map, NULL);
        if (code) goto native_failed;
    }
    bpf_object__for_each_program(program, obj->obj) obj->program_count++;
    if (obj->program_count) {
        obj->programs = calloc(obj->program_count, sizeof(*obj->programs));
        if (!obj->programs) { obj->program_count = 0; code = -ENOMEM; goto allocation_failed; }
    }
    size_t i = 0;
    bpf_object__for_each_program(program, obj->obj) {
        struct lmb_program_state *state = &obj->programs[i++];
        state->program = program;
        if (obj->log_capacity && obj->log_level) {
            state->log = calloc(1, obj->log_capacity);
            if (!state->log) { code = -ENOMEM; goto allocation_failed; }
        }
        code = bpf_program__set_log_buf(program, state->log,
                                        state->log ? obj->log_capacity : 0);
        if (code) goto native_failed;
        code = bpf_program__set_log_level(program, obj->log_level ? 1 : 0);
        if (code) goto native_failed;
    }
    obj->refs = 1; obj->external = 1;
    *out = obj;
    lmb_generic_clear();
    return 0;
allocation_failed:
    destroy(obj);
    return fail(op, 1, code, "allocation failed");
native_failed:
    destroy(obj);
    return fail(op, 2, code, "cannot open object");
}

int32_t lmb_object_configure_program_v1(struct lmb_object *obj,
    const struct lmb_program_options_v1 *opts) {
    const uint32_t op = LMB_GENERIC_OP_PROGRAM_CONFIGURE;
    struct bpf_program *program;
    struct lmb_program_state *state = NULL;
    char text[257], *target = NULL;
    int32_t code;
    if (!opts || !lmb_check_header(opts->abi_version, opts->struct_size, sizeof(*opts)))
        return fail(op, 4, -EINVAL, "invalid options header");
    if (!text_span(&opts->program, 1) || !text_span(&opts->attach_target, 0))
        return fail(op, 4, -EINVAL, "invalid program span");
    if (opts->autoload > 2 || opts->flags)
        return fail(op, 4, -EINVAL, "unsupported program options");
    if (!obj || obj->load_attempted)
        return fail(op, 4, -EINVAL, "configuration requires an opened object");
    if (obj->generation == UINT64_MAX)
        return fail(op, 4, -EOVERFLOW, "generation overflow");
    memcpy(text, opts->program.ptr, (size_t)opts->program.len); text[opts->program.len] = 0;
    program = bpf_object__find_program_by_name(obj->obj, text);
    if (!program) return fail(op, 4, -ENOENT, "program not found");
    for (size_t i = 0; i < obj->program_count; i++)
        if (obj->programs[i].program == program) state = &obj->programs[i];
    if (opts->attach_target.len) {
        enum bpf_prog_type type = bpf_program__type(program);
        const char *section = bpf_program__section_name(program);
        const char *suffix = strchr(section, '/');
        if (type != BPF_PROG_TYPE_TRACING && type != BPF_PROG_TYPE_LSM &&
            type != BPF_PROG_TYPE_EXT)
            return fail(op, 4, -EINVAL, "program does not accept a tracing target");
        if (suffix && suffix[1] && (strlen(suffix + 1) != opts->attach_target.len ||
            memcmp(suffix + 1, opts->attach_target.ptr, (size_t)opts->attach_target.len)))
            return fail(op, 4, -EINVAL, "target disagrees with program section");
        target = copy_span(opts->attach_target.ptr, (size_t)opts->attach_target.len);
        if (!target) return fail(op, 1, -ENOMEM, "allocation failed");
        code = bpf_program__set_attach_target(program, 0, target);
        if (code) { free(target); return fail(op, 2, code, "cannot configure tracing target"); }
    }
    if (opts->autoload) {
        code = bpf_program__set_autoload(program, opts->autoload == 1);
        if (code) { free(target); return fail(op, 2, code, "cannot configure autoload"); }
    }
    if (target) { free(state->attach_target); state->attach_target = target; }
    obj->generation++;
    lmb_generic_clear();
    return 0;
}

int32_t lmb_object_load_v1(struct lmb_object *obj) {
    const uint32_t op = LMB_GENERIC_OP_OBJECT_LOAD;
    int32_t code;
    if (!obj || obj->load_attempted)
        return fail(op, 4, -EINVAL, "object load already attempted or owner is null");
    obj->load_attempted = 1;
    code = bpf_object__load(obj->obj);
    obj->loaded = code == 0;
    for (size_t i = 0; i < obj->program_count; i++) {
        struct lmb_program_state *state = &obj->programs[i];
        if (state->log && (obj->log_level == 2 || code))
            state->log_actual = strnlen(state->log, obj->log_capacity);
        else {
            state->log_actual = 0;
            if (state->log) memset(state->log, 0, obj->log_capacity);
        }
    }
    if (code) return fail(op, 2, code, "object load failed");
    lmb_generic_clear();
    return 0;
}

int32_t lmb_object_program_info_v1(struct lmb_object *obj,
    const struct lmb_name_v1 *name, struct lmb_program_info_v1 *out) {
    const uint32_t op = LMB_GENERIC_OP_PROGRAM_INFO;
    struct lmb_out_span_v1 log;
    struct bpf_program *program;
    struct lmb_program_state *state = NULL;
    char text[257];
    if (!out || !lmb_check_header(out->abi_version, out->struct_size, sizeof(*out)) ||
        !name || !lmb_check_header(name->abi_version, name->struct_size, sizeof(*name)))
        return fail(op, 4, -EINVAL, "invalid info header");
    log = out->log;
    if (!lmb_generic_check_name(name) || !lmb_generic_check_span(log.ptr, log.len))
        return fail(op, 4, -EINVAL, "invalid info span");
    if (lmb_generic_ranges_overlap(out, sizeof(*out), name, sizeof(*name)) ||
        lmb_generic_ranges_overlap(out, sizeof(*out), name->name.ptr, name->name.len) ||
        lmb_generic_ranges_overlap(log.ptr, log.len, out, sizeof(*out)) ||
        lmb_generic_ranges_overlap(log.ptr, log.len, name, sizeof(*name)) ||
        lmb_generic_ranges_overlap(log.ptr, log.len, name->name.ptr, name->name.len))
        return fail(op, 4, -EINVAL, "info output aliases input");
    if (!obj) return fail(op, 4, -EINVAL, "null object");
    name_text(name, text);
    program = bpf_object__find_program_by_name(obj->obj, text);
    if (!program) return fail(op, 4, -ENOENT, "program not found");
    for (size_t i = 0; i < obj->program_count; i++)
        if (obj->programs[i].program == program) state = &obj->programs[i];
    memset(out, 0, sizeof(*out));
    out->abi_version = 1; out->struct_size = sizeof(*out); out->log = log;
    out->prog_type = bpf_program__type(program);
    out->attach_type = bpf_program__expected_attach_type(program);
    out->insn_count = bpf_program__insn_cnt(program);
    out->generation = obj->generation;
    out->autoload = bpf_program__autoload(program) ? 1 : 0;
    out->log_actual = state->log_actual;
    out->log_truncated = state->log_actual > log.len;
    size_t copied = state->log_actual < log.len ? state->log_actual : (size_t)log.len;
    if (copied) memcpy(log.ptr, state->log, copied);
    lmb_generic_clear();
    return 0;
}

int32_t lmb_object_map_info_v1(struct lmb_object *obj,
    const struct lmb_name_v1 *name, struct lmb_map_info_v1 *out) {
    const uint32_t op = LMB_GENERIC_OP_MAP_INFO;
    char text[257];
    struct bpf_map *map;
    uint32_t type, value;
    int cpus;
    if (!out || !lmb_check_header(out->abi_version, out->struct_size, sizeof(*out)) ||
        !name || !lmb_check_header(name->abi_version, name->struct_size, sizeof(*name)))
        return fail(op, 4, -EINVAL, "invalid map header");
    if (!lmb_generic_check_name(name)) return fail(op, 4, -EINVAL, "invalid map name");
    if (lmb_generic_ranges_overlap(out, sizeof(*out), name, sizeof(*name)) ||
        lmb_generic_ranges_overlap(out, sizeof(*out), name->name.ptr, name->name.len))
        return fail(op, 4, -EINVAL, "map output aliases input");
    if (!lmb_object_need_loaded(obj, op)) return -EINVAL;
    name_text(name, text);
    map = bpf_object__find_map_by_name(obj->obj, text);
    if (!map) return fail(op, 4, -ENOENT, "map not found");
    type = bpf_map__type(map); value = bpf_map__value_size(map);
    int percpu = type == BPF_MAP_TYPE_PERCPU_HASH || type == BPF_MAP_TYPE_PERCPU_ARRAY ||
        type == BPF_MAP_TYPE_LRU_PERCPU_HASH || type == BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE;
    if (percpu && value > UINT32_MAX - 7)
        return fail(op, 4, -EOVERFLOW, "map stride overflow");
    cpus = libbpf_num_possible_cpus();
    if (cpus <= 0) return fail(op, 2, cpus < 0 ? cpus : -EIO, "cannot query CPU count");
    memset(out, 0, sizeof(*out));
    out->abi_version = 1; out->struct_size = sizeof(*out);
    out->type = type; out->key_size = bpf_map__key_size(map); out->value_size = value;
    out->max_entries = bpf_map__max_entries(map); out->map_flags = bpf_map__map_flags(map);
    out->num_cpus = (uint32_t)cpus; out->stride = percpu ? (value + 7u) & ~7u : 0;
    lmb_generic_clear();
    return 0;
}

int32_t lmb_object_ref_v1(struct lmb_object *obj) {
    if (!obj) return fail(15, 4, -EINVAL, "null view owner");
    if (obj->refs == UINT_MAX) return fail(15, 4, -EOVERFLOW, "view count overflow");
    obj->refs++; lmb_generic_clear(); return 0;
}

void lmb_object_unref_v1(struct lmb_object *obj) {
    if (obj && --obj->refs == 0) destroy(obj);
}

int32_t lmb_object_gen_v1(const struct lmb_object *obj, uint64_t *generation) {
    if (!obj || !generation ||
        lmb_generic_ranges_overlap(generation, sizeof(*generation), obj, sizeof(*obj)))
        return fail(16, 4, -EINVAL, "invalid generation query");
    *generation = obj->generation; lmb_generic_clear(); return 0;
}

int32_t lmb_object_gen_check_v1(const struct lmb_object *obj, uint64_t expected) {
    if (!obj) return fail(17, 4, -EINVAL, "null view owner");
    if (expected != obj->generation) return fail(17, 4, -ESTALE, "stale object view");
    lmb_generic_clear(); return 0;
}

void lmb_object_release_v1(struct lmb_object **cell) {
    struct lmb_object *obj;
    if (!cell || !*cell) return;
    obj = *cell; *cell = NULL; obj->external = 0;
    lmb_object_unref_v1(obj);
}

int32_t lmb_object_close_v1(struct lmb_object **cell) {
    if (!cell) return fail(6, 4, -EINVAL, "null owner cell");
    if (*cell && lmb_object_live_children(*cell))
        return fail(6, 4, -EBUSY, "object still has live children or views");
    lmb_object_release_v1(cell); lmb_generic_clear(); return 0;
}
