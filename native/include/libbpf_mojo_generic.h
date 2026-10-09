/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */

/* libbpf-mojo generic ABI v1: opaque object/link/buffer owners.
 *
 * Authoritative contract: docs/generic-abi-v1.md. This header must
 * match it exactly; the static assertions below verify every
 * offset, size, and alignment on each build. Platform: x86-64
 * Linux, LP64, little-endian. AArch64 layout equivalence is not
 * established.
 *
 * This interface is additive: the v1 session API in
 * libbpf_mojo.h keeps its signatures, discriminants, and
 * behavior, and none of the records below reinterprets it.
 * Program/map names and map geometry reuse the v1 structs
 * (lmb_name_v1, lmb_map_info_v1) unchanged.
 */
#ifndef LIBBPF_MOJO_GENERIC_H
#define LIBBPF_MOJO_GENERIC_H

#include <stddef.h>
#include <stdint.h>

#include "libbpf_mojo.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    LMB_GENERIC_ABI_VERSION = 1,
    LMB_GENERIC_MAX_NAME_BYTES = 256,
    LMB_GENERIC_MAX_PATH_BYTES = 4096,
    LMB_GENERIC_ERROR_MSG_CAP = 1024,
    LMB_GENERIC_MAX_MSG_LEN = 1023,
    LMB_GENERIC_MAX_RAW_BYTES = 4096,
    LMB_GENERIC_MAX_FRAME_BYTES = 4104,
    LMB_GENERIC_FRAME_HEADER_SIZE = 8,
    LMB_GENERIC_FRAME_VERSION = 1,
    LMB_GENERIC_MAX_LOG_BYTES = 1048576,
    LMB_GENERIC_MAX_TEST_BYTES = 1048576
};

enum {
    LMB_AUTOLOAD_UNCHANGED = 0,
    LMB_AUTOLOAD_ENABLE = 1,
    LMB_AUTOLOAD_DISABLE = 2
};

enum {
    LMB_LOG_DISCARD = 0,
    LMB_LOG_ON_FAILURE = 1,
    LMB_LOG_ALWAYS = 2
};

enum {
    LMB_MAP_UPDATE_ANY = 0,
    LMB_MAP_UPDATE_NOEXIST = 1,
    LMB_MAP_UPDATE_EXIST = 2,
    LMB_MAP_UPDATE_LOCK = 4
};

enum lmb_generic_op_v1 {
    LMB_GENERIC_OP_NONE = 0,
    LMB_GENERIC_OP_OBJECT_OPEN = 1,
    LMB_GENERIC_OP_PROGRAM_CONFIGURE = 2,
    LMB_GENERIC_OP_OBJECT_LOAD = 3,
    LMB_GENERIC_OP_PROGRAM_INFO = 4,
    LMB_GENERIC_OP_MAP_INFO = 5,
    LMB_GENERIC_OP_OBJECT_CLOSE = 6,
    LMB_GENERIC_OP_MAP_LOOKUP = 7,
    LMB_GENERIC_OP_MAP_UPDATE = 8,
    LMB_GENERIC_OP_TEST_RUN = 9,
    LMB_GENERIC_OP_ATTACH = 10,
    LMB_GENERIC_OP_LINK_CLOSE = 11,
    LMB_GENERIC_OP_BUFFER_OPEN = 12,
    LMB_GENERIC_OP_BUFFER_POLL = 13,
    LMB_GENERIC_OP_BUFFER_CLOSE = 14
};

enum lmb_generic_domain_v1 {
    LMB_GENERIC_DOMAIN_NONE = 0,
    LMB_GENERIC_DOMAIN_POSIX = 1,
    LMB_GENERIC_DOMAIN_LIBBPF = 2,
    LMB_GENERIC_DOMAIN_KERNEL = 3,
    LMB_GENERIC_DOMAIN_BRIDGE = 4
};

enum lmb_attach_family_v1 {
    LMB_ATTACH_FAMILY_TRACEPOINT = 1
};

/* Nested span layouts, versioned by their enclosing struct. Input
 * spans are copied when retained and borrowed only for the call
 * otherwise; output spans are caller-owned mutable storage. */
struct lmb_span_v1 {
    const uint8_t *ptr;
    uint64_t len;
};

struct lmb_out_span_v1 {
    uint8_t *ptr;
    uint64_t len;
};

struct lmb_object_options_v1 {
    uint32_t abi_version;
    uint32_t struct_size;
    struct lmb_span_v1 name;
    struct lmb_span_v1 custom_btf;
    uint32_t log_level;
    uint32_t flags;
    uint64_t log_capacity;
    uint64_t _reserved;
};

struct lmb_program_options_v1 {
    uint32_t abi_version;
    uint32_t struct_size;
    struct lmb_span_v1 program;
    struct lmb_span_v1 attach_target;
    uint32_t autoload;
    uint32_t flags;
};

struct lmb_program_info_v1 {
    uint32_t abi_version;
    uint32_t struct_size;
    uint32_t prog_type;
    uint32_t attach_type;
    uint64_t insn_count;
    uint64_t generation;
    uint32_t autoload;
    uint32_t _pad0;
    struct lmb_out_span_v1 log;
    uint64_t log_actual;
    uint32_t log_truncated;
    uint32_t _reserved;
};

struct lmb_generic_error_v1 {
    uint32_t abi_version;
    uint32_t struct_size;
    uint32_t operation;
    uint32_t domain;
    int32_t code;
    uint32_t msg_len;
    uint8_t message[LMB_GENERIC_ERROR_MSG_CAP];
};

struct lmb_program_test_options_v1 {
    uint32_t abi_version;
    uint32_t struct_size;
    struct lmb_span_v1 data_in;
    struct lmb_out_span_v1 data_out;
    struct lmb_span_v1 ctx_in;
    struct lmb_out_span_v1 ctx_out;
    uint64_t repeat;
    uint64_t flags;
};

struct lmb_program_test_result_v1 {
    uint32_t abi_version;
    uint32_t struct_size;
    uint32_t retval;
    uint32_t _pad;
    uint64_t data_actual;
    uint64_t ctx_actual;
    uint64_t duration_ns;
};

struct lmb_attach_options_v1 {
    uint32_t abi_version;
    uint32_t struct_size;
    struct lmb_span_v1 program;
    uint32_t family;
    uint32_t flags;
    struct lmb_span_v1 target_a;
    struct lmb_span_v1 target_b;
    uint64_t _reserved;
};

struct lmb_buffer_options_v1 {
    uint32_t abi_version;
    uint32_t struct_size;
    struct lmb_span_v1 ring;
    uint32_t max_raw_bytes;
    uint32_t stage_slots;
    uint32_t flags;
    uint32_t _reserved;
};

struct lmb_object;
struct lmb_link;
struct lmb_buffer;

int32_t lmb_object_open_v1(const uint8_t *elf, uint64_t elf_bytes,
                           const struct lmb_object_options_v1 *opts,
                           struct lmb_object **out);
int32_t lmb_object_configure_program_v1(
    struct lmb_object *object, const struct lmb_program_options_v1 *opts);
int32_t lmb_object_load_v1(struct lmb_object *object);
int32_t lmb_object_program_info_v1(struct lmb_object *object,
                                   const struct lmb_name_v1 *name,
                                   struct lmb_program_info_v1 *out);
int32_t lmb_object_map_info_v1(struct lmb_object *object,
                               const struct lmb_name_v1 *name,
                               struct lmb_map_info_v1 *out);
int32_t lmb_object_close_v1(struct lmb_object **object);
void lmb_object_release_v1(struct lmb_object **object);
int32_t lmb_generic_last_error_v1(struct lmb_generic_error_v1 *out);
int32_t lmb_object_map_lookup_v1(struct lmb_object *object,
                                 const struct lmb_name_v1 *name,
                                 const uint8_t *key, uint64_t key_bytes,
                                 uint8_t *value, uint64_t capacity,
                                 uint64_t *needed);
int32_t lmb_object_map_update_v1(struct lmb_object *object,
                                 const struct lmb_name_v1 *name,
                                 const uint8_t *key, uint64_t key_bytes,
                                 const uint8_t *value, uint64_t value_bytes,
                                 uint64_t flags);
int32_t lmb_program_test_run_v1(
    struct lmb_object *object, const struct lmb_name_v1 *program,
    const struct lmb_program_test_options_v1 *opts,
    struct lmb_program_test_result_v1 *out);
int32_t lmb_object_attach_v1(struct lmb_object *object,
                             const struct lmb_attach_options_v1 *opts,
                             struct lmb_link **out);
int32_t lmb_link_close_v1(struct lmb_link **link);
int32_t lmb_buffer_open_v1(struct lmb_object *object,
                           const struct lmb_buffer_options_v1 *opts,
                           struct lmb_buffer **out);
int32_t lmb_buffer_poll_v1(struct lmb_buffer *buffer, uint8_t *dst,
                           uint64_t capacity, int32_t timeout_ms,
                           uint64_t *used, uint64_t *needed);
int32_t lmb_buffer_close_v1(struct lmb_buffer **buffer);

#ifdef __cplusplus
}
#endif

/* Layout contract: every offset, size, and alignment. */
_Static_assert(offsetof(struct lmb_span_v1, ptr) == 0, "span.ptr");
_Static_assert(offsetof(struct lmb_span_v1, len) == 8, "span.len");
_Static_assert(sizeof(struct lmb_span_v1) == 16, "span.size");
_Static_assert(_Alignof(struct lmb_span_v1) == 8, "span.align");

_Static_assert(offsetof(struct lmb_out_span_v1, ptr) == 0, "ospan.ptr");
_Static_assert(offsetof(struct lmb_out_span_v1, len) == 8, "ospan.len");
_Static_assert(sizeof(struct lmb_out_span_v1) == 16, "ospan.size");
_Static_assert(_Alignof(struct lmb_out_span_v1) == 8, "ospan.align");

_Static_assert(offsetof(struct lmb_object_options_v1, name) == 8,
               "oopts.name");
_Static_assert(offsetof(struct lmb_object_options_v1, custom_btf) == 24,
               "oopts.custom_btf");
_Static_assert(offsetof(struct lmb_object_options_v1, log_level) == 40,
               "oopts.log_level");
_Static_assert(offsetof(struct lmb_object_options_v1, flags) == 44,
               "oopts.flags");
_Static_assert(offsetof(struct lmb_object_options_v1, log_capacity) == 48,
               "oopts.log_capacity");
_Static_assert(offsetof(struct lmb_object_options_v1, _reserved) == 56,
               "oopts.reserved");
_Static_assert(sizeof(struct lmb_object_options_v1) == 64, "oopts.size");
_Static_assert(_Alignof(struct lmb_object_options_v1) == 8, "oopts.align");

_Static_assert(offsetof(struct lmb_program_options_v1, program) == 8,
               "popts.program");
_Static_assert(offsetof(struct lmb_program_options_v1, attach_target) == 24,
               "popts.attach_target");
_Static_assert(offsetof(struct lmb_program_options_v1, autoload) == 40,
               "popts.autoload");
_Static_assert(offsetof(struct lmb_program_options_v1, flags) == 44,
               "popts.flags");
_Static_assert(sizeof(struct lmb_program_options_v1) == 48, "popts.size");
_Static_assert(_Alignof(struct lmb_program_options_v1) == 8, "popts.align");

_Static_assert(offsetof(struct lmb_program_info_v1, prog_type) == 8,
               "pinfo.prog_type");
_Static_assert(offsetof(struct lmb_program_info_v1, attach_type) == 12,
               "pinfo.attach_type");
_Static_assert(offsetof(struct lmb_program_info_v1, insn_count) == 16,
               "pinfo.insn_count");
_Static_assert(offsetof(struct lmb_program_info_v1, generation) == 24,
               "pinfo.generation");
_Static_assert(offsetof(struct lmb_program_info_v1, autoload) == 32,
               "pinfo.autoload");
_Static_assert(offsetof(struct lmb_program_info_v1, log) == 40,
               "pinfo.log");
_Static_assert(offsetof(struct lmb_program_info_v1, log_actual) == 56,
               "pinfo.log_actual");
_Static_assert(offsetof(struct lmb_program_info_v1, log_truncated) == 64,
               "pinfo.log_truncated");
_Static_assert(offsetof(struct lmb_program_info_v1, _reserved) == 68,
               "pinfo.reserved");
_Static_assert(sizeof(struct lmb_program_info_v1) == 72, "pinfo.size");
_Static_assert(_Alignof(struct lmb_program_info_v1) == 8, "pinfo.align");

_Static_assert(offsetof(struct lmb_generic_error_v1, operation) == 8,
               "gerror.operation");
_Static_assert(offsetof(struct lmb_generic_error_v1, domain) == 12,
               "gerror.domain");
_Static_assert(offsetof(struct lmb_generic_error_v1, code) == 16,
               "gerror.code");
_Static_assert(offsetof(struct lmb_generic_error_v1, msg_len) == 20,
               "gerror.msg_len");
_Static_assert(offsetof(struct lmb_generic_error_v1, message) == 24,
               "gerror.message");
_Static_assert(sizeof(struct lmb_generic_error_v1) == 1048, "gerror.size");
_Static_assert(_Alignof(struct lmb_generic_error_v1) == 4, "gerror.align");

_Static_assert(offsetof(struct lmb_program_test_options_v1, data_in) == 8,
               "topts.data_in");
_Static_assert(offsetof(struct lmb_program_test_options_v1, data_out) == 24,
               "topts.data_out");
_Static_assert(offsetof(struct lmb_program_test_options_v1, ctx_in) == 40,
               "topts.ctx_in");
_Static_assert(offsetof(struct lmb_program_test_options_v1, ctx_out) == 56,
               "topts.ctx_out");
_Static_assert(offsetof(struct lmb_program_test_options_v1, repeat) == 72,
               "topts.repeat");
_Static_assert(offsetof(struct lmb_program_test_options_v1, flags) == 80,
               "topts.flags");
_Static_assert(sizeof(struct lmb_program_test_options_v1) == 88,
               "topts.size");
_Static_assert(_Alignof(struct lmb_program_test_options_v1) == 8,
               "topts.align");

_Static_assert(offsetof(struct lmb_program_test_result_v1, retval) == 8,
               "tresult.retval");
_Static_assert(offsetof(struct lmb_program_test_result_v1, data_actual) == 16,
               "tresult.data_actual");
_Static_assert(offsetof(struct lmb_program_test_result_v1, ctx_actual) == 24,
               "tresult.ctx_actual");
_Static_assert(offsetof(struct lmb_program_test_result_v1, duration_ns) == 32,
               "tresult.duration_ns");
_Static_assert(sizeof(struct lmb_program_test_result_v1) == 40,
               "tresult.size");
_Static_assert(_Alignof(struct lmb_program_test_result_v1) == 8,
               "tresult.align");

_Static_assert(offsetof(struct lmb_attach_options_v1, program) == 8,
               "aopts.program");
_Static_assert(offsetof(struct lmb_attach_options_v1, family) == 24,
               "aopts.family");
_Static_assert(offsetof(struct lmb_attach_options_v1, flags) == 28,
               "aopts.flags");
_Static_assert(offsetof(struct lmb_attach_options_v1, target_a) == 32,
               "aopts.target_a");
_Static_assert(offsetof(struct lmb_attach_options_v1, target_b) == 48,
               "aopts.target_b");
_Static_assert(offsetof(struct lmb_attach_options_v1, _reserved) == 64,
               "aopts.reserved");
_Static_assert(sizeof(struct lmb_attach_options_v1) == 72, "aopts.size");
_Static_assert(_Alignof(struct lmb_attach_options_v1) == 8, "aopts.align");

_Static_assert(offsetof(struct lmb_buffer_options_v1, ring) == 8,
               "bopts.ring");
_Static_assert(offsetof(struct lmb_buffer_options_v1, max_raw_bytes) == 24,
               "bopts.max_raw_bytes");
_Static_assert(offsetof(struct lmb_buffer_options_v1, stage_slots) == 28,
               "bopts.stage_slots");
_Static_assert(offsetof(struct lmb_buffer_options_v1, flags) == 32,
               "bopts.flags");
_Static_assert(offsetof(struct lmb_buffer_options_v1, _reserved) == 36,
               "bopts.reserved");
_Static_assert(sizeof(struct lmb_buffer_options_v1) == 40, "bopts.size");
_Static_assert(_Alignof(struct lmb_buffer_options_v1) == 8, "bopts.align");

#endif /* LIBBPF_MOJO_GENERIC_H */
