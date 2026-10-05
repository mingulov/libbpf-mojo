/* libbpf-mojo native ABI v1.
 *
 * Authoritative contract: docs/abi-v1.md. This header must match it
 * exactly; the static assertions below verify every offset, size, and
 * alignment on each build. Platform: x86-64 Linux, LP64,
 * little-endian.
 */
#ifndef LIBBPF_MOJO_H
#define LIBBPF_MOJO_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

enum {
    LMB_ABI_VERSION = 1,
    LMB_FRAME_HEADER_SIZE = 8,
    LMB_FRAME_VERSION = 1,
    LMB_MAX_RAW_BYTES = 4096,
    LMB_MAX_FRAME_BYTES = 4104,
    LMB_MAX_NAME_BYTES = 256,
    LMB_ERROR_MSG_CAP = 1024,
    LMB_MAX_MSG_LEN = 1023
};

enum lmb_attach_kind_v1 {
    LMB_ATTACH_TRACEPOINT = 1,
    LMB_ATTACH_TRACING = 2
};

enum lmb_op_v1 {
    LMB_OP_NONE = 0,
    LMB_OP_OPEN = 1,
    LMB_OP_LOAD = 2,
    LMB_OP_ATTACH = 3,
    LMB_OP_POLL = 4,
    LMB_OP_MAP_INFO = 5,
    LMB_OP_MAP_READ = 6,
    LMB_OP_MAP_WRITE = 7,
    LMB_OP_STATS = 8,
    LMB_OP_DETACH = 9,
    LMB_OP_CLOSE = 10
};

enum lmb_domain_v1 {
    LMB_DOMAIN_NONE = 0,
    LMB_DOMAIN_POSIX = 1,
    LMB_DOMAIN_LIBBPF = 2,
    LMB_DOMAIN_KERNEL = 3,
    LMB_DOMAIN_BRIDGE = 4
};

struct lmb_bytes_v1 {
    const uint8_t *ptr;
    uint32_t len;
    uint32_t _pad;
};

struct lmb_options_v1 {
    uint32_t abi_version;
    uint32_t struct_size;
    struct lmb_bytes_v1 ring;
    uint32_t max_raw_bytes;
    uint32_t stage_slots;
    uint32_t flags;
    uint32_t _reserved;
};

struct lmb_attach_v1 {
    uint32_t abi_version;
    uint32_t struct_size;
    struct lmb_bytes_v1 program;
    uint32_t kind;
    uint32_t flags;
    struct lmb_bytes_v1 target_a;
    struct lmb_bytes_v1 target_b;
};

struct lmb_name_v1 {
    uint32_t abi_version;
    uint32_t struct_size;
    struct lmb_bytes_v1 name;
};

struct lmb_map_info_v1 {
    uint32_t abi_version;
    uint32_t struct_size;
    uint32_t type;
    uint32_t key_size;
    uint32_t value_size;
    uint32_t max_entries;
    uint32_t map_flags;
    uint32_t num_cpus;
    uint32_t stride;
    uint32_t _reserved;
};

struct lmb_stats_v1 {
    uint32_t abi_version;
    uint32_t struct_size;
    uint64_t received;
    uint64_t delivered;
    uint64_t staged;
    uint64_t malformed;
    uint64_t dropped;
    int32_t last_error;
    uint32_t _reserved;
};

struct lmb_error_v1 {
    uint32_t abi_version;
    uint32_t struct_size;
    uint32_t operation;
    uint32_t domain;
    int32_t code;
    uint32_t msg_len;
    uint8_t message[LMB_ERROR_MSG_CAP];
};

struct lmb_session;

int32_t lmb_open(const uint8_t *elf, uint64_t elf_bytes,
                 const struct lmb_options_v1 *options,
                 struct lmb_session **out);
int32_t lmb_load(struct lmb_session *session);
int32_t lmb_attach(struct lmb_session *session,
                   const struct lmb_attach_v1 *sites, uint32_t count);
int32_t lmb_poll(struct lmb_session *session, uint8_t *dst,
                 uint32_t capacity, uint32_t *written, uint32_t *required,
                 int32_t timeout_ms);
int32_t lmb_map_info(struct lmb_session *session,
                     const struct lmb_name_v1 *name,
                     struct lmb_map_info_v1 *out);
int32_t lmb_map_read(struct lmb_session *session,
                     const struct lmb_name_v1 *name, const uint8_t *key,
                     uint32_t key_bytes, uint8_t *dst, uint32_t capacity,
                     uint32_t *required);
int32_t lmb_map_write(struct lmb_session *session,
                      const struct lmb_name_v1 *name, const uint8_t *key,
                      uint32_t key_bytes, const uint8_t *value,
                      uint32_t value_bytes);
int32_t lmb_stats(struct lmb_session *session, struct lmb_stats_v1 *out);
int32_t lmb_last_error(struct lmb_error_v1 *out);
int32_t lmb_detach(struct lmb_session *session);
int32_t lmb_close(struct lmb_session **session);

#ifdef __cplusplus
}
#endif

/* Layout contract: every offset, size, and alignment. */
_Static_assert(offsetof(struct lmb_bytes_v1, ptr) == 0, "bytes.ptr");
_Static_assert(offsetof(struct lmb_bytes_v1, len) == 8, "bytes.len");
_Static_assert(sizeof(struct lmb_bytes_v1) == 16, "bytes.size");
_Static_assert(_Alignof(struct lmb_bytes_v1) == 8, "bytes.align");

_Static_assert(offsetof(struct lmb_options_v1, ring) == 8, "options.ring");
_Static_assert(offsetof(struct lmb_options_v1, max_raw_bytes) == 24,
               "options.max_raw_bytes");
_Static_assert(offsetof(struct lmb_options_v1, stage_slots) == 28,
               "options.stage_slots");
_Static_assert(offsetof(struct lmb_options_v1, flags) == 32,
               "options.flags");
_Static_assert(sizeof(struct lmb_options_v1) == 40, "options.size");
_Static_assert(_Alignof(struct lmb_options_v1) == 8, "options.align");

_Static_assert(offsetof(struct lmb_attach_v1, program) == 8,
               "attach.program");
_Static_assert(offsetof(struct lmb_attach_v1, kind) == 24, "attach.kind");
_Static_assert(offsetof(struct lmb_attach_v1, flags) == 28,
               "attach.flags");
_Static_assert(offsetof(struct lmb_attach_v1, target_a) == 32,
               "attach.target_a");
_Static_assert(offsetof(struct lmb_attach_v1, target_b) == 48,
               "attach.target_b");
_Static_assert(sizeof(struct lmb_attach_v1) == 64, "attach.size");
_Static_assert(_Alignof(struct lmb_attach_v1) == 8, "attach.align");

_Static_assert(offsetof(struct lmb_name_v1, name) == 8, "name.name");
_Static_assert(sizeof(struct lmb_name_v1) == 24, "name.size");
_Static_assert(_Alignof(struct lmb_name_v1) == 8, "name.align");

_Static_assert(offsetof(struct lmb_map_info_v1, type) == 8, "map.type");
_Static_assert(offsetof(struct lmb_map_info_v1, key_size) == 12,
               "map.key_size");
_Static_assert(offsetof(struct lmb_map_info_v1, value_size) == 16,
               "map.value_size");
_Static_assert(offsetof(struct lmb_map_info_v1, max_entries) == 20,
               "map.max_entries");
_Static_assert(offsetof(struct lmb_map_info_v1, stride) == 32, "map.stride");
_Static_assert(sizeof(struct lmb_map_info_v1) == 40, "map.size");
_Static_assert(_Alignof(struct lmb_map_info_v1) == 4, "map.align");

_Static_assert(offsetof(struct lmb_stats_v1, received) == 8,
               "stats.received");
_Static_assert(offsetof(struct lmb_stats_v1, dropped) == 40,
               "stats.dropped");
_Static_assert(offsetof(struct lmb_stats_v1, last_error) == 48,
               "stats.last_error");
_Static_assert(sizeof(struct lmb_stats_v1) == 56, "stats.size");
_Static_assert(_Alignof(struct lmb_stats_v1) == 8, "stats.align");

_Static_assert(offsetof(struct lmb_error_v1, operation) == 8,
               "error.operation");
_Static_assert(offsetof(struct lmb_error_v1, code) == 16, "error.code");
_Static_assert(offsetof(struct lmb_error_v1, msg_len) == 20, "error.msg_len");
_Static_assert(offsetof(struct lmb_error_v1, message) == 24,
               "error.message");
_Static_assert(sizeof(struct lmb_error_v1) == 1048, "error.size");
_Static_assert(_Alignof(struct lmb_error_v1) == 4, "error.align");

#endif /* LIBBPF_MOJO_H */
