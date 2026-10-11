/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
#ifndef LMB_GENERIC_INTERNAL_H
#define LMB_GENERIC_INTERNAL_H
#include <stddef.h>
#include "libbpf_mojo_generic.h"

struct bpf_object;
struct bpf_program;
struct lmb_program_state {
    struct bpf_program *program;
    char *attach_target;
    char *log;
    size_t log_actual;
    unsigned load_failed;
};

struct lmb_object {
    uint8_t *elf;
    size_t elf_len;
    char *name;
    char *custom_btf;
    struct bpf_object *obj;
    struct lmb_program_state *programs;
    size_t program_count;
    uint32_t log_level;
    size_t log_capacity;
    uint64_t generation;
    unsigned refs;
    unsigned external;
    unsigned load_attempted;
    unsigned loaded;
};

void lmb_generic_record(uint32_t op, uint32_t domain, int32_t code,
                        const char *message);
void lmb_generic_clear(void);
int lmb_generic_check_span(const void *ptr, uint64_t len);
int lmb_generic_check_name(const struct lmb_name_v1 *name);
int lmb_generic_ranges_overlap(const void *a, uint64_t an,
                               const void *b, uint64_t bn);
unsigned lmb_object_live_children(const struct lmb_object *obj);
int lmb_object_need_loaded(const struct lmb_object *obj, uint32_t op);
/* Private generic children; no layout crosses the public boundary. */
struct bpf_link;
struct ring_buffer;
struct lmb_link {
    struct lmb_object *parent;
    struct bpf_link *link;
};
struct lmb_buffer {
    struct lmb_object *parent;
    struct ring_buffer *rb;
    uint32_t max_raw_bytes;
    uint32_t stage_len;
    uint8_t stage[4096];
    uint64_t received;
    uint64_t delivered;
    uint64_t malformed;
    uint64_t dropped;
};
#endif
