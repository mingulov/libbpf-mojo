/* SPDX-License-Identifier: GPL-3.0-or-later */

/* Internal bridge state shared by the native sources. Not installed. */
#ifndef LMB_INTERNAL_H
#define LMB_INTERNAL_H

#include <stddef.h>
#include <stdint.h>

#include "libbpf_mojo.h"

struct bpf_object;
struct bpf_link;
struct ring_buffer;

struct lmb_session {
    uint8_t *elf;
    uint64_t elf_len;
    char *ring_name;
    uint32_t max_raw_bytes;
    struct bpf_object *obj;
    struct bpf_link **links;
    uint32_t nlinks;
    uint32_t link_cap;
    struct ring_buffer *rb;
    int ring_fd;
    uint8_t stage[LMB_MAX_FRAME_BYTES];
    uint32_t stage_len;
    uint64_t received;
    uint64_t delivered;
    uint64_t malformed;
    uint64_t dropped;
    int32_t last_native_error;
    unsigned loaded : 1;
    unsigned attached : 1;
};

/* errors.c: thread-local records and input validation. */
void lmb_record(uint32_t op, uint32_t domain, int32_t code, const char *msg);
int lmb_check_header(uint32_t abi_version, uint32_t struct_size,
                     uint32_t want);
int lmb_check_bytes(const struct lmb_bytes_v1 *in, uint32_t max,
                    int required);
int lmb_copy_name(const struct lmb_bytes_v1 *in, char **out);
int lmb_ranges_overlap(const void *a, uint32_t a_len, const void *b,
                       uint32_t b_len);

/* ring.c: single-record staging callback. */
int lmb_ring_sample(void *ctx, void *data, size_t size);

#endif /* LMB_INTERNAL_H */
