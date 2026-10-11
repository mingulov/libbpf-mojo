/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <bpf/libbpf.h>
#include "generic_internal.h"
#include "internal.h"

static int32_t fail(uint32_t op, uint32_t domain, int32_t code, const char *text) {
    lmb_generic_record(op, domain, code, text); return code;
}
static int ring_name_valid(struct lmb_span_v1 span) {
    if (span.len > 256 || !lmb_generic_check_span(span.ptr, span.len)) return 0;
    struct lmb_bytes_v1 bytes = {span.ptr, (uint32_t)span.len, 0};
    return lmb_check_bytes(&bytes, 256, 1);
}
static int sample(void *ctx, void *data, size_t size) {
    struct lmb_buffer *buffer = ctx;
    buffer->received++;
    if (!size || size > buffer->max_raw_bytes) buffer->malformed++;
    else if (buffer->stage_len) buffer->dropped++;
    else { memcpy(buffer->stage, data, size); buffer->stage_len = (uint32_t)size; }
    /* A negative callback would still consume this borrowed record. */
    return 0;
}

int32_t lmb_buffer_open_v1(struct lmb_object *object,
        const struct lmb_buffer_options_v1 *opts, struct lmb_buffer **out) {
    const uint32_t op = LMB_GENERIC_OP_BUFFER_OPEN;
    char name[257];
    if (!out || !lmb_generic_check_span(out, sizeof(*out)))
        return fail(op, LMB_GENERIC_DOMAIN_BRIDGE, -EINVAL, "invalid buffer output");
    *out = NULL;
    if (!opts || !lmb_generic_check_span(opts, sizeof(*opts)) ||
        !lmb_check_header(opts->abi_version, opts->struct_size, sizeof(*opts)))
        return fail(op, LMB_GENERIC_DOMAIN_BRIDGE, -EINVAL, "invalid buffer options header");
    if (!ring_name_valid(opts->ring) || !opts->max_raw_bytes ||
        opts->max_raw_bytes > LMB_GENERIC_MAX_RAW_BYTES || opts->stage_slots != 1 ||
        opts->flags || opts->_reserved)
        return fail(op, LMB_GENERIC_DOMAIN_BRIDGE, -EINVAL, "invalid ring name, capacity or flags");
    if (lmb_generic_ranges_overlap(out, sizeof(*out), opts, sizeof(*opts)) ||
        lmb_generic_ranges_overlap(out, sizeof(*out), opts->ring.ptr, opts->ring.len))
        return fail(op, LMB_GENERIC_DOMAIN_BRIDGE, -EINVAL, "buffer output aliases ring input");
    if (!lmb_object_need_loaded(object, op)) return -EINVAL;
    memcpy(name, opts->ring.ptr, (size_t)opts->ring.len); name[opts->ring.len] = 0;
    struct bpf_map *map = bpf_object__find_map_by_name(object->obj, name);
    if (!map) return fail(op, LMB_GENERIC_DOMAIN_BRIDGE, -ENOENT, "ring map not found");
    if (bpf_map__type(map) != BPF_MAP_TYPE_RINGBUF)
        return fail(op, LMB_GENERIC_DOMAIN_BRIDGE, -EINVAL, "map is not a ring buffer");
    int fd = bpf_map__fd(map);
    if (fd < 0) return fail(op, LMB_GENERIC_DOMAIN_BRIDGE, -EINVAL, "ring map has no loaded FD");
    struct lmb_buffer *buffer = calloc(1, sizeof(*buffer));
    if (!buffer) return fail(op, LMB_GENERIC_DOMAIN_POSIX, -ENOMEM, "buffer allocation failed");
    int32_t code = lmb_object_ref_v1(object);
    if (code) { free(buffer); return fail(op, LMB_GENERIC_DOMAIN_BRIDGE, code, "buffer owner reference failed"); }
    buffer->parent = object; buffer->max_raw_bytes = opts->max_raw_bytes;
    buffer->rb = ring_buffer__new(fd, sample, buffer, NULL);
    code = (int32_t)libbpf_get_error(buffer->rb);
    if (code) {
        free(buffer); lmb_object_unref_v1(object);
        return fail(op, LMB_GENERIC_DOMAIN_LIBBPF, code, "ring consumer creation failed");
    }
    *out = buffer; lmb_generic_clear(); return 0;
}

int32_t lmb_buffer_poll_v1(struct lmb_buffer *buffer, uint8_t *dst,
        uint64_t capacity, int32_t timeout_ms, uint64_t *used, uint64_t *needed) {
    const uint32_t op = LMB_GENERIC_OP_BUFFER_POLL;
    if (!used || !needed || !lmb_generic_check_span(used, sizeof(*used)) ||
        !lmb_generic_check_span(needed, sizeof(*needed)) ||
        !lmb_generic_check_span(dst, capacity) || timeout_ms < -1 ||
        lmb_generic_ranges_overlap(used, sizeof(*used), needed, sizeof(*needed)) ||
        lmb_generic_ranges_overlap(used, sizeof(*used), dst, capacity) ||
        lmb_generic_ranges_overlap(needed, sizeof(*needed), dst, capacity))
        return fail(op, LMB_GENERIC_DOMAIN_BRIDGE, -EINVAL, "invalid poll spans, size cells or timeout");
    if (!buffer || !buffer->rb)
        return fail(op, LMB_GENERIC_DOMAIN_BRIDGE, -EINVAL, "buffer is not open");
    *used = 0; *needed = 0;
    if (!buffer->stage_len) {
        if (timeout_ms) {
            struct epoll_event event;
            int fd = ring_buffer__epoll_fd(buffer->rb);
            if (fd < 0) return fail(op, LMB_GENERIC_DOMAIN_LIBBPF, fd, "ring wait FD unavailable");
            int rc = epoll_wait(fd, &event, 1, timeout_ms);
            if (rc < 0) {
                int code = errno ? -errno : -EIO;
                return fail(op, LMB_GENERIC_DOMAIN_POSIX, code, "ring wait failed");
            }
            if (!rc) { lmb_generic_clear(); return 0; }
        }
        /* Bounded callback-visible malformed skip. DISCARD/BUSY behavior
         * belongs to libbpf; this is not a wall-clock latency bound. */
        for (unsigned i = 0; i < 64 && !buffer->stage_len; i++) {
            int rc = ring_buffer__consume_n(buffer->rb, 1);
            if (rc < 0) return fail(op, LMB_GENERIC_DOMAIN_LIBBPF, rc, "ring consumption failed");
            if (!rc) break;
        }
    }
    if (!buffer->stage_len) { lmb_generic_clear(); return 0; }
    uint32_t frame = LMB_GENERIC_FRAME_HEADER_SIZE + buffer->stage_len;
    if (capacity < frame) {
        *needed = frame;
        return fail(op, LMB_GENERIC_DOMAIN_BRIDGE, -ENOSPC, "destination too short; record retained");
    }
    for (unsigned i = 0; i < 4; i++) dst[i] = (uint8_t)(buffer->stage_len >> (8 * i));
    dst[4] = LMB_GENERIC_FRAME_VERSION; dst[5] = 0; dst[6] = 0; dst[7] = 0;
    memcpy(dst + LMB_GENERIC_FRAME_HEADER_SIZE, buffer->stage, buffer->stage_len);
    buffer->stage_len = 0; buffer->delivered++; *used = frame;
    lmb_generic_clear(); return 0;
}

int32_t lmb_buffer_close_v1(struct lmb_buffer **cell) {
    const uint32_t op = LMB_GENERIC_OP_BUFFER_CLOSE;
    if (!cell || !lmb_generic_check_span(cell, sizeof(*cell)))
        return fail(op, LMB_GENERIC_DOMAIN_BRIDGE, -EINVAL, "invalid buffer cell");
    if (*cell) {
        struct lmb_buffer *buffer = *cell; struct lmb_object *parent = buffer->parent;
        ring_buffer__free(buffer->rb); *cell = NULL; free(buffer); lmb_object_unref_v1(parent);
    }
    lmb_generic_clear(); return 0;
}
