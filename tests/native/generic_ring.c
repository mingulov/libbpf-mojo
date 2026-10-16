/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <bpf/libbpf.h>
#include "generic_internal.h"
#include "generic_events_host.h"

static void conservation(const struct lmb_buffer *b, uint64_t received,
        uint64_t delivered, uint64_t malformed, uint64_t dropped, int staged) {
    CHECK(b->received == received && b->delivered == delivered);
    CHECK(b->malformed == malformed && b->dropped == dropped);
    CHECK(!!b->stage_len == staged);
    CHECK(b->received == b->delivered + !!b->stage_len + b->malformed + b->dropped);
}
static struct lmb_buffer *open_ring(struct lmb_object *object) {
    struct lmb_buffer_options_v1 opts = ge_buffer_options();
    struct lmb_buffer *ring = NULL;
    CHECK(lmb_buffer_open_v1(object, &opts, &ring) == 0 && ring);
    if (!ring) return NULL;
    CHECK(ring->parent == object && ring->max_raw_bytes == 4096);
    CHECK(lmb_events_call_count(GE_MAPS) == 2);
    return ring;
}
static void refused(struct lmb_object *object, const struct lmb_buffer_options_v1 *opts, int code) {
    uint64_t calls = lmb_events_call_count(GE_NEW);
    unsigned refs = object ? object->refs : 0;
    struct lmb_buffer *ring = (void *)1;
    CHECK(lmb_buffer_open_v1(object, opts, &ring) == code && !ring);
    CHECK(lmb_events_call_count(GE_NEW) == calls);
    CHECK(!object || object->refs == refs); ge_diagnostic(12, 4, code);
}
static void validation(const char *fixture) {
    struct lmb_object *object = ge_object(fixture, 0);
    struct lmb_buffer_options_v1 opts = ge_buffer_options(), bad;
    refused(object, &opts, -EINVAL); refused(NULL, &opts, -EINVAL); refused(object, NULL, -EINVAL);
    CHECK(lmb_buffer_open_v1(object, &opts, NULL) == -EINVAL);
    CHECK(lmb_object_load_v1(object) == 0);
    for (unsigned i = 0; i < 14; i++) {
        bad = opts;
        switch(i) {
        case 0: bad.abi_version++; break;
        case 1: bad.struct_size--; break;
        case 2: bad.struct_size++; break;
        case 3: bad.max_raw_bytes = 0; break;
        case 4: bad.max_raw_bytes = 4097; break;
        case 5: bad.stage_slots = 0; break;
        case 6: bad.stage_slots = 2; break;
        case 7: bad.flags = 1; break;
        case 8: bad._reserved = 1; break;
        case 9: bad.ring.len = 0; break;
        case 10: bad.ring.ptr = NULL; break;
        case 11: bad.ring.len = 257; break;
        case 12: bad.ring.ptr = (void *)(UINTPTR_MAX - 2); break;
        case 13: bad.ring.ptr = (const uint8_t *)"a\0b"; bad.ring.len = 3; break;
        }
        refused(object, &bad, -EINVAL);
    }
    const uint8_t utf8[][4] = {{0xc0,0xaf}, {0xed,0xa0,0x80}, {0xf4,0x90,0x80,0x80}, {0x80}, {0xe2,0x82}};
    const unsigned sizes[] = {2,3,4,1,2};
    for (unsigned i = 0; i < 5; i++) { bad = opts; bad.ring.ptr = utf8[i]; bad.ring.len = sizes[i]; refused(object, &bad, -EINVAL); }
    bad = opts; bad.ring.ptr = (const uint8_t *)"missing"; bad.ring.len = 7; refused(object, &bad, -ENOENT);
    bad = opts; bad.ring.ptr = (const uint8_t *)"filter"; refused(object, &bad, -EINVAL);
    bad = opts; CHECK(lmb_buffer_open_v1(object, &bad, (void *)&bad.max_raw_bytes) == -EINVAL);
    uint8_t name[8] = "events"; bad = opts; bad.ring.ptr = name;
    CHECK(lmb_buffer_open_v1(object, &bad, (void *)name) == -EINVAL);
    ge_map_fd_fault(-1); refused(object, &opts, -EINVAL); ge_map_fd_fault(0);
    struct lmb_buffer *ring = open_ring(object);
    uint8_t bytes[64], payload[16]; uint64_t used, needed;
    ge_payload(payload, 1); ge_publish(payload, 16, 0);
    CHECK(lmb_buffer_poll_v1(ring, NULL, 0, 0, &used, &needed) == -ENOSPC);
    uint64_t calls = lmb_events_call_count(GE_CONSUME), waits = lmb_events_call_count(GE_WAIT);
    struct {uint64_t cells[8];} aligned;
    for (unsigned i = 0; i < 10; i++) {
        memset(bytes, 0xa5, sizeof(bytes)); memset(&aligned, 0x5a, sizeof(aligned));
        used = needed = 123;
        int32_t rc;
        switch(i) {
        case 0: rc = lmb_buffer_poll_v1(ring, bytes, 24, 0, NULL, &needed); break;
        case 1: rc = lmb_buffer_poll_v1(ring, bytes, 24, 0, &used, NULL); break;
        case 2: rc = lmb_buffer_poll_v1(ring, bytes, 24, 0, &used, &used); break;
        case 3: rc = lmb_buffer_poll_v1(ring, bytes, 24, 0, &aligned.cells[0], (void *)((uint8_t *)&aligned + 4)); break;
        case 4: rc = lmb_buffer_poll_v1(ring, bytes, 24, 0, (void *)(bytes + 16), &needed); break;
        case 5: rc = lmb_buffer_poll_v1(ring, bytes, 24, 0, &used, (void *)(bytes + 23)); break;
        case 6: rc = lmb_buffer_poll_v1(ring, bytes, 24, -2, &used, &needed); break;
        case 7: rc = lmb_buffer_poll_v1(ring, NULL, 24, 0, &used, &needed); break;
        case 8: rc = lmb_buffer_poll_v1(ring, (void *)(UINTPTR_MAX - 8), 24, 0, &used, &needed); break;
        default: rc = lmb_buffer_poll_v1(NULL, bytes, 24, 0, &used, &needed); break;
        }
        CHECK(rc == -EINVAL && used == 123 && needed == 123);
        ge_sentinel(bytes, sizeof(bytes), 0xa5); ge_sentinel(&aligned, sizeof(aligned), 0x5a);
        CHECK(ring->stage_len == 16 && !memcmp(ring->stage, payload, 16));
        CHECK(lmb_events_call_count(GE_CONSUME) == calls && lmb_events_call_count(GE_WAIT) == waits);
        ge_diagnostic(13, 4, -EINVAL);
    }
    /* Adjacent cells and full-capacity destination; deliberately unaligned destination too. */
    memset(&aligned, 0xa5, sizeof(aligned));
    CHECK(lmb_buffer_poll_v1(ring, (void *)&aligned, 24, 0, &aligned.cells[3], &aligned.cells[4]) == 0);
    CHECK(aligned.cells[3] == 24 && aligned.cells[4] == 0); ge_frame((void *)&aligned, 1);
    ge_publish(payload, 16, 0); memset(bytes, 0xa5, sizeof(bytes));
    CHECK(lmb_buffer_poll_v1(ring, bytes + 1, 24, 0, &used, &needed) == 0 && used == 24 && !needed);
    ge_frame(bytes + 1, 1); CHECK(bytes[0] == 0xa5); ge_sentinel(bytes + 25, 39, 0xa5);
    CHECK(lmb_buffer_close_v1(&ring) == 0); CHECK(lmb_object_close_v1(&object) == 0);
    opts.max_raw_bytes = 1;
    CHECK(lmb_buffer_open_v1(object = ge_object(fixture, 1), &opts, &ring) == 0);
    uint8_t byte = 42, small[9]; ge_publish(&byte, 1, 0);
    CHECK(lmb_buffer_poll_v1(ring, small, 9, 0, &used, &needed) == 0 && used == 9 && !needed);
    const uint8_t expected[9] = {1,0,0,0,1,0,0,0,42}; CHECK(!memcmp(small, expected, 9));
    ge_publish(payload, 16, 0); CHECK(lmb_buffer_poll_v1(ring, small, 9, 0, &used, &needed) == 0 && !used);
    conservation(ring, 2, 1, 1, 0, 0);
    CHECK(lmb_buffer_close_v1(&ring) == 0); CHECK(lmb_object_close_v1(&object) == 0);
    puts("ring validation: options, type/load, aliases, partial cells, overflow and adjacent/unaligned outputs checked");
}
static void rollback(const char *fixture) {
    struct lmb_object *object = ge_object(fixture, 1);
    struct lmb_buffer_options_v1 opts = ge_buffer_options();
    struct lmb_buffer *ring = NULL;
    struct lmb_link *sibling = NULL; struct lmb_attach_options_v1 attach = ge_attach_options();
    CHECK(lmb_object_attach_v1(object, &attach, &sibling) == 0);
    unsigned refs = object->refs, fds = ge_fd_count();
    ge_alloc_fault(0); CHECK(lmb_buffer_open_v1(object, &opts, &ring) == 0);
    unsigned boundaries = ge_alloc_finish(); CHECK(boundaries >= 5);
    CHECK(lmb_buffer_close_v1(&ring) == 0);
    for (unsigned n = 1; n <= boundaries; n++) {
        ge_alloc_fault(n); CHECK(lmb_buffer_open_v1(object, &opts, &ring) == -ENOMEM && !ring);
        CHECK(ge_alloc_finish() == n); ge_diagnostic(12, n == 1 ? 1 : 2, -ENOMEM);
        CHECK(object->refs == refs && ge_fd_count() == fds && !lmb_events_call_count(GE_MAPS));
    }
    for (unsigned n = 1; n <= 2; n++) {
        ge_map_fault(n); CHECK(lmb_buffer_open_v1(object, &opts, &ring) == -ENOMEM && !ring);
        CHECK(object->refs == refs && ge_fd_count() == fds && !lmb_events_call_count(GE_MAPS));
        ge_diagnostic(12, 2, -ENOMEM);
    }
    ge_map_fault(0);
    for (unsigned n = 0; n < 3; n++) {
        if (n == 0) ge_info_fault(-EBADF);
        if (n == 1) ge_epoll_fault(-EMFILE, 0);
        if (n == 2) ge_epoll_fault(0, -EPERM);
        int codes[] = {-EBADF, -EMFILE, -EPERM};
        CHECK(lmb_buffer_open_v1(object, &opts, &ring) == codes[n] && !ring);
        CHECK(object->refs == refs && ge_fd_count() == fds && !lmb_events_call_count(GE_MAPS));
        ge_diagnostic(12, 2, codes[n]); ge_info_fault(0); ge_epoll_fault(0, 0);
    }
    for (int null_result = 0; null_result < 2; null_result++) {
        ge_new_fault(-EACCES, null_result);
        CHECK(lmb_buffer_open_v1(object, &opts, &ring) == -EACCES && !ring);
        CHECK(object->refs == refs && ge_fd_count() == fds); ge_diagnostic(12, 2, -EACCES);
    }
    ge_new_fault(0, 0);
    object->refs = UINT_MAX; uint64_t calls = lmb_events_call_count(GE_NEW);
    CHECK(lmb_buffer_open_v1(object, &opts, &ring) == -EOVERFLOW && !ring);
    CHECK(object->refs == UINT_MAX && lmb_events_call_count(GE_NEW) == calls); ge_diagnostic(12, 4, -EOVERFLOW);
    object->refs = refs;
    ring = open_ring(object);
    CHECK(lmb_object_close_v1(&object) == -EBUSY && object);
    uint64_t before = lmb_events_close_count();
    lmb_object_release_v1(&object); CHECK(!object);
    CHECK(lmb_link_close_v1(&sibling) == 0 && lmb_events_close_count() == before);
    uint8_t payload[16], frame[24]; uint64_t used, needed;
    ge_payload(payload, 42); ge_publish(payload, 16, 0);
    CHECK(lmb_buffer_poll_v1(ring, frame, 24, 0, &used, &needed) == 0 && used == 24); ge_frame(frame, 42);
    CHECK(lmb_buffer_close_v1(&ring) == 0 && !ring && lmb_events_close_count() == before + 1);
    CHECK(lmb_buffer_close_v1(&ring) == 0); ge_diagnostic(0, 0, 0);
    CHECK(lmb_buffer_close_v1(NULL) == -EINVAL); ge_diagnostic(14, 4, -EINVAL);
    printf("ring rollback: %u allocation boundaries, both maps, info/epoll/register, signed NULL/error-pointer and final-release checked\n", boundaries);
}
static void framing(struct lmb_buffer *ring) {
    uint8_t payload[16], bytes[4112]; uint64_t used, needed;
    ge_payload(payload, UINT64_C(0x0102030405060708)); ge_publish(payload, 16, 0);
    ge_overwrite_source(1); memset(bytes, 0xa5, sizeof(bytes));
    CHECK(lmb_buffer_poll_v1(ring, bytes + 1, 23, 0, &used, &needed) == -ENOSPC && !used && needed == 24);
    ge_diagnostic(13, 4, -ENOSPC); ge_sentinel(bytes, sizeof(bytes), 0xa5);
    uint64_t calls = lmb_events_call_count(GE_CONSUME), waits = lmb_events_call_count(GE_WAIT);
    for (unsigned i = 0; i < 3; i++) {
        CHECK(lmb_buffer_poll_v1(ring, bytes + 1, 23, -1, &used, &needed) == -ENOSPC && !used && needed == 24);
        CHECK(lmb_events_call_count(GE_CONSUME) == calls && lmb_events_call_count(GE_WAIT) == waits);
    }
    CHECK(lmb_buffer_poll_v1(ring, bytes + 1, 24, -1, &used, &needed) == 0 && used == 24 && !needed);
    ge_frame(bytes + 1, UINT64_C(0x0102030405060708)); ge_diagnostic(0, 0, 0);
    CHECK(bytes[0] == 0xa5); ge_sentinel(bytes + 25, sizeof(bytes) - 25, 0xa5);
    CHECK(lmb_buffer_poll_v1(ring, bytes, 24, 0, &used, &needed) == 0 && !used && !needed);
    /* Completed prefix in a consumer's 47-byte destination; held next is a separate call. */
    uint8_t destination[49]; memset(destination, 0xa5, sizeof(destination));
    ge_payload(payload, 10); ge_publish(payload, 16, 0); ge_payload(payload, 11); ge_publish(payload, 16, 0);
    CHECK(lmb_buffer_poll_v1(ring, destination + 1, 47, 0, &used, &needed) == 0 && used == 24);
    ge_frame(destination + 1, 10);
    CHECK(lmb_buffer_poll_v1(ring, destination + 25, 23, 0, &used, &needed) == -ENOSPC && !used && needed == 24);
    for (unsigned n = 0; n < 3; n++) CHECK(lmb_buffer_poll_v1(ring, destination + 25, 23, 0, &used, &needed) == -ENOSPC);
    ge_frame(destination + 1, 10); ge_sentinel(destination + 25, 24, 0xa5); CHECK(destination[0] == 0xa5);
    CHECK(lmb_buffer_poll_v1(ring, bytes, 24, 0, &used, &needed) == 0 && used == 24); ge_frame(bytes, 11);
    ge_payload(payload, 12); ge_publish(payload, 16, 0); ge_payload(payload, 13); ge_publish(payload, 16, 0);
    memset(bytes, 0xa5, sizeof(bytes));
    CHECK(lmb_buffer_poll_v1(ring, bytes, 48, 0, &used, &needed) == 0 && used == 24); ge_frame(bytes, 12);
    ge_sentinel(bytes + 24, 24, 0xa5);
    CHECK(lmb_buffer_poll_v1(ring, bytes, 48, 0, &used, &needed) == 0 && used == 24); ge_frame(bytes, 13);
    ge_overwrite_source(0);
    uint8_t large[4097]; for (unsigned i = 0; i < sizeof(large); i++) large[i] = (uint8_t)i;
    ge_publish(large, 4096, 0); memset(bytes, 0xa5, sizeof(bytes));
    CHECK(lmb_buffer_poll_v1(ring, bytes, 4103, 0, &used, &needed) == -ENOSPC && needed == 4104 && !used);
    ge_sentinel(bytes, sizeof(bytes), 0xa5);
    CHECK(lmb_buffer_poll_v1(ring, bytes, 4104, 0, &used, &needed) == 0 && used == 4104 && !needed);
    const uint8_t header[8] = {0,16,0,0,1,0,0,0}; CHECK(!memcmp(bytes, header, 8)); CHECK(!memcmp(bytes + 8, large, 4096));
    ge_sentinel(bytes + 4104, 8, 0xa5);
    ge_publish(large, 4097, 0); memset(bytes, 0xa5, sizeof(bytes));
    CHECK(lmb_buffer_poll_v1(ring, bytes, sizeof(bytes), 0, &used, &needed) == 0 && !used && !needed); ge_sentinel(bytes, sizeof(bytes), 0xa5);
    ge_empty_position(65528); ge_payload(payload, 14); ge_publish(payload, 16, 0);
    CHECK(lmb_buffer_poll_v1(ring, bytes, 24, 0, &used, &needed) == 0 && used == 24); ge_frame(bytes, 14);
    /* BUSY remains queued; DISCARD advances without a callback-received record. */
    uint64_t received = ring->received;
    ge_publish(payload, 16, 1u << 31); uint64_t position = ge_consumer();
    CHECK(lmb_buffer_poll_v1(ring, bytes, 24, 0, &used, &needed) == 0 && !used && ge_consumer() == position);
    ge_unbusy(); CHECK(lmb_buffer_poll_v1(ring, bytes, 24, 0, &used, &needed) == 0 && used == 24);
    ge_publish(payload, 16, 1u << 30);
    CHECK(lmb_buffer_poll_v1(ring, bytes, 24, 0, &used, &needed) == 0 && !used);
    CHECK(ge_consumer() == ge_producer() && ring->received == received + 1);
    for (unsigned i = 0; i < 64; i++) ge_publish(NULL, 0, 0);
    ge_publish(payload, 16, 0); uint64_t count = lmb_events_call_count(GE_CONSUME);
    CHECK(lmb_buffer_poll_v1(ring, bytes, 24, 0, &used, &needed) == 0 && !used);
    CHECK(lmb_events_call_count(GE_CONSUME) == count + 64);
    CHECK(lmb_buffer_poll_v1(ring, bytes, 24, 0, &used, &needed) == 0 && used == 24);
    puts("ring framing: 16/24, 0/23 retries, prefix47/next24, one-frame48, 4096/4104, wrap, BUSY/DISCARD and 64-step budget checked");
}
static void waits(struct lmb_buffer *ring) {
    uint8_t bytes[24]; uint64_t used = 123, needed = 123;
    memset(bytes, 0xa5, sizeof(bytes));
    uint64_t consumes = lmb_events_call_count(GE_CONSUME), waits = lmb_events_call_count(GE_WAIT);
    ge_wait_result(0, 0);
    CHECK(lmb_buffer_poll_v1(ring, bytes, 24, 17, &used, &needed) == 0 && !used && !needed); ge_diagnostic(0, 0, 0);
    CHECK(lmb_events_call_count(GE_CONSUME) == consumes && lmb_events_call_count(GE_WAIT) == waits + 1);
    CHECK(ge_last_timeout() == 17);
    ge_wait_result(-1, EINTR);
    CHECK(lmb_buffer_poll_v1(ring, bytes, 24, -1, &used, &needed) == -EINTR && !used && !needed); ge_diagnostic(13, 1, -EINTR);
    CHECK(lmb_events_call_count(GE_CONSUME) == consumes && lmb_events_call_count(GE_WAIT) == waits + 2);
    CHECK(ge_last_timeout() == -1);
    ge_wait_result(-1, EIO);
    CHECK(lmb_buffer_poll_v1(ring, bytes, 24, 35, &used, &needed) == -EIO && !used && !needed); ge_diagnostic(13, 1, -EIO);
    CHECK(ge_last_timeout() == 35);
    ge_wait_result(1, 0); ge_consume_fault(-ENOSPC);
    CHECK(lmb_buffer_poll_v1(ring, bytes, 24, 36, &used, &needed) == -ENOSPC && !used && !needed); ge_diagnostic(13, 2, -ENOSPC);
    CHECK(ge_last_timeout() == 36);
    ge_consume_fault(0); ge_epoll_fd_fault(-EBADF);
    uint64_t prior_waits = lmb_events_call_count(GE_WAIT);
    CHECK(lmb_buffer_poll_v1(ring, bytes, 24, 37, &used, &needed) == -EBADF && !used && !needed);
    ge_diagnostic(13, 2, -EBADF); CHECK(lmb_events_call_count(GE_WAIT) == prior_waits);
    ge_epoll_fd_fault(0); ge_sentinel(bytes, sizeof(bytes), 0xa5);
    puts("ring waits: empty timeout, exact ready path, EINTR without retry, POSIX and signed LIBBPF errors checked");
}
static void stats_snapshot(const char *fixture) {
    struct lmb_object *object = ge_object(fixture, 1);
    struct lmb_buffer_options_v1 opts = ge_buffer_options();
    struct lmb_buffer *ring = NULL;
    struct lmb_buffer_stats_v1 snapshot, again, before;
    uint8_t payload[16], large[4097], bytes[24];
    uint64_t used, needed;
    memset(&snapshot, 0, sizeof(snapshot));
    snapshot.abi_version = 1;
    snapshot.struct_size = sizeof(snapshot);
    CHECK(lmb_buffer_stats_v1(NULL, &snapshot) == -EINVAL);
    ge_diagnostic(20, 4, -EINVAL);
    CHECK(lmb_buffer_open_v1(object, &opts, &ring) == 0 && ring);
    CHECK(lmb_buffer_stats_v1(ring, NULL) == -EINVAL);
    ge_diagnostic(20, 4, -EINVAL);
    for (unsigned i = 0; i < 4; i++) {
        memset(&snapshot, 0x5a, sizeof(snapshot));
        snapshot.abi_version = 1;
        snapshot.struct_size = sizeof(snapshot);
        switch (i) {
        case 0: snapshot.abi_version = 0; break;
        case 1: snapshot.abi_version = 2; break;
        case 2: snapshot.struct_size = sizeof(snapshot) - 1; break;
        default: snapshot.struct_size = sizeof(snapshot) + 1; break;
        }
        memcpy(&before, &snapshot, sizeof(before));
        CHECK(lmb_buffer_stats_v1(ring, &snapshot) == -EINVAL);
        ge_diagnostic(20, 4, -EINVAL);
        CHECK(!memcmp(&snapshot, &before, sizeof(snapshot)));
    }
    CHECK(sizeof(snapshot) == 48);
    memset(&snapshot, 0, sizeof(snapshot));
    snapshot.abi_version = 1;
    snapshot.struct_size = sizeof(snapshot);
    CHECK(lmb_buffer_stats_v1(ring, &snapshot) == 0);
    CHECK(!snapshot.received && !snapshot.delivered && !snapshot.staged);
    CHECK(!snapshot.malformed && !snapshot.dropped);
    CHECK(snapshot.abi_version == 1 && snapshot.struct_size == sizeof(snapshot));
    ge_diagnostic(0, 0, 0);
    ge_payload(payload, 81);
    ge_publish(payload, 16, 0);
    CHECK(lmb_buffer_poll_v1(ring, bytes, 23, 0, &used, &needed) == -ENOSPC);
    ge_diagnostic(13, 4, -ENOSPC);
    CHECK(lmb_buffer_stats_v1(ring, &snapshot) == 0 && snapshot.staged == 1);
    ge_diagnostic(0, 0, 0);
    memset(&again, 0, sizeof(again));
    again.abi_version = 1;
    again.struct_size = sizeof(again);
    CHECK(lmb_buffer_stats_v1(ring, &again) == 0);
    CHECK(!memcmp(&snapshot, &again, sizeof(snapshot)));
    ge_payload(payload, 82);
    ge_publish(payload, 16, 0);
    CHECK(ring_buffer__consume_n(ring->rb, 1) == 1);
    CHECK(lmb_buffer_poll_v1(ring, bytes, 24, 0, &used, &needed) == 0);
    ge_frame(bytes, 81);
    ge_publish(NULL, 0, 0);
    memset(large, 0x6d, sizeof(large));
    ge_publish(large, 4097, 0);
    ge_payload(payload, 83);
    ge_publish(payload, 16, 0);
    CHECK(lmb_buffer_poll_v1(ring, bytes, 24, 0, &used, &needed) == 0);
    ge_frame(bytes, 83);
    CHECK(lmb_buffer_stats_v1(ring, &snapshot) == 0);
    CHECK(snapshot.received == 5 && snapshot.delivered == 2 && !snapshot.staged);
    CHECK(snapshot.malformed == 2 && snapshot.dropped == 1);
    CHECK(snapshot.received == snapshot.delivered + snapshot.staged +
        snapshot.malformed + snapshot.dropped);
    CHECK(lmb_object_close_v1(&object) == -EBUSY && object);
    CHECK(lmb_buffer_stats_v1(ring, &snapshot) == 0 && snapshot.received == 5);
    lmb_object_release_v1(&object);
    CHECK(!object);
    CHECK(lmb_buffer_stats_v1(ring, &snapshot) == 0 && snapshot.received == 5);
    ge_payload(payload, 84);
    ge_publish(payload, 16, 0);
    CHECK(lmb_buffer_poll_v1(ring, bytes, 24, 0, &used, &needed) == 0);
    ge_frame(bytes, 84);
    CHECK(lmb_buffer_stats_v1(ring, &snapshot) == 0);
    CHECK(snapshot.received == 6 && snapshot.delivered == 3);
    CHECK(lmb_buffer_close_v1(&ring) == 0 && !ring);
    puts("ring stats: validation, zeros, staged snapshot, read-only, 5/2/0/2/1, BUSY/release teardown checked");
}
static int negative_callback(void *ctx, void *data, size_t size) {
    unsigned *count = ctx; (*count)++; CHECK(size == 16 && data != NULL); return -ENOSPC;
}
static void negative_consumed(int mutation) {
    unsigned callbacks = 0; uint8_t payload[16]; ge_payload(payload, 77);
    struct ring_buffer *reader = ring_buffer__new(ge_ring_fd(), negative_callback, &callbacks, NULL);
    CHECK(reader != NULL);
    uint64_t before = ge_consumer(); ge_publish(payload, 16, 0);
    CHECK(ring_buffer__consume_n(reader, 1) == -ENOSPC && callbacks == 1);
    uint64_t after = ge_consumer();
    if (mutation) {
        /* Deliberately replay the consumed payload through the producer.
         * The independent one-record/position oracle stays unchanged. */
        puts("MUTATION: replay a negative-callback record that was already consumed");
        ge_publish(payload, 16, 0);
    }
    int next = ring_buffer__consume_n(reader, 1);
    CHECK(after == before + 24);
    CHECK(ge_consumer() == before + 24 && ge_producer() == before + 24);
    CHECK(next == 0 && callbacks == 1);
    if (!mutation)
        puts("negative callback mechanism: -ENOSPC consumed24 bytes, next consume0, exactly one callback");
    ring_buffer__free(reader);
}
static void sequence(const char *fixture, int mixed) {
    struct lmb_object *object = ge_object(fixture, 1); struct lmb_buffer *ring = open_ring(object);
    uint8_t payload[4097], bytes[24]; uint64_t used, needed, expected = 0;
    ge_overwrite_source(1); memset(payload, 0x6d, sizeof(payload));
    for (uint64_t i = 0; i < 100000; i++) {
        ge_payload(payload, i + 1);
        unsigned kind = mixed ? (unsigned)(i % 1000) : 999;
        ge_publish(payload, kind == 0 ? 0 : kind == 1 ? 4097 : 16, 0);
        if (kind == 0 || kind == 1) {
            CHECK(lmb_buffer_poll_v1(ring, bytes, 24, 0, &used, &needed) == 0 && !used && !needed);
        } else if (kind == 2) {
            for (unsigned n = 0; n < 3; n++) CHECK(lmb_buffer_poll_v1(ring, bytes, 23, 0, &used, &needed) == -ENOSPC && needed == 24 && !used);
        } else if (kind == 3) {
            CHECK(ring->stage_len == 16); CHECK(ring_buffer__consume_n(ring->rb, 1) == 1);
            CHECK(lmb_buffer_poll_v1(ring, bytes, 24, 0, &used, &needed) == 0 && used == 24 && !needed);
            ge_frame(bytes, i); expected++;
        } else {
            CHECK(lmb_buffer_poll_v1(ring, bytes, 24, 0, &used, &needed) == 0 && used == 24 && !needed);
            ge_frame(bytes, i + 1); expected++;
        }
    }
    CHECK(expected == (mixed ? 99700u : 100000u));
    conservation(ring, 100000, expected, mixed ? 200 : 0, mixed ? 100 : 0, 0);
    CHECK(ge_consumer() == ge_producer());
    CHECK(lmb_buffer_poll_v1(ring, bytes, 24, 0, &used, &needed) == 0 && !used && !needed);
    printf("ring %s100k: received=%llu delivered=%llu malformed=%llu dropped=%llu staged=%u; payload set/order exact\n", mixed ? "mixed " : "valid ",
        (unsigned long long)ring->received, (unsigned long long)ring->delivered,
        (unsigned long long)ring->malformed, (unsigned long long)ring->dropped, !!ring->stage_len);
    ge_overwrite_source(0); CHECK(lmb_buffer_close_v1(&ring) == 0); CHECK(lmb_object_close_v1(&object) == 0);
}
int main(int argc, char **argv) {
    if (argc < 2 || argc > 3 || (argc == 3 && strcmp(argv[2], "--negative-replay"))) return 2;
    unsigned fds = ge_fd_count(); ge_begin(argv[1]);
    if (argc == 3) { negative_consumed(1); return ge_end("negative replay mutation"); }
    validation(argv[1]); rollback(argv[1]);
    struct lmb_object *object = ge_object(argv[1], 1); struct lmb_buffer *ring = open_ring(object);
    framing(ring); waits(ring);
    CHECK(lmb_buffer_close_v1(&ring) == 0); CHECK(lmb_object_close_v1(&object) == 0);
    stats_snapshot(argv[1]);
    negative_consumed(0); sequence(argv[1], 0); sequence(argv[1], 1);
    int result = ge_end("generic ring"); int stable = ge_fd_count() == fds; CHECK(stable);
    return result || !stable;
}
