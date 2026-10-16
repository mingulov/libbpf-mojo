/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* Cross-adapter ring conformance: the v1 session ring consumer and
 * the generic buffer ring consumer driven by one controlled
 * producer through the maintained libbpf reader. Each row runs the
 * same input script against both adapters with independently
 * authored oracles. Identical rows pin shared staging/framing
 * behavior; rows that differ (diagnostic lifetime, error latch,
 * counter width and access, parent-close BUSY) assert the
 * difference, so neither contract can silently drift into the
 * other. Adapters run in sequential phases sharing one producer;
 * every row starts and ends with a drained ring. */
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <bpf/libbpf.h>
#include "internal.h"
#include "generic_internal.h"
#include "generic_events_host.h"

static uint32_t le32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
        ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static uint32_t le16(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8);
}
/* Row hygiene: faults cleared, ring drained, no live state leaks. */
static void row_begin(void) {
    lmb_events_scenario(GE_DEFAULT);
    CHECK(ge_consumer() == ge_producer());
}
static void row_drained(void) {
    CHECK(ge_consumer() == ge_producer());
}
static uint8_t *read_file(const char *path, size_t *len_out) {
    FILE *file = fopen(path, "rb");
    uint8_t *bytes;
    long n;
    CHECK(file != NULL);
    if (!file)
        exit(1);
    CHECK(fseek(file, 0, SEEK_END) == 0);
    n = ftell(file);
    CHECK(n > 0);
    rewind(file);
    bytes = malloc((size_t)n);
    CHECK(bytes != NULL);
    if (!bytes)
        exit(1);
    CHECK(fread(bytes, 1, (size_t)n, file) == (size_t)n);
    fclose(file);
    *len_out = (size_t)n;
    return bytes;
}
/* A v1 session opened on the shared events fixture. Loading runs
 * under the host seams: parsing is real, loading is the
 * aggregate seam, and the ring reader is the maintained
 * implementation over owned mappings. */
static struct lmb_session *open_session(const char *fixture) {
    struct lmb_options_v1 opts;
    struct lmb_session *session = NULL;
    uint8_t *elf;
    size_t elf_len;
    memset(&opts, 0, sizeof(opts));
    opts.abi_version = 1;
    opts.struct_size = sizeof(opts);
    opts.ring.ptr = (const uint8_t *)"events";
    opts.ring.len = 6;
    opts.max_raw_bytes = 4096;
    opts.stage_slots = 1;
    elf = read_file(fixture, &elf_len);
    CHECK(lmb_open(elf, (uint64_t)elf_len, &opts, &session) == 0 && session);
    memset(elf, 0xcc, elf_len);
    free(elf);
    if (!session)
        exit(1);
    CHECK(lmb_load(session) == 0);
    return session;
}
static void session_counters(struct lmb_session *s, uint64_t *received,
        uint64_t *delivered, uint64_t *staged, uint64_t *malformed,
        uint64_t *dropped, int32_t *last_error) {
    struct lmb_stats_v1 stats;
    memset(&stats, 0, sizeof(stats));
    stats.abi_version = 1;
    stats.struct_size = sizeof(stats);
    CHECK(lmb_stats(s, &stats) == 0);
    *received = stats.received;
    *delivered = stats.delivered;
    *staged = stats.staged;
    *malformed = stats.malformed;
    *dropped = stats.dropped;
    *last_error = stats.last_error;
}
static void session_diagnostic(uint32_t *op, uint32_t *domain, int32_t *code) {
    struct lmb_error_v1 error;
    memset(&error, 0, sizeof(error));
    error.abi_version = 1;
    error.struct_size = sizeof(error);
    CHECK(lmb_last_error(&error) == 0);
    *op = error.operation;
    *domain = error.domain;
    *code = error.code;
}
struct buffer_pair {
    struct lmb_object *object;
    struct lmb_buffer *buffer;
};
static struct buffer_pair open_buffer(const char *fixture) {
    struct lmb_buffer_options_v1 opts = ge_buffer_options();
    struct buffer_pair pair;
    pair.object = ge_object(fixture, 1);
    pair.buffer = NULL;
    CHECK(lmb_buffer_open_v1(pair.object, &opts, &pair.buffer) == 0 && pair.buffer);
    if (!pair.buffer)
        exit(1);
    return pair;
}
static void close_buffer(struct buffer_pair *pair) {
    CHECK(lmb_buffer_close_v1(&pair->buffer) == 0 && !pair->buffer);
    CHECK(lmb_object_close_v1(&pair->object) == 0 && !pair->object);
}
static void buffer_counters(const struct lmb_buffer *b, uint64_t *received,
        uint64_t *delivered, uint64_t *staged, uint64_t *malformed,
        uint64_t *dropped) {
    *received = b->received;
    *delivered = b->delivered;
    *staged = b->stage_len ? 1 : 0;
    *malformed = b->malformed;
    *dropped = b->dropped;
}
static void check_bytes_frame(const uint8_t *bytes, const uint8_t *payload,
        uint32_t len) {
    CHECK(le32(bytes) == len && le16(bytes + 4) == 1 && le16(bytes + 6) == 0);
    CHECK(!memcmp(bytes + 8, payload, len));
}

/* Fresh handles report zero counters before any record flows. */
static void fresh_session(const char *fixture) {
    uint64_t received, delivered, staged, malformed, dropped;
    int32_t last_error;
    row_begin();
    struct lmb_session *s = open_session(fixture);
    session_counters(s, &received, &delivered, &staged, &malformed, &dropped,
        &last_error);
    CHECK(!received && !delivered && !staged && !malformed && !dropped);
    CHECK(last_error == 0);
    CHECK(lmb_close(&s) == 0 && !s);
    row_drained();
    puts("conform/fresh session: zero counters and no latched error");
}
static void fresh_buffer(const char *fixture) {
    uint64_t received, delivered, staged, malformed, dropped;
    row_begin();
    struct buffer_pair pair = open_buffer(fixture);
    buffer_counters(pair.buffer, &received, &delivered, &staged, &malformed,
        &dropped);
    CHECK(!received && !delivered && !staged && !malformed && !dropped);
    close_buffer(&pair);
    row_drained();
    puts("conform/fresh buffer: zero counters");
}
/* Timeout yields success with zero cells on both adapters; the
 * bounded wait reaches the waiter once with the exact timeout,
 * and a non-blocking poll drains without waiting. */
static void timeout_session(const char *fixture) {
    uint8_t dst[24];
    uint32_t written = 123, required = 123;
    uint64_t waits, consumes;
    row_begin();
    struct lmb_session *s = open_session(fixture);
    memset(dst, 0xa5, sizeof(dst));
    waits = lmb_events_call_count(GE_WAIT);
    consumes = lmb_events_call_count(GE_CONSUME);
    ge_wait_result(0, 0);
    CHECK(lmb_poll(s, dst, sizeof(dst), &written, &required, 17) == 0);
    CHECK(!written && !required);
    CHECK(ge_last_timeout() == 17);
    CHECK(lmb_events_call_count(GE_WAIT) == waits + 1);
    CHECK(lmb_events_call_count(GE_CONSUME) == consumes);
    ge_sentinel(dst, sizeof(dst), 0xa5);
    CHECK(lmb_poll(s, dst, sizeof(dst), &written, &required, 0) == 0);
    CHECK(!written && !required);
    CHECK(lmb_events_call_count(GE_WAIT) == waits + 1);
    CHECK(lmb_events_call_count(GE_CONSUME) == consumes + 1);
    CHECK(lmb_close(&s) == 0 && !s);
    row_drained();
    puts("conform/timeout session: 0/0 with one exact wait, drain without wait");
}
static void timeout_buffer(const char *fixture) {
    uint8_t dst[24];
    uint64_t used = 123, needed = 123, waits, consumes;
    row_begin();
    struct buffer_pair pair = open_buffer(fixture);
    memset(dst, 0xa5, sizeof(dst));
    waits = lmb_events_call_count(GE_WAIT);
    consumes = lmb_events_call_count(GE_CONSUME);
    ge_wait_result(0, 0);
    CHECK(lmb_buffer_poll_v1(pair.buffer, dst, sizeof(dst), 17, &used, &needed) == 0);
    CHECK(!used && !needed);
    CHECK(ge_last_timeout() == 17);
    CHECK(lmb_events_call_count(GE_WAIT) == waits + 1);
    CHECK(lmb_events_call_count(GE_CONSUME) == consumes);
    ge_sentinel(dst, sizeof(dst), 0xa5);
    ge_diagnostic(0, 0, 0);
    CHECK(lmb_buffer_poll_v1(pair.buffer, dst, sizeof(dst), 0, &used, &needed) == 0);
    CHECK(!used && !needed);
    CHECK(lmb_events_call_count(GE_WAIT) == waits + 1);
    CHECK(lmb_events_call_count(GE_CONSUME) == consumes + 1);
    close_buffer(&pair);
    row_drained();
    puts("conform/timeout buffer: 0/0 with one exact wait, drain without wait");
}
/* Interrupted waits report EINTR with zero cells on both; the
 * session latches no native error for the interruption. */
static void eintr_session(const char *fixture) {
    uint8_t dst[24];
    uint32_t written = 123, required = 123;
    uint64_t received, delivered, staged, malformed, dropped;
    int32_t last_error;
    uint32_t op, domain;
    int32_t code;
    row_begin();
    struct lmb_session *s = open_session(fixture);
    ge_wait_result(-1, EINTR);
    CHECK(lmb_poll(s, dst, sizeof(dst), &written, &required, 17) == -EINTR);
    CHECK(!written && !required);
    CHECK(ge_last_timeout() == 17);
    session_diagnostic(&op, &domain, &code);
    CHECK(op == 4 && domain == 1 && code == -EINTR);
    session_counters(s, &received, &delivered, &staged, &malformed, &dropped,
        &last_error);
    CHECK(!received && last_error == 0);
    CHECK(lmb_close(&s) == 0 && !s);
    row_drained();
    puts("conform/eintr session: EINTR with zero cells, nothing latched");
}
static void eintr_buffer(const char *fixture) {
    uint8_t dst[24];
    uint64_t used = 123, needed = 123;
    row_begin();
    struct buffer_pair pair = open_buffer(fixture);
    ge_wait_result(-1, EINTR);
    CHECK(lmb_buffer_poll_v1(pair.buffer, dst, sizeof(dst), 17, &used, &needed) == -EINTR);
    CHECK(!used && !needed);
    CHECK(ge_last_timeout() == 17);
    ge_diagnostic(13, 1, -EINTR);
    close_buffer(&pair);
    row_drained();
    puts("conform/eintr buffer: EINTR with zero cells");
}
/* Malformed records (empty and oversized) are skipped and counted;
 * one poll still delivers the queued valid record. */
static void malformed_session(const char *fixture) {
    uint8_t dst[24], payload[16], large[4097];
    uint32_t written = 0, required = 0;
    uint64_t received, delivered, staged, malformed, dropped, consumes;
    int32_t last_error;
    row_begin();
    struct lmb_session *s = open_session(fixture);
    ge_payload(payload, 7);
    memset(large, 0x6d, sizeof(large));
    ge_publish(NULL, 0, 0);
    ge_publish(large, 4097, 0);
    ge_publish(payload, 16, 0);
    consumes = lmb_events_call_count(GE_CONSUME);
    CHECK(lmb_poll(s, dst, sizeof(dst), &written, &required, 0) == 0);
    CHECK(written == 24 && !required);
    ge_frame(dst, 7);
    CHECK(lmb_events_call_count(GE_CONSUME) == consumes + 3);
    session_counters(s, &received, &delivered, &staged, &malformed, &dropped,
        &last_error);
    CHECK(received == 3 && delivered == 1 && !staged);
    CHECK(malformed == 2 && !dropped && last_error == 0);
    CHECK(lmb_poll(s, dst, sizeof(dst), &written, &required, 0) == 0);
    CHECK(!written && !required);
    CHECK(lmb_close(&s) == 0 && !s);
    row_drained();
    puts("conform/malformed session: skip 2, deliver 1, reconcile 3/1/2");
}
static void malformed_buffer(const char *fixture) {
    uint8_t dst[24], payload[16], large[4097];
    uint64_t used = 0, needed = 0;
    uint64_t received, delivered, staged, malformed, dropped, consumes;
    row_begin();
    struct buffer_pair pair = open_buffer(fixture);
    ge_payload(payload, 7);
    memset(large, 0x6d, sizeof(large));
    ge_publish(NULL, 0, 0);
    ge_publish(large, 4097, 0);
    ge_publish(payload, 16, 0);
    consumes = lmb_events_call_count(GE_CONSUME);
    CHECK(lmb_buffer_poll_v1(pair.buffer, dst, sizeof(dst), 0, &used, &needed) == 0);
    CHECK(used == 24 && !needed);
    ge_frame(dst, 7);
    CHECK(lmb_events_call_count(GE_CONSUME) == consumes + 3);
    buffer_counters(pair.buffer, &received, &delivered, &staged, &malformed,
        &dropped);
    CHECK(received == 3 && delivered == 1 && !staged);
    CHECK(malformed == 2 && !dropped);
    CHECK(lmb_buffer_poll_v1(pair.buffer, dst, sizeof(dst), 0, &used, &needed) == 0);
    CHECK(!used && !needed);
    close_buffer(&pair);
    row_drained();
    puts("conform/malformed buffer: skip 2, deliver 1, reconcile 3/1/2");
}
/* Short retries retain the staged record without further ring or
 * wait calls; one sufficient call delivers it exactly once. */
static void short_session(const char *fixture) {
    uint8_t dst[24], payload[16];
    uint32_t written = 123, required = 123;
    uint64_t received, delivered, staged, malformed, dropped, consumes, waits;
    int32_t last_error;
    uint32_t op, domain;
    int32_t code;
    row_begin();
    struct lmb_session *s = open_session(fixture);
    ge_payload(payload, 9);
    ge_publish(payload, 16, 0);
    memset(dst, 0xa5, sizeof(dst));
    CHECK(lmb_poll(s, dst, 23, &written, &required, 0) == -ENOSPC);
    CHECK(!written && required == 24);
    ge_sentinel(dst, sizeof(dst), 0xa5);
    session_diagnostic(&op, &domain, &code);
    CHECK(op == 4 && domain == 4 && code == -ENOSPC);
    consumes = lmb_events_call_count(GE_CONSUME);
    waits = lmb_events_call_count(GE_WAIT);
    for (unsigned i = 0; i < 2; i++) {
        written = 123;
        required = 123;
        memset(dst, 0xa5, sizeof(dst));
        CHECK(lmb_poll(s, dst, 23, &written, &required, -1) == -ENOSPC);
        CHECK(!written && required == 24);
        ge_sentinel(dst, sizeof(dst), 0xa5);
        CHECK(lmb_events_call_count(GE_CONSUME) == consumes);
        CHECK(lmb_events_call_count(GE_WAIT) == waits);
    }
    CHECK(lmb_poll(s, dst, 24, &written, &required, 0) == 0);
    CHECK(written == 24 && !required);
    ge_frame(dst, 9);
    session_counters(s, &received, &delivered, &staged, &malformed, &dropped,
        &last_error);
    CHECK(received == 1 && delivered == 1 && !staged);
    CHECK(!malformed && !dropped);
    CHECK(lmb_poll(s, dst, sizeof(dst), &written, &required, 0) == 0);
    CHECK(!written && !required);
    CHECK(lmb_close(&s) == 0 && !s);
    row_drained();
    puts("conform/short session: 23/23 retained, 24 delivers once");
}
static void short_buffer(const char *fixture) {
    uint8_t dst[24], payload[16];
    uint64_t used = 123, needed = 123, consumes, waits;
    uint64_t received, delivered, staged, malformed, dropped;
    row_begin();
    struct buffer_pair pair = open_buffer(fixture);
    ge_payload(payload, 9);
    ge_publish(payload, 16, 0);
    memset(dst, 0xa5, sizeof(dst));
    CHECK(lmb_buffer_poll_v1(pair.buffer, dst, 23, 0, &used, &needed) == -ENOSPC);
    CHECK(!used && needed == 24);
    ge_sentinel(dst, sizeof(dst), 0xa5);
    ge_diagnostic(13, 4, -ENOSPC);
    consumes = lmb_events_call_count(GE_CONSUME);
    waits = lmb_events_call_count(GE_WAIT);
    for (unsigned i = 0; i < 2; i++) {
        used = 123;
        needed = 123;
        memset(dst, 0xa5, sizeof(dst));
        CHECK(lmb_buffer_poll_v1(pair.buffer, dst, 23, -1, &used, &needed) == -ENOSPC);
        CHECK(!used && needed == 24);
        ge_sentinel(dst, sizeof(dst), 0xa5);
        CHECK(lmb_events_call_count(GE_CONSUME) == consumes);
        CHECK(lmb_events_call_count(GE_WAIT) == waits);
    }
    CHECK(lmb_buffer_poll_v1(pair.buffer, dst, 24, 0, &used, &needed) == 0);
    CHECK(used == 24 && !needed);
    ge_frame(dst, 9);
    buffer_counters(pair.buffer, &received, &delivered, &staged, &malformed,
        &dropped);
    CHECK(received == 1 && delivered == 1 && !staged);
    CHECK(!malformed && !dropped);
    CHECK(lmb_buffer_poll_v1(pair.buffer, dst, sizeof(dst), 0, &used, &needed) == 0);
    CHECK(!used && !needed);
    close_buffer(&pair);
    row_drained();
    puts("conform/short buffer: 23/23 retained, 24 delivers once");
}
/* One call delivers at most one frame even when two records wait
 * and the destination fits both: single-frame behavior holds on
 * both adapters, with no multi-frame batching. */
static void single_session(const char *fixture) {
    uint8_t dst[48], payload[16];
    uint32_t written = 0, required = 0;
    uint64_t received, delivered, staged, malformed, dropped;
    int32_t last_error;
    row_begin();
    struct lmb_session *s = open_session(fixture);
    ge_payload(payload, 21);
    ge_publish(payload, 16, 0);
    ge_payload(payload, 22);
    ge_publish(payload, 16, 0);
    memset(dst, 0xa5, sizeof(dst));
    CHECK(lmb_poll(s, dst, sizeof(dst), &written, &required, 0) == 0);
    CHECK(written == 24 && !required);
    ge_frame(dst, 21);
    ge_sentinel(dst + 24, 24, 0xa5);
    CHECK(lmb_poll(s, dst, sizeof(dst), &written, &required, 0) == 0);
    CHECK(written == 24 && !required);
    ge_frame(dst, 22);
    session_counters(s, &received, &delivered, &staged, &malformed, &dropped,
        &last_error);
    CHECK(received == 2 && delivered == 2 && !staged);
    CHECK(!malformed && !dropped);
    CHECK(lmb_close(&s) == 0 && !s);
    row_drained();
    puts("conform/single session: 48-byte destination takes 24 + 24");
}
static void single_buffer(const char *fixture) {
    uint8_t dst[48], payload[16];
    uint64_t used = 0, needed = 0;
    uint64_t received, delivered, staged, malformed, dropped;
    row_begin();
    struct buffer_pair pair = open_buffer(fixture);
    ge_payload(payload, 21);
    ge_publish(payload, 16, 0);
    ge_payload(payload, 22);
    ge_publish(payload, 16, 0);
    memset(dst, 0xa5, sizeof(dst));
    CHECK(lmb_buffer_poll_v1(pair.buffer, dst, sizeof(dst), 0, &used, &needed) == 0);
    CHECK(used == 24 && !needed);
    ge_frame(dst, 21);
    ge_sentinel(dst + 24, 24, 0xa5);
    CHECK(lmb_buffer_poll_v1(pair.buffer, dst, sizeof(dst), 0, &used, &needed) == 0);
    CHECK(used == 24 && !needed);
    ge_frame(dst, 22);
    buffer_counters(pair.buffer, &received, &delivered, &staged, &malformed,
        &dropped);
    CHECK(received == 2 && delivered == 2 && !staged);
    CHECK(!malformed && !dropped);
    close_buffer(&pair);
    row_drained();
    puts("conform/single buffer: 48-byte destination takes 24 + 24");
}
/* Borrowed ring memory mutated after the callback cannot corrupt
 * delivery: both adapters frame from their owned staging copy.
 * The session callback is additionally driven directly with a
 * caller buffer that is clobbered before the poll. */
static void mutation_session(const char *fixture) {
    uint8_t dst[24], payload[16], direct[16], want[16];
    uint32_t written = 0, required = 0;
    uint64_t received, delivered, staged, malformed, dropped;
    int32_t last_error;
    row_begin();
    struct lmb_session *s = open_session(fixture);
    ge_payload(payload, 31);
    ge_overwrite_source(1);
    ge_publish(payload, 16, 0);
    CHECK(lmb_poll(s, dst, sizeof(dst), &written, &required, 0) == 0);
    CHECK(written == 24 && !required);
    ge_frame(dst, 31);
    ge_overwrite_source(0);
    for (unsigned i = 0; i < sizeof(direct); i++)
        direct[i] = (uint8_t)(i * 7u + 3u);
    memcpy(want, direct, sizeof(want));
    CHECK(lmb_ring_sample(s, direct, sizeof(direct)) == 0);
    memset(direct, 0xcc, sizeof(direct));
    CHECK(lmb_poll(s, dst, sizeof(dst), &written, &required, 0) == 0);
    CHECK(written == 24 && !required);
    check_bytes_frame(dst, want, 16);
    session_counters(s, &received, &delivered, &staged, &malformed, &dropped,
        &last_error);
    CHECK(received == 2 && delivered == 2 && !staged);
    CHECK(!malformed && !dropped);
    CHECK(lmb_close(&s) == 0 && !s);
    row_drained();
    puts("conform/mutation session: owned copy survives source clobber");
}
static void mutation_buffer(const char *fixture) {
    uint8_t dst[24], payload[16];
    uint64_t used = 0, needed = 0;
    uint64_t received, delivered, staged, malformed, dropped;
    row_begin();
    struct buffer_pair pair = open_buffer(fixture);
    ge_payload(payload, 31);
    ge_overwrite_source(1);
    ge_publish(payload, 16, 0);
    CHECK(lmb_buffer_poll_v1(pair.buffer, dst, sizeof(dst), 0, &used, &needed) == 0);
    CHECK(used == 24 && !needed);
    ge_frame(dst, 31);
    ge_overwrite_source(0);
    buffer_counters(pair.buffer, &received, &delivered, &staged, &malformed,
        &dropped);
    CHECK(received == 1 && delivered == 1 && !staged);
    CHECK(!malformed && !dropped);
    close_buffer(&pair);
    row_drained();
    puts("conform/mutation buffer: owned copy survives source clobber");
}
/* Mixed valid/malformed/dropped traffic reconciles exactly:
 * received == delivered + staged + malformed + dropped. The
 * drop is a valid record consumed while the single slot is
 * occupied; malformed records are the empty and oversized ones. */
static void conservation_session(const char *fixture) {
    uint8_t dst[24], payload[16], large[4097];
    uint32_t written = 0, required = 0;
    uint64_t received, delivered, staged, malformed, dropped, consumes;
    int32_t last_error;
    row_begin();
    struct lmb_session *s = open_session(fixture);
    consumes = lmb_events_call_count(GE_CONSUME);
    ge_payload(payload, 41);
    ge_publish(payload, 16, 0);
    CHECK(lmb_poll(s, dst, 23, &written, &required, 0) == -ENOSPC);
    CHECK(!written && required == 24);
    ge_payload(payload, 42);
    ge_publish(payload, 16, 0);
    CHECK(s->stage_len == 16);
    CHECK(ring_buffer__consume_n(s->rb, 1) == 1);
    CHECK(lmb_poll(s, dst, 24, &written, &required, 0) == 0);
    CHECK(written == 24 && !required);
    ge_frame(dst, 41);
    ge_publish(NULL, 0, 0);
    memset(large, 0x6d, sizeof(large));
    ge_publish(large, 4097, 0);
    ge_payload(payload, 43);
    ge_publish(payload, 16, 0);
    CHECK(lmb_poll(s, dst, 24, &written, &required, 0) == 0);
    CHECK(written == 24 && !required);
    ge_frame(dst, 43);
    CHECK(lmb_events_call_count(GE_CONSUME) == consumes + 5);
    session_counters(s, &received, &delivered, &staged, &malformed, &dropped,
        &last_error);
    CHECK(received == 5 && delivered == 2 && !staged);
    CHECK(malformed == 2 && dropped == 1);
    CHECK(received == delivered + staged + malformed + dropped);
    CHECK(lmb_close(&s) == 0 && !s);
    row_drained();
    puts("conform/conservation session: 5 == 2 + 0 + 2 + 1");
}
static void conservation_buffer(const char *fixture) {
    uint8_t dst[24], payload[16], large[4097];
    uint64_t used = 0, needed = 0;
    uint64_t received, delivered, staged, malformed, dropped, consumes;
    row_begin();
    struct buffer_pair pair = open_buffer(fixture);
    consumes = lmb_events_call_count(GE_CONSUME);
    ge_payload(payload, 41);
    ge_publish(payload, 16, 0);
    CHECK(lmb_buffer_poll_v1(pair.buffer, dst, 23, 0, &used, &needed) == -ENOSPC);
    CHECK(!used && needed == 24);
    ge_payload(payload, 42);
    ge_publish(payload, 16, 0);
    CHECK(pair.buffer->stage_len == 16);
    CHECK(ring_buffer__consume_n(pair.buffer->rb, 1) == 1);
    CHECK(lmb_buffer_poll_v1(pair.buffer, dst, 24, 0, &used, &needed) == 0);
    CHECK(used == 24 && !needed);
    ge_frame(dst, 41);
    ge_publish(NULL, 0, 0);
    memset(large, 0x6d, sizeof(large));
    ge_publish(large, 4097, 0);
    ge_payload(payload, 43);
    ge_publish(payload, 16, 0);
    CHECK(lmb_buffer_poll_v1(pair.buffer, dst, 24, 0, &used, &needed) == 0);
    CHECK(used == 24 && !needed);
    ge_frame(dst, 43);
    CHECK(lmb_events_call_count(GE_CONSUME) == consumes + 5);
    buffer_counters(pair.buffer, &received, &delivered, &staged, &malformed,
        &dropped);
    CHECK(received == 5 && delivered == 2 && !staged);
    CHECK(malformed == 2 && dropped == 1);
    CHECK(received == delivered + staged + malformed + dropped);
    close_buffer(&pair);
    row_drained();
    puts("conform/conservation buffer: 5 == 2 + 0 + 2 + 1");
}
/* Intentional diagnostic-lifetime difference: the v1 record
 * survives a later success, while a generic success clears the
 * generic record. Both report the short capacity failure first. */
static void error_session(const char *fixture) {
    uint8_t dst[24], payload[16];
    uint32_t written = 0, required = 0;
    uint32_t op, domain;
    int32_t code;
    row_begin();
    struct lmb_session *s = open_session(fixture);
    ge_payload(payload, 51);
    ge_publish(payload, 16, 0);
    CHECK(lmb_poll(s, dst, 23, &written, &required, 0) == -ENOSPC);
    session_diagnostic(&op, &domain, &code);
    CHECK(op == 4 && domain == 4 && code == -ENOSPC);
    CHECK(lmb_poll(s, dst, 24, &written, &required, 0) == 0);
    CHECK(written == 24 && !required);
    ge_frame(dst, 51);
    session_diagnostic(&op, &domain, &code);
    CHECK(op == 4 && domain == 4 && code == -ENOSPC);
    CHECK(lmb_close(&s) == 0 && !s);
    row_drained();
    puts("conform/error session: short diagnostic preserved across success");
}
static void error_buffer(const char *fixture) {
    uint8_t dst[24], payload[16];
    uint64_t used = 0, needed = 0;
    row_begin();
    struct buffer_pair pair = open_buffer(fixture);
    ge_payload(payload, 51);
    ge_publish(payload, 16, 0);
    CHECK(lmb_buffer_poll_v1(pair.buffer, dst, 23, 0, &used, &needed) == -ENOSPC);
    ge_diagnostic(13, 4, -ENOSPC);
    CHECK(lmb_buffer_poll_v1(pair.buffer, dst, 24, 0, &used, &needed) == 0);
    CHECK(used == 24 && !needed);
    ge_frame(dst, 51);
    ge_diagnostic(0, 0, 0);
    close_buffer(&pair);
    row_drained();
    puts("conform/error buffer: success clears the short diagnostic");
}
/* Intentional latch difference: a libbpf consumption failure
 * latches the session's terminal native error and survives
 * later success, while the buffer reports only the per-call
 * diagnostic. The failed consumption loses no record on
 * either adapter. */
static void fault_session(const char *fixture) {
    uint8_t dst[24], payload[16];
    uint32_t written = 123, required = 123;
    uint64_t received, delivered, staged, malformed, dropped;
    int32_t last_error;
    uint32_t op, domain;
    int32_t code;
    row_begin();
    struct lmb_session *s = open_session(fixture);
    ge_payload(payload, 61);
    ge_publish(payload, 16, 0);
    ge_consume_fault(-ENOSPC);
    CHECK(lmb_poll(s, dst, 24, &written, &required, 0) == -ENOSPC);
    CHECK(!written && !required);
    session_diagnostic(&op, &domain, &code);
    CHECK(op == 4 && domain == 2 && code == -ENOSPC);
    session_counters(s, &received, &delivered, &staged, &malformed, &dropped,
        &last_error);
    CHECK(!received && last_error == -ENOSPC);
    ge_consume_fault(0);
    CHECK(lmb_poll(s, dst, 24, &written, &required, 0) == 0);
    CHECK(written == 24 && !required);
    ge_frame(dst, 61);
    session_counters(s, &received, &delivered, &staged, &malformed, &dropped,
        &last_error);
    CHECK(received == 1 && delivered == 1 && last_error == -ENOSPC);
    CHECK(lmb_close(&s) == 0 && !s);
    row_drained();
    puts("conform/fault session: LIBBPF short latches, record survives");
}
static void fault_buffer(const char *fixture) {
    uint8_t dst[24], payload[16];
    uint64_t used = 123, needed = 123;
    uint64_t received, delivered, staged, malformed, dropped;
    row_begin();
    struct buffer_pair pair = open_buffer(fixture);
    ge_payload(payload, 61);
    ge_publish(payload, 16, 0);
    ge_consume_fault(-ENOSPC);
    CHECK(lmb_buffer_poll_v1(pair.buffer, dst, 24, 0, &used, &needed) == -ENOSPC);
    CHECK(!used && !needed);
    ge_diagnostic(13, 2, -ENOSPC);
    buffer_counters(pair.buffer, &received, &delivered, &staged, &malformed,
        &dropped);
    CHECK(!received && !delivered && !staged);
    CHECK(!malformed && !dropped);
    ge_consume_fault(0);
    CHECK(lmb_buffer_poll_v1(pair.buffer, dst, 24, 0, &used, &needed) == 0);
    CHECK(used == 24 && !needed);
    ge_frame(dst, 61);
    ge_diagnostic(0, 0, 0);
    close_buffer(&pair);
    row_drained();
    puts("conform/fault buffer: LIBBPF short diagnosed, record survives");
}
/* Ownership: closing a session frees staged and pending state
 * outright, while closing a generic object with a live buffer
 * reports BUSY, preserves the usable owner, and leaves the
 * buffer pollable. Each row drains its leftovers with a fresh
 * handle and holds owned FDs steady. */
static void ownership_session(const char *fixture) {
    uint8_t dst[24], payload[16];
    uint32_t written = 0, required = 0;
    unsigned fds;
    row_begin();
    fds = ge_fd_count();
    struct lmb_session *s = open_session(fixture);
    ge_payload(payload, 71);
    ge_publish(payload, 16, 0);
    CHECK(lmb_poll(s, dst, 23, &written, &required, 0) == -ENOSPC);
    ge_payload(payload, 72);
    ge_publish(payload, 16, 0);
    CHECK(lmb_close(&s) == 0 && !s);
    CHECK(ge_consumer() != ge_producer());
    s = open_session(fixture);
    CHECK(lmb_poll(s, dst, 24, &written, &required, 0) == 0);
    CHECK(written == 24 && !required);
    ge_frame(dst, 72);
    CHECK(lmb_close(&s) == 0 && !s);
    CHECK(ge_fd_count() == fds);
    row_drained();
    puts("conform/ownership session: close frees staged and pending state");
}
static void ownership_buffer(const char *fixture) {
    uint8_t dst[24], payload[16];
    uint64_t used = 0, needed = 0;
    unsigned fds;
    row_begin();
    fds = ge_fd_count();
    struct buffer_pair pair = open_buffer(fixture);
    ge_payload(payload, 71);
    ge_publish(payload, 16, 0);
    CHECK(lmb_buffer_poll_v1(pair.buffer, dst, 23, 0, &used, &needed) == -ENOSPC);
    CHECK(lmb_object_close_v1(&pair.object) == -EBUSY && pair.object);
    ge_diagnostic(6, 4, -EBUSY);
    CHECK(lmb_buffer_poll_v1(pair.buffer, dst, 24, 0, &used, &needed) == 0);
    CHECK(used == 24 && !needed);
    ge_frame(dst, 71);
    ge_payload(payload, 72);
    ge_publish(payload, 16, 0);
    close_buffer(&pair);
    CHECK(ge_consumer() != ge_producer());
    pair = open_buffer(fixture);
    CHECK(lmb_buffer_poll_v1(pair.buffer, dst, 24, 0, &used, &needed) == 0);
    CHECK(used == 24 && !needed);
    ge_frame(dst, 72);
    close_buffer(&pair);
    CHECK(ge_fd_count() == fds);
    row_drained();
    puts("conform/ownership buffer: BUSY preserves owner, teardown frees");
}
int main(int argc, char **argv) {
    unsigned fds;
    int result, stable;
    if (argc != 2)
        return 2;
    fds = ge_fd_count();
    ge_begin(argv[1]);
    fresh_session(argv[1]);
    timeout_session(argv[1]);
    eintr_session(argv[1]);
    malformed_session(argv[1]);
    short_session(argv[1]);
    single_session(argv[1]);
    mutation_session(argv[1]);
    conservation_session(argv[1]);
    error_session(argv[1]);
    fault_session(argv[1]);
    ownership_session(argv[1]);
    CHECK(ge_consumer() == ge_producer());
    fresh_buffer(argv[1]);
    timeout_buffer(argv[1]);
    eintr_buffer(argv[1]);
    malformed_buffer(argv[1]);
    short_buffer(argv[1]);
    single_buffer(argv[1]);
    mutation_buffer(argv[1]);
    conservation_buffer(argv[1]);
    error_buffer(argv[1]);
    fault_buffer(argv[1]);
    ownership_buffer(argv[1]);
    result = ge_end("ring conformance");
    stable = ge_fd_count() == fds;
    CHECK(stable);
    return result || !stable;
}
