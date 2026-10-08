/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */

/* Synthetic record source through the real poll boundary. Drives
 * lmb_ring_sample and lmb_poll with staged records without loading a
 * kernel object, so it needs no privileges and runs deterministically
 * anywhere. The internal.h inclusion and the armed-session trick are
 * test-only: production builds expose no synthetic input switch.
 *
 * Arming: lmb_poll requires a loaded session with a ring, but a
 * pre-staged record takes the framing path without touching the
 * ring. The test sets loaded plus a dummy nonzero rb, stages records
 * via the real callback, polls only while a record is staged, then
 * disarms (loaded=0, rb=NULL) before close so teardown frees only
 * real state. A second delivery is impossible once the stage reads
 * empty, which the live suite also proves with its drained check. */
#include <stdint.h>

#include "internal.h"
#include "testutil.h"

#define GUARD 16
#define FILL_GUARD 0xA5u
#define FILL_DST 0x5Au

static uint8_t payload16[16];
static uint8_t payload_max[LMB_MAX_RAW_BYTES];
static uint8_t payload_over[LMB_MAX_RAW_BYTES + 1];
static _Alignas(4) uint8_t zone[GUARD + LMB_MAX_FRAME_BYTES + GUARD];

static void fill_pattern(uint8_t *p, uint32_t n) {
    uint32_t i;
    for (i = 0; i < n; i++)
        p[i] = (uint8_t)(i * 7u + 3u);
}

static void prep_zone(uint32_t cap) {
    uint32_t i;
    for (i = 0; i < GUARD; i++) {
        zone[i] = FILL_GUARD;
        zone[GUARD + cap + i] = FILL_GUARD;
    }
    for (i = 0; i < cap; i++)
        zone[GUARD + i] = FILL_DST;
}

static int guards_ok(uint32_t cap) {
    uint32_t i;
    for (i = 0; i < GUARD; i++)
        if (zone[i] != FILL_GUARD || zone[GUARD + cap + i] != FILL_GUARD)
            return 0;
    return 1;
}

static int dst_clean(uint32_t cap) {
    uint32_t i;
    for (i = 0; i < cap; i++)
        if (zone[GUARD + i] != FILL_DST)
            return 0;
    return 1;
}

static void arm(struct lmb_session *s) {
    s->loaded = 1;
    s->rb = (struct ring_buffer *)(uintptr_t)1;
}

static void disarm(struct lmb_session *s) {
    s->loaded = 0;
    s->rb = NULL;
}

static int read_stats(struct lmb_session *s, struct lmb_stats_v1 *st) {
    memset(st, 0, sizeof(*st));
    st->abi_version = LMB_ABI_VERSION;
    st->struct_size = sizeof(*st);
    return lmb_stats(s, st);
}

int main(int argc, char **argv) {
    const char *fixture = lmb_fixture(argc, argv);
    uint8_t *elf = NULL;
    uint64_t elf_len = 0;
    struct lmb_options_v1 o;
    struct lmb_session *s = NULL;
    struct lmb_stats_v1 st;
    struct lmb_error_v1 err;
    uint32_t written = 0, required = 0;
    int32_t rc;

    if (lmb_read_file(fixture, &elf, &elf_len) != 0 || elf_len == 0) {
        LMB_FAIL("fixture-load", "cannot read %s", fixture);
        return 1;
    }
    fill_pattern(payload16, sizeof(payload16));
    fill_pattern(payload_max, sizeof(payload_max));
    fill_pattern(payload_over, sizeof(payload_over));

    lmb_make_options(&o, "events", LMB_MAX_RAW_BYTES);
    if (lmb_open(elf, elf_len, &o, &s) != 0 || !s) {
        LMB_FAIL("setup-open", "open must succeed");
        free(elf);
        return 1;
    }
    arm(s);

    LMB_CHECK(lmb_ring_sample(s, payload16, sizeof(payload16)) == 0 &&
                  read_stats(s, &st) == 0 && st.received == 1 &&
                  st.staged == 1 && st.malformed == 0,
              "sample-stage", "first record must stage");

    LMB_CHECK(lmb_ring_sample(s, payload16, sizeof(payload16)) == 0 &&
                  read_stats(s, &st) == 0 && st.received == 2 &&
                  st.staged == 1 && st.dropped == 1 &&
                  st.malformed == 0,
              "sample-stage-full",
              "second record must count dropped, keep first");

    /* One byte short of the 24-byte frame: exact ENOSPC boundary
     * with nothing copied and the record retained. */
    prep_zone(23);
    written = 0xDEAD;
    required = 0xDEAD;
    rc = lmb_poll(s, zone + GUARD, 23, &written, &required, 0);
    LMB_CHECK(rc == -ENOSPC && written == 0 && required == 24 &&
                  read_stats(s, &st) == 0 && st.staged == 1 &&
                  guards_ok(23) && dst_clean(23),
              "retry-23",
              "capacity 23 must retain required=24 untouched");
    memset(&err, 0, sizeof(err));
    err.abi_version = LMB_ABI_VERSION;
    err.struct_size = sizeof(err);
    LMB_CHECK(lmb_last_error(&err) == 0 &&
                  err.operation == LMB_OP_POLL &&
                  err.domain == LMB_DOMAIN_BRIDGE &&
                  err.code == -ENOSPC,
              "error-replaced",
              "ENOSPC must replace the error record");

    /* Exact fit delivers the retained frame once, byte-exact. */
    prep_zone(24);
    written = 0;
    required = 0xDEAD;
    rc = lmb_poll(s, zone + GUARD, 24, &written, &required, 0);
    LMB_CHECK(rc == 0 && written == 24 && required == 0 &&
                  lmb_le32(zone + GUARD) == 16 &&
                  lmb_le16(zone + GUARD + 4) == LMB_FRAME_VERSION &&
                  lmb_le16(zone + GUARD + 6) == 0 &&
                  memcmp(zone + GUARD + LMB_FRAME_HEADER_SIZE, payload16,
                         sizeof(payload16)) == 0 &&
                  read_stats(s, &st) == 0 && st.delivered == 1 &&
                  st.staged == 0 && guards_ok(24),
              "retry-24", "capacity 24 must deliver the frame exactly");

    memset(&err, 0, sizeof(err));
    err.abi_version = LMB_ABI_VERSION;
    err.struct_size = sizeof(err);
    LMB_CHECK(lmb_last_error(&err) == 0 &&
                  err.operation == LMB_OP_POLL &&
                  err.domain == LMB_DOMAIN_BRIDGE &&
                  err.code == -ENOSPC,
              "error-preserved-on-success",
              "success must preserve the stored record");

    LMB_CHECK(read_stats(s, &st) == 0 && st.staged == 0 &&
                  st.delivered == 1,
              "consume-once",
              "empty stage cannot deliver the record twice");

    /* Aliased outputs are refused before any state changes. */
    LMB_CHECK(lmb_ring_sample(s, payload16, sizeof(payload16)) == 0,
              "alias-stage", "alias probe must stage");
    {
        uint32_t cells[2] = {0xDEAD, 0xDEAD};
        prep_zone(24);
        written = 0xDEAD;
        required = 0xDEAD;
        rc = lmb_poll(s, zone + GUARD, 24, cells, cells, 0);
        LMB_CHECK(rc == -EINVAL && cells[0] == 0xDEAD &&
                      cells[1] == 0xDEAD &&
                      read_stats(s, &st) == 0 && st.staged == 1 &&
                      lmb_error_is(LMB_OP_POLL, LMB_DOMAIN_BRIDGE),
                  "alias-cells",
                  "shared written/required must fail untouched");
        written = 0;
        required = 0;
        rc = lmb_poll(s, zone + GUARD, 24, &written, &required, 0);
        LMB_CHECK(rc == 0 && written == 24, "alias-recover",
                  "session must stay usable after alias refusal");
    }
    LMB_CHECK(lmb_ring_sample(s, payload16, sizeof(payload16)) == 0,
              "alias-stage-2", "second alias probe must stage");
    {
        uint32_t req = 0xDEAD;
        prep_zone(24);
        rc = lmb_poll(s, zone + GUARD, 24,
                      (uint32_t *)(void *)(zone + GUARD + 4), &req,
                      0);
        LMB_CHECK(rc == -EINVAL && req == 0xDEAD &&
                      dst_clean(24) && read_stats(s, &st) == 0 &&
                      st.staged == 1,
                  "alias-dst",
                  "written inside dst must fail untouched");
        written = 0;
        required = 0;
        rc = lmb_poll(s, zone + GUARD, 24, &written, &required, 0);
        LMB_CHECK(rc == 0 && written == 24, "alias-recover-2",
                  "session must stay usable after alias refusal");
    }

    LMB_CHECK(lmb_ring_sample(s, payload_over, sizeof(payload_over)) ==
                  0 &&
                  read_stats(s, &st) == 0 && st.staged == 0 &&
                  st.malformed == 1 && st.dropped == 1,
              "oversize", "oversized record must count malformed");

    LMB_CHECK(lmb_ring_sample(s, payload16, 0) == 0 &&
                  read_stats(s, &st) == 0 && st.staged == 0 &&
                  st.malformed == 2,
              "empty", "empty record must count malformed");

    LMB_CHECK(lmb_ring_sample(s, payload_max, sizeof(payload_max)) ==
                  0 &&
                  read_stats(s, &st) == 0 && st.staged == 1,
              "max-stage", "maximum record must stage");
    prep_zone(LMB_MAX_FRAME_BYTES);
    written = 0;
    required = 0xDEAD;
    rc = lmb_poll(s, zone + GUARD, LMB_MAX_FRAME_BYTES, &written,
                  &required, 0);
    LMB_CHECK(rc == 0 && written == LMB_MAX_FRAME_BYTES &&
                  required == 0 &&
                  lmb_le32(zone + GUARD) == LMB_MAX_RAW_BYTES &&
                  memcmp(zone + GUARD + LMB_FRAME_HEADER_SIZE,
                         payload_max, sizeof(payload_max)) == 0 &&
                  guards_ok(LMB_MAX_FRAME_BYTES),
              "max-exact", "maximum frame must round-trip byte-exact");

    /* Repeated short retries retain one record; an unaligned
     * exact-fit destination delivers it byte-exact. */
    LMB_CHECK(lmb_ring_sample(s, payload16, sizeof(payload16)) == 0,
              "retryloop-stage", "retry probe must stage");
    {
        int k, rok = 1;
        for (k = 0; k < 5; k++) {
            prep_zone(23);
            written = 0xDEAD;
            required = 0xDEAD;
            if (lmb_poll(s, zone + GUARD, 23, &written, &required,
                         0) != -ENOSPC ||
                written != 0 || required != 24 || !guards_ok(23) ||
                !dst_clean(23)) {
                rok = 0;
                break;
            }
        }
        LMB_CHECK(rok && read_stats(s, &st) == 0 && st.staged == 1,
                  "retryloop-retained",
                  "five short retries must retain the record");
    }
    prep_zone(25);
    written = 0;
    required = 0xDEAD;
    rc = lmb_poll(s, zone + GUARD + 1, 24, &written, &required, 0);
    LMB_CHECK(rc == 0 && written == 24 && required == 0 &&
                  lmb_le32(zone + GUARD + 1) == 16 &&
                  lmb_le16(zone + GUARD + 5) == LMB_FRAME_VERSION &&
                  lmb_le16(zone + GUARD + 7) == 0 &&
                  memcmp(zone + GUARD + 1 + LMB_FRAME_HEADER_SIZE,
                         payload16, sizeof(payload16)) == 0 &&
                  zone[GUARD] == FILL_DST && guards_ok(25),
              "retryloop-unaligned",
              "unaligned exact fit must deliver byte-exact");

    LMB_CHECK(read_stats(s, &st) == 0 && st.received == 8 &&
                  st.delivered == 5 && st.staged == 0 &&
                  st.malformed == 2 && st.dropped == 1 &&
                  st.received == st.delivered + st.staged +
                                    st.malformed + st.dropped,
              "conservation", "received must reconcile (r=%llu d=%llu)",
              (unsigned long long)st.received,
              (unsigned long long)st.delivered);

    /* Bulk reconciliation: one hundred thousand stage/deliver
     * cycles must conserve exactly. */
    {
        int bulk_ok = 1;
        long n;
        for (n = 0; n < 100000; n++) {
            written = 0;
            required = 0;
            if (lmb_ring_sample(s, payload16, sizeof(payload16)) !=
                    0 ||
                lmb_poll(s, zone + GUARD, 24, &written, &required,
                         0) != 0 ||
                written != 24 || required != 0) {
                bulk_ok = 0;
                break;
            }
        }
        LMB_CHECK(bulk_ok, "bulk-100k",
                  "100k stage/deliver cycles must succeed");
    }
    LMB_CHECK(read_stats(s, &st) == 0 && st.received == 100008 &&
                  st.delivered == 100005 && st.staged == 0 &&
                  st.malformed == 2 && st.dropped == 1 &&
                  st.received == st.delivered + st.staged +
                                    st.malformed + st.dropped,
              "bulk-conservation",
              "bulk counters must reconcile (r=%llu d=%llu)",
              (unsigned long long)st.received,
              (unsigned long long)st.delivered);

    disarm(s);
    LMB_CHECK(lmb_close(&s) == 0 && s == NULL, "close-ok",
              "close after disarm must succeed");

    free(elf);
    return lmb_failures ? 1 : 0;
}
