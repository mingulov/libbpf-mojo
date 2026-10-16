/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */

/* Shared single-slot staging and framing for the v1 session ring
 * consumer and the generic buffer ring consumer. These helpers are
 * pure: they classify one borrowed record and encode one frame,
 * and they own no counters, diagnostics, or wait behavior. Each
 * adapter keeps its own owner struct, error channel, statistics
 * shape, and drain control; only the byte-level staging decision
 * and frame layout are shared, and the cross-adapter conformance
 * test pins both adapters to identical behavior on every row.
 * Not installed; internal to the bridge build. */
#ifndef LMB_RING_STAGE_H
#define LMB_RING_STAGE_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* One frame header: u32 payload length, u16 framing version, u16
 * reserved zero. Both adapters document framing version 1 with an
 * 8-byte header; each call site asserts its own header constant
 * against this shared size. */
#define LMB_STAGE_HEADER_SIZE 8u

enum lmb_stage_class {
    /* Stageable: copy the borrowed bytes into the owned slot. */
    LMB_STAGE_OK = 0,
    /* Empty or oversized: unusable data, never staged. */
    LMB_STAGE_MALFORMED = 1,
    /* Valid but the single slot is occupied: capacity loss. */
    LMB_STAGE_DROPPED = 2
};

/* Classify one borrowed record. An empty record cannot be staged
 * because a zero stage length reads back as no record, so it is
 * malformed; the same holds past the raw cap. A valid record that
 * arrives while the slot is occupied is dropped. A record that
 * classifies OK always satisfies 1 <= size <= max_raw. */
static inline enum lmb_stage_class lmb_classify_record(size_t size,
        uint32_t max_raw, uint32_t stage_len) {
    if (size == 0 || size > max_raw)
        return LMB_STAGE_MALFORMED;
    if (stage_len != 0)
        return LMB_STAGE_DROPPED;
    return LMB_STAGE_OK;
}

/* Whole-frame bytes for a classified payload length. */
static inline uint32_t lmb_frame_total(uint32_t payload_len) {
    return LMB_STAGE_HEADER_SIZE + payload_len;
}

/* Encode one frame: little-endian length, version, reserved zero,
 * then exactly the payload bytes. The caller supplies its own
 * framing-version constant and a destination of at least
 * lmb_frame_total(len) bytes. */
static inline void lmb_encode_frame(uint8_t *dst, const uint8_t *payload,
        uint32_t len, uint16_t version) {
    dst[0] = (uint8_t)len;
    dst[1] = (uint8_t)(len >> 8);
    dst[2] = (uint8_t)(len >> 16);
    dst[3] = (uint8_t)(len >> 24);
    dst[4] = (uint8_t)version;
    dst[5] = (uint8_t)(version >> 8);
    dst[6] = 0;
    dst[7] = 0;
    memcpy(dst + LMB_STAGE_HEADER_SIZE, payload, len);
}

#endif /* LMB_RING_STAGE_H */
