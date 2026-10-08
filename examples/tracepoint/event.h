/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */

/* Tracepoint example wire payload.
 *
 * Both the BPF probe (probe.bpf.c) and the C reference consumer
 * (tests/native/reference_consumer.c) share this definition. The Mojo
 * collector (main.mojo) parses the same byte layout with explicit
 * little-endian reads; the offsets below are the contract.
 *
 * Payload layout (16 bytes, little-endian):
 *   offset 0: seq   u64   per-attach sequence from the count map
 *   offset 8: tgid  u32   trigger thread-group id in our namespace
 *   offset 12: tag  u32   must equal TP_TAG
 */
#ifndef TRACEPOINT_EVENT_H
#define TRACEPOINT_EVENT_H

/* linux/types.h keeps this header consumable by both the BPF
 * target and userspace; stdint.h drags in host-only headers. */
#include <linux/types.h>

#define TP_TAG 0xA04u
#define TP_RING_NAME "events"
#define TP_FILTER_MAP "filter"
#define TP_SEQ_MAP "count"
#define TP_PROGRAM "trace_probe"

struct tp_event {
    __u64 seq;
    __u32 tgid;
    __u32 tag;
};

#endif /* TRACEPOINT_EVENT_H */
