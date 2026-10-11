/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
#ifndef LMB_TEST_GENERIC_EVENTS_H
#define LMB_TEST_GENERIC_EVENTS_H
#include <linux/types.h>
#define GENERIC_EVENTS_CAPACITY 65536u
#define GENERIC_EVENT_VERSION 1u
#define GENERIC_EVENT_BYTES 32u
/* Test wire contract on the initial little-endian fixture target. */
struct generic_event {
    __u16 version;
    __u16 record_size;
    __u32 tgid;
    __u32 tid;
    __u32 cpu;
    __u64 sequence;
    __u64 monotonic_ns;
};
struct generic_producer_counts {
    __u64 attempted;
    __u64 successful;
    __u64 failed;
};
_Static_assert(sizeof(struct generic_event) == GENERIC_EVENT_BYTES, "event bytes");
_Static_assert(__builtin_offsetof(struct generic_event, sequence) == 16, "sequence offset");
_Static_assert(__builtin_offsetof(struct generic_event, monotonic_ns) == 24, "time offset");
#endif
