/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* Independent tracepoint control: one selected initial-namespace TID. */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "generic_events.h"
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, GENERIC_EVENTS_CAPACITY);
} events SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} filter SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct generic_producer_counts);
} producer_counts SEC(".maps");
SEC("tracepoint/syscalls/sys_enter_getpid")
int on_getpid(void *ctx) {
    (void)ctx;
    __u32 zero = 0;
    __u64 identity = bpf_get_current_pid_tgid();
    __u32 tid = (__u32)identity;
    __u32 *selected = bpf_map_lookup_elem(&filter, &zero);
    if (!selected || !*selected || tid != *selected) return 0;
    struct generic_producer_counts *counts = bpf_map_lookup_elem(&producer_counts, &zero);
    if (!counts) return 0;
    struct generic_event event = {
        .version = GENERIC_EVENT_VERSION,
        .record_size = GENERIC_EVENT_BYTES,
        .tgid = identity >> 32, .tid = tid,
        .cpu = bpf_get_smp_processor_id(),
        .sequence = __sync_fetch_and_add(&counts->attempted, 1) + 1,
        .monotonic_ns = bpf_ktime_get_ns(),
    };
    if (bpf_ringbuf_output(&events, &event, sizeof(event), 0) == 0)
        __sync_fetch_and_add(&counts->successful, 1);
    else
        __sync_fetch_and_add(&counts->failed, 1);
    return 0;
}
char LICENSE[] SEC("license") = "Apache-2.0 WITH LLVM-exception";
