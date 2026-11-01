/* SPDX-License-Identifier: GPL-2.0-only */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
struct { __uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, 4);
    __type(key, __u32); __type(value, __u64); } counts SEC(".maps");
static __always_inline int count(__u32 key) {
    __u32 owner_key = 3;
    __u64 *owner = bpf_map_lookup_elem(&counts, &owner_key);
    if (!owner || *owner != (__u32)bpf_get_current_pid_tgid()) return 0;
    __u64 *value = bpf_map_lookup_elem(&counts, &key);
    if (value) __sync_fetch_and_add(value, 1);
    return 0;
}
SEC("kprobe") int probe_entry(void *ctx) { (void)ctx; return count(0); }
SEC("kretprobe") int probe_return(void *ctx) { (void)ctx; return count(1); }
struct { __uint(type, BPF_MAP_TYPE_RINGBUF); __uint(max_entries, 4096); } events SEC(".maps");
SEC("fentry/__x64_sys_getpid") int probe_tracing(void *ctx) { (void)ctx; return count(2); }
char LICENSE[] SEC("license") = "GPL";
