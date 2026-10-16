// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} counter SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8);
    __type(key, __u32);
    __type(value, __u64);
} values SEC(".maps");

SEC("xdp")
int lmb_map_live(struct xdp_md *ctx)
{
    (void)ctx;
    __u32 key = 0;
    __u64 *value = bpf_map_lookup_elem(&counter, &key);
    if (value) {
#ifdef LMB_INCREMENT_TWO_MUTANT
        *value += 2;
#else
        *value += 1;
#endif
    }
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "Apache-2.0 WITH LLVM-exception";
