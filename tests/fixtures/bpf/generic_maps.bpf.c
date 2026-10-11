/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* Independent C control, not an implementation of a consumer algorithm. */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct odd_value { unsigned char bytes[13]; };
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
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct odd_value);
} percpu_values SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, 8);
    __type(key, __u32);
    __type(value, struct odd_value);
} percpu_hash SEC(".maps");

SEC("xdp")
int packet_control(struct xdp_md *ctx) {
    __u32 key = 0;
    __u64 *value = bpf_map_lookup_elem(&counter, &key);
    if (value) *value += 1;
    unsigned char *data = (void *)(long)ctx->data;
    unsigned char *end = (void *)(long)ctx->data_end;
    return data + 1 <= end && data[0] == 0 ? XDP_DROP : XDP_PASS;
}

char LICENSE[] SEC("license") = "Apache-2.0 WITH LLVM-exception";
