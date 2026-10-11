/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#ifndef GENERIC_NO_MAP
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} counter SEC(".maps");
#endif

SEC("socket")
int first(struct __sk_buff *ctx) {
    return ctx->len > 41 ? 42 : 0;
}

SEC("socket")
int second(struct __sk_buff *ctx) {
    return ctx->len;
}

#ifdef GENERIC_TRACING
SEC("fentry/do_sys_open")
int traced(void *ctx) {
    (void)ctx;
    return 0;
}
#endif

char LICENSE[] SEC("license") = "Apache-2.0 WITH LLVM-exception";
