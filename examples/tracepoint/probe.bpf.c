/* Tracepoint example probe: one sequenced record per observed getpid
 * syscall from the configured trigger identity.
 *
 * The filter map carries the trigger's namespace identity (keys 1 and
 * 2: st_dev/st_ino of /proc/self/ns/pid in the collector's
 * namespace) plus the wanted TGID (key 0); matching uses
 * bpf_get_ns_current_pid_tgid so the example works on the host and
 * in containers. All other activity is ignored in BPF, which keeps
 * the 128-observation reconciliation exact under unrelated load.
 *
 * The count map holds the next sequence number (key 0). Each
 * emission takes its sequence with an atomic fetch-and-add, so the
 * collector can reconcile the ring payloads against this counter
 * plus the trigger's independent ledger.
 */
#include <linux/bpf.h>
#include <linux/types.h>

#include <bpf/bpf_helpers.h>

#include "event.h"

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4096);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, __u64);
} filter SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} count SEC(".maps");

/* Namespace-aware self match: the caller's TGID in the collector's
 * namespace when it matches the filter, else 0 (never a trigger). */
static __always_inline __u32 self_match(void) {
    __u32 pidkey = 0, devkey = 1, inokey = 2;
    __u64 *want, *devp, *inop;
    struct bpf_pidns_info ns;

    want = bpf_map_lookup_elem(&filter, &pidkey);
    devp = bpf_map_lookup_elem(&filter, &devkey);
    inop = bpf_map_lookup_elem(&filter, &inokey);
    if (!want || !devp || !inop)
        return 0;
    __builtin_memset(&ns, 0, sizeof(ns));
    if (bpf_get_ns_current_pid_tgid(*devp, *inop, &ns, sizeof(ns)) != 0)
        return 0;
    if ((__u64)ns.tgid != *want || ns.tgid == 0)
        return 0;
    return ns.tgid;
}

SEC("tracepoint/syscalls/sys_enter_getpid")
int trace_probe(void *ctx) {
    struct tp_event ev;
    __u32 key = 0, tgid;
    __u64 *slot;

    (void)ctx;
    tgid = self_match();
    if (!tgid)
        return 0;
    slot = bpf_map_lookup_elem(&count, &key);
    if (!slot)
        return 0;
    ev.seq = __sync_fetch_and_add(slot, 1);
    ev.tgid = tgid;
    ev.tag = TP_TAG;
    bpf_ringbuf_output(&events, &ev, sizeof(ev), 0);
    return 0;
}

char LMB_LICENSE[] SEC("license") = "GPL";
