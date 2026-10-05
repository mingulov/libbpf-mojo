/* Synthetic test program: emits a 16-byte record per observed getpid
 * syscall when the caller's PID matches the filter map. All other
 * activity is ignored in BPF, which keeps the native tests
 * deterministic under unrelated host load.
 *
 * PID namespaces: bpf_get_current_pid_tgid observes the initial PID
 * namespace, while a test in a container sees its own namespace IDs.
 * The filter therefore carries the test's namespace identity (keys 1
 * and 2: st_dev/st_ino of /proc/self/ns/pid) plus the wanted TGID
 * (key 0), and matching uses bpf_get_ns_current_pid_tgid so the same
 * fixture works on the host and in containers.
 *
 * Producer health is observable: test_stats counts runs, matched
 * attempts, and failed ring submissions (keys 0-2). test_pinned
 * carries pinning metadata so the bridge must actively disable it;
 * a bridge that honored pinning would fail or escape here. */
#include <linux/bpf.h>
#include <linux/types.h>

#include <bpf/bpf_helpers.h>

/* LIBBPF_PIN_BY_NAME from enum libbpf_pin_type; spelled out because the
 * host header declaring it is not consumable by the BPF target. */
#define FIXTURE_PIN_BY_NAME 1

struct test_event {
    __u32 pid;
    __u32 tag;
    __u64 tstamp;
};

struct small_event {
    __u32 pid;
    __u32 tag;
};

struct odd_val {
    __u8 b[5];
};

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
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, __u64);
} test_hash SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u64);
} test_percpu SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, __u64);
} test_lru SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, struct odd_val);
} test_odd SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, struct odd_val);
} test_percpu_odd SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 3);
    __type(key, __u32);
    __type(value, __u64);
} test_stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __uint(pinning, FIXTURE_PIN_BY_NAME);
    __type(key, __u32);
    __type(value, __u64);
} test_pinned SEC(".maps");

static __always_inline void bump(__u32 key) {
    __u64 *slot = bpf_map_lookup_elem(&test_stats, &key);
    if (slot)
        __sync_fetch_and_add(slot, 1);
}

/* Namespace-aware self match: the caller's TGID in the test's
 * namespace when it matches the filter, else 0 (never a test
 * process). Runs counted before filtering; attempts on match. */
static __always_inline __u32 self_match(void) {
    __u32 pidkey = 0, devkey = 1, inokey = 2;
    __u64 *want, *devp, *inop;
    struct bpf_pidns_info ns;

    bump(0);
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
    bump(1);
    return ns.tgid;
}

SEC("tracepoint/syscalls/sys_enter_getpid")
int on_getpid(void *ctx) {
    struct test_event ev;
    __u32 tgid;

    (void)ctx;
    tgid = self_match();
    if (!tgid)
        return 0;
    ev.pid = tgid;
    ev.tag = 0xA02u;
    ev.tstamp = bpf_ktime_get_ns();
    if (bpf_ringbuf_output(&events, &ev, sizeof(ev), 0) != 0)
        bump(2);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_getpid")
int on_getpid_small(void *ctx) {
    struct small_event ev;
    __u32 tgid;

    (void)ctx;
    tgid = self_match();
    if (!tgid)
        return 0;
    ev.pid = tgid;
    ev.tag = 0xA03u;
    if (bpf_ringbuf_output(&events, &ev, sizeof(ev), 0) != 0)
        bump(2);
    return 0;
}

char LMB_LICENSE[] SEC("license") = "GPL";
