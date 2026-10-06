<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# libbpf-mojo native ABI v1

Version: ABI major 1. Status: frozen for implementation. This document is
the authoritative contract for the C boundary; `native/include/libbpf_mojo.h`
must match it exactly, and both C static assertions and Mojo layout
assertions must verify every offset below.

Platform: x86-64 Linux, LP64, little-endian. All multi-byte integers in
memory structs use native byte order; all integers in batch frames use
explicit little-endian order.

## Functions

```c
struct lmb_session; /* opaque owner, heap allocated by lmb_open */

int32_t lmb_open(const uint8_t *elf, uint64_t elf_bytes,
                 const struct lmb_options_v1 *options,
                 struct lmb_session **out);
int32_t lmb_load(struct lmb_session *session);
int32_t lmb_attach(struct lmb_session *session,
                   const struct lmb_attach_v1 *sites, uint32_t count);
int32_t lmb_poll(struct lmb_session *session, uint8_t *dst,
                 uint32_t capacity, uint32_t *written,
                 uint32_t *required, int32_t timeout_ms);
int32_t lmb_map_info(struct lmb_session *session,
                     const struct lmb_name_v1 *name,
                     struct lmb_map_info_v1 *out);
int32_t lmb_map_read(struct lmb_session *session,
                     const struct lmb_name_v1 *name,
                     const uint8_t *key, uint32_t key_bytes,
                     uint8_t *dst, uint32_t capacity, uint32_t *required);
int32_t lmb_map_write(struct lmb_session *session,
                      const struct lmb_name_v1 *name,
                      const uint8_t *key, uint32_t key_bytes,
                      const uint8_t *value, uint32_t value_bytes);
int32_t lmb_stats(struct lmb_session *session, struct lmb_stats_v1 *out);
int32_t lmb_last_error(struct lmb_error_v1 *out);
int32_t lmb_detach(struct lmb_session *session);
int32_t lmb_close(struct lmb_session **session);
```

Every call returns 0 on success or a negative error. The sign-magnitude of
a failure return is a hint only; structured diagnostics come from
`lmb_last_error`, which preserves the operation, error domain, original
native/libbpf code, and a bounded sanitized message. Never reinterpret every
libbpf failure as a POSIX errno, and never require callers to parse strings.

## Struct header rule

Every top-level parameter struct begins with (nested `lmb_bytes_v1`
members are field layouts versioned by their enclosing struct, not
independent contracts):

| Offset | Type | Field | Value |
|---|---|---|---|
| 0 | u32 | `abi_version` | Must be 1 |
| 4 | u32 | `struct_size` | Must equal `sizeof` the struct |

A wrong version, a short struct, or a struct that fails its own size check
is refused before any other validation. Offsets below assume the header.

## Common byte string

```c
struct lmb_bytes_v1 {
    const uint8_t *ptr; /* offset 0, 8 bytes */
    uint32_t len;       /* offset 8 */
    uint32_t _pad;      /* offset 12, must be 0 */
};                      /* size 16, align 8 */
```

Inputs are pointer-plus-length, copied by the callee when retained; no input
pointer is kept. Name fields hold at most 256 bytes of strict UTF-8
(ASCII is the common case) with no embedded NUL; overlong encodings,
surrogates, and code points above U+10FFFF are refused. A null `ptr`
requires `len == 0` and means "empty".

## Options

```c
struct lmb_options_v1 {
    uint32_t abi_version;      /* 0 */
    uint32_t struct_size;      /* 4, must be 40 */
    struct lmb_bytes_v1 ring;  /* 8, ring map name, required */
    uint32_t max_raw_bytes;    /* 24, 1..4096; raw event cap */
    uint32_t stage_slots;      /* 28, must be 1 in v1 */
    uint32_t flags;            /* 32, must be 0 */
    uint32_t _reserved;        /* 36, must be 0 */
};                             /* size 40, align 8 */
```

`lmb_open` copies the ELF bytes, the options, and the ring name into owned
storage, and clears `*out` before any fallible work. One ring map per
session; one owned staging slot for a retained 4,096-byte record.

## Attach sites

```c
enum lmb_attach_kind_v1 {
    LMB_ATTACH_TRACEPOINT = 1,
    LMB_ATTACH_TRACING = 2, /* fentry/fexit-style kernel tracing */
};

struct lmb_attach_v1 {
    uint32_t abi_version;      /* 0 */
    uint32_t struct_size;      /* 4, must be 64 */
    struct lmb_bytes_v1 program; /* 8, BPF program name in the object */
    uint32_t kind;             /* 24, lmb_attach_kind_v1 */
    uint32_t flags;            /* 28, must be 0 */
    struct lmb_bytes_v1 target_a; /* 32, tracepoint: category; tracing: symbol */
    struct lmb_bytes_v1 target_b; /* 48, tracepoint: event; tracing: empty */
};                             /* size 64, align 8 */
```

`uprobe_multi` is a separate optional extension with its own capability and
test; it is not part of v1 attach. Attach is one explicit transaction per
loaded session: all required sites attach, or every link created by that
call is destroyed and the call fails. No implicit autoload, autoattach,
dynamic plugin loading, or persistent pinning.

Kernel tracing programs must declare their attach target in the ELF
object (the usual section-name convention); `lmb_attach` verifies that
`target_a` matches the ELF-declared target and fails the transaction on
mismatch. Targets cannot be supplied at attach time because the pinned
libbpf rejects target assignment on an already loaded object. Tracepoint
attachments resolve `target_a`/`target_b` as category/event at attach
time and need no pre-load target.

## Map access

```c
struct lmb_name_v1 {
    uint32_t abi_version;   /* 0 */
    uint32_t struct_size;   /* 4, must be 24 */
    struct lmb_bytes_v1 name; /* 8, map name, max 256 bytes */
};                          /* size 24, align 8 */

struct lmb_map_info_v1 {
    uint32_t abi_version;   /* 0 */
    uint32_t struct_size;   /* 4, must be 40 */
    uint32_t type;          /* 8, BPF map type id */
    uint32_t key_size;      /* 12 */
    uint32_t value_size;    /* 16 */
    uint32_t max_entries;   /* 20 */
    uint32_t map_flags;     /* 24 */
    uint32_t num_cpus;      /* 28, valid for per-CPU maps */
    uint32_t stride;        /* 32, per-CPU padded value stride, else 0 */
    uint32_t _reserved;     /* 36, must be 0 */
};                          /* size 40, align 4 */
```

Map type, key/value sizes, per-CPU stride and CPU count are queried and
checked before every access. Unsupported map operations return a typed
error. A sequence of map reads is not an atomic cross-CPU snapshot.

Per-CPU maps are hash, array, LRU hash, and cgroup storage; every other
map type uses ordinary single-value sizing. A null map name is refused
with `-EINVAL` before any lookup.

Exact map rules: `key_bytes` must equal the map's `key_size`, otherwise
the call fails without access. For writes, `value_bytes` must equal
`value_size` (ordinary maps) or `stride * num_cpus` (per-CPU maps).
`stride` is `round_up(value_size, 8)`; the product
`stride * num_cpus` is checked for `u32` overflow and the call fails
with a `BRIDGE` diagnostic when it cannot fit. A failed possible-CPU
query fails with a `LIBBPF` diagnostic carrying the original code,
never disguised as overflow. Reads need capacity for one value
(`value_size`) or one per-CPU spread (`stride * num_cpus`); a short
destination returns `-ENOSPC` with `required` set, nothing written,
and the thread-local record replaced with the
`MAP_READ`/`BRIDGE`/`-ENOSPC` diagnostic. `num_cpus` is the
possible-CPU count observed when the map was queried.

`lmb_map_read` reports `required` like `lmb_poll`: a short destination
returns `-ENOSPC` with `required` set and nothing written. On any other
failure `required` is 0 once arguments validate; the
argument-validation path itself leaves outputs untouched. Output
aliasing is forbidden:
the `required` cell must lie outside `[key, key+key_bytes)` and
`[dst, dst+capacity)`; aliased outputs are refused with `-EINVAL`
before anything is written.

## Batch framing

One raw event is at most 4,096 bytes. A bridge frame is:

| Offset | Type | Field |
|---|---|---|
| 0 | u32 LE | payload length in bytes |
| 4 | u16 LE | framing version, must be 1 |
| 6 | u16 LE | reserved, must be 0 |
| 8 | bytes | exactly payload-length bytes |

No native padding. Maximum total frame is 4,104 bytes. A 16-byte payload
requires a 24-byte frame.

## Poll semantics

One staging slot means one frame per call: `lmb_poll` delivers at most
one framed record, and the retained record is always the staged one. A
caller drains pending records with repeated calls.

- Timeout yields success with `written == 0` and `required == 0`.
- When a staged next frame cannot fit and nothing has been copied, return
  `-ENOSPC` with `written == 0`, `required` equal to the whole-frame
  length, retain the record, and replace the thread-local record with
  the `POLL`/`BRIDGE`/`-ENOSPC` diagnostic. A later retry delivers it
  exactly once.
- A negative libbpf ring-callback return consumes the borrowed record, so
  retention requires a bridge-owned copy made before returning. Each
  libbpf consumption step takes at most one record.
- One call consumes records until one stages, the ring drains, or 64
  records have been skipped, whichever comes first: malformed records
  never surface as errors and never stall a call while a stageable
  record is already queued. Returning `0/0` therefore means no
  deliverable frame was found in this call, not that the ring stayed
  empty; the caller retries. The skip bound keeps one call finite
  under a malformed flood.
- On success `required` is always 0; the caller learns a retained
  record's size from the next call.
- Malformed records are skipped and counted in `stats.malformed`; they
  never fail a call that also stages a valid record. Empty and
  oversized records count as malformed: an empty record cannot be
  staged because a zero stage length reads back as no record, so it
  is declared malformed to keep the conservation identity exact. A
  valid record lost because the single slot was already occupied
  counts as `dropped` (unavoidable capacity loss), never as
  malformed.
- Transport errors return directly with nothing copied: fallible work
  (waiting, consumption) always precedes the frame copy, so a
  partial-copy-then-error outcome is impossible. Errors latch
  `stats.last_error` and replace the thread-local record.
- Output aliasing is forbidden: `written` and `required` must be
  distinct cells, and both must lie outside `[dst, dst+capacity)`.
  Aliased outputs are refused with `-EINVAL` before anything is
  written. Argument-validation failures leave all outputs untouched;
  later failures report `written == 0` with `required` as documented
  per case.

`timeout_ms` is 0 for non-blocking, positive for a bounded wait, and -1 for
an unbounded wait subject to signal interruption. Interrupted waits report
`-EINTR` with `written == 0` and `required == 0`, distinctly from
timeout. A bounded wait that wakes to malformed-only records returns
`0/0` without re-waiting the remainder; the caller retries with a fresh
timeout.

## Statistics

```c
struct lmb_stats_v1 {
    uint32_t abi_version; /* 0 */
    uint32_t struct_size; /* 4, must be 56 */
    uint64_t received;    /* 8 */
    uint64_t delivered;   /* 16 */
    uint64_t staged;      /* 24, currently held (0 or 1 in v1) */
    uint64_t malformed;   /* 32 */
    uint64_t dropped;     /* 40, explicitly declared drops only */
    int32_t last_error;   /* 48, terminal native error or 0 */
    uint32_t _reserved;   /* 52, must be 0 */
};                        /* size 56, align 8 */
```

Bridge counters stay separate from any application BPF counters.
`malformed` and `dropped` are disjoint: empty, oversized, or
unparseable records count as `malformed`, while valid records lost to
transport overrun or unavoidable capacity (including a valid record
that arrives while the single slot is occupied) count as `dropped`.
Under a test source,
`received == delivered + staged + malformed + dropped`. Silent loss is
never reported as timeout.

`last_error` latches the most recent native failure code on the
session, or 0 when no native operation has failed. Usage errors,
interrupted waits, and successes never change it; per-call diagnosis
always comes from the thread-local record instead.

## Errors

```c
enum lmb_op_v1 {
    LMB_OP_NONE = 0,
    LMB_OP_OPEN = 1, LMB_OP_LOAD = 2, LMB_OP_ATTACH = 3,
    LMB_OP_POLL = 4, LMB_OP_MAP_INFO = 5, LMB_OP_MAP_READ = 6,
    LMB_OP_MAP_WRITE = 7, LMB_OP_STATS = 8, LMB_OP_DETACH = 9,
    LMB_OP_CLOSE = 10,
};

enum lmb_domain_v1 {
    LMB_DOMAIN_NONE = 0,
    LMB_DOMAIN_POSIX = 1,
    LMB_DOMAIN_LIBBPF = 2,
    LMB_DOMAIN_KERNEL = 3,
    LMB_DOMAIN_BRIDGE = 4, /* usage errors: bad version, size, args */
};

struct lmb_error_v1 {
    uint32_t abi_version;  /* 0 */
    uint32_t struct_size;  /* 4, must be 1048 */
    uint32_t operation;    /* 8, lmb_op_v1 */
    uint32_t domain;       /* 12, lmb_domain_v1 */
    int32_t code;          /* 16, original signed native code */
    uint32_t msg_len;      /* 20, bytes used in message */
    uint8_t message[1024]; /* 24, sanitized, no object contents */
};                         /* size 1048, align 4 */
```

`lmb_last_error` copies a thread-local record, including failed-open
diagnostics when no session exists. It does not clear the record; the next
failing operation replaces it. Every nonzero return replaces the record,
including `-ENOSPC` capacity signals; only inspection calls with an
invalid output header are exempt. The caller reads it immediately on the
same calling thread. One calling thread owns a handle initially.

Domains name the failing call layer: direct libc/syscall failures are
`POSIX`, libbpf API failures (including syscalls libbpf makes
internally) are `LIBBPF`, direct BPF syscalls through `<bpf/bpf.h>`
are `KERNEL`, and bridge validation/capacity decisions are `BRIDGE`.
The original signed code is always preserved; `-ENOSPC` from bridge
capacity checks reports domain `BRIDGE`.

An inspection call with an invalid output header fails without replacing
the stored record; inspection failures have no operation discriminant of
their own. The initial record before any failure is all zeros (operation
`NONE`, domain `NONE`, code 0, empty message). `msg_len` is at most 1023;
`message[msg_len]` is always NUL, and longer messages are byte-truncated
to fit.

## Lifecycle

- `lmb_detach` destroys every attachment link and reports the first
  teardown error, if any, after releasing all of them; success is
  resource evidence, not proof of application-level measurement
  quiescence. A detached session may attach again.
- `lmb_close` destroys owned objects, links, maps, ring consumers, and
  staged state, nulls the caller's handle, and tolerates an already-null
  pointee. Partial load/attach failures roll back only this handle's
  resources. Close releases everything even when a teardown step
  fails, then reports the first teardown error.
- `lmb_load` prepares every program in the object; no program executes
  until an explicit `lmb_attach`. Map pin metadata in the object is
  disabled before loading: the bridge never creates, reuses, or
  leaves behind filesystem pins.
- The dynamic library exports only the eleven `lmb_*` operations; the
  bundled libbpf and all bridge internals stay local. It outlives all
  owners and foreign callables. Signal handlers set a flag; ordinary
  control flow performs teardown. The bridge silences its private
  libbpf log channel; diagnostics flow only through the sanitized
  thread-local record and `stats.last_error`.

## Compatibility and versioning

ABI major 1 is independent of batch framing version 1, BPF payload
versions, and any consumer schema version. A wire or layout change requires
new decoder/layout fixtures and matched packaging. Source compatibility and
runtime ABI compatibility are documented separately when v2 is proposed.

## Native build driver

The native library and tests must build with CMake plus Ninja, invoked
only through `tools/build` (single supported path). Pinned versions live
in `toolchain.lock.json`. The implementation must build libbpf from the
pinned source tarball recorded there and verify the hash before use. No
native targets exist yet.
