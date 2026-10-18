<!-- SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception -->
# libbpf-mojo generic ABI v1

Version: generic ABI 1. Status: frozen for implementation. This
document is the authoritative contract for the generic
object/link/buffer boundary;
`native/include/libbpf_mojo_generic.h` must match it exactly, and
both C static assertions and Mojo layout assertions must verify
every offset below. `docs/abi-v1.md` remains the authoritative
contract for the v1 session surface and is unchanged by this
interface.

Platform: x86-64 Linux, LP64, little-endian. All multi-byte
integers in memory structs use native byte order; all integers in
batch frames use explicit little-endian order. AArch64 layout
equivalence is not established: x86-64 layout evidence does not
qualify other architectures, which need their own hardware probes.

## Compatibility baseline

The v1 session API keeps its signatures, discriminants, field
offsets, and error rules. The shared library keeps SONAME
`libbpf_mojo.so.1` and the `LIBBPF_MOJO_1` node with exactly the
eleven original operations: `lmb_open`, `lmb_load`, `lmb_attach`,
`lmb_poll`, `lmb_map_info`, `lmb_map_read`, `lmb_map_write`,
`lmb_stats`, `lmb_last_error`, `lmb_detach`, `lmb_close`. Generic
entry points live in the additive `LIBBPF_MOJO_GENERIC_1` node and
are never mandatory for v1 consumers: resolving and calling the
eleven v1 operations must succeed on a library with no generic
symbols at all, and the Mojo `NativeLib` loader still requires
exactly those eleven.

Program/map names and map geometry reuse the v1 structs
(`struct lmb_name_v1`, `struct lmb_map_info_v1`) unchanged; the
generic header includes the v1 header rather than redeclaring
them. Nothing in this interface reinterprets ABI v1.

The frozen old-consumer record is `tests/native/abi_v1_frozen.h`
(byte-identical to the v1 header at library commit `6289c15`,
except its provenance comment and renamed guard) with the
`tests/native/old_consumer_v1.c` fixture, which includes only the
frozen header, links the candidate library, and exercises all
eleven operations unprivileged. The first-consumer package pin
(library commit `e50a4b6`) carries byte-identical ABI v1 bytes;
both identities stay usable. The v1 Mojo wrapper behavior record
is the existing suite: move-only `Session`, close/destructor
composition without double-free, structured error preservation
across success, eighteen session tests plus the error, batch, and
layout suites, four move/borrow compile-fail cases, and one
compile-pass transfer case. Fixtures must stay forward
compatible: they never assert the absence of allowlisted generic
symbols, so they keep passing as the implementation lands.

## Functions

```c
struct lmb_object; /* opaque owner, heap allocated by object_open */
struct lmb_link;   /* opaque attach owner */
struct lmb_buffer; /* opaque ring-buffer owner */

int32_t lmb_object_open_v1(const uint8_t *elf, uint64_t elf_bytes,
    const struct lmb_object_options_v1 *opts,
    struct lmb_object **out);
int32_t lmb_object_configure_program_v1(struct lmb_object *object,
    const struct lmb_program_options_v1 *opts);
int32_t lmb_object_load_v1(struct lmb_object *object);
int32_t lmb_object_program_info_v1(struct lmb_object *object,
    const struct lmb_name_v1 *name, struct lmb_program_info_v1 *out);
int32_t lmb_object_map_info_v1(struct lmb_object *object,
    const struct lmb_name_v1 *name, struct lmb_map_info_v1 *out);
int32_t lmb_object_close_v1(struct lmb_object **object);
void lmb_object_release_v1(struct lmb_object **object);
int32_t lmb_generic_last_error_v1(struct lmb_generic_error_v1 *out);
int32_t lmb_object_map_lookup_v1(struct lmb_object *object,
    const struct lmb_name_v1 *name, const uint8_t *key,
    uint64_t key_bytes, uint8_t *value, uint64_t capacity,
    uint64_t *needed);
int32_t lmb_object_map_update_v1(struct lmb_object *object,
    const struct lmb_name_v1 *name, const uint8_t *key,
    uint64_t key_bytes, const uint8_t *value, uint64_t value_bytes,
    uint64_t flags);
/* Optional additions; the original twenty-name generic set is unchanged. */
int32_t lmb_object_map_delete_v1(
    struct lmb_object *object, const struct lmb_name_v1 *name,
    const uint8_t *key, uint64_t key_bytes, uint64_t flags);
int32_t lmb_object_map_next_key_v1(
    struct lmb_object *object, const struct lmb_name_v1 *name,
    uint32_t has_current, const uint8_t *current, uint64_t current_bytes,
    uint8_t *next, uint64_t capacity, uint64_t *needed);
int32_t lmb_program_test_run_v1(struct lmb_object *object,
    const struct lmb_name_v1 *program,
    const struct lmb_program_test_options_v1 *opts,
    struct lmb_program_test_result_v1 *out);
int32_t lmb_object_attach_v1(struct lmb_object *object,
    const struct lmb_attach_options_v1 *opts, struct lmb_link **out);
int32_t lmb_link_close_v1(struct lmb_link **link);
int32_t lmb_buffer_open_v1(struct lmb_object *object,
    const struct lmb_buffer_options_v1 *opts,
    struct lmb_buffer **out);
int32_t lmb_buffer_poll_v1(struct lmb_buffer *buffer, uint8_t *dst,
    uint64_t capacity, int32_t timeout_ms, uint64_t *used,
    uint64_t *needed);
int32_t lmb_buffer_close_v1(struct lmb_buffer **buffer);
/* Optional per-buffer stats snapshot; the original twenty-name set is unchanged. */
int32_t lmb_buffer_stats_v1(struct lmb_buffer *buffer,
    struct lmb_buffer_stats_v1 *out);
int32_t lmb_object_ref_v1(struct lmb_object *object);
void lmb_object_unref_v1(struct lmb_object *object);
int32_t lmb_object_gen_v1(const struct lmb_object *object,
    uint64_t *generation);
int32_t lmb_object_gen_check_v1(const struct lmb_object *object,
    uint64_t expected);
```

Every call except `lmb_object_release_v1` and
`lmb_object_unref_v1` returns 0 on success or a negative error;
the two destructor-path calls return `void`. The sign-magnitude
of a failure return is a hint only; structured diagnostics come
from `lmb_generic_last_error_v1`, which preserves the operation,
error domain, original signed native code, and a bounded
sanitized message. Never reinterpret failures as POSIX errno,
and never require callers to parse strings.

## Struct header rule

Every top-level parameter struct begins with (nested span members
are field layouts versioned by their enclosing struct, not
independent contracts):

| Offset | Type | Field | Value |
|---|---|---|---|
| 0 | u32 | `abi_version` | Must be 1 |
| 4 | u32 | `struct_size` | Must equal `sizeof` the struct |

A wrong version or a struct that fails its own size check is
refused before any other validation. Short and oversized structs
both fail: `struct_size` must equal the frozen size exactly.

## Common spans

```c
struct lmb_span_v1 {
    const uint8_t *ptr; /* offset 0, 8 bytes */
    uint64_t len;       /* offset 8 */
};                      /* size 16, align 8 */

struct lmb_out_span_v1 {
    uint8_t *ptr;       /* offset 0, 8 bytes */
    uint64_t len;       /* offset 8 */
};                      /* size 16, align 8 */
```

Input spans are copied when retained and borrowed only for the
call otherwise; output spans are caller-owned mutable storage
written only during the call. Length-zero spans ignore their
pointer (it may be null or not); nonzero lengths require a
non-null pointer. Lengths are `uint64_t` with checked conversion
to `size_t` before use; on LP64 x86-64 the conversion is total,
and the check still applies wherever `size_t` is narrower.

Name spans (object, program, map, ring, attach targets) hold at
most 256 bytes of strict UTF-8 with no embedded NUL, exactly as
v1 names. The custom-BTF span is instead a raw path of at most
4096 bytes with no embedded NUL: paths are OS bytes, not text.

## Object options

```c
struct lmb_object_options_v1 {
    uint32_t abi_version;       /* 0 */
    uint32_t struct_size;       /* 4, must be 64 */
    struct lmb_span_v1 name;    /* 8, object name, copied */
    struct lmb_span_v1 custom_btf; /* 24, BTF path, copied */
    uint32_t log_level;         /* 40, 0 discard, 1 on failure, 2 always */
    uint32_t flags;             /* 44, must be 0 */
    uint64_t log_capacity;      /* 48, per-program log cap, 0 none */
    uint64_t _reserved;         /* 56, must be 0 */
};                              /* size 64, align 8 */
```

`lmb_object_open_v1` copies the ELF bytes, the options, the object
name, and the BTF path into owned storage, parses the object
eagerly, and clears `*out` before any fallible work. An empty
name selects the upstream default; an empty BTF path selects
normal kernel BTF discovery. `log_level` selects verifier-log
retention (0 discards, 1 retains failing programs, 2 retains
every load attempt); `log_capacity` bounds each per-program
retained log to `1..1048576` bytes, with 0 meaning no per-program
buffers. The kernel-facing working buffer is a fixed 1048576
bytes per program: the kernel fails the load when its running
verifier log outgrows the working buffer, even on loads whose
retained summary is short, so a small retention bound never
fails the load by itself. Retention keeps the first
`log_capacity` bytes of what the kernel wrote. A level above 0
with capacity 0 attempts verbose loads
but retains nothing. Garbage ELF fails here with a signed libbpf
code, not at load: unlike v1 open (which copies without
parsing), generic open must parse so that pre-load configuration
can name programs.

## Program options

```c
struct lmb_program_options_v1 {
    uint32_t abi_version;        /* 0 */
    uint32_t struct_size;        /* 4, must be 48 */
    struct lmb_span_v1 program;  /* 8, program name, required */
    struct lmb_span_v1 attach_target; /* 24, tracing symbol or empty */
    uint32_t autoload;           /* 40, 0 unchanged, 1 enable, 2 disable */
    uint32_t flags;              /* 44, must be 0 */
};                               /* size 48, align 8 */
```

Configuration runs before load only; after load every configure
call fails. `program` must name a program in the object. A
non-empty `attach_target` is a strict UTF-8 symbol applied
through the pinned pre-load attach-target API; it is rejected on
program types that do not accept one, and it must equal the
ELF-declared target suffix when the section declares one (no
silent override). Each successful configure bumps the object
generation by one; repeated configures are last-wins per field.

## Program info

```c
struct lmb_program_info_v1 {
    uint32_t abi_version;     /* 0 */
    uint32_t struct_size;     /* 4, must be 72 */
    uint32_t prog_type;       /* 8, BPF program type id */
    uint32_t attach_type;     /* 12, expected attach type id */
    uint64_t insn_count;      /* 16, instructions in current state */
    uint64_t generation;      /* 24, object config generation */
    uint32_t autoload;        /* 32, 0 disabled, 1 enabled */
    uint32_t _pad0;           /* 36, zeroed output */
    struct lmb_out_span_v1 log; /* 40, caller log storage */
    uint64_t log_actual;      /* 56, full retained log bytes */
    uint32_t log_truncated;   /* 64, 0 or 1 */
    uint32_t _reserved;       /* 68, zeroed output */
};                            /* size 72, align 8 */
```

The caller fills the header and the `log` span; every other field
is an output. The implementation validates, then memsets the
whole struct before filling it, so pads and reserved fields read
back zero and no uninitialized bytes leak. Info works on opened
objects before and after load: metadata reflects current object
state, and the log fields reflect the most recent load attempt
(zero when none ran). The call copies `min(log_actual, log.len)`
bytes; `log_truncated` is 1 exactly when `log_actual` exceeds the
provided storage. `generation` exposes the object config
generation for owner-bound view validation (see below).

## Map info

Generic map introspection reuses `struct lmb_map_info_v1`
unchanged (size 40, align 4; see `docs/abi-v1.md`): type,
key/value sizes, max entries, map flags, per-CPU count and
stride. Like v1, it is load-gated: unloaded objects report
`-EINVAL`.

## Error record

```c
enum lmb_generic_op_v1 {
    LMB_GENERIC_OP_NONE = 0,
    LMB_GENERIC_OP_OBJECT_OPEN = 1,
    LMB_GENERIC_OP_PROGRAM_CONFIGURE = 2,
    LMB_GENERIC_OP_OBJECT_LOAD = 3,
    LMB_GENERIC_OP_PROGRAM_INFO = 4,
    LMB_GENERIC_OP_MAP_INFO = 5,
    LMB_GENERIC_OP_OBJECT_CLOSE = 6,
    LMB_GENERIC_OP_MAP_LOOKUP = 7,
    LMB_GENERIC_OP_MAP_UPDATE = 8,
    LMB_GENERIC_OP_TEST_RUN = 9,
    LMB_GENERIC_OP_ATTACH = 10,
    LMB_GENERIC_OP_LINK_CLOSE = 11,
    LMB_GENERIC_OP_BUFFER_OPEN = 12,
    LMB_GENERIC_OP_BUFFER_POLL = 13,
    LMB_GENERIC_OP_BUFFER_CLOSE = 14,
    LMB_GENERIC_OP_VIEW_REF = 15,
    LMB_GENERIC_OP_VIEW_GEN = 16,
    LMB_GENERIC_OP_VIEW_CHECK = 17,
    LMB_GENERIC_OP_MAP_DELETE = 18,
    LMB_GENERIC_OP_MAP_NEXT_KEY = 19,
    LMB_GENERIC_OP_BUFFER_STATS = 20,
};

enum lmb_generic_domain_v1 {
    LMB_GENERIC_DOMAIN_NONE = 0,
    LMB_GENERIC_DOMAIN_POSIX = 1,
    LMB_GENERIC_DOMAIN_LIBBPF = 2,
    LMB_GENERIC_DOMAIN_KERNEL = 3,
    LMB_GENERIC_DOMAIN_BRIDGE = 4,
};

struct lmb_generic_error_v1 {
    uint32_t abi_version;  /* 0 */
    uint32_t struct_size;  /* 4, must be 1048 */
    uint32_t operation;    /* 8, lmb_generic_op_v1 */
    uint32_t domain;       /* 12, lmb_generic_domain_v1 */
    int32_t code;          /* 16, original signed native code */
    uint32_t msg_len;      /* 20, bytes used in message */
    uint8_t message[1024]; /* 24, sanitized, fully zero-tailed */
};                         /* size 1048, align 4 */
```

Domains name the failing call layer with the same values as v1:
direct libc/syscall failures are `POSIX`, libbpf API failures
(including syscalls libbpf makes internally) are `LIBBPF`, direct
BPF syscalls through `<bpf/bpf.h>` are `KERNEL`, and bridge
validation/capacity decisions are `BRIDGE`. The original signed
code is always preserved. The record lives in thread-local
storage separate from the v1 record: failing a v1 call never
clobbers the generic record and vice versa.

Two rules differ deliberately from v1. First, every successful
generic operation clears the current generic record to all
zeros, while v1 preserves its record across success. Second, the
generic message is fully zero-tailed (`message[msg_len..1023]`
are zero), while v1 guarantees only the terminator. Inspection
with an invalid output header fails without replacing the stored
record; retrieval otherwise preserves it. Failed-open
diagnostics are retrievable with no object.

## Test-run options and result

```c
struct lmb_program_test_options_v1 {
    uint32_t abi_version;         /* 0 */
    uint32_t struct_size;         /* 4, must be 88 */
    struct lmb_span_v1 data_in;   /* 8, copied packet input */
    struct lmb_out_span_v1 data_out; /* 24, borrowed packet output */
    struct lmb_span_v1 ctx_in;    /* 40, copied context input */
    struct lmb_out_span_v1 ctx_out;  /* 56, borrowed context output */
    uint64_t repeat;              /* 72, 1..2147483647 */
    uint64_t flags;               /* 80, must be 0 */
};                                /* size 88, align 8 */

struct lmb_program_test_result_v1 {
    uint32_t abi_version; /* 0 */
    uint32_t struct_size; /* 4, must be 40 */
    uint32_t retval;      /* 8, program return value */
    uint32_t _pad;        /* 12, zeroed output */
    uint64_t data_actual; /* 16, output packet bytes */
    uint64_t ctx_actual;  /* 24, output context bytes */
    uint64_t duration_ns; /* 32, average ns per repetition */
};                        /* size 40, align 8 */
```

Each of the four buffers is bounded to 1048576 bytes. Inputs are
copied into bridge-owned snapshots before the native call. Both
inputs and the required option/name values are captured before
any output commit, so inputs may alias either output or the
result record. Outputs are caller-owned and borrowed only for
the call. Both nonempty output spans must be disjoint from each
other and from the complete result record; overlap returns
`BRIDGE`/`-EINVAL` before native work. Adjacent intervals are
legal. Nothing is retained past return. `repeat` is
conversion-checked to the upstream signed range.

Zero-length spans ignore their supplied pointer and forward
null/zero. An omitted output requests no copy. On success,
`data_actual` and `ctx_actual` report the native returned lengths,
including for omitted outputs; a nonzero omitted-output length
does not mean bytes were copied. Each nonempty output receives
exactly its returned actual extent, with its tail untouched. If
native success reports an actual size beyond a nonempty output's
capacity, return `BRIDGE`/`-EOVERFLOW` and leave both outputs and
the result unchanged. Omitted outputs do not undergo that
capacity check. Do not clamp lengths or retry the operation.

The initial result profile supports `BPF_PROG_TYPE_XDP`, with
flags zero. After ordinary input, loaded-owner and named-program
validation, other program types return `BRIDGE`/`-EOPNOTSUPP`
without execution. Broader program types and options require
their own native field-validity evidence.

The result is all-or-nothing: on success all four fields are
valid (`retval`, both actual lengths, and duration independently).
On any failure, both caller outputs and the complete result
record remain unchanged, even if native code wrote partial
scratch outputs or result fields. Native failure retains its
original signed code in `KERNEL`. Execute exactly one native
test-run call; never silently retry EINTR, ENOSPC or another
error. This caller-output guarantee does not undo kernel side
effects. The bridge uses separate scratch outputs and a local
result, zero-initializes the complete pinned native options with
`sz`, and leaves unsupported fields such as cpu and batch zero.

## Attach options

```c
enum lmb_attach_family_v1 {
    LMB_ATTACH_FAMILY_TRACEPOINT = 1,
};

struct lmb_attach_options_v1 {
    uint32_t abi_version;        /* 0 */
    uint32_t struct_size;        /* 4, must be 72 */
    struct lmb_span_v1 program;  /* 8, BPF program name, required */
    uint32_t family;             /* 24, lmb_attach_family_v1 */
    uint32_t flags;              /* 28, must be 0 */
    struct lmb_span_v1 target_a; /* 32, tracepoint category */
    struct lmb_span_v1 target_b; /* 48, tracepoint event */
    uint64_t _reserved;          /* 64, must be 0 */
};                               /* size 72, align 8 */
```

One call attaches one site and produces one link. Only family 1 (tracepoint)
is valid. Unknown families, nonzero flags and nonzero reserved fields return
BRIDGE/-EINVAL before native work. Category and event are required strict
UTF-8 names; the bridge copies them before the upstream call. After ordinary
argument validation, a loaded object and the named program are required. A
missing program returns BRIDGE/-ENOENT. A program whose type is not
BPF_PROG_TYPE_TRACEPOINT returns BRIDGE/-EOPNOTSUPP without attachment. A
tracepoint program without a loaded program FD returns BRIDGE/-EINVAL. A
valid request calls bpf_program__attach_tracepoint with the explicitly
supplied category and event. The output link is cleared before validation
and stays null on failure. Pre-load tracing-target configuration remains an
object capability; this interface has no tracing, LSM or extension attach
family. Their attachment and target qualification require separately
specified interfaces and tests.

## Buffer options

```c
struct lmb_buffer_options_v1 {
    uint32_t abi_version;      /* 0 */
    uint32_t struct_size;      /* 4, must be 40 */
    struct lmb_span_v1 ring;   /* 8, ring map name, required */
    uint32_t max_raw_bytes;    /* 24, 1..4096 */
    uint32_t stage_slots;      /* 28, must be 1 */
    uint32_t flags;            /* 32, must be 0 */
    uint32_t _reserved;        /* 36, must be 0 */
};                             /* size 40, align 8 */
```

One ring map per buffer; one owned staging slot for a retained
4096-byte record. Opening requires a loaded object whose maps
include the named ring. No ring is required to open or load a
generic object.

## Buffer statistics

```c
struct lmb_buffer_stats_v1 {
    uint32_t abi_version; /* 0 */
    uint32_t struct_size; /* 4, must be 48 */
    uint64_t received;    /* 8 */
    uint64_t delivered;   /* 16 */
    uint64_t staged;      /* 24, currently held (0 or 1) */
    uint64_t malformed;   /* 32 */
    uint64_t dropped;     /* 40, explicitly declared drops only */
};                        /* size 48, align 8 */
```

`lmb_buffer_stats_v1` snapshots one buffer's transport
counters without consuming a record. Counter meanings match
the `buffer_poll` conservation identity: `received` counts
callback-seen records, `delivered` counts framed records
handed to the caller, `staged` is 1 exactly while a record is
retained, `malformed` counts empty and oversized records, and
`dropped` counts valid records lost to the occupied slot.
`received == delivered + staged + malformed + dropped` holds
after every call. The snapshot is read-only: it changes no
counter, disturbs no staged record, and reports identical
bytes when called twice with no poll in between.

The caller sets the header (`abi_version` 1, `struct_size`
48); success preserves the header and fills the five
counters. A null buffer, a null output, or a header that
fails its own size check reports `BRIDGE`/`-EINVAL` with
operation `BUFFER_STATS` and leaves the output struct
unchanged. Success clears the generic diagnostic record,
like every other generic success.

Unlike the v1 session snapshot, this record carries no
latched native error: native failures surface only through
the per-call generic diagnostic, never through a sticky
counter. The snapshot stays available while the buffer is
open, including with a staged record, under a `BUSY`
parent, and after parent release while the buffer's own
reference is alive.

## Ownership and lifetime

`lmb_object_close_v1` is the explicit close: with live
children or views it returns `-EBUSY` and preserves the non-null,
usable owner handle; with no children it releases everything
exactly once, nulls the caller's handle, and reports the first
teardown error or 0. A null argument fails; a null pointee
succeeds trivially (and, like every success, clears the generic
record). `lmb_object_release_v1` is the infallible destructor
path: it nulls the caller's handle and drops the external
reference even with live children, each of which retains its own
native and library references; the last release performs native
destruction exactly once. A moved-from or null owner release is
a no-op. Link and buffer closes detach and free their own
resource, drop their object reference, null the handle, then
report the first teardown error; null pointees succeed
trivially. Partial load/attach failures roll back only the
calling handle's resources.

`ProgramView` and `MapView` are retained owner-bound views,
not free pointers: each view holds one native object reference
(acquired with `lmb_object_ref_v1`, released with
`lmb_object_unref_v1`) and retains the library handle at the
Mojo layer, so the native state and the library provably
outlive every view. A view survives owner moves and parent
release: moving the Mojo owner transfers only the external
handle, and releasing the parent only drops the external
reference while views keep the native state alive. Views
capture the object configuration generation at creation (with
`lmb_object_gen_v1`) and re-check it before operations (with
`lmb_object_gen_check_v1`); a view whose generation no longer
matches fails with domain `BRIDGE` and `-ESTALE` (116 on
Linux) without touching the operation outputs. View
references count exactly like children for explicit-close
`BUSY` and for last-release destruction: with live views,
explicit close returns `-EBUSY` and preserves the usable
owner; the last release of any kind (external, child, or
view) performs native destruction exactly once. Map geometry
never changes after open, so map views additionally gate on
load state (map operations on an unloaded object report
`-EINVAL`). All owners remain single-threaded until a
separately tested concurrency contract exists.

The dynamic library outlives all owners and foreign callables:
Mojo owners destroy native state before dropping their library
handle. Signal handlers set a flag; ordinary control flow
performs teardown. Exactly one bridge instance exists per
process: consumers load the bridge from one path, and handles
never cross instances.

## Validation order

Every operation validates in this order, before any native
call: output-handle cells, struct headers, spans and names
(lengths, null rules, UTF-8, padding), enums, flags, and
reserved fields, integer conversions and overflow, output
aliasing, object state (configured/loaded), named-entity
lookup, then the native call. Handle-producing calls clear
their output slot first, even before header validation, so a
failed call always leaves a null handle on a valid argument;
callers still must not pass an occupied slot, to avoid
leaking the previous handle.

Validation failures leave non-handle buffers and result
structs unchanged, except explicitly documented size outputs
(which are never produced on the validation path itself: a
rejected call writes nothing but the cleared handle and the
diagnostic record). Runtime failures expose only fields the
pinned native contract guarantees valid. The view operations
take no structs: they validate their object pointer and
output cell before any state access, in the same
pointers-before-state position.

## Per-operation failure-output tables

- `object_open`: `*out` cleared first, null on failure. No
  other outputs. Parse failures report `LIBBPF` with the
  signed upstream code.
- `configure_program`: no outputs; the object and its
  generation are unchanged on failure. Unknown programs
  report `BRIDGE`/`-ENOENT`; post-load calls report
  `BRIDGE`/`-EINVAL`.
- `object_load`: no outputs; the object stays usable for
  info and close. Second loads report `BRIDGE`/`-EINVAL`.
  Loading never attaches and never requires a ring.
- `program_info`: caller header plus `log` span are inputs;
  validation failure leaves the whole struct unchanged.
  Success overwrites every field (pads and reserved read
  zero). Log bytes copied are `min(log_actual, log.len)`.
- `map_info`: v1 geometry rules; validation failure leaves
  the struct unchanged. Unloaded objects report
  `BRIDGE`/`-EINVAL`.
- `object_close`: BUSY preserves the handle and reports
  `BRIDGE`/`-EBUSY`; otherwise frees everything, nulls the
  handle, and reports the first teardown error or 0.
- `object_release`: infallible; always nulls a valid
  argument. No diagnostic record is written.
- `generic_last_error`: invalid headers fail without
  touching the stored record; success copies it fully and
  preserves it.
- `map_lookup`: `needed` untouched on validation failure,
  0 on post-validation failure except `-ENOSPC` (where it
  carries the required length and the destination is
  untouched). Values copy exactly the required bytes:
  `value_size`, or `stride * num_cpus` for per-CPU maps.
  Spread overflow reports `BRIDGE`/`-EOVERFLOW`; a failed
  CPU-count query reports `LIBBPF` with the original code,
  never disguised as overflow. Kernel misses report
  `KERNEL` with the signed code and leave the destination
  untouched. Bloom filters report `BRIDGE`/`-EOPNOTSUPP`
  before extent math, allocation, or the native call, with
  `needed` 0 and the destination untouched: a bloom value
  is membership input, not an output value. Insertion keeps
  the update path.
- `map_update`: no outputs. Flags must carry low two bits
  of `0` (`ANY`), `1` (`NOEXIST`), or `2` (`EXIST`) with
  only bit 2 (`LOCK`, 4) additionally permitted; all other
  bits are rejected before the native call. Sizes must
  match exactly (single value or full per-CPU spread).
  Kernel refusals report `KERNEL` with the signed code.
- `test_run`: result and both outputs unchanged on any failure.
  Each nonempty output receives exactly its native actual extent
  on success; omitted outputs request no copy but retain native
  actual lengths. Nonempty outputs must be disjoint from each
  other and the complete result; adjacent intervals and input
  aliases are legal. Oversized native success is
  `BRIDGE`/`-EOVERFLOW`; native failure preserves its signed
  `KERNEL` code. One native call, no retry or kernel rollback.
  The initial profile is XDP; other validated program types
  return `BRIDGE`/`-EOPNOTSUPP` without execution.
- `object_attach`: `*out` cleared first, null on failure,
  no links leaked. Unknown programs report
  `BRIDGE`/`-ENOENT`.
- `link_close`, `buffer_close`: free own resource, drop
  the object reference, null the handle, then report the
  first teardown error or 0.
- `buffer_open`: `*out` cleared first, null on failure.
  Unknown rings report `BRIDGE`/`-ENOENT`; unloaded
  objects report `BRIDGE`/`-EINVAL`.
- `object_ref`: null object fails with `BRIDGE`/`-EINVAL`
  and operation `VIEW_REF`. Success adds one view reference
  and clears the generic record.
- `object_unref`: infallible; a null object is a no-op. No
  diagnostic record is written. Dropping the last reference
  of any kind destroys the native state exactly once.
- `object_gen`: null object or null output cell fails with
  `BRIDGE`/`-EINVAL` and operation `VIEW_GEN`. Success
  writes the current configuration generation and clears
  the generic record.
- `object_gen_check`: null object fails with
  `BRIDGE`/`-EINVAL`; a generation that no longer matches
  fails with `BRIDGE`/`-ESTALE` (116 on Linux). Both use
  operation `VIEW_CHECK`. Success clears the generic
  record.
- `buffer_poll`: mirrors v1 poll with 64-bit cells.
  `used` and `needed` must be distinct cells outside
  `[dst, dst+capacity)`. Success writes one frame (`used`
  set, `needed` 0); a staged frame that cannot fit an
  empty destination returns `-ENOSPC` with `used` 0 and
  `needed` set to the whole-frame length, retains the
  record, and a later retry delivers it exactly once;
  timeout yields success with both zero; interrupted waits
  report `-EINTR` with both zero, distinctly from timeout.
  One call consumes until one record stages, the ring
  drains, or 64 records pass without staging. Malformed
  records are skipped and counted, never surfaced; valid
  records lost to the occupied slot count as drops; the
  conservation identity `received == delivered + staged +
  malformed + dropped` holds per buffer. Counters are
  observable through the optional `buffer_stats` snapshot;
  conservation is still proven behaviorally with controlled
  sources.
- `buffer_stats`: read-only snapshot of one buffer's five
  counters; the header is preserved and the conservation
  identity holds after every call. A null buffer, a null
  output, or a bad header reports `BRIDGE`/`-EINVAL` with
  operation `BUFFER_STATS` and leaves the output struct
  unchanged. Success clears the generic record. No error
  latch: native failures surface only through the per-call
  diagnostic, unlike v1 stats.

Each successful buffer_poll call returns at most one complete frame. A
consumer may assemble several frames by polling repeatedly into successive
portions of its own destination. If a later call reports ENOSPC, earlier
successful frames remain the consumer's completed prefix, and the next frame
remains owned by the buffer. This is a sequence of calls, not a multi-frame
native success or an atomic batch transaction. Repeated insufficient-capacity
calls preserve that held frame until one sufficient call delivers it exactly
once. A zero-byte success can also mean that the bounded malformed-record
skip limit was reached; it is not proof that no records were classified as
malformed.

## Batch framing

One raw event is at most 4096 bytes. A bridge frame is:

| Offset | Type | Field |
|---|---|---|
| 0 | u32 LE | payload length in bytes |
| 4 | u16 LE | framing version, must be 1 |
| 6 | u16 LE | reserved, must be 0 |
| 8 | bytes | exactly payload-length bytes |

No native padding. Maximum total frame is 4104 bytes. A 16-byte
payload requires a 24-byte frame. Framing version 1 is shared
with v1; payload bytes stay opaque to the library.

## ABI type rules

Fixed-width integers only: no `bool`, no `size_t`, no
platform `int` widths in signatures or structs. All
`uint64_t` lengths are conversion-checked to `size_t` before
use. Pointers cross only as spans, opaque owners, and output
cells. No callbacks cross the boundary: consumption is
poll-based, and native callbacks (ring sampling, libbpf
logging) stay inside C. No Mojo object layout crosses the
boundary: C and Mojo agree on every offset, and only
addresses of plain buffers cross at call time. No upstream
opaque pointer (`bpf_object`, `bpf_link`, `bpf_map`,
`ring_buffer`) crosses between instances or escapes as a
free-standing pointer; each generic Mojo owner retains the
library handle.

## Pinned-upstream adapters

The bridge builds libbpf from the pinned v1.7.0 source
recorded in `toolchain.lock.json` (tag `v1.7.0`, commit
`f5dcbae736e5d7f83a35718e01be1a8e3010fa39`, tarball sha256
`7ab5feff...2051b7b`) and links it statically with every
non-bridge symbol local. The fetched source carries map
`libbpf.map` (sha256 `f77f9e1a...35050`, nodes `LIBBPF_0.0.1`
through `LIBBPF_1.7.0`) and public headers installed under
`bpf/` (`libbpf.h` `d8af3464...a4f57d4`, `bpf.h`
`14cc65a1...355652`, `btf.h` `c87ad358...6aa45`, plus
`libbpf_common.h`, `libbpf_legacy.h`, `libbpf_version.h`,
`bpf_helpers.h`, `bpf_helper_defs.h`, `bpf_tracing.h`,
`bpf_core_read.h`, `bpf_endian.h`, `usdt.bpf.h`, and
`skel_internal.h`). The bridge calls only this inventory:
object open/load/close, map iteration and pin-path clearing,
program find/type/attach-type/insn-count/autoload/log
getters and setters, pre-load attach-target setting, map
geometry and element lookup/update, test-run, tracepoint
attach, link destroy, ring-buffer new/poll/consume/epoll/free,
CPU counting, error decoding, print silencing, and BTF parse/free
for eager custom-BTF path validation, plus `bpf_prog_load` forwarding
to observe terminal per-program load results. The pinned object-open API
copies that path without parsing it; the bridge parses it before
opening so invalid custom BTF fails at the contracted open boundary.

Forwarding rules are frozen. Option structs passed upstream
(`bpf_object_open_opts`, `bpf_test_run_opts`) are
zero-filled with `sz` set to the pinned `sizeof` (last
fields `bpf_token_path` and `batch_size` respectively);
truncated sizes are never passed. Object open sets the
copied name, the copied BTF path, and the mapped log
level (`0` requests no logging with retry-on-error,
`1`/`2` request verbose loads), disables map pinning and
implicit BPF token derivation (empty token path; token
operation is unsupported here), and leaves kconfig and
relaxed maps unset. Verifier logs use fixed 1048576-byte
per-program kernel working buffers with retention bounded by
the configured capacity; the shared object-level buffer
stays unset. Test-run zeroes the upstream cpu and batch
fields. Upstream `bool` fields are set explicitly (never
exposed in this ABI); the variadic print callback is
silenced with null rather than forwarded; upstream static
inline helpers and macros are consumed inside C only (map
update flags are frozen here as numeric values `0/1/2/4`
with kernel-UAPI provenance, not by macro inclusion).

A single libbpf implementation instance is preserved: the
static archive links into exactly one shared object whose
version script hides every upstream symbol, and
`dlsym("bpf_...")` against the candidate library resolves
nothing (probed on every run). Consumers load the bridge
from one path per process.

## View reference discipline

Owner-bound views use native reference discipline through
the exported `lmb_object_ref_v1`, `lmb_object_unref_v1`,
`lmb_object_gen_v1`, and `lmb_object_gen_check_v1`
operations above, so Mojo views retain real native
references without touching raw upstream pointers. The
external owner holds one reference, each live link, buffer,
or view holds one; dropping the last reference of any kind
destroys the native state exactly once, after a link or
buffer child has detached or freed its own resource.
Explicit close consults the live child-plus-view count for
its `BUSY` decision; that count itself stays internal to
the native implementation:

```c
unsigned lmb_object_live_children(const struct lmb_object *obj);
```

(declared in the native implementation's own internal
headers, never exported, operating only on the opaque
bridge owner, never on raw upstream pointers, and counting
live views together with live links and buffers).

## Versioning

Generic ABI 1 is independent of v1 session ABI 1, batch
framing 1, BPF payload layouts, and any consumer schema. A
record or semantic change requires a new frozen revision
with its own fixtures; additive symbols join the generic
version node, and v1 names never move nodes. Diagnostics,
generations, and validity rules above are part of the
frozen record, not implementation detail.

## Validation contracts

Result-reporting formats for this interface are the
versioned `test-contracts-v1` and `suite-result-v1`
contracts, consumed as the `mojobpf-test-contracts`
version 1 schema bundle (manifest digest
`f26344f33e5efd863ece1ce59d8e19bf26daaae0c82b97074afd176ae7011ad7`).
This is forward-looking: the library ships schema
acquisition only (the pin plus `tests/contracts/`), with
no result emitter, validator, or conformance test.
Acquire the bundle by exporting from an installed mojobpf
package or an unpacked mojobpf source archive, and verify
its manifest digest before use; there is no unpinned mode.
Standalone library operation has no runtime dependency on
that package.

## Downstream slice layout

Non-normative: this section records the historical
implementation-slice layout for the frozen contract
above; it prescribes no integrator workflow.

The object-lifecycle, maps/test-run, and attach/ring slices
build on this frozen contract. Each slice owns disjoint new
files; every shared contract input stays with the ABI
integrator, which serializes all header, export-map, CMake,
export-check, FFI, probe, and documentation edits. Slice
implementers request shared edits through the integrator and
never write shared files directly. Every path below is relative
to the library repository root.

| Slice | Exclusive new files | Justification |
|---|---|---|
| Object lifecycle | `native/src/object.c`, `src/libbpf_mojo/object.mojo`, `tests/native/generic_object.c`, `tests/mojo/test_generic_object.mojo` | Implements object open/configure/load/info/close/release plus the view reference ABI, and owns the object-lifecycle tests. |
| Maps and test-run | `native/src/object_maps.c`, `native/src/program_test.c`, `src/libbpf_mojo/maps.mojo`, `src/libbpf_mojo/program.mojo`, `tests/native/generic_maps.c`, `tests/native/generic_testrun.c`, `tests/mojo/test_generic_maps.mojo`, `tests/mojo/test_generic_testrun.mojo` | Implements checked map access and the test-run adapter, and owns the map/test-run tests. |
| Attach and ring | `native/src/generic_attach.c`, `native/src/generic_ring.c`, `src/libbpf_mojo/link.mojo`, `src/libbpf_mojo/buffer.mojo`, `tests/native/generic_attach.c`, `tests/native/generic_ring.c`, `tests/mojo/test_generic_link.mojo`, `tests/mojo/test_generic_buffer.mojo` | Implements link/buffer owners with the poll framing contract, and owns the attach/event tests. |

No path appears in more than one row. Retained shared files:
`native/include/libbpf_mojo_generic.h`,
`native/libbpf_mojo.map`, `native/CMakeLists.txt`,
`tests/native/check_exports.sh`,
`tests/native/generic_abi_probe.c`,
`tests/native/abi_v1_frozen.h`,
`tests/native/old_consumer_v1.c`,
`tests/mojo/test_generic_abi.mojo`,
`tests/mojo/test_generic_layout.mojo`,
`src/libbpf_mojo/_ffi.mojo`, and this document.

## Optional keyed-map delete and traversal

The original twenty generic operations retain their signatures and version
nodes. Two optional symbols, `lmb_object_map_delete_v1` and
`lmb_object_map_next_key_v1`, append at `LIBBPF_MOJO_GENERIC_1`; SONAME remains
`libbpf_mojo.so.1`. They reuse the same retained object and calling thread.
Each requires a loaded object, valid versioned name and positive map key size.
Missing maps return `BRIDGE/-ENOENT`; zero-key channels return
`BRIDGE/-EOPNOTSUPP`. Keys must have exactly the map's key size. Span wrap,
null nonempty storage, invalid headers and unsupported `has_current` values
return `BRIDGE/-EINVAL` before a native call.

Delete forwards `bpf_map_delete_elem_flags` once with the exact key and full
u64 flags, including unknown bits. The native map operation decides applicable
flags. An absent key remains `KERNEL/-ENOENT`; it never becomes success.
Every nonzero native return retains its exact signed code, independent of
ambient errno. Neither operation retries, including on EINTR.

For next-key, `has_current` is exactly zero or one. Zero requires
`current_bytes == 0` and ignores the pointer; libbpf receives actual NULL.
One requires a valid nonempty current span with the exact positive key size.
An empty provided current is invalid. `needed` is a valid u64 output disjoint
from the name record, name bytes, current bytes and the full destination span.
All validation and name copying precede caller output commits. Short capacity
sets only `*needed = key_size`, returns `BRIDGE/-ENOSPC` and leaves bytes
untouched. Other pre-call failures preserve both outputs.

With enough capacity the bridge snapshots current bytes and allocates separate
key-size scratch. Current/destination aliases are allowed. Allocation failure
returns `POSIX/-ENOMEM` with untouched outputs. Immediately before the sole
`bpf_map_get_next_key`, `*needed` becomes zero. A nonzero native result, including
terminal `KERNEL/-ENOENT`, preserves every destination byte. Native zero copies
exactly key-size bytes, preserves destination tails, sets `*needed = key_size`
and clears the generic diagnostic. All scratch is released on every path.
Traversal has no order, uniqueness or snapshot guarantee: changing/deleting a
cursor can cause a kernel first-key restart. The bridge neither hides restarts
nor sorts, caches or filters keys. HASH/ARRAY host scripts establish forwarding
contracts; actual map applicability and successful kernel operations require
separate target qualification.

## Optional per-buffer stats snapshot

`lmb_buffer_stats_v1` appends at `LIBBPF_MOJO_GENERIC_1`; SONAME remains
`libbpf_mojo.so.1`. Buffer creation still requires only open, poll and close:
the stats symbol resolves only when called, so object-only and older buffer
libraries keep working and report `BRIDGE/-ENOSYS` for the snapshot itself.
The snapshot reuses the buffer's retained owner and calling thread. It adds
no product event types and reinterprets no v1 session record: counter names
match the poll conservation identity, and the absence of a `last_error` latch
is deliberate, since generic diagnosis flows through the per-call record.
