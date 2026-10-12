<!-- SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception -->
# Ownership, errors, and transport

How a consumer holds a session, what outlives what, and how
failures surface. `docs/abi-v1.md` is normative for layouts and
signatures; this page states the rules in prose.

## Session lifecycle

`lmb_open` copies the ELF bytes, options, and ring name into
owned storage and heap-allocates an opaque session. A failed
open clears its output handle. `lmb_close` takes the caller's
handle pointer, frees everything the session owns (objects,
links, ring state, staged records), nulls the pointer, and
tolerates an already-null pointee, so explicit close and
deterministic destruction compose without double-free.

The Mojo `Session` owner is movable but not duplicable: raw
handles, map pointers, and borrowed callback data cannot
outlive their owner. One calling thread owns a handle;
cross-handle concurrency is unsupported until separately
validated.

## Generic object and view lifecycle

The additive generic API parses ELF eagerly and opens valid objects
without a ring. It copies retained ELF bytes, object names, custom-BTF
path bytes and configuration. Program configuration is named and runs
before a load attempt. Loading is explicit and never attaches. A failed
load preserves its signed libbpf error and leaves metadata and teardown
usable; a second load is rejected. Loaded map metadata requires a
successful load.

Verifier-log retention applies per program: `LOG_ON_FAILURE` retains
only failed program loads, while `LOG_ALWAYS` also retains successful
program logs. An object failure before any program attempt produces
no program logs. Each retained log respects the configured cap.

`Object` is move-only. Its `program(name)` and `map(name)` methods
return move-only `ProgramView` and `MapView` owners. Views retain a
native object reference and share the same dynamic library handle.
Moving or releasing the parent preserves those references. Each view
captures the configuration generation; successful configuration
invalidates older views, whose metadata calls fail with `BRIDGE/-ESTALE`
without writing outputs. A map view additionally requires successful
loading before its metadata can be read.

Explicit `Object.close()` with a live view, link or buffer fails with `BRIDGE/-EBUSY`
and preserves the usable owner. Close without children or views nulls its handle.
`Object.release()` and the destructor drop the external reference even
with views alive. The last reference destroys the native state once.
Closing a view releases its reference and is repeatable. Native teardown
runs before the last shared library handle is dropped.

Generic diagnostics are independent of session diagnostics. Successful
generic calls clear the generic record; error retrieval and destructor
release preserve it. Read an error immediately on the calling thread.
The [generic ABI contract](generic-abi-v1.md) defines exact output
validity and version checks. Host tests validate parsing and ownership;
they do not qualify successful kernel loading, attachment or map access.

## Generic native links and rings

`lmb_object_attach_v1` attaches one explicitly named tracepoint site and
returns one owned link. Only the tracepoint family and a tracepoint
program are supported by this interface; other program types fail before
attachment. The category and event are required copied names. Each
successful link or buffer adds one native parent reference. A failed
creation unwinds only that call's resources, leaving previous children
usable. Native link close destroys its link, nulls/frees the child and
drops the reference even when destruction reports an error. Explicit
close reports the signed libbpf error after that cleanup.

`lmb_buffer_open_v1` requires a loaded named ring map and owns the pinned
libbpf consumer, its C callback state and one copied 4,096-byte slot. It
requires one stage slot and zero flags/reserved fields. Buffer close calls
libbpf's void free operation, nulls/frees the child and drops the reference;
it cannot report unexposed close or unmap errors. Repeated null close is
successful. A remaining child or view keeps the native object alive after
external-owner release, and the last reference destroys it once, after
child teardown. A caller that cancels link-then-buffer setup closes the
successful link when later buffer creation fails.

Each native `lmb_buffer_poll_v1` returns at most one complete frame. It
copies callback bytes before the borrowed source can change, consumes at
most one callback-visible record per step, and stops after a record stages,
the reader drains or 64 steps pass. Held bytes are delivered before any
new wait or consumption. Insufficient capacity returns `BRIDGE/-ENOSPC`
with `used` zero and `needed` set to the full frame size; repeated short
calls keep the same bytes until one sufficient retry delivers them once.
A consumer can assemble a prefix through repeated calls: earlier frames
remain committed if a later call is short, and the next frame stays held.
There is no multi-frame native transaction.

The two u64 size cells must be wholly disjoint from each other and the
entire destination capacity. Validation rejection preserves those cells,
the destination and staging. Empty success clears the size cells, including
when the malformed skip limit is reached. EINTR is a POSIX error with
both cells zero, no automatic retry and no destination write. Internal
per-buffer counters obey `received = delivered + held + malformed + dropped`;
no generic stats operation is exported. Correctly bounded ordinary polls
do not consume a valid record while the slot is occupied. Host robustness
tests deliberately exercise that callback case and count the loss.

Typed Mojo `Link` and `Buffer` are move-only and share the originating library.
Factories validate the retained view's generation before acquiring a child,
and preflight their optional acquisition, poll and destructor symbols. Missing
destruction support refuses before native acquisition. Both children survive
the parent/view's local scope; native teardown precedes dynamic-library release.
Close remains available without a generation check. A closed buffer clears its
stored parent values and rejects later polling before checking that parent.

`Buffer.poll` borrows a mutable span and returns a copyable `BufferPollResult`
with u64 `used`/`needed` cells and an owned diagnostic. It preserves the native
short-buffer error, signed EINTR and LIBBPF failures. Only the expected
BUFFER_POLL/BRIDGE/-ENOSPC diagnostic and valid required extent classify as
short. Immediate same-thread error capture preserves a result after later
successful operations. The [usage guide](links-and-ring.md) specifies these
signatures and outcomes. Host tests prove ownership, forwarding and the actual
libbpf reader contract; successful kernel attachment and event production
require live evidence.

## Attach and teardown

`lmb_attach` is an explicit transaction: every required site
succeeds, or all links created by that call are destroyed.
Load failure and partial attachment roll back what the
operation owned. There is no implicit auto-attach and no
persistent pinning. `lmb_detach` releases links; successful
detach is resource evidence, not proof that the application
measured everything.

## Errors

Every call returns 0 or a negative error. The return's
magnitude is a hint only; structured diagnostics come from
`lmb_last_error`, a thread-local record naming the operation,
error domain, original native/libbpf code, and a bounded
sanitized message (1,024 bytes). Read it on the same thread,
immediately: the next failing operation replaces it.
Failed-open diagnostics are retrievable without a session.
Never reinterpret every libbpf failure as a POSIX errno, and
never require callers to parse strings.

## Batches and the short-buffer contract

One poll call delivers at most one framed record: u32
little-endian payload length, u16 framing version 1, u16
reserved zero, then exactly the payload (4,096-byte payload
maximum, 4,104-byte frame maximum, no native padding). Polling
copies only complete frames into caller-owned storage.

When the staged frame cannot fit an empty destination, `lmb_poll`
returns `-ENOSPC`, reports the whole-frame length in
`required`, writes nothing, and retains the record; a later
retry with room delivers it exactly once. Timeout yields
success with zero bytes. A negative libbpf callback return
consumes the borrowed record, so the bridge copies each record
into its owned staging slot before returning.

Library statistics (`lmb_stats`: received, delivered, held,
malformed, dropped) describe the bridge only. Malformed and
oversized records are skipped and counted, never surfaced as
call failures; a valid record lost to the single occupied slot
counts as dropped (explicit capacity loss, never silent).
Bridge counters never prove a consumer's semantic completeness.

## Maps

`lmb_map_info` reports the map type and key/value sizes; every
read and write rechecks them, including per-CPU stride and CPU
count with bounded allocation. A short `lmb_map_read`
destination behaves like poll (`-ENOSPC`, `required` set,
nothing written). Output aliasing is forbidden for the two
ranges the ABI names: the `required` cell must lie outside
`[key, key+key_bytes)` and `[dst, dst+capacity)`, and an
overlap is refused with `-EINVAL` before anything is
written. The map-name struct is not part of that check.

The additive `lmb_object_map_lookup_v1` and `lmb_object_map_update_v1`
operate on the same retained generic object and require successful load.
They neither change generation nor acquire another resource owner. Keys
match metadata exactly. Ordinary values match `value_size`; per-CPU values
include every eight-byte padded slot for the possible-CPU count, including
offline CPUs. The complete spread must fit u32. A sequence of reads is
not an atomic snapshot.

Lookup uses owned scratch of the required extent and copies exactly that
extent only after the pinned native call succeeds. The destination and
its tail remain untouched on every failure, including a native failure
after dirty scratch writes. Key/destination aliasing is allowed. The
`needed` cell must be outside the key and full destination capacity;
argument/extent rejection preserves it, a short destination reports the
exact extent with `BRIDGE/-ENOSPC`, and native failure reports zero.

Update forwards flags 0/1/2/4/5/6 unchanged. LOCK forwarding is not a
promise that a particular map accepts a spin-lock operation. Native
lookup/update failures preserve the returned signed code in the KERNEL
domain; possible-CPU query failures use LIBBPF, extent rejection uses
BRIDGE, and scratch allocation failure uses POSIX. Operations do not
retry kernel refusals or normalize update flags. These native calls have
guarded host contract evidence; successful kernel behavior remains
unqualified.

The additive `lmb_program_test_run_v1` borrows the same loaded object and
does not create an owner or change its generation. The initial profile is
XDP with flags zero. Ordinary validation, loaded state and named-program
lookup precede the unsupported-type rejection. Packet and context inputs,
option values and the program name are captured before any output commit.
Inputs may alias outputs or the result; the two nonempty outputs must be
disjoint from each other and from the complete result. Adjacent intervals
are legal. Each call releases all input snapshots and output scratch.

On success, each nonempty output receives exactly its native actual
extent and retains its tail. Omitted outputs request no copy, while the
result still reports their native lengths. A successful native result
beyond a nonempty output's capacity returns `BRIDGE/-EOVERFLOW` without
copyback. Every failure leaves both caller outputs and the full result
unchanged. Native failures retain their signed KERNEL code; allocation
failure uses POSIX and a failed program-FD getter preserves its LIBBPF
code. The call executes one native test-run without retry. Caller-output
preservation does not undo kernel side effects. Guarded host adapter tests
establish these buffer/error rules; actual kernel behavior remains
unqualified.

The Mojo functions in `libbpf_mojo.maps` and `libbpf_mojo.program`
borrow these same views. Generation checks precede allocation and the
map/test-run call. Closed and stale views fail before those operations.
Raw map lookup returns an owned byte list containing all per-CPU padding;
scalar helpers require an ordinary four-byte key/eight-byte value and
preserve native-endian widths. `test_run` takes immutable inputs and
mutable outputs, and returns a copyable `ProgramTestResult` only on
success. Its result fields are independent native values. Borrowed spans
do not escape the call; views continue to own their object/library
references until close or destruction.

All three typed FFI operations resolve optional symbols when called.
Missing operations raise their own `BRIDGE/-ENOSYS`; they do not prevent
an older library's object or session operations. A failing native call's
generic diagnostic is captured immediately on the same thread, before
another generic operation can clear it. The [typed usage guide](maps-and-test-run.md)
states extents, omissions, aliases and installed-consumer limits.

## Versions

Four versions stay independent: ABI major (1, in every
struct's `abi_version` header), batch framing (1), BPF
payload layout (owned by the application), and the consumer's
schema. Unknown ABI majors and short structs are rejected;
see `docs/abi-v1.md` for the exact header rule.
