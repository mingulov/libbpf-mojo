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

`Object` is move-only. Its `program(name)` and `map(name)` methods
return move-only `ProgramView` and `MapView` owners. Views retain a
native object reference and share the same dynamic library handle.
Moving or releasing the parent preserves those references. Each view
captures the configuration generation; successful configuration
invalidates older views, whose metadata calls fail with `BRIDGE/-ESTALE`
without writing outputs. A map view additionally requires successful
loading before its metadata can be read.

Explicit `Object.close()` with a live view fails with `BRIDGE/-EBUSY`
and preserves the usable owner. Close without views nulls its handle.
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

## Versions

Four versions stay independent: ABI major (1, in every
struct's `abi_version` header), batch framing (1), BPF
payload layout (owned by the application), and the consumer's
schema. Unknown ABI majors and short structs are rejected;
see `docs/abi-v1.md` for the exact header rule.
