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
