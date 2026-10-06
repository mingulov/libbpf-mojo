<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Mojo unsafe-operation inventory

Every raw-pointer operation in `src/libbpf_mojo/` with its pointer,
capacity, initialization, lifetime, and thread preconditions. Consumer
accounting and CLI code must never add to this list: all unsafe work
stays behind the `Session`/`NativeLib` boundary.

Conventions used below:

- **Pointee escape rule.** Every pointer the native call dereferences
  is passed as a `Pointer` value, never as a `UInt64` address.
  Passing an address as an integer loses escape information: on
  Mojo 1.1.0 the optimizer reordered stack stores across the call
  and the native side observed stale struct contents (deterministic
  `lmb_open: invalid options`; direct `Pointer` arguments fixed it).
  Only the opaque session handle crosses as `UInt64`; it has no
  Mojo-side pointee.
- **Output mutability rule.** Every natively written pointee is a
  `MutPointer` (or a `mut List`), which the compiler enforces: an
  immutable borrow cannot reach a native write. Input-only
  pointees keep inferred mutability and accept either.
- **Subtraction bounds rule.** Range checks never add untrusted
  lengths: they compare `start <= total` and `length <= total -
  start`, and length matches subtract (`payload == count - 8`).
  No check can wrap around.
- **Single thread.** A `Session` must be used from one thread only.
  Native error records are thread-local, and each method captures
  its failure immediately after the call.
- **Empty spans.** `unsafe_ptr()` on an empty span does not trap.
  The native side never dereferences a zero-length input
  (`lmb_check_bytes` returns before touching `ptr`; sized operations
  fail or report `required` on length alone), so empty spans pass
  their pointer through unconditionally.

## `NativeLib` (`src/libbpf_mojo/_ffi.mojo`)

| Operation | Pointer | Capacity | Init | Lifetime | Threads |
|---|---|---|---|---|---|
| `OwnedDLHandle(path)` | N/A (loader path) | N/A | N/A | Owned; closed on drop. The `Session` owns its `NativeLib`, so the library outlives every call and handle. | One owner; no sharing. |
| Symbol validation in `__init__` | N/A (symbol lookup) | N/A | Handle must be open. | All 11 ABI symbols resolve before any handle exists, so a partial library fails before acquiring state. | Owner thread only. |
| `get_function[Int32](name)` per call | N/A (symbol lookup) | N/A | Handle must be open. | Callable used immediately; never stored. | Owner thread only. |
| `extern` call with `Pointer` args | Non-null `Pointer` per parameter: struct locals (`Pointer(to=x)`) or span data (`span.unsafe_ptr()`, possibly offset). | Pointee capacity exact: ABI structs are `size_of`-verified mirrors; spans carry caller length plus the wrapper's range check. | Input structs fully initialized before the call; out-cells are plain locals the call fills. | Every pointee outlives the call (locals and caller spans in enclosing frames). No pointer is retained. | Owner thread only. |
| `f(session)` with `UInt64` handle | Opaque native handle, 0 when closed. | N/A (not dereferenced by Mojo). | Set by `lmb_open`, cleared by `lmb_close`. | Valid between open and close; native calls reject 0/closed handles with `-EINVAL`. | Owner thread only. |

## `Session` (`src/libbpf_mojo/session.mojo`)

Construction acquires its own native handle through `lmb_open`;
there is no raw-handle adoption constructor, so two owners can
never free one native allocation. Moves transfer both the handle
and the library; the destructor closes exactly once.

| Operation | Pointer | Capacity | Init | Lifetime | Threads |
|---|---|---|---|---|---|
| `Pointer(to=local)` for ABI structs and out-cells | Address of a fully built local (`OptionsV1`, `AttachV1`, `NameV1`, stat/info/error mirrors, `written`/`required`, handle cells). Outputs use `MutPointer`. | Exact mirror size (layout tests). | Struct fields assigned before the call; out-cells default-initialized. | Local outlives the call; values copied out before return. | Owner thread only. |
| `poll` destination | `mut List[UInt8]` from the caller; the compiler rejects immutable borrows. | Subtraction-checked (`start <= total`, `cap <= total - start`). | Caller-owned; empty spans pass through (never dereferenced at length 0). | Caller list outlives the call. | Owner thread only. |
| `attach` sites | One contiguous `List[AttachV1]` passed in a single native call, preserving all-or-none atomicity; empty lists are rejected without calling. | Contiguous list storage. | Each site built from caller spec strings, alive for the call. | Local; no wrapper rollback (the native call is atomic). | Owner thread only. |
| `span.unsafe_ptr()` for bytes | Caller span data (`elf`, `dst`, `key`, `value`) or owned bytes (`String.as_bytes()`). | Span length, checked with `checked_u32` (no silent narrowing) and range-checked (`start + capacity <= len`). | Caller-initialized; destination spans are caller-owned. | Caller data outlives the call (open copies; poll/map finish before return). | Owner thread only. |
| `UInt64(pointer)` into `BytesV1` fields | Address value stored as struct data, not passed as a call argument. | Length field beside it, checked. | Set at construction. | Same as the enclosing struct argument. | Owner thread only. |
| `__deinit__` close | `Pointer(to=cell)` where `cell` copies the handle. | 8 bytes. | Copy of `_handle`. | Local; the library handle is moved out first so the call always has a live loader. Errors are swallowed: destruction cannot raise; explicit `close()` reports them. | Owner thread only. |
| `map_read` trim | Reads `buf[i]` for `i < need`, where `need` comes from a post-success `map_info`. | `need <= capacity` guaranteed by the successful native call. | Filled by the call. | Local list, returned by move. | Owner thread only. |
| `map_read`/`map_write` spans | Input spans (`key`, `value`) with inferred mutability; the read destination is an owned local list. | `checked_u32` lengths (no silent narrowing). | Caller-initialized. | Spans outlive the call. | Owner thread only. |

## `batch.mojo`

| Operation | Pointer | Capacity | Init | Lifetime | Threads |
|---|---|---|---|---|---|
| `decode_frame` reads | `data.unsafe_ptr().unsafe_offset(start)`, read with `read_u*_le` only. Never cast to a struct, so any alignment decodes identically. | `count` validated without wrapping arithmetic: `8 <= count <= 4104`, `start <= total`, `need <= total - start`, `payload_len == count - 8`, nonzero. Reserved bytes must be zero. | Caller poll buffer. | Reads complete before return; the payload is copied into an owned list. No borrowed record escapes. | Any thread (pure). |

## Readers (`read_u8_le`, `read_u16_le`, `read_u32_le`, `read_u64_le`)

Each loads N bytes at `base + off` through `unsafe_offset`/`unsafe_load`.
Callers guarantee `off + N` stays inside the pointee: layout tests use
`size_of`-exact locals; `decode_frame` validates `count` first; the RSS
probe reads a fixed struct offset. Pure; any thread.

## Test-only (`tests/mojo/testutil.mojo`)

| Operation | Notes |
|---|---|
| `TestFake.arm/sample/disarm` | Pass `session._handle` (opaque `UInt64`, test-only field access) and `payload.unsafe_ptr()` to the test-support library. Sessions are borrowed, never owned, so handles never escape. Payloads are bounded to 8192 bytes (covers deliberate oversize probes). |
| Armed-test guards | Every armed interval sits in `try/finally` with `disarm` in the `finally` arm, so an assertion failure can never drop an armed session onto the dummy ring pointer. |
| `poll_guarded` | Refuses to poll while `staged == 0` instead of driving the dummy ring into consumption; live timeout coverage belongs to the privileged gate. |
| `peak_rss_kb` | `getrusage` via libc into a 144-byte local; reads `ru_maxrss` at offset 32. Fixed layout, local lifetime. |
