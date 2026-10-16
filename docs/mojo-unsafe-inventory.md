<!-- SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception -->
# Mojo unsafe-operation inventory

Every raw-pointer operation in `src/libbpf_mojo/` with its pointer,
capacity, initialization, lifetime, and thread preconditions. Consumer
accounting and CLI code must never add to this list: all unsafe work
stays behind the library's typed owner, map/program and internal FFI
boundaries.

Conventions used below:

- **Pointee escape rule.** Every pointer the native call dereferences
  is passed as a `Pointer` value, never as a `UInt64` address.
  Passing an address as an integer loses escape information: on
  Mojo 1.1.0 the optimizer reordered stack stores across the call
  and the native side observed stale struct contents (deterministic
  `lmb_open: invalid options`; direct `Pointer` arguments fixed it).
  Only opaque native handles cross as `UInt64`; they have no
  Mojo-side pointee.
- **Output mutability rule.** Every natively written pointee is a
  `MutPointer` (or a `mut List`), which the compiler enforces: an
  immutable borrow cannot reach a native write. Input-only
  pointees use immutable pointers. Older session calls keep inferred
  mutability; typed generic calls require immutable inputs.
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

## Generic typed calls (`maps.mojo`, `program.mojo`, `GenericLib`)

The existing views retain one native object reference and an
`ArcPointer[GenericLib]`. Their generation is checked before allocation
or the new operation; the shared library remains loaded throughout each
call and diagnostic capture. These rules apply on the owner thread.

| Operation | Pointer/capacity and initialization | Lifetime and checks |
|---|---|---|
| Optional `object_map_lookup` / `object_map_update` | Names and byte inputs are `ImmPointer`; lookup destination and `needed` are `MutPointer`. Extents/flags are exact UInt64, return is signed Int32. | Resolve only when called; no callable is retained. Missing symbols raise their own BRIDGE/-ENOSYS. Native errors are captured immediately. |
| Optional `program_test_run` | Immutable name/options pointers and mutable result pointer. Options/result are the existing fully initialized 88/40-byte fixed records. | The view and all local records outlive the call; no pointer is retained. Result becomes a public value only after success. |
| Raw lookup list | `Span(result).unsafe_ptr()` addresses exactly the ordinary value size or checked `stride * possible_cpus` extent, bounded to u32 and LP64 indices. `needed` is a separate UInt64 local. | Generation/metadata/key checks precede allocation. The native adapter validates the same geometry, uses scratch and copies only after success. The owned list is moved to the caller. |
| Raw update spans | Immutable `key.unsafe_ptr()` and `value.unsafe_ptr()`, lengths from the spans. | Caller storage lives through the call. Native checks exact geometry and flags before one update; neither span escapes. |
| Scalar byte encoding/decoding | `Pointer(to=scalar).unsafe_bitcast[UInt8]()` reads/writes only size_of[UInt32] or size_of[UInt64] bytes. | The aligned scalar local lives through every byte access. Values use native endian; no byte buffer is cast to an unaligned integer pointer. Geometry rejects per-CPU and non-4/8 maps first. |
| Test-run span fields | `UInt64(span.unsafe_ptr())` is stored inside each options span record, with its exact UInt64 extent. The record itself crosses as a typed pointer. | Borrowed spans/backing storage live through the synchronous call. Native snapshots both inputs and uses separate output scratch. Nonempty outputs must be disjoint. Pinned-compiler tests independently check all four lengths, initialized input bytes, copied bytes and preserved tails. Empty native pointers are normalized to null. |

The deliberate alias test in `test_generic_testrun.mojo` uses
`as_unsafe_any_origin()` only for two immutable input pointers. Both
backing lists stay alive and unmoved until return; the native adapter
snapshots those inputs before output writes. This tests a native alias
contract that safe Mojo origins ordinarily refuse. Public modules do not
erase span origins.

## `link.mojo` and `buffer.mojo`

| Operation | Pointer and extent | Initialization, lifetime and thread preconditions |
|---|---|---|
| Optional factory preflight | Symbol lookup through the view's original `GenericLib`; no child pointer yet. | Generation is checked first. Attach+close or open+poll+close must all resolve before acquisition. The unchanged object/Session slices stay independent. |
| Attach/ring options | Local fixed-width `AttachOptionsV1`/`BufferOptionsV1` cross as typed immutable pointers. Embedded name spans carry `UInt64` addresses plus exact u64 byte lengths. | Every record field is initialized. The view name and caller strings live through the synchronous call; native code copies required names and retains no Mojo pointer. |
| Child handle cells | Initialized local UInt64 cells cross as `MutPointer[UInt64]`. Native handles are opaque integers to Mojo. | A successful factory owns one child; no raw-handle adoption API exists. Move transfers that child and its shared library. Close/destruction use a local cell, retain the native null result and never destroy twice. |
| Ring destination and sizes | `dst.unsafe_ptr()` is mutable, with capacity `UInt64(len(dst))`; separate initialized u64 `used` and `needed` locals cross as typed mutable pointers. | The destination and cells outlive the call. Native range/overlap checks precede writes. No output span escapes. The child retains its native parent; generation is checked before polling. Closed handles fail before parent access. |
| Buffer stats snapshot | Local 48-byte `BufferStatsV1` crosses as a typed mutable pointer; the opaque child handle crosses as `UInt64`. | Header fields initialized before the call. Generation is checked first; closed handles raise before native access. The missing-symbol path raises without calling. Values are copied into an owned `BufferStats` after success. |
| Error capture and teardown | Generic error-record locals use the existing immediate capture helper. | A failing native operation is captured before another generic call. Explicit close does not check generation and exposes signed teardown failure. Native children retire before the last ArcPointer/OwnedDLHandle. All operations remain on the owning thread. |

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
