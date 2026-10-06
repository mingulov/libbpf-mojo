<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Agent instructions for libbpf-mojo

## Purpose and status

Build a small, reusable Mojo interface to libbpf through one C compatibility layer. The repository is `libbpf-mojo`, the Mojo package is `libbpf_mojo`, the proposed native library is `libbpf_mojo.so.1`, and C entry points use `lmb_`. This is an independent project, not an upstream libbpf component or a Mojo-to-eBPF compiler.

As of 2026-10-05, this repository contains a README and contributor instructions only. There is no implementation, supported ABI, build wrapper, or passing runtime gate yet. The contracts below guide the first feasibility experiment; freeze exact declarations and toolchain pins before implementing them, and update this status as work lands.

MemVeil is the first intended consumer. This library owns native resources, typed errors, bounded transport, and Mojo ownership wrappers. Applications own probes, event meanings, filtering, correlation, accounting, capture formats, privacy policy, and reporting. Do not add MemVeil device/mapping types, DMA semantics, or product schemas to the library.

## Working rules and layout

Read the README and relevant public ABI/build documentation, check repository status and HEAD, and preserve unrelated edits, stashes, and worktrees. Keep changes and any authorized commits in this repository. Builds/tests/packages must work from a standalone clone or source archive using declared dependencies. All documentation, comments, generated text, and release material must be self-contained. References to other public projects, their published APIs, and documented dependencies are allowed when relevant. Describe contributor requirements and contracts directly in this repository.

Target ownership, to create as required:

| Path | Responsibility |
|---|---|
| `native/include/` | One versioned public C ABI |
| `native/src/` | libbpf object/link/map ownership, callbacks, staging, and errors |
| `src/libbpf_mojo/` | Typed Mojo owners and one internal FFI module |
| `tests/native/`, `tests/mojo/`, `tests/live/` | Independent native, language-boundary, and live-kernel evidence |
| `examples/` | Small owned C eBPF fixtures and Mojo consumers |
| `tools/`, `docs/` | Standalone build/test/package wrappers and public contracts |

Use the official Modular Mojo guidance when available, then validate against the selected compiler and its documentation. Pin compiler distribution/build, libbpf, clang, and build dependencies. Evolving skill examples are not compilation evidence. Keep the C layer small: a systems-language feasibility problem must not quietly turn application logic into C or introduce Python into runtime collection.

## Initial API scope

Support object open/load, explicit tracepoint/tracing attachment, one ring per session, whole-record batches, checked map operations, structured errors, and owned teardown. Add a small `uprobe_multi` fixture when exercising that optional capability. Broader attachment kinds require a named consumer and tests; do not build a general binding generator, dynamic plugin system, automatic pinning system, or shared observer framework.

Initial live qualification uses x86-64 Linux ≥ 7.0. Functional capability checks and actual load/attach evidence still decide availability. Keep an application's semantic kernel profiles outside this library. `uprobe_multi` testing must prove target/thread/process scope, not merely that an attach call returned success.

Proposed operations are `lmb_open`, `lmb_load`, `lmb_attach`, `lmb_poll`, `lmb_map_info`, `lmb_map_read`, `lmb_map_write`, `lmb_stats`, `lmb_last_error`, `lmb_detach`, and `lmb_close`. Freeze exact signatures, discriminants, field offsets, and error rules in public ABI documentation before implementation. Keep bridge ABI, batch framing, BPF payload, and consumer schema versions distinct.

## ABI and ownership invariants

- All public ABI structs begin with fixed-width `abi_version` and `struct_size`. Define padding/alignment and byte order explicitly. Assert layouts, widths, and signedness in both C and Mojo; no Mojo object layout crosses the boundary.
- Validate pointer-plus-length inputs, capacities, sizes, versions, enum values, and integer conversions before access. Copy retained configuration, names, and object bytes into owned storage; never retain an undocumented borrowed pointer.
- `open` clears its output handle before possible failure. A Mojo session is movable but not duplicable. Raw handles, map pointers, and borrowed callback data cannot outlive their owner or escape as uncontrolled application state.
- C owns libbpf objects, links, ring consumers, callback state, and staged records. Mojo owns configuration and caller output buffers. Native callbacks do not invoke arbitrary Mojo closures.
- One calling thread owns a handle initially. Cross-handle concurrency requires separate validation before it is advertised. Retrieve thread-local errors immediately on the same calling thread.
- Load failure and partial attachment roll back resources owned by the operation. Initial attachment is an explicit transaction: every required site succeeds or all links created by that call are destroyed. No implicit autoattachment or persistent pinning.
- `close` nulls the caller's handle and tolerates an already-null pointee. Explicit close and deterministic destruction must compose without double-free. Library unloading occurs only after handles, links, ring readers, and callable pointers have retired.
- Signal handlers set a flag; normal control flow performs cleanup. Successful detach is resource evidence, not proof of application-level measurement quiescence.
- Query and verify map type/key/value sizes. For per-CPU maps, check padded stride and CPU count with bounded allocation. A sequence of map reads is not automatically an atomic snapshot.

## Transport and errors

Use libbpf's maintained ring consumer. Do not port another project's mmap reader or reimplement ring synchronization in Mojo. Ring callback memory is borrowed and must be copied before it is retained.

**A negative libbpf callback return consumes the record.** Returning `-ENOSPC` from a callback does not make the record available on the next poll. Own a bounded staging copy first and limit consumption to the available staging capacity. Recheck this behavior against the pinned libbpf implementation and exercise the real adapter.

Initial raw-event maximum is 4,096 bytes with one owned staging slot. A batch frame has little-endian u32 payload length, u16 framing version 1, u16 reserved zero, then exactly the payload; maximum frame size is 4,104 bytes without native padding. Application payloads remain opaque to the library. Decoder bounds and alignment must not depend on casting an unaligned buffer to a native struct.

Polling copies only complete frames into caller-owned storage. Timeout yields success with zero bytes. If the next held frame cannot fit into an empty destination, return `-ENOSPC`, report its full required size, and retain it. If earlier frames fit, return that successful batch and retain the next frame. A later retry delivers the held frame exactly once. Count malformed records and unavoidable drops explicitly; never report silent loss as timeout.

Calls return success or a negative error, with structured operation, error domain, original signed native/libbpf code, and bounded sanitized explanation. Do not reinterpret all libbpf failures as POSIX errno or make callers parse strings. Failed-open diagnostics must be retrievable without a session. The proposed thread-local error record uses a bounded 1,024-byte message, survives inspection, and is replaced by the next failing operation. Freeze and test these semantics with the ABI.

Keep bridge receive/deliver/stage/malformed/drop statistics separate from application BPF counters. A synthetic source must reconcile its received records with delivered, held, and explicitly discarded records. Library statistics do not prove a consumer's semantic completeness. Avoid raw pointer-bearing logs and implicit global logging changes; errors must not expose object contents or secrets.

## Mojo loading and packaging

Keep native imports in one internal FFI module with typed wrappers. Lazily load the bridge so importing analysis-only consumer modules need not initialize libbpf or require collection privileges. Ensure the dynamic library outlives every owner and foreign callable.

Package from pinned sources and declare runtime shared-library dependencies, search paths, architecture, and ABI compatibility. Test a clean consumer outside the development tree without a Mojo compiler. A development path override may be explicit; release artifacts must resolve dependencies from pinned published sources or packages. Include required source/license notices and preserve per-file provenance.

## Test gates

No build/test commands exist yet. Bootstrap must create documented wrappers such as `tools/build`, `tools/test`, and `tools/package`, plus the selected compiler's actual test runner. Verify wrapper help and compiler versions before use; do not invent `mojo test` or mark an unrun command successful.

Required evidence for the first implementation:

- Native ABI: layout agreement, rejected versions/short structs, failed open clearing output, repeated null close, invalid map sizes, per-CPU stride/count checks, and rollback at each partial failure boundary.
- Native transport: 16-byte payload → 24-byte frame; capacity 23 returns required 24 without loss; retry with capacity 24 yields exactly one record. Include guard bytes, partial batches, malformed/oversized input, timeout/EINTR, and a real libbpf callback path.
- Mojo: movable ownership, library lifetime, structured error preservation, exact large integers, unaligned decoding, and the same short-buffer contract. A bounded 100,000-record synthetic run checks every payload and reconciles statistics.
- Native sanitizers and resource checks: address/undefined-behavior sanitizers, repeated load/attach failures, and stable owned-FD/allocation counts. These do not replace BPF verification or live tests.
- Live integration: owned C eBPF fixtures, a C reference consumer and Mojo consumer, a controlled workload with independent expected counts, actual loading/attachment, cleanup, and optional capability-specific scope checks.
- Packaging: compile and run the standalone example from the exact extracted artifact in a clean runtime; test missing/incompatible library behavior separately from successful execution.

Use the designated isolated environment for privileged fixtures and respect resource locks. Record exact source/tree state, toolchain and artifact identities, kernel/capabilities, commands, expected/actual results, losses, and cleanup. Separate PASS from FAIL, BLOCKED, SKIPPED, and NOT RUN. Mocked loading is not live integration, and a consumer's DMA/SWIOTLB correctness is outside these gates.

For documentation-only changes, check accuracy, links, scope, and whitespace; do not add implementation-mirroring tests. Update ABI/build documentation with behavior changes and explain any compatibility impact. Do not publish, provision infrastructure, or modify other repositories solely because a plan discusses those actions.
