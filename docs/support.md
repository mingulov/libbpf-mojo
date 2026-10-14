<!-- SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception -->
# Support envelope (0.2.0, ABI v1)

## Tested configuration

- x86-64 Linux, kernel >= 7.0 for live collection. A version
  string is eligibility only: each capability still needs its
  own functional check and live evidence. Passive inspection
  and offline work have no kernel floor.
- Shipped artifacts add packaged-binary floors on top: the
  x86-64-v2 CPU baseline and glibc >= 2.38 (recorded in
  the package manifest; see `docs/build.md`). Pure offline
  module use needs neither: importing analysis-only Mojo
  modules never initializes libbpf or requires privilege.
- Exact toolchain in `toolchain.lock.json` (Mojo 1.1.0 via
  pixi, libbpf 1.7.0 source, system clang/bpftool/CMake).
  `tools/build --check-toolchain` verifies the pins.
- `libbpf_mojo.so.1` plus the libraries named by the package
  manifest; consumers resolve the bridge from the pinned
  release tarball, never from a sibling checkout.

## Compatibility

- ABI major 1 is frozen: every top-level parameter struct
  begins with `abi_version` and `struct_size`, and unknown
  majors or short structs are rejected. A v2 proposal would
  document its own negotiation separately.
- Batch framing version 1, BPF payload layout, and consumer
  schemas version independently of the ABI major.
- The Mojo package `libbpf_mojo` is importable from the
  release tarball; importing analysis-only modules never
  initializes libbpf or requires privilege (the bridge loads
  lazily at session open).

## What the gates prove

`tools/test --help` lists the suites: native layout and
transport contracts, Mojo ownership and decoding, live
tracepoint attachment with an independent workload ledger,
cleanup/FD stability, packaging (manifest hashes, standalone
consumer, clean-room negatives), the demo runner, and
unprivileged self-tests. A skipped privileged suite is
reported as skipped, never as success. The default native
scope fails on any skipped selected test; offline lanes use
`--host-only` with declared `NOT_RUN` omissions.

## Generic object checkpoint

The additive generic interface implements twenty operations: object
open/configure/load/program-info/map-info/close/release, generic
diagnostic retrieval, native view ref/unref/generation/check, and
native checked map lookup/update, explicit XDP program test-run,
and native tracepoint attach/link-close and ring open/poll/close.
The original eleven session operations, their symbol versions and
SONAME are preserved.

Host tests exercise real pinned libbpf parsing of ringless, multi-program,
map-free and BTF-bearing objects, malformed ELF and custom BTF failures,
copied inputs, partial allocation failures, signed errors, retained views,
parent moves/releases, generation changes and stable FD counts. Native
load tests return controlled object failures and script per-program
outcomes through the pinned load API, intercepting its BPF requests
before execution. They cover log retention and retries without
establishing load support. Mojo owners
and views use one shared library handle and move-only ownership.

Native map host tests parse a standard independent ELF/BTF control and
run the actual pinned libbpf lookup/update wrappers against scripted
syscall responses. They cover ARRAY/HASH values, all six permitted update
flags, dirty scratch followed by signed kernel failure, allocation failure,
bloom lookup refusal with insertion preserved,
per-CPU values of 1/7/8/9/13 bytes, possible counts including offline CPUs,
overflow, protected-page boundaries and stable owned FD counts. Synthetic
FD accessors never install descriptors into libbpf owners. The permanent
host guard stops unscripted BPF commands before execution and rejects
unknown syscall signatures; its deliberate trap controls fail as expected.

Native test-run host tests parse real XDP and tracepoint programs and
execute pinned libbpf's test-run wrapper against the guarded syscall.
They inspect the entire native options record, four independent lengths,
retval and duration, input/option/name aliases, adjacent outputs, omitted
outputs, exact extents and tails, dirty native failures, single-call error
forwarding and oversized-success rejection. Every observed owned
allocation boundary is failed and recovered; protected pages bound all
four spans. These scripted tests do not qualify kernel execution. The
initial result profile accepts XDP only, with flags zero; other validated
program types return `BRIDGE/-EOPNOTSUPP` without execution.

Run `tools/test native --host-only` and `tools/test mojo --host-only`
for the explicit host scope. Omitted runtime cases are reported
`NOT_RUN` and are excluded from their pass counts. The default suites
keep their runtime checks. The native host scope runs guarded framing
checks and omits the valid-fixture dual-load case and its privilege
probe; that regression fails if the boundary is crossed. The native host
runner selects ten guarded CTest twins and eleven export checks, without
double-counting the ordinary tests. The guard runs only in native test
executables, including the shared bridge's bundled libbpf. Successful generic load, loaded map geometry,
tracing-target configuration and their target/platform evidence remain
unqualified. Native generic map and XDP test-run calls have host contract
evidence only. Typed Mojo map/test-run functions are implemented over the
same retained views. Their scripted host tests cover full-width scalar
values, raw per-CPU padding, exact flag/error forwarding, bloom refusal
forwarding, independent
result fields, input snapshots, untouched failure buffers and last-release
destruction. Optional operation symbols resolve only when called, preserving
object-only libraries. Host tests compile Mojo without the interposer and
guard each resulting native executable. The guard forwards the pinned
allocator's exact rseq signature, preserves errno and resolves safely
before its constructor; unknown signatures and unscripted BPF fail closed.

Installed consumers compile from extracted modules only, then run after
relocation with their input sources removed and no compiler on PATH. They
exercise existing session behavior, generic view ownership and typed
unloaded/closed/stale errors. Test-only scripted libraries are not shipped.
Successful kernel operations, including installed package map/test-run
execution, remain unqualified. Native and typed Mojo links and buffers have
host contract evidence. Their installed consumers use extracted public modules
only, then run after source removal and relocation. Product-library cases prove
unloaded/closed and option refusals; an explicit external test-library mode
proves successful children, copied bytes, short retry and last-release cleanup
over the actual pinned reader. Each attempt can retain binaries and complete
command logs through `LMB_PACKAGE_CONSUMER_OUT`. These test libraries and schema
acquisition helpers do not enter runtime packages. Successful installed kernel
attachment and event production remain unqualified.

Generic ring tests execute pinned libbpf's maintained reader over owned
memfd-backed mappings with a controlled producer. They prove copied
callback data, exact 16-to-24 framing, repeated short retries, one frame
per poll, consumer prefix retention, wraparound, BUSY/DISCARD behavior,
the 64-step malformed skip, signed errors and interrupted waits. Two
100,000-record controls check every delivered sequence and reconcile
received/delivered/held/malformed/drop counts; the mixed control finishes
100000/99700/0/200/100. A negative callback mechanism control confirms
that returning ENOSPC consumes the record; the reader does not replay it.
These are native single-threaded host controls, without kernel production,
weak-memory, multi-CPU, ARM or performance qualification.

Tracepoint attachment host tests use parsed real programs and intercept
the attachment boundary with owned test tokens. They check explicit copied
target names, exact type/family and option refusals, signed diagnostics,
allocation/reference overflow, native setup rollback and destruction
failures. They preserve existing children, enforce parent-close BUSY and
keep links/buffers/views alive after parent release. Ring construction
failure tests cover each observed allocation, both mappings, map-info,
epoll creation and registration, with references, mappings and owned FDs
returning to baseline. No test BPF or perf-event request reaches the
kernel. Successful tracepoint attachment, real signals/blocking, kernel
ring production and target resource cleanup remain unqualified.

## Out of scope

A general binding generator, dynamic plugins, automatic
pinning, a shared observer framework, cross-handle
concurrency, and any application semantics (probes, event
meanings, correlation, accounting, formats, reporting) all
belong elsewhere. Application correctness is outside these
gates: library statistics never prove a consumer measured
completely.
