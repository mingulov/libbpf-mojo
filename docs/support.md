<!-- SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception -->
# Support envelope (0.1.0, ABI v1)

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
reported as skipped, never as success.

## Generic object checkpoint

The additive generic interface implements twelve operations: object
open/configure/load/program-info/map-info/close/release, generic
diagnostic retrieval, and native view ref/unref/generation/check.
The original eleven session operations, their symbol versions and
SONAME are preserved.

Host tests exercise real pinned libbpf parsing of ringless, multi-program,
map-free and BTF-bearing objects, malformed ELF and custom BTF failures,
copied inputs, partial allocation failures, signed errors, retained views,
parent moves/releases, generation changes and stable FD counts. Native
load tests intercept the load boundary with a controlled failure before
kernel work; that result does not establish load support. Mojo owners
and views use one shared library handle and move-only ownership.

Run `tools/test native --host-only` and `tools/test mojo --host-only`
for the explicit host scope. Omitted runtime cases are reported
`NOT_RUN` and are excluded from their pass counts. The default suites
keep their runtime checks. Successful generic load, loaded map geometry,
tracing-target configuration and their target/platform evidence remain
unqualified. Generic map operations, program test-run, links and buffers
are not implemented by this checkpoint.

## Out of scope

A general binding generator, dynamic plugins, automatic
pinning, a shared observer framework, cross-handle
concurrency, and any application semantics (probes, event
meanings, correlation, accounting, formats, reporting) all
belong elsewhere. Application correctness is outside these
gates: library statistics never prove a consumer measured
completely.
