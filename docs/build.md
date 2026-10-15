<!-- SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception -->
# Build and toolchain guide

This repository builds with a pinned Mojo toolchain managed by pixi, plus
system C tooling for the native bridge. Pinned versions live in
`toolchain.lock.json` (cmake carries a minimum floor, the rest are
exact); the `pixi.lock` file carries authoritative conda package hashes.

## Prerequisites

- `pixi` 0.81.0 exactly, to create the Mojo environment.
- System `clang`, `ninja`, `make`, and `bpftool` at the locked
  versions, plus `cmake` at or above the locked floor, for the
  native bridge and test fixtures.
- `libelf` headers (`libelf-dev 0.194-4`), `zlib` headers, and
  `pkg-config` at the locked versions, for the libbpf source build. The
  native build verifies them with `pkg-config` and fails closed when
  they are absent; install them with `apt-get install libelf-dev`
  (plus its dependencies) before building native targets.
- `python3` for development-only validation tooling.

Run `pixi install` once after cloning. Every Mojo command below runs inside
that environment; the `tools/` wrappers do this for you.

## Standalone source archives

A complete source archive contains `native/`, `src/`, `examples/`,
`tests/`, `tools/`, documentation, licenses, and both toolchain locks.
For example, create one from a clean revision with
`git archive --prefix=libbpf-mojo-source/ HEAD | gzip -n > source.tar.gz`.
Extract it into a new directory and run `./tools/build`, then
`./tools/test native --host-only`, `./tools/test package-consumer`,
and `./tools/package` there, using the
prerequisites above. No Git metadata is required to build or package.
From a checkout, `./tools/test source-export` builds fresh HEAD exports,
including under an unrelated Git parent, and checks consumption, source
seals, timestamp refusal and repeated package determinism.

Source exports seal the declared archive inventory and record the revision
as `unknown`; they never borrow the identity or ignore rules of an enclosing
repository. Bind the complete source archive's hash to the generated runtime
archive's hash when distributing a candidate. The runtime/development bundle
contains the bridge, examples, public header and Mojo wrappers; it is not
the full corresponding native source archive.

Archive members use `SOURCE_DATE_EPOCH` when supplied: only ASCII decimal
seconds in `0..4294967295` (at most ten digits) are accepted. Malformed or
out-of-range values fail before staging. Without an override, an owning Git
checkout uses its HEAD commit time; a Git-free source tree uses the stable
Unix epoch zero. The gzip header time is always zero. This makes repeated
packaging of the same sealed build deterministic without inventing a source
revision or using the current clock. Real Git worktrees and submodules keep
their own identities even when `.git` is a file.

## Layout and wrappers

| Path | Purpose |
|---|---|
| `tools/build` | Single supported build path; also `--check-toolchain` |
| `tools/test <suite>` | Suite runner; `--help` lists suites |
| `tools/package` | Standalone artifact builder |
| `native/` | C bridge sources and the one public ABI header |
| `src/libbpf_mojo/` | Typed Mojo owners and one internal FFI module |
| `tests/native/`, `tests/mojo/`, `tests/live/` | ABI, boundary, and live-kernel evidence |
| `examples/` | Small owned C eBPF fixtures and Mojo consumers |

Wrappers print their underlying pinned commands to the build log and return
nonzero on failure. A skipped selected test fails its suite, never
success evidence: host-only lanes declare live omissions as `NOT_RUN`
before selection, and privileged live suites report skip (exit 77),
which blocks qualification instead of passing.

## Verified toolchain probes

The following was verified against Mojo 1.1.0 by compiling and running
small probes; skill guidance alone was not trusted. Probe sources were
disposable development checks, not shipped tests.

- Integers: `UInt64`/`Int` are exact, including values above 2^53 and
  round-trips through `String`. Unsigned overflow **wraps silently** even
  in unoptimized builds.
- `std.ffi.external_call` calls linked C (a `getpid` probe returned the
  caller's PID). `std.ffi.OwnedDLHandle` loads a named `.so` at runtime
  with `get_function` and `check_symbol`; a missing library raises a
  catchable error. `get_function` takes the return type only and does not
  validate argument types.
- Files: `open()` read/write round-trips; `std.pathlib.Path.exists()`
  works; `std.os` provides `mkdir`, `listdir`, `remove`, and `getenv`.
  `os.rename` does not exist.
- `std.time.perf_counter_ns` and `std.time.sleep` compile; there is no
  `std.time.now`.
- `mojo build` offers `-O` levels (default 3), `-g` levels (default
  none), and `--sanitize address|thread`. There is no Mojo UBSan flag.

## Library behavior

Implemented: the native bridge (`native/`, frozen in `docs/abi-v1.md`)
is built with CMake plus Ninja through `tools/build`. The default
`tools/test native` requires every selected test to pass: framing,
synthetic staging, live poll/attach/map suites, owned C fixtures,
and the generic ABI probe. A required live test that exits 77, or
a probe subcase that skips, fails the suite even though CTest's own
aggregate status stays zero, so the default scope needs collection
privilege for its live selection. `tools/test native --host-only`
runs the declared offline scope under the no-BPF guard and publishes
the omitted live cases as named `NOT_RUN` lines; any skip inside
that host selection means broken provisioning and fails the run.
Sanitizer evidence: `tools/build --sanitize` configures a
separate `build-san/` tree with AddressSanitizer and UBSan using the
pinned gcc (this Ubuntu release ships no clang-21 compiler-rt);
`LMB_BUILD_DIR=build-san tools/test native --host-only` runs the
host scope there. CTest sets `ASAN_OPTIONS=allocator_may_return_null=1`
for the framing suite (it intentionally passes a giant allocation size);
repeat that variable when running the sanitizer binaries by hand.
Keep native sanitizer evidence separate from Mojo sanitizer evidence.

Implemented: the Mojo layer (`src/libbpf_mojo/`) holds one internal
FFI module with every foreign declaration plus layout assertions on
both sides, move-only session owners with deterministic
destruction, lazy native loading so import never requires
collection privileges, and explicit checked helpers wherever
external arithmetic applies. `tools/test mojo` proves it
(layout/ownership/error/batch suites plus compile-fail/pass
probes); `tools/test mojo --host-only` runs the same files
under the guard with the privilege branch declared `NOT_RUN`.

Implemented: the tracepoint example (`examples/tracepoint/`,
`tests/live/`, `tests/package/`, `tests/runner/`,
`tests/selftest/`) proves real load/attach/event flow through
Mojo, fault cleanup back to the owned-FD baseline, and
clean-room packaging. `tools/test live-tracepoint` reconciles
128 real observations on the Mojo lane and repeats them on a C
reference consumer of the identical object; `tools/test cleanup`
injects bad attach, bad object, post-first-link failure, and
interrupted poll; `tools/test package` rebuilds the tarball and
runs it in a fresh container with neither compiler nor Pixi;
`tools/test runner` and `tools/test selftest` cover runner
teardown and the Python probes without privilege. The live
suites need BPF privilege and `bpftool`, and report SKIP
without them.

## Compile-fail diagnostic checks

Compile-fail tests require a nonzero compiler exit and complete supported
text diagnostics: each located error or note has one source excerpt followed
by renderer carets. Only primary error messages can satisfy a fixture's CHECK;
notes, source excerpts, import context, final driver trailers and the fixture's
exact path do not contribute. A MUST-REJECT control requires an admitted primary
error whose messages all lack CHECK. Empty, truncated, unsupported or ambiguous
rendering fails either kind of fixture, even after an earlier matching error.

`./tools/test selftest` includes fake-compiler controls of the shipped matcher.
These establish diagnostic interpretation separately from fresh compilation of
all compile-fail fixtures with the pinned compiler in `./tools/test mojo`.

## Sanitizer and debugger support (Mojo 1.1.0)

Evaluated with isolated deliberately faulty fixtures on x86-64, plus
the clean suites:

- `mojo build --sanitize address` works: a Mojo heap overflow is
  caught with Mojo symbol names, and `-g` adds the exact
  `file.mojo:line`. Exit is `SIGABRT` with
  `ASAN_OPTIONS=abort_on_error=1`.
- `mojo run --sanitize address` is broken: the JIT cannot
  materialize the `__asan_*` symbols. Sanitized Mojo runs require
  an ahead-of-time `mojo build`.
- Mixed language is a real coverage gap: an uninstrumented C
  overflow called from an ASan Mojo binary is missed; the same
  object built with `-fsanitize=address` is caught with its C
  source line. Native code must be built sanitized too (the
  `build-san/` tree); a Mojo-side flag alone proves nothing about C.
- `mojo build --sanitize thread` is unusable on the tested
  machine: the runtime dies at startup inside tcmalloc
  (`MmapAligned` failure), identically on host and container and
  with ASLR disabled. No concurrent calling model is proposed
  (single-threaded synchronous owners), so ThreadSanitizer is not
  applicable; revisit if threading is introduced. There is no Mojo
  UBSan flag.
- Clean suites ahead-of-time plus ASan: 46/47 pass with zero
  sanitizer findings (including no LeakSanitizer leaks at exit).
  The one failure is the RSS-growth bound under the ASan
  quarantine allocator, a non-sanitizer invariant.
- `mojo debug` (LLDB) batch mode works and stops with the bug
  class as the stop reason; `-g` binaries carry standard debug
  sections. No system gdb/lldb is required.

## Shipped artifact baseline

- Shipped Mojo binaries build with `--target-cpu x86-64-v2`. The
  default `znver4` target emits AVX instructions that fault on
  older CPUs; the packaged artifacts must run anywhere in the
  declared baseline (verified: zero ymm/zmm instructions).
- The packaged examples need glibc >= 2.38 (measured floor across
  the bridge, trigger, reference, and Mojo collector), libelf,
  zlib, Linux >= 7.0, and BPF privilege. Same-host containers
  cannot qualify other CPUs or older userlands.
- `tools/package` records these floors in the packaged README and
  refuses sanitizer trees: `build-san/` binaries need ASan/UBSan
  runtimes and are test-only, never releasable.

## Compiler settings

- Shipped builds keep the compiler's normal safety checks enabled.
  Explicit input validation never depends on debug assertions.
- Optimization and debug info use `-O` and `-g` levels recorded in the
  build log. Sanitized Mojo runs use ahead-of-time
  `mojo build --sanitize address`, never `mojo run --sanitize`.
- The Mojo driver offers address and thread sanitizers only; native C
  additionally builds with address/undefined-behavior sanitizers. Each
  result is separate evidence: a clean native run does not prove
  Mojo-generated accesses were checked.
- No compiler internals, unfinished async, or unstable APIs are used.
  `mojo format` keeps sources canonical.
