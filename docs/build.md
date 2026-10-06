# Build and toolchain guide

This repository builds with a pinned Mojo toolchain managed by pixi, plus
system C tooling for the native bridge. Exact versions live in
`toolchain.lock.json`; the `pixi.lock` file carries authoritative conda
package hashes.

## Prerequisites

- `pixi` 0.81.0 exactly, to create the Mojo environment.
- System `clang`, `cmake`, `ninja`, `make`, and `bpftool` at the locked
  versions, for the native bridge and test fixtures.
- `libelf` headers (`libelf-dev 0.194-4`), `zlib` headers, and
  `pkg-config` at the locked versions, for the libbpf source build. The
  native build verifies them with `pkg-config` and fails closed when
  they are absent; install them with `apt-get install libelf-dev`
  (plus its dependencies) before building native targets.
- `python3` for development-only validation tooling.

Run `pixi install` once after cloning. Every Mojo command below runs inside
that environment; the `tools/` wrappers do this for you.

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
nonzero on failure. A skipped privileged test is reported as skipped, never
as success evidence.

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
is built with CMake plus Ninja through `tools/build`, and proven by
`tools/test native` (framing, synthetic staging, live poll/attach/map
suites plus owned C fixtures). Tests needing collection privileges
report SKIP without them and prove behavior in a privileged isolated
environment. Sanitizer evidence: `tools/build --sanitize` configures a
separate `build-san/` tree with AddressSanitizer and UBSan using the
pinned gcc (this Ubuntu release ships no clang-21 compiler-rt);
`LMB_BUILD_DIR=build-san tools/test native` runs the same suites
there. CTest sets `ASAN_OPTIONS=allocator_may_return_null=1` for the
framing suite (it intentionally passes a giant allocation size);
repeat that variable when running the sanitizer binaries by hand.
Keep native sanitizer evidence separate from Mojo sanitizer evidence.

Implemented: the Mojo layer (`src/libbpf_mojo/`) holds one internal
FFI module with every foreign declaration plus layout assertions on
both sides, move-only session owners with deterministic
destruction, lazy native loading so import never requires
collection privileges, and explicit checked helpers wherever
external arithmetic applies. `tools/test mojo` proves it
(layout/ownership/error/batch suites plus compile-fail/pass
probes).

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
