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

## Planned library behavior

Not yet implemented. Each item lands with its owning feature and tests;
no `native/` or `src/` product code exists yet.

- One internal FFI module holding every foreign declaration, with
  layout/width/signedness assertions on both sides of the boundary.
  String arguments to retrieved callables must use `as_c_string_span()`,
  never a raw `String`.
- Move-only Mojo session owners with deterministic destruction, lazy
  native loading so import never requires collection privileges, and
  explicit checked helpers wherever external arithmetic applies.
- The native bridge built with CMake plus Ninja through `tools/build`,
  with address/undefined-behavior sanitizer evidence kept separate from
  Mojo sanitizer evidence.

## Compiler settings

- Shipped builds keep the compiler's normal safety checks enabled.
  Explicit input validation never depends on debug assertions.
- Optimization and debug info use `-O` and `-g` levels recorded in the
  build log. Test builds add `mojo --sanitize address` where supported.
- The Mojo driver offers address and thread sanitizers only; native C
  additionally builds with address/undefined-behavior sanitizers. Each
  result is separate evidence: a clean native run does not prove
  Mojo-generated accesses were checked.
- No compiler internals, unfinished async, or unstable APIs are used.
  `mojo format` keeps sources canonical.
