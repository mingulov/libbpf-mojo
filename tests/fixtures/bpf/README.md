<!-- SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception -->
# Native test fixtures

These C sources are **synthetic test programs**, not product probes.
They exist so the native test suites can prove loading, attachment,
ring consumption, and map access against a known object. Fixture
behavior carries no product meaning: a passing fixture test proves the
bridge transport, never any application's event semantics.

## Files

- `ring_test.bpf.c`: two tracepoint programs plus maps.
  - Program `on_getpid` on `syscalls:sys_enter_getpid` emits a
    16-byte record (pid, tag `0xA02`, timestamp) for the one PID
    stored in the `filter` map (key 0). Everything else is ignored
    in BPF, which keeps tests deterministic under host load. Tests
    must trigger it with real syscalls: a vDSO-served `getpid()`
    never reaches the tracepoint.
  - Program `on_getpid_small` on the same tracepoint emits an
    8-byte record (pid, tag `0xA03`) under the same filter, for
    skip-loop tests with a small raw cap.
  - `events`: ring buffer feeding the poll tests.
  - `filter`: hash map holding the target PID (key 0) plus the
    test's PID-namespace identity (keys 1-2: `st_dev`/`st_ino` of
    `/proc/self/ns/pid`). BPF observes the initial namespace, so
    matching uses `bpf_get_ns_current_pid_tgid`; the same fixture
    works on the host and in containers. Tests assume no nested PID
    namespace mints a colliding PID during the run.
  - `test_hash`: hash map for ordinary map round-trips.
  - `test_percpu`: per-CPU array for stride/spread rules.
  - `test_lru`: LRU per-CPU hash; per-CPU sizing must cover it.
  - `test_odd`: hash map with 5-byte values for stride padding.
  - `test_percpu_odd`: per-CPU array with 5-byte values (stride 8).
  - `test_stats`: array counting program runs, matched attempts,
    and failed ring submissions (keys 0-2).
  - `test_pinned`: hash map carrying `LIBBPF_PIN_BY_NAME` metadata.
    The bridge must disable pinning before loading; honoring it
    would fail the load or escape a filesystem pin.

## Build

The CMake build compiles fixtures with the pinned `clang` BPF target
and libbpf headers; see the top-level `CMakeLists.txt`. Fixture
objects land in the build tree, never in the source tree.

## Privileges

Loading and attaching fixtures needs collection privileges. The
native suites report SKIP (not success) when the kernel refuses with
a permission error, and prove behavior in a privileged isolated
environment. Fixture programs attach only to the getpid tracepoint
and emit pids and timestamps; they read no payloads.
