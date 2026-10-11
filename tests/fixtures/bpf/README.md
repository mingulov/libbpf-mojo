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
environment. The tracepoint fixture programs attach only to the getpid
tracepoint and emit pids and timestamps; they read no payloads.

## Generic maps and XDP control

`generic_maps.bpf.c` is a C control object for native map geometry and
explicit XDP testing. It declares BTF maps `counter` (ARRAY, u32 key,
u64 value, one entry), `values` (HASH, u32/u64, eight entries),
`percpu_values` (PERCPU_ARRAY, u32 key, 13-byte byte-array value,
one entry), and `percpu_hash` (PERCPU_HASH, the same key/value,
eight entries). A per-CPU value occupies a 16-byte padded slot.

Its scalar packet oracle is explicit: each invocation increments
`counter[0]` once when the lookup succeeds; an available first input byte
equal to zero returns XDP_DROP (1), otherwise it returns XDP_PASS (2).
No packet or context output is modified. Map helpers are used with the
source's truthful `Apache-2.0 WITH LLVM-exception` ELF license string.

Host tests compile and parse this standard ELF/BTF object locally but
intercept all BPF syscalls. Parsing and scripted map operations do not
establish loading, verifier acceptance, runtime execution or target
support. The fixture is an independent test control, not production
kernel code.

## Generic tracepoint events control

`generic_events.bpf.c` is an independent C fixture with program `on_getpid`
for `syscalls:sys_enter_getpid`, a 65,536-byte `events` ring, an ARRAY
`filter` with u32 selected TID at key zero, and `producer_counts` with
u64 attempted/successful/failed counters at key zero. Selection uses the
low 32-bit initial-PID-namespace TID, so live tests must establish that
namespace identity. Events carry a 32-byte little-endian test contract:
u16 version/size at 0/2, u32 TGID/TID/CPU at 4/8/12, u64 attempted
sequence/time at 16/24. Sequence advances on attempts, including output
failure. `generic_events.h` specifies the fixture layout; the library
treats all payloads as opaque.

Both new files use `Apache-2.0 WITH LLVM-exception`; the BPF source carries
that exact truthful ELF license string. Existing fixture declarations and
licenses are preserved. Compilation/parsing do not establish target
verifier or helper acceptance.

Native host controls use this object's parsed program/map metadata and
a separate 16-byte sequence/complement payload. They script loaded state
and the attachment boundary, and feed controlled mapped ring records to
the actual pinned libbpf reader. No host fixture load, attach or BPF
syscall executes. The 16-byte transport payload frames to 24 bytes;
the 32-byte fixture payload would frame to 40 bytes in later live tests.
