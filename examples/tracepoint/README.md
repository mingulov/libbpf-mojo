# Tracepoint example

Small real collection through the whole stack: a C eBPF probe on the
`getpid` tracepoint, the native bridge, and a Mojo owner. A C
trigger fires 128 direct syscalls behind a readiness barrier; the
collector reconciles the ring payloads against a BPF sequence
counter and the trigger's independent ledger.

## Files

- `probe.bpf.c`: the probe. Filters to one trigger identity
  (TGID plus PID-namespace device/inode, matched with
  `bpf_get_ns_current_pid_tgid`), emits `{seq, tgid, tag}` records
  to the `events` ring, counts emissions in the `count` map.
- `event.h`: the 16-byte wire payload shared by the probe and the
  C reference consumer. The Mojo collector parses the same layout
  with explicit little-endian reads.
- `trigger.c`: the workload. Waits for a pidfile plus the
  readiness barrier, fires direct `syscall(SYS_getpid)` traps,
  writes the ledger. Direct syscalls are the explicit workload
  contract: the run must emit exactly `count` traps, and any libc
  `getpid` call would be an extra trap — x86-64 has no `getpid`
  vDSO entry and glibc >= 2.25 keeps no PID cache — i.e. an
  unaccounted observation.
- `main.mojo`: the Mojo collector. Opens, loads, configures,
  attaches, releases the trigger, collects, settles, and writes a
  `KEY=VALUE` record. Exits 0 when complete, 3 on a short window,
  77 without privilege, 2 on usage errors, 1 otherwise.
- `run-tracepoint.sh`: the packaged demo runner. Resolves
  everything from the package root.

## Run it

From a source checkout, after `tools/build`:

    ./tools/test live-tracepoint   # Mojo lane + C reference lane
    ./tools/test cleanup           # fault injection + FD baselines
    ./tools/test runner            # runner teardown vs fake doubles
    ./tools/test selftest          # unprivileged stdlib probes

The live suites need BPF privilege and `bpftool`; without
privilege they report SKIP, never success. The runner and
selftest suites need neither privilege nor containers.

From the `tools/package` tarball, on x86-64-v2 Linux >= 7.0
with glibc >= 2.38, libelf, zlib, and privilege:

    ./run-tracepoint.sh [want-count] [timeout-s]

## Design notes

- The trigger never calls `getpid` itself: any post-attach call
  would be a 129th observation. It learns its TGID through a
  pidfile from the parent.
- Namespace identity comes from C `stat`, or equivalently from
  coreutils `stat -L`: without `-L`, stat reports the
  `/proc/self/ns/*` symlink itself (a fresh wrong inode per call)
  instead of following it to the stable namespace identity.
- Kernel-side object teardown occasionally lags the last close by
  a fraction of a second; the suites poll briefly rather than
  asserting synchronously.
