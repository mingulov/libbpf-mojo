#!/usr/bin/env python3
"""Cleanup proof: failed or interrupted BPF usage releases everything.

Drives the Mojo fault driver (bad_attach, bad_elf, rollback) and
the C reference's --eintr lane through a status/go/bye handshake:
the child writes "ready", parks on <go> while the parent samples
its exact FD set, runs the fault, writes a recognized outcome
line, parks on <bye> while the parent re-samples, then exits.
Each row asserts the expected outcome, an exactly reconciled FD
set, and no surviving owned BPF objects afterwards.

A complete line proves content visibility, not writer closure:
the writer's FD may still be open when the newline lands, which
would contaminate either FD sample. The parent therefore waits
for the writer FD to close before sampling. Children that fail
before "ready" publish an early outcome line instead; those rows
skip FD comparison (no baseline exists) but still join the
child, classify the verdict, and run the leftover audit.

The bad_elf garbage input lives in the row's private temporary
directory, never at a predictable shared path. Exit 0 on pass,
77 on explicit skip (no privilege, no bpftool), 1 on failure.
Standard library only.
"""

import os
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import liveutil
from liveutil import Fail, Skip  # noqa: E402,F401

READY_TIMEOUT = 60.0
OUTCOME_TIMEOUT = 120.0
WRITER_TIMEOUT = 10.0

# Expected outcome prefixes per row. Recognition is by family
# (any complete line from a known outcome family ends the wait);
# acceptance is per row in drive_case. Anything else, including
# a torn concurrent write, keeps waiting instead of becoming a
# verdict.
OUTCOMES = {
    "bad_attach": ("fault=attach",),
    "bad_elf": ("fault=load",),
    "rollback": ("fault=attach reattach=ok",),
    "eintr": ("eintr=1 reusable=1",),
}
FAMILIES = ("fault=", "privilege=", "driver=", "setup=", "eintr=")


class ChildGone(Exception):
    """The child exited while a verdict was still pending."""

    def __init__(self, rc, seen):
        super().__init__("child exited %d" % rc)
        self.rc = rc
        self.seen = seen


def is_zombie(pid):
    """True when pid is a zombie: present but already dead.

    A zombie's fd directory denies listing (EACCES), so access
    errors must consult this before crying confinement. Never
    reaps: the callers own the child lifecycle.
    """
    try:
        with open("/proc/%d/stat" % pid, "r", encoding="utf-8") as handle:
            fields = handle.read().rsplit(")", 1)[1].split()
    except OSError:
        return False
    return bool(fields) and fields[0] == "Z"


def fds_of(pid):
    """Exact FD set of a live process, or None if it is gone.

    A zombie counts as gone (its fd directory denies listing);
    a momentary denial on a live process is retried, and only
    a persistent one fails (hidepid?).
    """
    deadline = time.monotonic() + 1.0
    while True:
        try:
            return set(int(name)
                       for name in os.listdir("/proc/%d/fd" % pid))
        except (FileNotFoundError, NotADirectoryError):
            return None
        except PermissionError:
            if is_zombie(pid):
                return None
            if time.monotonic() >= deadline:
                raise Fail("cannot read /proc/%d/fd (hidepid?)"
                           % pid)
            time.sleep(0.005)


def wait_status_line(status, proc, timeout_s, label, ready_ok):
    """First complete ready/outcome line, or ChildGone.

    A written verdict always wins over child death: the content
    check runs before the liveness check, so a verdict written
    just before a crash is still classified, not masked.
    """
    deadline = time.monotonic() + timeout_s
    seen = None
    while True:
        try:
            with open(status, "r", encoding="utf-8") as handle:
                seen = handle.read()
        except OSError:
            seen = None
        if seen is not None and seen.endswith("\n"):
            line = seen[:-1]
            if line.startswith(FAMILIES):
                return line
            if ready_ok and line == "ready":
                return line
        if proc.poll() is not None:
            raise ChildGone(proc.returncode, seen)
        if time.monotonic() >= deadline:
            raise Fail("%s: no recognized line (last: %r)"
                       % (label, seen))
        time.sleep(0.005)


def wait_writer_closed(pid, path, label):
    """Wait until no FD of pid targets path (R3).

    Identity is by device/inode, not pathname spelling:
    /proc fd targets are resolved paths, so a status file
    reached through a symlinked directory never matches the
    unresolved spelling (a symlinked TMPDIR bypassed the wait
    entirely). The canonicalized spelling is kept as an OR
    fallback for replaced files, whose inode already differs.
    Returns True once the writer closed, False if the process
    is gone. Sampling an FD set while the status writer is
    still open counts a transient FD as owned state.
    """
    try:
        expect = os.stat(path)
        want = (expect.st_dev, expect.st_ino)
    except OSError:
        want = None
    real = os.path.realpath(path)
    deadline = time.monotonic() + WRITER_TIMEOUT
    while True:
        try:
            names = os.listdir("/proc/%d/fd" % pid)
        except (FileNotFoundError, NotADirectoryError):
            return False
        except PermissionError:
            # A zombie's fd directory denies listing, so a
            # denial on a zombie means the process is gone, not
            # that the reader is confined. Any other momentary
            # denial is retried like a raced close; only one
            # that survives to the deadline fails.
            if is_zombie(pid):
                return False
            names = None
        if names is not None:
            for name in names:
                entry = "/proc/%d/fd/%s" % (pid, name)
                try:
                    target = os.readlink(entry)
                except OSError:
                    continue  # Raced a close; not our writer.
                if target == real or target == path:
                    break
                if want is not None:
                    try:
                        found = os.stat(entry)
                    except OSError:
                        continue  # Raced a close; not our writer.
                    if (found.st_dev, found.st_ino) == want:
                        break
            else:
                return True
        if time.monotonic() >= deadline:
            if names is None:
                raise Fail("%s: cannot read /proc/%d/fd (hidepid?)"
                           % (label, pid))
            raise Fail("%s: status writer still holds %s" % (label, path))
        time.sleep(0.005)


def classify_gone(case, gone, phase):
    """A dead child with no written verdict: exit code decides."""
    if gone.rc == liveutil.SKIP:
        raise Skip("%s: driver exited 77 during %s" % (case, phase))
    raise Fail("%s: driver exited %d during %s (last: %r)"
               % (case, gone.rc, phase, gone.seen))


def join(child, case):
    try:
        return child.wait(timeout=60)
    except subprocess.TimeoutExpired:
        raise Fail("%s: driver did not exit after bye" % case)


def drive_case(case, child, status, go, bye):
    """Run one handshake; return (outcome, fd-summary).

    Raises Skip/Fail. The child is always joined (or drained
    before a verdict Fail); reaping and the leftover audit belong
    to the caller and run even when this raises.
    """
    try:
        line = wait_status_line(status, child, READY_TIMEOUT,
                                "%s ready" % case, True)
    except ChildGone as gone:
        classify_gone(case, gone, "ready wait")
    early = line != "ready"
    base = None
    if not early:
        if not wait_writer_closed(child.pid, status, case):
            raise Fail("%s: driver exited after ready" % case)
        base = fds_of(child.pid)
        if base is None:
            raise Fail("%s: driver exited before the go barrier" % case)
        liveutil.publish(go, "go")
        try:
            outcome = wait_status_line(status, child, OUTCOME_TIMEOUT,
                                       "%s outcome" % case, False)
        except ChildGone as gone:
            classify_gone(case, gone, "outcome wait")
    else:
        outcome = line
    if outcome.startswith("privilege=1"):
        liveutil.publish(bye, "bye")
        rc = join(child, case)
        if rc != liveutil.SKIP:
            raise Fail("%s: privilege outcome but exit %d" % (case, rc))
        raise Skip("%s: driver reports no privilege" % case)
    if not any(outcome == prefix or outcome.startswith(prefix)
               for prefix in OUTCOMES[case]):
        # Drain the parked child before failing on its verdict.
        liveutil.publish(bye, "bye")
        try:
            child.wait(timeout=60)
        except subprocess.TimeoutExpired:
            pass  # Teardown reaps; the outcome is the verdict.
        raise Fail("%s: unexpected outcome %r" % (case, outcome))
    if not early:
        if not wait_writer_closed(child.pid, status, case):
            raise Fail("%s: driver exited after outcome" % case)
        after = fds_of(child.pid)
        if after is None:
            raise Fail("%s: driver exited before fd re-sampling" % case)
        if after != base:
            raise Fail("%s: fds %s -> %s (leaked %s, closed foreign %s)"
                       % (case, sorted(base), sorted(after),
                          sorted(after - base), sorted(base - after)))
        summary = "%d->%d" % (len(base), len(after))
    else:
        # No baseline exists before an early verdict, so there is
        # nothing exact to compare against; the join plus the
        # leftover audit below are the row's teardown proof.
        summary = "unsampled (early verdict)"
    liveutil.publish(bye, "bye")
    rc = join(child, case)
    if rc != 0:
        raise Fail("%s: driver exit %d after outcome %r"
                   % (case, rc, outcome))
    return outcome, summary


def run_case(case, tmp, elf, garbage):
    if case == "eintr":
        argv = [liveutil.need_file(os.path.join(
            liveutil.EXAMPLES, "reference_consumer")),
            "--eintr", elf]
    else:
        argv = [liveutil.need_file(os.path.join(
            liveutil.EXAMPLES, "fault_driver")), case]
        argv.append(garbage if case == "bad_elf" else elf)
    status = os.path.join(tmp, "status")
    go = os.path.join(tmp, "go")
    bye = os.path.join(tmp, "bye")
    argv += [status, go, bye]
    env = dict(os.environ)
    env["LMB_NATIVE_LIB"] = liveutil.need_file(liveutil.NATIVE_LIB)

    liveutil.require_privilege()
    before = liveutil.snapshot()
    try:
        child = subprocess.Popen(argv, env=env)
    except OSError as exc:
        raise Fail("%s: cannot start driver: %s" % (case, exc))

    # Teardown order is fixed: reap first, audit second, original
    # outcome last. The audit runs on every path — pass, Fail,
    # Skip, OSError, or interruption during the flow — because a
    # row that cannot prove cleanup cannot pass. A Skip that
    # leaked becomes a Fail; anything Fail-shaped merges both
    # messages; an interrupt stays an interrupt (noted on
    # stderr when the audit fails too).
    outcome_exc = None
    result = None
    try:
        result = drive_case(case, child, status, go, bye)
    except BaseException as exc:
        if isinstance(exc, OSError):
            exc = Fail("%s: os error: %s" % (case, exc))
        outcome_exc = exc
    try:
        liveutil.reap(child)
    finally:
        try:
            liveutil.assert_no_leftover(before, case)
        except Fail as exc:
            if outcome_exc is None:
                outcome_exc = exc
            elif isinstance(outcome_exc, (Fail, Skip)):
                outcome_exc = Fail("%s; also: %s" % (outcome_exc, exc))
            else:
                print("teardown also failed: %s" % exc, file=sys.stderr)
    if outcome_exc is not None:
        raise outcome_exc
    outcome, summary = result
    print("PASS %s: %s, fds %s, no leftover" % (case, outcome, summary))


def main():
    liveutil.require_privilege()
    elf = liveutil.need_file(os.path.join(liveutil.EXAMPLES, "probe.bpf.o"))
    for case in ("bad_attach", "bad_elf", "rollback", "eintr"):
        with tempfile.TemporaryDirectory(prefix="cu-%s-" % case) as tmp:
            garbage = os.path.join(tmp, "bad-elf.bin")
            with open(garbage, "wb") as handle:
                handle.write(b"not an ELF object\x00\x01\x02\x03" * 16)
            run_case(case, tmp, elf, garbage)


if __name__ == "__main__":
    sys.exit(liveutil.run_main(main))
