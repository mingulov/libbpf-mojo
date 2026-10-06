#!/usr/bin/env python3
"""Live tracepoint proof: 128 real observations through Mojo.

Spawns the C trigger (128 direct getpid traps behind a readiness
barrier), collects them with the Mojo owner, and reconciles three
independent measurements: the ring payloads, the BPF sequence
counter, and the trigger ledger. Then repeats the identical run
with the C reference consumer to isolate boundary failures.

Asserts the exact 0..127 sequence in order (single-threaded
trigger), zero malformed/dropped/mismatched records, and no
leftover BPF programs, maps, or links afterwards. Exit 0 on pass,
77 on explicit skip (no privilege, no bpftool), 1 on failure.
Standard library only.
"""

import os
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import liveutil
from liveutil import Fail, Skip  # noqa: E402,F401

WANT = 128


def check_record(label, out):
    rec = liveutil.parse_record(out)
    want = {
        "observed": str(WANT),
        "want": str(WANT),
        "counter": str(WANT),
        "received": str(WANT),
        "delivered": str(WANT),
        "malformed": "0",
        "dropped": "0",
        "mismatches": "0",
        "complete": "true",
    }
    for key, value in want.items():
        if rec.get(key) != value:
            raise Fail("%s: record %s=%r, want %r (full: %r)"
                       % (label, key, rec.get(key), value, rec))
    seqs = rec.get("seqs", "").split(",") if rec.get("seqs") else []
    if seqs != [str(i) for i in range(WANT)]:
        raise Fail("%s: sequence is not exactly 0..%d in order "
                   "(got %d entries)" % (label, WANT - 1, len(seqs)))
    return rec


def drive_case(label, trig, coll, ledger, out):
    """Classify a started run; return the checked record.

    The collector's verdict comes first: on a privilege SKIP the
    trigger is still parked on the barrier, and reporting the
    trigger's wait as the failure would mislabel the row.
    """
    try:
        coll_out, _ = coll.communicate(timeout=180)
    except subprocess.TimeoutExpired:
        raise Fail("%s: collector timed out" % label)
    if coll.returncode == liveutil.SKIP:
        raise Skip("%s: collector reports no privilege" % label)
    try:
        trig_rc = trig.wait(timeout=30)
    except subprocess.TimeoutExpired:
        raise Fail("%s: trigger timed out" % label)
    if trig_rc != 0:
        raise Fail("%s: trigger exit %d" % (label, trig_rc))
    if coll.returncode != 0:
        raise Fail("%s: collector exit %d: %s"
                   % (label, coll.returncode, coll_out.strip()))
    if not os.path.exists(out):
        raise Fail("%s: collector wrote no record" % label)
    with open(ledger, "r", encoding="utf-8") as handle:
        words = handle.read().strip().split()
    expect_ledger = ["tgid=%d" % trig.pid, "count=%d" % WANT]
    if words != expect_ledger:
        raise Fail("%s: ledger %r, want %r" % (label, words, expect_ledger))
    return check_record(label, out)


def run_case(label, collector, tmp):
    elf = liveutil.need_file(os.path.join(liveutil.EXAMPLES, "probe.bpf.o"))
    trigger = liveutil.need_file(
        os.path.join(liveutil.EXAMPLES, "tracepoint_trigger"))
    collector = liveutil.need_file(collector)
    ready = os.path.join(tmp, "ready")
    ledger = os.path.join(tmp, "ledger")
    out = os.path.join(tmp, "out")
    pidfile = os.path.join(tmp, "tgid")
    dev, ino = liveutil.ns_identity()
    env = dict(os.environ)
    env["LMB_NATIVE_LIB"] = liveutil.need_file(liveutil.NATIVE_LIB)

    before = liveutil.snapshot()
    trig = coll = None
    outcome_exc = None
    result = None
    try:
        # The trigger learns its TGID from us through an atomically
        # published pidfile: it must never call getpid itself, or
        # the reconciliation gains a 129th observation.
        trig = subprocess.Popen(
            [trigger, ready, ledger, str(WANT), "60", pidfile])
        liveutil.publish(pidfile, str(trig.pid))
        try:
            coll = subprocess.Popen(
                [collector, elf, str(trig.pid), str(dev), str(ino),
                 ready, out, str(WANT), "60"],
                env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True)
        except OSError as exc:
            raise Fail("%s: cannot start collector: %s" % (label, exc))
        result = drive_case(label, trig, coll, ledger, out)
    except BaseException as exc:
        if isinstance(exc, OSError):
            exc = Fail("%s: os error: %s" % (label, exc))
        outcome_exc = exc
    # Teardown order is fixed: reap first, audit second, original
    # outcome last. The audit runs on every path — pass, Fail,
    # Skip, OSError, or interruption during the flow — because a
    # row that cannot prove cleanup cannot pass. A Skip that
    # leaked becomes a Fail; anything Fail-shaped merges both
    # messages; an interrupt stays an interrupt (noted on
    # stderr when the audit fails too).
    try:
        liveutil.reap(trig)
        liveutil.reap(coll)
    finally:
        try:
            liveutil.assert_no_leftover(before, label)
        except Fail as exc:
            if outcome_exc is None:
                outcome_exc = exc
            elif isinstance(outcome_exc, (Fail, Skip)):
                outcome_exc = Fail("%s; also: %s" % (outcome_exc, exc))
            else:
                print("teardown also failed: %s" % exc, file=sys.stderr)
    if outcome_exc is not None:
        raise outcome_exc
    print("PASS %s: %d/%d reconciled, counter=%s, no leftover"
          % (label, WANT, WANT, result["counter"]))


def main():
    liveutil.require_privilege()
    mojo_main = os.path.join(liveutil.EXAMPLES, "tracepoint_main")
    ref = os.path.join(liveutil.EXAMPLES, "reference_consumer")
    with tempfile.TemporaryDirectory(prefix="tp-mojo-") as tmp:
        run_case("mojo", mojo_main, tmp)
    with tempfile.TemporaryDirectory(prefix="tp-ref-") as tmp:
        run_case("reference", ref, tmp)


if __name__ == "__main__":
    sys.exit(liveutil.run_main(main))
