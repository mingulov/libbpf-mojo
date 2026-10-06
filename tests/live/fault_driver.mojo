# SPDX-License-Identifier: GPL-3.0-or-later

"""Cleanup-suite fault driver: inject failures through the Mojo owner.

Usage: fault_driver <mode> <elf> <status> <go> <bye>

Modes:
  bad_attach  attach a nonexistent program; expect an attach error
  bad_elf     open garbage bytes (<elf> is the garbage file); expect
              a load error (ELF parsing rejects the input)
  rollback    attach [good, bad] (expect attach error rolling back
              the first link), then attach [good] alone, which must
              succeed, proving no half-attached state survives

Protocol with the test driver: write "ready" to <status>, spin
until <go> exists, run the fault, write the outcome line to
<status>, spin until <bye> exists, then close and exit. The parent
samples /proc/<pid>/fd between the outcome write and <bye>, so the
owned-FD count is observed while the session is fully closed but
the process is still alive.

Exit 0 when the expected fault (and only it) happened, 77 when a
privileged step is denied, 1 otherwise.
"""
from std.sys import argv, exit
from std.pathlib import Path
from std.time import perf_counter_ns, sleep

from libbpf_mojo._ffi import ATTACH_TRACEPOINT, OP_ATTACH, OP_LOAD
from libbpf_mojo.error import EPERM, LmbError
from libbpf_mojo.session import AttachSpec, Session

comptime EACCES = Int32(-13)


def wait_file(path: String) raises:
    # Bounded backstop: the parent always answers within a minute,
    # so 300s here only fires if the parent is gone.
    var start_ns = perf_counter_ns()
    var budget_ns = 300 * 1000000000
    while not Path(path).exists():
        if perf_counter_ns() - start_ns >= budget_ns:
            raise Error("timed out waiting for " + path)
        sleep(0.005)


def good_site() -> AttachSpec:
    return AttachSpec(
        String("trace_probe"),
        ATTACH_TRACEPOINT,
        String("syscalls"),
        String("sys_enter_getpid"),
    )


def bad_site() -> AttachSpec:
    return AttachSpec(
        String("no_such_program"),
        ATTACH_TRACEPOINT,
        String("syscalls"),
        String("sys_enter_getpid"),
    )


def is_privilege(op: UInt32, code: Int32) -> Bool:
    # Same rule as the example collector: EPERM always means the
    # environment; EACCES only at attach (post-load); load-time
    # EACCES fails closed since the verifier is a suspect.
    if code == EPERM:
        return True
    return code == EACCES and op == OP_ATTACH


def mode_bad_attach(elf: Span[UInt8, _]) raises LmbError -> String:
    var session = Session.open(elf, String("events"), UInt32(64))
    var outcome: String
    try:
        session.load()
        var specs = List[AttachSpec]()
        specs.append(bad_site())
        session.attach(specs^)
        outcome = "fault=none unexpected-success"
    except e:
        if is_privilege(e.operation, e.code):
            outcome = "privilege=1"
        elif e.operation == OP_ATTACH:
            outcome = "fault=attach code=" + String(Int(e.code))
        else:
            outcome = "fault=wrong op=" + String(Int(e.operation))
    try:
        session.close()
    except e:
        pass
    return outcome^


def mode_bad_elf(raw: Span[UInt8, _]) raises LmbError -> String:
    # Garbage is rejected at load (ELF parsing), not at open: open
    # only retains the bytes. The operation is the contract; the
    # exact libbpf errno for malformed input is an implementation
    # detail, so only the operation is asserted.
    var session = Session.open(raw, String("events"), UInt32(64))
    var outcome = String("fault=none unexpected-success")
    try:
        session.load()
    except e:
        if e.operation == OP_LOAD:
            outcome = "fault=load"
        else:
            outcome = "fault=wrong op=" + String(Int(e.operation))
    try:
        session.close()
    except e:
        pass
    return outcome^


def mode_rollback(elf: Span[UInt8, _]) raises LmbError -> String:
    var session = Session.open(elf, String("events"), UInt32(64))
    var outcome: String
    try:
        session.load()
        var specs = List[AttachSpec]()
        specs.append(good_site())
        specs.append(bad_site())
        try:
            session.attach(specs^)
            outcome = "fault=none unexpected-success"
        except e:
            if is_privilege(e.operation, e.code):
                outcome = "privilege=1"
            elif e.operation == OP_ATTACH:
                var retry = List[AttachSpec]()
                retry.append(good_site())
                try:
                    session.attach(retry^)
                    session.detach()
                    outcome = "fault=attach reattach=ok"
                except e2:
                    outcome = "fault=attach reattach=failed"
            else:
                outcome = "fault=wrong op=" + String(Int(e.operation))
    except e:
        if is_privilege(e.operation, e.code):
            outcome = "privilege=1"
        else:
            outcome = "setup=failed op=" + String(Int(e.operation))
    try:
        session.close()
    except e:
        pass
    return outcome^


def run_mode(mode: String, data: Span[UInt8, _]) raises -> String:
    """Run one fault mode; unexpected bridge failures stay visible."""
    try:
        if mode == "bad_attach":
            return mode_bad_attach(data)
        if mode == "bad_elf":
            return mode_bad_elf(data)
        return mode_rollback(data)
    except e:
        return String("driver=failed ") + String(e)


def main() raises:
    var args = argv()
    if len(args) != 6:
        print("usage: fault_driver <mode> <elf> <status> <go> <bye>")
        exit(2)
    var mode = args[1]
    if mode != "bad_attach" and mode != "bad_elf" and mode != "rollback":
        print("unknown mode: " + mode)
        exit(2)
    Path(args[3]).write_text(String("ready\n"))
    wait_file(args[4])
    var outcome: String
    try:
        var data = Path(args[2]).read_bytes()
        outcome = run_mode(mode, Span(data))
    except e:
        outcome = "driver=failed " + String(e)
    Path(args[3]).write_text(outcome + "\n")
    wait_file(args[5])
    if outcome == "privilege=1":
        exit(77)
    if (
        outcome.startswith("fault=attach")
        or outcome.startswith("fault=load")
    ):
        exit(0)
    print("unexpected outcome: " + outcome)
    exit(1)
