# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

"""Tracepoint example collector: real load/attach/event flow in Mojo.

Usage: tracepoint_main <elf> <tgid> <ns-dev> <ns-ino> <ready-path>
                      <out-path> <want-count> <timeout-s>

Opens the probe object, configures the trigger filter, attaches to
the getpid tracepoint, then creates <ready-path> to release the
trigger and collects <want-count> observations. Writes a KEY=VALUE
settlement record to <out-path> and exits 0 when the window is
complete, 3 when it ended short (partial record, honest
complete=false), 77 when the kernel denies the privileged step
(EPERM anywhere, EACCES at attach; load-time EACCES fails closed
since verifier rejection and LSM denial are indistinguishable),
2 on usage errors, 1 on other failures. The collection window is
an elapsed-time deadline of <timeout-s> from the first poll.

Wire layout (see examples/tracepoint/event.h): each 16-byte payload
is seq u64 @0, tgid u32 @8, tag u32 @12, little-endian.
"""
from std.sys import argv, exit
from std.pathlib import Path
from std.time import perf_counter_ns

from libbpf_mojo._ffi import (
    ATTACH_TRACEPOINT,
    OP_ATTACH,
    read_u32_le,
    read_u64_le,
)
from libbpf_mojo.batch import decode_frame
from libbpf_mojo.error import EPERM, LmbError
from libbpf_mojo.session import AttachSpec, Session

comptime EACCES = Int32(-13)
comptime TP_TAG = UInt32(0xA04)


@fieldwise_init
struct Fail(Copyable, Writable):
    """A fatal example failure carrying its exit code."""

    var code: Int
    var message: String


def u32_le(value: UInt32) -> List[UInt8]:
    var out = List[UInt8]()
    for i in range(4):
        out.append(UInt8((value >> UInt32(i * 8)) & UInt32(0xFF)))
    return out^


def u64_le(value: UInt64) -> List[UInt8]:
    var out = List[UInt8]()
    for i in range(8):
        out.append(UInt8((value >> UInt64(i * 8)) & UInt64(0xFF)))
    return out^


def parse_u64(text: String) raises Fail -> UInt64:
    try:
        var n = Int(text)
        if n < 0:
            raise Error("negative number: " + text)
        return UInt64(n)
    except e:
        raise Fail(2, String("usage error: ") + String(e))


def parse_tgid(text: String) raises Fail -> UInt32:
    # Range-checked before narrowing: unsigned narrowing wraps
    # silently, which would filter a different identity.
    try:
        var n = Int(text)
        if n <= 0 or n > 0xFFFFFFFF:
            raise Error("tgid out of u32 range: " + text)
        return UInt32(n)
    except e:
        raise Fail(2, String("usage error: ") + String(e))


def close_quietly(mut session: Session):
    """Best-effort close; the deinit backstop still applies."""
    try:
        session.close()
    except e:
        pass


def must_attach(mut session: Session) raises LmbError:
    """Attach the example probe; structured errors propagate."""
    var specs = List[AttachSpec]()
    specs.append(
        AttachSpec(
            String("trace_probe"),
            ATTACH_TRACEPOINT,
            String("syscalls"),
            String("sys_enter_getpid"),
        )
    )
    session.attach(specs^)


def run(args: List[String]) raises Fail -> Int:
    """Full collection flow; every failure carries its exit code."""
    if len(args) != 9:
        raise Fail(
            2,
            String(
                "usage: tracepoint_main <elf> <tgid> <ns-dev> <ns-ino>"
                " <ready> <out> <want> <timeout-s>"
            ),
        )
    var elf_path = args[1]
    var want_tgid = parse_tgid(args[2])
    var ns_dev = parse_u64(args[3])
    var ns_ino = parse_u64(args[4])
    var ready_path = args[5]
    var out_path = args[6]
    var want: Int
    var timeout_s: Int
    try:
        want = Int(args[7])
        timeout_s = Int(args[8])
        if want <= 0 or want > 1000000 or timeout_s <= 0 or timeout_s > 3600:
            raise Error("count or timeout out of range")
    except e:
        raise Fail(2, String("usage error: ") + String(e))
    var elf: List[UInt8]
    try:
        elf = Path(elf_path).read_bytes()
    except e:
        raise Fail(1, String("cannot read object: ") + String(e))
    var session: Session
    try:
        session = Session.open(Span(elf), String("events"), UInt32(64))
    except e:
        raise Fail(1, String("open failed: ") + String(e))
    try:
        session.load()
        var key0 = u32_le(UInt32(0))
        var key1 = u32_le(UInt32(1))
        var key2 = u32_le(UInt32(2))
        var tgid_value = u64_le(UInt64(want_tgid))
        var dev_value = u64_le(ns_dev)
        var ino_value = u64_le(ns_ino)
        session.map_write(String("filter"), Span(key0), Span(tgid_value))
        session.map_write(String("filter"), Span(key1), Span(dev_value))
        session.map_write(String("filter"), Span(key2), Span(ino_value))
        must_attach(session)
    except e:
        # EPERM always means the environment denied the step.
        # EACCES at attach is also environmental: the program
        # already loaded, so the verifier accepted it. EACCES at
        # load is ambiguous (verifier vs LSM) and fails closed.
        var skipped = e.code == EPERM or (
            e.code == EACCES and e.operation == OP_ATTACH
        )
        var detail: String
        if skipped:
            detail = (
                String("privilege denied at op=")
                + String(Int(e.operation))
                + String(" code=")
                + String(Int(e.code))
            )
        else:
            detail = (
                String("setup failed op=")
                + String(Int(e.operation))
                + String(" code=")
                + String(Int(e.code))
                + String(": ")
                + e.message
            )
            if e.code == EACCES:
                detail += (
                    String(" (load-time EACCES fails closed:")
                    + String(" verifier or LSM)")
                )
        close_quietly(session)
        if skipped:
            raise Fail(77, detail)
        raise Fail(1, detail)
    try:
        Path(ready_path).write_text(String("ready\n"))
    except e:
        close_quietly(session)
        raise Fail(1, String("cannot release trigger: ") + String(e))
    var seqs = List[UInt64]()
    var mismatches = 0
    var dst = List[UInt8](length=4104, fill=UInt8(0))
    var start_ns = perf_counter_ns()
    var budget_ns = timeout_s * 1000000000
    while len(seqs) < want:
        var elapsed_ns = perf_counter_ns() - start_ns
        if elapsed_ns >= budget_ns:
            break
        var remain_ms = (budget_ns - elapsed_ns) // 1000000
        var wait_ms = Int32(1000)
        if remain_ms < 1000:
            wait_ms = Int32(remain_ms)
        var result = session.poll(dst, 0, UInt32(4104), wait_ms)
        if not result.is_batch():
            if result.is_error():
                close_quietly(session)
                raise Fail(1, String("poll: ") + String(result.error))
            continue
        try:
            var frame = decode_frame(Span(dst), 0, result.written)
            if len(frame.payload) != 16:
                mismatches += 1
                continue
            var base = Span(frame.payload).unsafe_ptr()
            var seq = read_u64_le(base, 0)
            var tgid = read_u32_le(base, 8)
            var tag = read_u32_le(base, 12)
            if tgid != want_tgid or tag != TP_TAG:
                mismatches += 1
                continue
            seqs.append(seq)
        except e:
            close_quietly(session)
            raise Fail(1, String("decode: ") + String(e))
    var counter = UInt64(0)
    try:
        var key = u32_le(UInt32(0))
        var counter_bytes = session.map_read(
            String("count"), Span(key), UInt32(8)
        )
        if len(counter_bytes.data) == 8:
            counter = read_u64_le(
                Span(counter_bytes.data).unsafe_ptr(), 0
            )
    except e:
        close_quietly(session)
        raise Fail(1, String("counter read: ") + String(e))
    var received: UInt64
    var delivered: UInt64
    var malformed: UInt64
    var dropped: UInt64
    try:
        var stats = session.stats()
        received = stats.received
        delivered = stats.delivered
        malformed = stats.malformed
        dropped = stats.dropped
        session.detach()
    except e:
        close_quietly(session)
        raise Fail(1, String("settle: ") + String(e))
    var observed = len(seqs)
    var complete = observed == want and mismatches == 0
    var csv = String("")
    for i in range(observed):
        if i > 0:
            csv += ","
        csv += String(Int(seqs[i]))
    var report = String("")
    report += "observed=" + String(observed) + "\n"
    report += "want=" + String(want) + "\n"
    report += "seqs=" + csv + "\n"
    report += "counter=" + String(Int(counter)) + "\n"
    report += "received=" + String(Int(received)) + "\n"
    report += "delivered=" + String(Int(delivered)) + "\n"
    report += "malformed=" + String(Int(malformed)) + "\n"
    report += "dropped=" + String(Int(dropped)) + "\n"
    report += "mismatches=" + String(mismatches) + "\n"
    report += "complete=" + String("true" if complete else "false") + "\n"
    try:
        Path(out_path).write_text(report)
    except e:
        close_quietly(session)
        raise Fail(1, String("cannot write record: ") + String(e))
    close_quietly(session)
    return 0 if complete else 3


def main() raises:
    var raw = argv()
    var args = List[String]()
    for i in range(len(raw)):
        args.append(raw[i])
    var code: Int
    try:
        code = run(args^)
    except e:
        print(e.message)
        code = e.code
    exit(code)
