# SPDX-License-Identifier: GPL-3.0-or-later

"""Structured error contracts: constants match the C ABI and every
failure carries operation/domain/code without string parsing."""
from std.sys import exit
from std.testing import TestSuite, assert_equal, assert_true

from libbpf_mojo._ffi import (
    ATTACH_TRACING,
    ATTACH_TRACEPOINT,
    DOMAIN_BRIDGE,
    DOMAIN_KERNEL,
    DOMAIN_LIBBPF,
    DOMAIN_NONE,
    DOMAIN_POSIX,
    FRAME_HEADER_SIZE,
    FRAME_VERSION,
    MAX_FRAME_BYTES,
    MAX_RAW_BYTES,
    OP_ATTACH,
    OP_CLOSE,
    OP_DETACH,
    OP_LOAD,
    OP_MAP_INFO,
    OP_MAP_READ,
    OP_MAP_WRITE,
    OP_NONE,
    OP_OPEN,
    OP_POLL,
    OP_STATS,
)
from libbpf_mojo._ffi import NativeLib
from libbpf_mojo.error import (
    EBADMSG,
    EBUSY,
    EINVAL,
    ENOENT,
    ENOSPC,
    ENOSYS,
    EOVERFLOW,
    LmbError,
    message_from_bytes,
)
from libbpf_mojo.session import AttachSpec, Session, checked_u32
from testutil import (
    must_close,
    must_open,
    read_fixture_elf,
    stub_lib_path,
)


def test_abi_constants() raises:
    assert_equal(OP_NONE, UInt32(0))
    assert_equal(OP_OPEN, UInt32(1))
    assert_equal(OP_LOAD, UInt32(2))
    assert_equal(OP_ATTACH, UInt32(3))
    assert_equal(OP_POLL, UInt32(4))
    assert_equal(OP_MAP_INFO, UInt32(5))
    assert_equal(OP_MAP_READ, UInt32(6))
    assert_equal(OP_MAP_WRITE, UInt32(7))
    assert_equal(OP_STATS, UInt32(8))
    assert_equal(OP_DETACH, UInt32(9))
    assert_equal(OP_CLOSE, UInt32(10))
    assert_equal(DOMAIN_NONE, UInt32(0))
    assert_equal(DOMAIN_POSIX, UInt32(1))
    assert_equal(DOMAIN_LIBBPF, UInt32(2))
    assert_equal(DOMAIN_KERNEL, UInt32(3))
    assert_equal(DOMAIN_BRIDGE, UInt32(4))
    assert_equal(ATTACH_TRACEPOINT, UInt32(1))
    assert_equal(ATTACH_TRACING, UInt32(2))
    assert_equal(FRAME_HEADER_SIZE, UInt32(8))
    assert_equal(FRAME_VERSION, UInt32(1))
    assert_equal(MAX_RAW_BYTES, UInt32(4096))
    assert_equal(MAX_FRAME_BYTES, UInt32(4104))
    assert_equal(EINVAL, Int32(-22))
    assert_equal(ENOSPC, Int32(-28))
    assert_equal(ENOENT, Int32(-2))
    assert_equal(EBUSY, Int32(-16))
    assert_equal(EBADMSG, Int32(-74))
    assert_equal(ENOSYS, Int32(-38))
    assert_equal(EOVERFLOW, Int32(-75))


def test_lmb_error_fields() raises:
    var e = LmbError(UInt32(4), UInt32(4), Int32(-28), String("short"))
    assert_equal(e.operation, UInt32(4))
    assert_equal(e.domain, UInt32(4))
    assert_equal(e.code, Int32(-28))
    assert_equal(e.message, String("short"))
    assert_true(String(e).byte_length() > 0)


def boom() raises LmbError:
    raise LmbError(UInt32(3), UInt32(2), Int32(-1), String("k"))


def test_raise_catch_preserves() raises:
    var op = UInt32(0)
    var domain = UInt32(0)
    var code = Int32(0)
    var raised = False
    try:
        boom()
    except e:
        op = e.operation
        domain = e.domain
        code = e.code
        raised = True
    assert_true(raised)
    assert_equal(op, UInt32(3))
    assert_equal(domain, UInt32(2))
    assert_equal(code, Int32(-1))


def test_open_error_structured() raises:
    var elf = read_fixture_elf()
    var op = UInt32(0)
    var domain = UInt32(0)
    var code = Int32(0)
    var msg_len = 0
    var raised = False
    try:
        var s = Session.open(
            Span(elf), String("events"), UInt32(0)
        )
        s.close()
    except e:
        op = e.operation
        domain = e.domain
        code = e.code
        msg_len = e.message.byte_length()
        raised = True
    assert_true(raised)
    assert_equal(op, OP_OPEN)
    assert_equal(domain, DOMAIN_BRIDGE)
    assert_equal(code, EINVAL)
    assert_true(msg_len > 0)


def test_last_error_roundtrip() raises:
    var elf = read_fixture_elf()
    var s = must_open(Span(elf))
    var first: LmbError
    try:
        first = s.last_error()
    except e:
        raise Error("fresh last_error failed: " + String(e))
    assert_equal(first.operation, OP_NONE)
    assert_equal(first.domain, DOMAIN_NONE)
    assert_equal(first.code, Int32(0))
    assert_equal(first.message, String(""))
    var op = UInt32(0)
    var raised = False
    try:
        var specs = List[AttachSpec]()
        specs.append(
            AttachSpec(
                String("prog"),
                ATTACH_TRACEPOINT,
                String("syscalls"),
                String("sys_enter_open"),
            )
        )
        s.attach(specs)
    except e:
        op = e.operation
        raised = True
    assert_true(raised)
    assert_equal(op, OP_ATTACH)
    var after: LmbError
    try:
        after = s.last_error()
    except e:
        raise Error("last_error after failure failed")
    assert_equal(after.operation, OP_ATTACH)
    assert_equal(after.domain, DOMAIN_BRIDGE)
    assert_equal(after.code, EINVAL)
    var received: UInt64
    try:
        var st = s.stats()
        received = st.received
    except e:
        raise Error("stats failed: " + String(e))
    assert_equal(received, UInt64(0))
    var kept: LmbError
    try:
        kept = s.last_error()
    except e:
        raise Error("last_error after success failed")
    assert_equal(kept.operation, OP_ATTACH)
    assert_equal(kept.domain, DOMAIN_BRIDGE)
    assert_equal(kept.code, EINVAL)
    must_close(s^)


def test_checked_u32() raises:
    var small: UInt32
    try:
        small = checked_u32(6, OP_OPEN)
    except e:
        raise Error("checked_u32(6) failed")
    assert_equal(small, UInt32(6))
    var code = Int32(0)
    var op = UInt32(0)
    var raised = False
    try:
        var big = checked_u32(0x100000000, OP_POLL)
    except e:
        code = e.code
        op = e.operation
        raised = True
    assert_true(raised)
    assert_equal(op, OP_POLL)
    assert_equal(code, EOVERFLOW)


def test_message_from_bytes() raises:
    var good = List[UInt8]()
    good.append(UInt8(0x6C))
    good.append(UInt8(0x6D))
    good.append(UInt8(0x62))
    assert_equal(message_from_bytes(good), String("lmb"))
    var bad = List[UInt8]()
    bad.append(UInt8(0xFF))
    bad.append(UInt8(0xFE))
    assert_equal(
        message_from_bytes(bad), String("(undecodable error message)")
    )


def test_unresolved_symbol() raises:
    var code = Int32(0)
    var op = UInt32(0)
    var raised = False
    try:
        var lib = NativeLib(String("libc.so.6"))
    except e:
        code = e.code
        op = e.operation
        raised = True
    assert_true(raised)
    assert_equal(op, OP_OPEN)
    assert_equal(code, ENOSYS)


def test_incomplete_library() raises:
    var path = stub_lib_path()
    var code = Int32(0)
    var op = UInt32(0)
    var msg = String("")
    var raised = False
    try:
        var lib = NativeLib(path)
    except e:
        code = e.code
        op = e.operation
        msg = e.message.copy()
        raised = True
    assert_true(raised)
    assert_equal(op, OP_OPEN)
    assert_equal(code, ENOSYS)
    assert_equal(msg, String("incomplete native library: lmb_close"))


def run() raises -> Int:
    var suite = TestSuite()
    suite.test[test_abi_constants]()
    suite.test[test_lmb_error_fields]()
    suite.test[test_raise_catch_preserves]()
    suite.test[test_open_error_structured]()
    suite.test[test_last_error_roundtrip]()
    suite.test[test_checked_u32]()
    suite.test[test_message_from_bytes]()
    suite.test[test_unresolved_symbol]()
    suite.test[test_incomplete_library]()
    suite^.run()
    return 0


def main() raises:
    var code = run()
    if code != 0:
        exit(code)
