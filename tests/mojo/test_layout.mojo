# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

"""Layout, width, and signedness assertions for the native ABI mirrors.

Every struct mirror must match the C ABI byte for byte; sizes come
from the C compiler (see A01 abi_check.c) and offsets are verified by
reading raw bytes back through the FFI readers.
"""
from std.sys import align_of, exit, size_of
from std.testing import TestSuite, assert_equal

from libbpf_mojo._ffi import (
    AttachV1,
    BytesV1,
    ErrorV1,
    MapInfoV1,
    NameV1,
    OptionsV1,
    StatsV1,
    read_u8_le,
    read_u32_le,
    read_u64_le,
)


def test_sizes() raises:
    assert_equal(size_of[BytesV1](), 16)
    assert_equal(size_of[OptionsV1](), 40)
    assert_equal(size_of[AttachV1](), 64)
    assert_equal(size_of[NameV1](), 24)
    assert_equal(size_of[MapInfoV1](), 40)
    assert_equal(size_of[StatsV1](), 56)
    assert_equal(size_of[ErrorV1](), 1048)


def test_alignments() raises:
    assert_equal(align_of[BytesV1](), 8)
    assert_equal(align_of[OptionsV1](), 8)
    assert_equal(align_of[AttachV1](), 8)
    assert_equal(align_of[NameV1](), 8)
    assert_equal(align_of[MapInfoV1](), 4)
    assert_equal(align_of[StatsV1](), 8)
    assert_equal(align_of[ErrorV1](), 4)


def test_bytes_offsets() raises:
    var b = BytesV1(
        UInt64(0x1122334455667788), UInt32(0xAABBCCDD), UInt32(0)
    )
    var p = Pointer(to=b).unsafe_bitcast[UInt8]()
    assert_equal(read_u64_le(p, 0), UInt64(0x1122334455667788))
    assert_equal(read_u32_le(p, 8), UInt32(0xAABBCCDD))
    assert_equal(read_u32_le(p, 12), UInt32(0))


def test_options_offsets() raises:
    var ring = BytesV1(UInt64(0xDEAD), UInt32(6), UInt32(0))
    var o = OptionsV1(
        UInt32(1),
        UInt32(40),
        ring.copy(),
        UInt32(4096),
        UInt32(1),
        UInt32(0),
        UInt32(0),
    )
    var p = Pointer(to=o).unsafe_bitcast[UInt8]()
    assert_equal(read_u32_le(p, 0), UInt32(1))
    assert_equal(read_u32_le(p, 4), UInt32(40))
    assert_equal(read_u64_le(p, 8), UInt64(0xDEAD))
    assert_equal(read_u32_le(p, 16), UInt32(6))
    assert_equal(read_u32_le(p, 24), UInt32(4096))
    assert_equal(read_u32_le(p, 28), UInt32(1))
    assert_equal(read_u32_le(p, 32), UInt32(0))
    assert_equal(read_u32_le(p, 36), UInt32(0))


def test_attach_offsets() raises:
    var prog = BytesV1(UInt64(0x11), UInt32(9), UInt32(0))
    var target_b = BytesV1(UInt64(0x22), UInt32(16), UInt32(0))
    var a = AttachV1(
        UInt32(1),
        UInt32(64),
        prog.copy(),
        UInt32(1),
        UInt32(0),
        BytesV1(UInt64(0x33), UInt32(8), UInt32(0)).copy(),
        target_b.copy(),
    )
    var p = Pointer(to=a).unsafe_bitcast[UInt8]()
    assert_equal(read_u32_le(p, 0), UInt32(1))
    assert_equal(read_u32_le(p, 4), UInt32(64))
    assert_equal(read_u64_le(p, 8), UInt64(0x11))
    assert_equal(read_u32_le(p, 16), UInt32(9))
    assert_equal(read_u32_le(p, 24), UInt32(1))
    assert_equal(read_u32_le(p, 28), UInt32(0))
    assert_equal(read_u64_le(p, 32), UInt64(0x33))
    assert_equal(read_u32_le(p, 40), UInt32(8))
    assert_equal(read_u64_le(p, 48), UInt64(0x22))
    assert_equal(read_u32_le(p, 56), UInt32(16))


def test_map_info_offsets() raises:
    var m = MapInfoV1(
        UInt32(1),
        UInt32(40),
        UInt32(2),
        UInt32(4),
        UInt32(8),
        UInt32(64),
        UInt32(0),
        UInt32(6),
        UInt32(0),
        UInt32(0),
    )
    var p = Pointer(to=m).unsafe_bitcast[UInt8]()
    assert_equal(read_u32_le(p, 0), UInt32(1))
    assert_equal(read_u32_le(p, 4), UInt32(40))
    assert_equal(read_u32_le(p, 8), UInt32(2))
    assert_equal(read_u32_le(p, 12), UInt32(4))
    assert_equal(read_u32_le(p, 16), UInt32(8))
    assert_equal(read_u32_le(p, 20), UInt32(64))
    assert_equal(read_u32_le(p, 24), UInt32(0))
    assert_equal(read_u32_le(p, 28), UInt32(6))
    assert_equal(read_u32_le(p, 32), UInt32(0))
    assert_equal(read_u32_le(p, 36), UInt32(0))


def test_name_offsets() raises:
    var name = BytesV1(UInt64(0x77), UInt32(5), UInt32(0))
    var n = NameV1(UInt32(1), UInt32(24), name.copy())
    var p = Pointer(to=n).unsafe_bitcast[UInt8]()
    assert_equal(read_u32_le(p, 0), UInt32(1))
    assert_equal(read_u32_le(p, 4), UInt32(24))
    assert_equal(read_u64_le(p, 8), UInt64(0x77))
    assert_equal(read_u32_le(p, 16), UInt32(5))


def test_stats_offsets() raises:
    var s = StatsV1(
        UInt32(1),
        UInt32(56),
        UInt64(0x1122334455667788),
        UInt64(7),
        UInt64(8),
        UInt64(9),
        UInt64(10),
        Int32(-22),
        UInt32(0),
    )
    var p = Pointer(to=s).unsafe_bitcast[UInt8]()
    assert_equal(read_u32_le(p, 0), UInt32(1))
    assert_equal(read_u32_le(p, 4), UInt32(56))
    assert_equal(read_u64_le(p, 8), UInt64(0x1122334455667788))
    assert_equal(read_u64_le(p, 16), UInt64(7))
    assert_equal(read_u64_le(p, 24), UInt64(8))
    assert_equal(read_u64_le(p, 32), UInt64(9))
    assert_equal(read_u64_le(p, 40), UInt64(10))
    assert_equal(read_u32_le(p, 48), UInt32(0xFFFFFFEA))
    assert_equal(read_u32_le(p, 52), UInt32(0))


def test_error_offsets() raises:
    var e = ErrorV1(
        UInt32(1),
        UInt32(1048),
        UInt32(3),
        UInt32(2),
        Int32(-28),
        UInt32(11),
        Array[UInt8, 1024](fill=0),
    )
    e.message[0] = UInt8(0x41)
    e.message[1023] = UInt8(0x5A)
    var p = Pointer(to=e).unsafe_bitcast[UInt8]()
    assert_equal(read_u32_le(p, 0), UInt32(1))
    assert_equal(read_u32_le(p, 4), UInt32(1048))
    assert_equal(read_u32_le(p, 8), UInt32(3))
    assert_equal(read_u32_le(p, 12), UInt32(2))
    assert_equal(read_u32_le(p, 16), UInt32(0xFFFFFFE4))
    assert_equal(read_u32_le(p, 20), UInt32(11))
    assert_equal(read_u8_le(p, 24), UInt32(0x41))
    assert_equal(read_u8_le(p, 24 + 1023), UInt32(0x5A))


def run() raises -> Int:
    var suite = TestSuite()
    suite.test[test_sizes]()
    suite.test[test_alignments]()
    suite.test[test_bytes_offsets]()
    suite.test[test_options_offsets]()
    suite.test[test_attach_offsets]()
    suite.test[test_map_info_offsets]()
    suite.test[test_name_offsets]()
    suite.test[test_stats_offsets]()
    suite.test[test_error_offsets]()
    suite^.run()
    return 0


def main() raises:
    var code = run()
    if code != 0:
        exit(code)
