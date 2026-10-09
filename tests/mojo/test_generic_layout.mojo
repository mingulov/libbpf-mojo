# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

"""Layout, width, and signedness assertions for the generic ABI mirrors.

Every generic struct mirror must match
``native/include/libbpf_mojo_generic.h`` byte for byte; sizes come
from the C compiler (header static assertions) and offsets are
verified by reading raw bytes back through the FFI readers.
Program/map names and map geometry reuse the v1 ``NameV1`` and
``MapInfoV1`` mirrors, covered by ``test_layout.mojo``.
"""
from std.sys import align_of, exit, size_of
from std.testing import TestSuite, assert_equal

from libbpf_mojo._ffi import (
    AttachOptionsV1,
    BufferOptionsV1,
    GenericErrorV1,
    GenericOutSpanV1,
    GenericSpanV1,
    ObjectOptionsV1,
    ProgramInfoV1,
    ProgramOptionsV1,
    TestOptionsV1,
    TestResultV1,
    read_u8_le,
    read_u32_le,
    read_u64_le,
)


def test_sizes() raises:
    assert_equal(size_of[GenericSpanV1](), 16)
    assert_equal(size_of[GenericOutSpanV1](), 16)
    assert_equal(size_of[ObjectOptionsV1](), 64)
    assert_equal(size_of[ProgramOptionsV1](), 48)
    assert_equal(size_of[ProgramInfoV1](), 72)
    assert_equal(size_of[GenericErrorV1](), 1048)
    assert_equal(size_of[TestOptionsV1](), 88)
    assert_equal(size_of[TestResultV1](), 40)
    assert_equal(size_of[AttachOptionsV1](), 72)
    assert_equal(size_of[BufferOptionsV1](), 40)


def test_alignments() raises:
    assert_equal(align_of[GenericSpanV1](), 8)
    assert_equal(align_of[GenericOutSpanV1](), 8)
    assert_equal(align_of[ObjectOptionsV1](), 8)
    assert_equal(align_of[ProgramOptionsV1](), 8)
    assert_equal(align_of[ProgramInfoV1](), 8)
    assert_equal(align_of[GenericErrorV1](), 4)
    assert_equal(align_of[TestOptionsV1](), 8)
    assert_equal(align_of[TestResultV1](), 8)
    assert_equal(align_of[AttachOptionsV1](), 8)
    assert_equal(align_of[BufferOptionsV1](), 8)


def test_span_offsets() raises:
    var s = GenericSpanV1(UInt64(0x1122334455667788), UInt64(0xAABBCCDDEE))
    var p = Pointer(to=s).unsafe_bitcast[UInt8]()
    assert_equal(read_u64_le(p, 0), UInt64(0x1122334455667788))
    assert_equal(read_u64_le(p, 8), UInt64(0xAABBCCDDEE))
    var o = GenericOutSpanV1(UInt64(0xDEAD), UInt64(4096))
    var q = Pointer(to=o).unsafe_bitcast[UInt8]()
    assert_equal(read_u64_le(q, 0), UInt64(0xDEAD))
    assert_equal(read_u64_le(q, 8), UInt64(4096))


def test_object_options_offsets() raises:
    var o = ObjectOptionsV1(
        UInt32(1),
        UInt32(64),
        GenericSpanV1(UInt64(0x11), UInt64(9)).copy(),
        GenericSpanV1(UInt64(0), UInt64(0)).copy(),
        UInt32(1),
        UInt32(0),
        UInt64(65536),
        UInt64(0),
    )
    var p = Pointer(to=o).unsafe_bitcast[UInt8]()
    assert_equal(read_u32_le(p, 0), UInt32(1))
    assert_equal(read_u32_le(p, 4), UInt32(64))
    assert_equal(read_u64_le(p, 8), UInt64(0x11))
    assert_equal(read_u64_le(p, 16), UInt64(9))
    assert_equal(read_u64_le(p, 24), UInt64(0))
    assert_equal(read_u64_le(p, 32), UInt64(0))
    assert_equal(read_u32_le(p, 40), UInt32(1))
    assert_equal(read_u32_le(p, 44), UInt32(0))
    assert_equal(read_u64_le(p, 48), UInt64(65536))
    assert_equal(read_u64_le(p, 56), UInt64(0))


def test_program_options_offsets() raises:
    var o = ProgramOptionsV1(
        UInt32(1),
        UInt32(48),
        GenericSpanV1(UInt64(0x22), UInt64(5)).copy(),
        GenericSpanV1(UInt64(0x33), UInt64(12)).copy(),
        UInt32(1),
        UInt32(0),
    )
    var p = Pointer(to=o).unsafe_bitcast[UInt8]()
    assert_equal(read_u32_le(p, 0), UInt32(1))
    assert_equal(read_u32_le(p, 4), UInt32(48))
    assert_equal(read_u64_le(p, 8), UInt64(0x22))
    assert_equal(read_u64_le(p, 16), UInt64(5))
    assert_equal(read_u64_le(p, 24), UInt64(0x33))
    assert_equal(read_u64_le(p, 32), UInt64(12))
    assert_equal(read_u32_le(p, 40), UInt32(1))
    assert_equal(read_u32_le(p, 44), UInt32(0))


def test_program_info_offsets() raises:
    var i = ProgramInfoV1(
        UInt32(1),
        UInt32(72),
        UInt32(6),
        UInt32(0),
        UInt64(128),
        UInt64(3),
        UInt32(1),
        UInt32(0),
        GenericOutSpanV1(UInt64(0x44), UInt64(64)).copy(),
        UInt64(90),
        UInt32(1),
        UInt32(0),
    )
    var p = Pointer(to=i).unsafe_bitcast[UInt8]()
    assert_equal(read_u32_le(p, 0), UInt32(1))
    assert_equal(read_u32_le(p, 4), UInt32(72))
    assert_equal(read_u32_le(p, 8), UInt32(6))
    assert_equal(read_u32_le(p, 12), UInt32(0))
    assert_equal(read_u64_le(p, 16), UInt64(128))
    assert_equal(read_u64_le(p, 24), UInt64(3))
    assert_equal(read_u32_le(p, 32), UInt32(1))
    assert_equal(read_u32_le(p, 36), UInt32(0))
    assert_equal(read_u64_le(p, 40), UInt64(0x44))
    assert_equal(read_u64_le(p, 48), UInt64(64))
    assert_equal(read_u64_le(p, 56), UInt64(90))
    assert_equal(read_u32_le(p, 64), UInt32(1))
    assert_equal(read_u32_le(p, 68), UInt32(0))


def test_generic_error_offsets() raises:
    var e = GenericErrorV1(
        UInt32(1),
        UInt32(1048),
        UInt32(9),
        UInt32(3),
        Int32(-28),
        UInt32(7),
        Array[UInt8, 1024](fill=0),
    )
    e.message[0] = UInt8(0x41)
    e.message[1023] = UInt8(0x5A)
    var p = Pointer(to=e).unsafe_bitcast[UInt8]()
    assert_equal(read_u32_le(p, 0), UInt32(1))
    assert_equal(read_u32_le(p, 4), UInt32(1048))
    assert_equal(read_u32_le(p, 8), UInt32(9))
    assert_equal(read_u32_le(p, 12), UInt32(3))
    assert_equal(read_u32_le(p, 16), UInt32(0xFFFFFFE4))
    assert_equal(read_u32_le(p, 20), UInt32(7))
    assert_equal(read_u8_le(p, 24), UInt32(0x41))
    assert_equal(read_u8_le(p, 24 + 1023), UInt32(0x5A))


def test_test_options_offsets() raises:
    var o = TestOptionsV1(
        UInt32(1),
        UInt32(88),
        GenericSpanV1(UInt64(0x51), UInt64(64)).copy(),
        GenericOutSpanV1(UInt64(0x52), UInt64(128)).copy(),
        GenericSpanV1(UInt64(0), UInt64(0)).copy(),
        GenericOutSpanV1(UInt64(0), UInt64(0)).copy(),
        UInt64(1),
        UInt64(0),
    )
    var p = Pointer(to=o).unsafe_bitcast[UInt8]()
    assert_equal(read_u32_le(p, 0), UInt32(1))
    assert_equal(read_u32_le(p, 4), UInt32(88))
    assert_equal(read_u64_le(p, 8), UInt64(0x51))
    assert_equal(read_u64_le(p, 16), UInt64(64))
    assert_equal(read_u64_le(p, 24), UInt64(0x52))
    assert_equal(read_u64_le(p, 32), UInt64(128))
    assert_equal(read_u64_le(p, 40), UInt64(0))
    assert_equal(read_u64_le(p, 48), UInt64(0))
    assert_equal(read_u64_le(p, 56), UInt64(0))
    assert_equal(read_u64_le(p, 64), UInt64(0))
    assert_equal(read_u64_le(p, 72), UInt64(1))
    assert_equal(read_u64_le(p, 80), UInt64(0))


def test_test_result_offsets() raises:
    var r = TestResultV1(
        UInt32(1),
        UInt32(40),
        UInt32(2),
        UInt32(0),
        UInt64(60),
        UInt64(0),
        UInt64(1234),
    )
    var p = Pointer(to=r).unsafe_bitcast[UInt8]()
    assert_equal(read_u32_le(p, 0), UInt32(1))
    assert_equal(read_u32_le(p, 4), UInt32(40))
    assert_equal(read_u32_le(p, 8), UInt32(2))
    assert_equal(read_u32_le(p, 12), UInt32(0))
    assert_equal(read_u64_le(p, 16), UInt64(60))
    assert_equal(read_u64_le(p, 24), UInt64(0))
    assert_equal(read_u64_le(p, 32), UInt64(1234))


def test_attach_options_offsets() raises:
    var o = AttachOptionsV1(
        UInt32(1),
        UInt32(72),
        GenericSpanV1(UInt64(0x61), UInt64(7)).copy(),
        UInt32(1),
        UInt32(0),
        GenericSpanV1(UInt64(0x62), UInt64(9)).copy(),
        GenericSpanV1(UInt64(0x63), UInt64(11)).copy(),
        UInt64(0),
    )
    var p = Pointer(to=o).unsafe_bitcast[UInt8]()
    assert_equal(read_u32_le(p, 0), UInt32(1))
    assert_equal(read_u32_le(p, 4), UInt32(72))
    assert_equal(read_u64_le(p, 8), UInt64(0x61))
    assert_equal(read_u64_le(p, 16), UInt64(7))
    assert_equal(read_u32_le(p, 24), UInt32(1))
    assert_equal(read_u32_le(p, 28), UInt32(0))
    assert_equal(read_u64_le(p, 32), UInt64(0x62))
    assert_equal(read_u64_le(p, 40), UInt64(9))
    assert_equal(read_u64_le(p, 48), UInt64(0x63))
    assert_equal(read_u64_le(p, 56), UInt64(11))
    assert_equal(read_u64_le(p, 64), UInt64(0))


def test_buffer_options_offsets() raises:
    var o = BufferOptionsV1(
        UInt32(1),
        UInt32(40),
        GenericSpanV1(UInt64(0x71), UInt64(6)).copy(),
        UInt32(4096),
        UInt32(1),
        UInt32(0),
        UInt32(0),
    )
    var p = Pointer(to=o).unsafe_bitcast[UInt8]()
    assert_equal(read_u32_le(p, 0), UInt32(1))
    assert_equal(read_u32_le(p, 4), UInt32(40))
    assert_equal(read_u64_le(p, 8), UInt64(0x71))
    assert_equal(read_u64_le(p, 16), UInt64(6))
    assert_equal(read_u32_le(p, 24), UInt32(4096))
    assert_equal(read_u32_le(p, 28), UInt32(1))
    assert_equal(read_u32_le(p, 32), UInt32(0))
    assert_equal(read_u32_le(p, 36), UInt32(0))


def run() raises -> Int:
    var suite = TestSuite()
    suite.test[test_sizes]()
    suite.test[test_alignments]()
    suite.test[test_span_offsets]()
    suite.test[test_object_options_offsets]()
    suite.test[test_program_options_offsets]()
    suite.test[test_program_info_offsets]()
    suite.test[test_generic_error_offsets]()
    suite.test[test_test_options_offsets]()
    suite.test[test_test_result_offsets]()
    suite.test[test_attach_options_offsets]()
    suite.test[test_buffer_options_offsets]()
    suite^.run()
    return 0


def main() raises:
    var code = run()
    if code != 0:
        exit(code)
