# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

"""The public top-level surface: absolute values, not aliases.

Every constant below is pinned to its ABI value, so drift in
the private definition breaks loudly here. Downstream
consumers import these from ``libbpf_mojo`` directly.
"""
from std.sys import exit
from std.testing import TestSuite, assert_equal

from libbpf_mojo import (
    OP_NONE,
    OP_OPEN,
    OP_LOAD,
    OP_ATTACH,
    OP_POLL,
    OP_MAP_INFO,
    OP_MAP_READ,
    OP_MAP_WRITE,
    OP_STATS,
    OP_DETACH,
    OP_CLOSE,
    DOMAIN_NONE,
    DOMAIN_POSIX,
    DOMAIN_LIBBPF,
    DOMAIN_KERNEL,
    DOMAIN_BRIDGE,
    ATTACH_TRACEPOINT,
    ATTACH_TRACING,
    FRAME_HEADER_SIZE,
    FRAME_VERSION,
    MAX_RAW_BYTES,
    MAX_FRAME_BYTES,
    GENERIC_OP_NONE,
    GENERIC_OP_OBJECT_OPEN,
    GENERIC_OP_PROGRAM_CONFIGURE,
    GENERIC_OP_OBJECT_LOAD,
    GENERIC_OP_PROGRAM_INFO,
    GENERIC_OP_MAP_INFO,
    GENERIC_OP_OBJECT_CLOSE,
    GENERIC_OP_MAP_LOOKUP,
    GENERIC_OP_MAP_UPDATE,
    GENERIC_OP_MAP_DELETE,
    GENERIC_OP_MAP_NEXT_KEY,
    GENERIC_OP_TEST_RUN,
    GENERIC_OP_ATTACH,
    GENERIC_OP_LINK_CLOSE,
    GENERIC_OP_BUFFER_OPEN,
    GENERIC_OP_BUFFER_POLL,
    GENERIC_OP_BUFFER_CLOSE,
    GENERIC_OP_VIEW_REF,
    GENERIC_OP_VIEW_GEN,
    GENERIC_OP_VIEW_CHECK,
    GENERIC_OP_BUFFER_STATS,
    GENERIC_DOMAIN_NONE,
    GENERIC_DOMAIN_POSIX,
    GENERIC_DOMAIN_LIBBPF,
    GENERIC_DOMAIN_KERNEL,
    GENERIC_DOMAIN_BRIDGE,
    ATTACH_FAMILY_TRACEPOINT,
    AUTOLOAD_UNCHANGED,
    AUTOLOAD_ENABLE,
    AUTOLOAD_DISABLE,
    LOG_DISCARD,
    LOG_ON_FAILURE,
    LOG_ALWAYS,
    MAP_UPDATE_ANY,
    MAP_UPDATE_NOEXIST,
    MAP_UPDATE_EXIST,
    MAP_UPDATE_LOCK,
    GENERIC_MAX_LOG_BYTES,
    GENERIC_MAX_TEST_BYTES,
    read_u8_le,
    read_u16_le,
    read_u32_le,
    read_u64_le,
)


def test_public_constant_values() raises:
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
    assert_equal(GENERIC_OP_NONE, UInt32(0))
    assert_equal(GENERIC_OP_OBJECT_OPEN, UInt32(1))
    assert_equal(GENERIC_OP_PROGRAM_CONFIGURE, UInt32(2))
    assert_equal(GENERIC_OP_OBJECT_LOAD, UInt32(3))
    assert_equal(GENERIC_OP_PROGRAM_INFO, UInt32(4))
    assert_equal(GENERIC_OP_MAP_INFO, UInt32(5))
    assert_equal(GENERIC_OP_OBJECT_CLOSE, UInt32(6))
    assert_equal(GENERIC_OP_MAP_LOOKUP, UInt32(7))
    assert_equal(GENERIC_OP_MAP_UPDATE, UInt32(8))
    assert_equal(GENERIC_OP_MAP_DELETE, UInt32(18))
    assert_equal(GENERIC_OP_MAP_NEXT_KEY, UInt32(19))
    assert_equal(GENERIC_OP_TEST_RUN, UInt32(9))
    assert_equal(GENERIC_OP_ATTACH, UInt32(10))
    assert_equal(GENERIC_OP_LINK_CLOSE, UInt32(11))
    assert_equal(GENERIC_OP_BUFFER_OPEN, UInt32(12))
    assert_equal(GENERIC_OP_BUFFER_POLL, UInt32(13))
    assert_equal(GENERIC_OP_BUFFER_CLOSE, UInt32(14))
    assert_equal(GENERIC_OP_VIEW_REF, UInt32(15))
    assert_equal(GENERIC_OP_VIEW_GEN, UInt32(16))
    assert_equal(GENERIC_OP_VIEW_CHECK, UInt32(17))
    assert_equal(GENERIC_OP_BUFFER_STATS, UInt32(20))
    assert_equal(GENERIC_DOMAIN_NONE, UInt32(0))
    assert_equal(GENERIC_DOMAIN_POSIX, UInt32(1))
    assert_equal(GENERIC_DOMAIN_LIBBPF, UInt32(2))
    assert_equal(GENERIC_DOMAIN_KERNEL, UInt32(3))
    assert_equal(GENERIC_DOMAIN_BRIDGE, UInt32(4))
    assert_equal(ATTACH_FAMILY_TRACEPOINT, UInt32(1))
    assert_equal(AUTOLOAD_UNCHANGED, UInt32(0))
    assert_equal(AUTOLOAD_ENABLE, UInt32(1))
    assert_equal(AUTOLOAD_DISABLE, UInt32(2))
    assert_equal(LOG_DISCARD, UInt32(0))
    assert_equal(LOG_ON_FAILURE, UInt32(1))
    assert_equal(LOG_ALWAYS, UInt32(2))
    assert_equal(MAP_UPDATE_ANY, UInt32(0))
    assert_equal(MAP_UPDATE_NOEXIST, UInt32(1))
    assert_equal(MAP_UPDATE_EXIST, UInt32(2))
    assert_equal(MAP_UPDATE_LOCK, UInt32(4))
    assert_equal(GENERIC_MAX_LOG_BYTES, UInt64(1048576))
    assert_equal(GENERIC_MAX_TEST_BYTES, UInt64(1048576))

def test_public_read_helpers() raises:
    var zone = [UInt8(0x01), UInt8(0x02), UInt8(0x03), UInt8(0x04),
                UInt8(0x05), UInt8(0x06), UInt8(0x07), UInt8(0x08)]
    var p = Span(zone).unsafe_ptr()
    assert_equal(read_u8_le(p, 0), UInt32(0x01))
    assert_equal(read_u16_le(p, 0), UInt32(0x0201))
    assert_equal(read_u32_le(p, 0), UInt32(0x04030201))
    assert_equal(read_u64_le(p, 0), UInt64(0x0807060504030201))
    assert_equal(read_u16_le(p, 6), UInt32(0x0807))

def run() raises -> Int:
    var suite = TestSuite()
    suite.test[test_public_constant_values]()
    suite.test[test_public_read_helpers]()
    suite^.run()
    return 0


def main() raises:
    var code = run()
    if code != 0:
        exit(code)