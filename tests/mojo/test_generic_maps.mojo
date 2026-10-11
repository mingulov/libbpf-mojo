# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Typed map boundary checks over the retained public MapView."""
from std.os import getenv
from std.pathlib import Path
from std.testing import TestSuite, assert_equal, assert_true
from libbpf_mojo._ffi import AUTOLOAD_DISABLE
from libbpf_mojo.maps import lookup, update, lookup_u64, update_u64
from libbpf_mojo.object import Object, MapView


def loaded() raises -> Object:
    var data = Path(getenv("LMB_GENERIC_MAPS_FIXTURE")).read_bytes()
    var obj = Object.open_with_lib(Span(data), getenv("LMB_GENERIC_TESTFAKE_LIB"))
    var reset = obj._lib[]._handle.get_function[NoneType]("lmb_test_generic_reset")
    reset()
    obj.load()
    return obj^


def scenario(mut view: MapView, number: UInt32) raises:
    var f = view._lib[]._handle.get_function[NoneType]("lmb_test_generic_scenario")
    f(number)


def calls(mut view: MapView, operation: UInt32) raises -> UInt64:
    var f = view._lib[]._handle.get_function[UInt64]("lmb_test_generic_call_count")
    return f(operation)


def closes(mut view: MapView) raises -> UInt64:
    var f = view._lib[]._handle.get_function[UInt64]("lmb_test_generic_close_count")
    return f()


def test_raw_and_scalar_values() raises:
    var obj = loaded()
    var view = obj.map("counter")
    assert_equal(lookup_u64(view, UInt32(0)), UInt64(0xfedcba9876543210))
    update_u64(view, UInt32(0), UInt64(0x8000000000000041))
    assert_equal(lookup_u64(view, UInt32(0)), UInt64(0x8000000000000041))
    var key = List[UInt8](length=4, fill=0)
    var value = List[UInt8](length=8, fill=0)
    for i in range(8):
        value[i] = UInt8(0x91 + i)
    update(view, Span(key), Span(value))
    var actual = lookup(view, Span(key))
    assert_equal(len(actual), 8)
    for i in range(8):
        assert_equal(actual[i], value[i])
    assert_equal(calls(view, UInt32(7)), UInt64(3))
    assert_equal(calls(view, UInt32(8)), UInt64(2))
    view.close()
    obj.close()
    assert_equal(closes(view), UInt64(1))


def test_flags_and_signed_errors() raises:
    var obj = loaded()
    var view = obj.map("values")
    var key = List[UInt8](length=4, fill=0)
    var value = List[UInt8](length=8, fill=0x5b)
    for flags in [UInt64(0), UInt64(1), UInt64(2), UInt64(4), UInt64(5), UInt64(6)]:
        update(view, Span(key), Span(value), flags)
    var before = calls(view, UInt32(0))
    for flags in [UInt64(3), UInt64(7), UInt64(8), UInt64(1) << 63, UInt64(0xffffffffffffffff)]:
        var refused = False
        try:
            update(view, Span(key), Span(value), flags)
        except e:
            assert_equal(e.operation, UInt32(8))
            assert_equal(e.domain, UInt32(4))
            assert_equal(e.code, Int32(-22))
            refused = True
        assert_true(refused)
    assert_equal(calls(view, UInt32(0)), before)
    for code, operation, number in [(Int32(-2), UInt32(7), UInt32(1)),
                                   (Int32(-5), UInt32(8), UInt32(2))]:
        scenario(view, number)
        var refused = False
        try:
            if operation == 7:
                var absent = lookup(view, Span(key))
                _ = absent^
            else:
                update(view, Span(key), Span(value))
        except e:
            assert_equal(e.operation, operation)
            assert_equal(e.domain, UInt32(3))
            assert_equal(e.code, code)
            assert_true(e.message.byte_length() > 0)
            refused = True
        assert_true(refused)
    scenario(view, UInt32(0))
    var bad_key = List[UInt8](length=3, fill=0)
    var refused = False
    before = calls(view, UInt32(0))
    try:
        var absent = lookup(view, Span(bad_key))
        _ = absent^
    except e:
        assert_equal(e.code, Int32(-22))
        refused = True
    assert_true(refused)
    assert_equal(calls(view, UInt32(0)), before)
    view.close()
    obj.close()


def test_scalar_key_width_and_invalid_value_extent() raises:
    var obj = loaded()
    var view = obj.map("values")
    scenario(view, UInt32(9))
    update_u64(view, UInt32(0x89abcdef), UInt64(0xffffffffffffffff))
    assert_equal(lookup_u64(view, UInt32(0x89abcdef)), UInt64(0xffffffffffffffff))
    scenario(view, UInt32(0))
    var key = List[UInt8](length=4, fill=0)
    var short = List[UInt8](length=7, fill=0xa5)
    var before = calls(view, UInt32(0))
    var refused = False
    try:
        update(view, Span(key), Span(short))
    except e:
        assert_equal(e.operation, UInt32(8))
        assert_equal(e.domain, UInt32(4))
        assert_equal(e.code, Int32(-22))
        refused = True
    assert_true(refused)
    assert_equal(calls(view, UInt32(0)), before)
    view.close()
    obj.close()


def test_percpu_extent_and_padding() raises:
    var obj = loaded()
    var key = List[UInt8](length=4, fill=0)
    for name in [String("percpu_values"), String("percpu_hash")]:
        var view = obj.map(name.copy())
        var info = view.info()
        assert_equal(info.key_size, UInt32(4))
        assert_equal(info.value_size, UInt32(13))
        assert_equal(info.stride, UInt32(16))
        assert_equal(info.num_cpus, UInt32(3))
        var actual = lookup(view, Span(key))
        assert_equal(len(actual), 48)
        for cpu in range(3):
            for byte in range(16):
                var expected = UInt8(0x21 + cpu * 17 + byte)
                if byte >= 13:
                    expected = UInt8(0xe0 + cpu * 3 + byte - 13)
                assert_equal(actual[cpu * 16 + byte], expected)
        actual[0] = 0xf1
        actual[47] = 0xa7
        update(view, Span(key), Span(actual))
        var copy = lookup(view, Span(key))
        for i in range(48):
            assert_equal(copy[i], actual[i])
        var before = calls(view, UInt32(7))
        var refused = False
        try:
            _ = lookup_u64(view, UInt32(0))
        except e:
            assert_equal(e.operation, UInt32(7))
            assert_equal(e.domain, UInt32(4))
            assert_equal(e.code, Int32(-22))
            refused = True
        assert_true(refused)
        assert_equal(calls(view, UInt32(7)), before)
        before = calls(view, UInt32(8))
        refused = False
        try:
            update_u64(view, UInt32(0), UInt64(0xffffffffffffffff))
        except e:
            assert_equal(e.operation, UInt32(8))
            assert_equal(e.code, Int32(-22))
            refused = True
        assert_true(refused)
        assert_equal(calls(view, UInt32(8)), before)
        view.close()
    obj.close()


def test_moves_parent_release_and_last_close() raises:
    var obj = loaded()
    var first = obj.map("counter")
    var second = obj.map("counter")
    var moved = obj^
    var moved_view = first^
    var refused = False
    try:
        moved.close()
    except e:
        assert_equal(e.code, Int32(-16))
        refused = True
    assert_true(refused)
    moved.release()
    assert_equal(lookup_u64(moved_view, UInt32(0)), UInt64(0xfedcba9876543210))
    moved_view.close()
    moved_view.close()
    assert_equal(closes(second), UInt64(0))
    second.close()
    assert_equal(closes(second), UInt64(1))
    second.close()
    moved.close()
    assert_equal(closes(second), UInt64(1))


def from_owner_scope() raises -> MapView:
    var obj = loaded()
    return obj.map("counter")


def test_library_after_owner_scope() raises:
    var view = from_owner_scope()
    assert_equal(lookup_u64(view, UInt32(0)), UInt64(0xfedcba9876543210))
    assert_equal(closes(view), UInt64(0))
    view.close()
    assert_equal(closes(view), UInt64(1))


def test_stale_closed_and_optional_symbols() raises:
    var data = Path(getenv("LMB_GENERIC_MAPS_FIXTURE")).read_bytes()
    var obj = Object.open_with_lib(Span(data), getenv("LMB_GENERIC_TESTFAKE_LIB"))
    var view = obj.map("counter")
    var reset = obj._lib[]._handle.get_function[NoneType]("lmb_test_generic_reset")
    reset()
    obj.configure_program("packet_control", AUTOLOAD_DISABLE)
    var key = List[UInt8](length=4, fill=0)
    var bytes = List[UInt8](length=8, fill=0x5a)
    for operation in [UInt32(7), UInt32(8)]:
        var refused = False
        try:
            if operation == 7:
                var absent = lookup(view, Span(key))
                _ = absent^
            else:
                update(view, Span(key), Span(bytes))
        except e:
            assert_equal(e.operation, UInt32(17))
            assert_equal(e.code, Int32(-116))
            refused = True
        assert_true(refused)
        assert_equal(calls(view, operation), UInt64(0))
    view.close()
    var refused = False
    try:
        _ = lookup_u64(view, UInt32(0))
    except e:
        assert_equal(e.operation, UInt32(17))
        assert_equal(e.code, Int32(-22))
        refused = True
    assert_true(refused)
    assert_equal(calls(view, UInt32(7)), UInt64(0))
    obj.close()
    var older = Object.open_with_lib(Span(data), getenv("LMB_GENERIC_OBJECTONLY_LIB"))
    older.load()
    var old_view = older.map("counter")
    var info = old_view.info()
    assert_equal(info.value_size, UInt32(8))
    for operation in [UInt32(7), UInt32(8)]:
        refused = False
        try:
            if operation == 7:
                var absent = lookup(old_view, Span(key))
                _ = absent^
            else:
                update(old_view, Span(key), Span(bytes))
        except e:
            assert_equal(e.operation, operation)
            assert_equal(e.domain, UInt32(4))
            assert_equal(e.code, Int32(-38))
            refused = True
        assert_true(refused)
    old_view.close()
    older.close()


def main() raises:
    var suite = TestSuite()
    suite.test[test_raw_and_scalar_values]()
    suite.test[test_flags_and_signed_errors]()
    suite.test[test_scalar_key_width_and_invalid_value_extent]()
    suite.test[test_percpu_extent_and_padding]()
    suite.test[test_moves_parent_release_and_last_close]()
    suite.test[test_library_after_owner_scope]()
    suite.test[test_stale_closed_and_optional_symbols]()
    suite^.run()
    print("NOT_RUN generic_maps.kernel-runtime: scripted Mojo FFI evidence only")
