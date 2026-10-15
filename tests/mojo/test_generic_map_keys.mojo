# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Owned key results and exact diagnostics through the real bridge host seam."""
from std.os import getenv
from std.pathlib import Path
from std.testing import TestSuite, assert_equal, assert_true
from libbpf_mojo._ffi import AUTOLOAD_DISABLE
from libbpf_mojo.maps import delete, first_key, next_key
from libbpf_mojo.error import LmbError
from libbpf_mojo.object import Object, MapView, _query_name
from test_generic_maps import loaded, scenario, calls, closes


def key_bytes(value: UInt32) -> List[UInt8]:
    var result = List[UInt8](length=4, fill=0)
    var pointer = Pointer(to=value).unsafe_bitcast[UInt8]()
    for i in range(4):
        result[i] = pointer.unsafe_offset(i).unsafe_load()
    return result^


def test_null_first_and_exact_current() raises:
    var obj = loaded()
    var view = obj.map("values")
    var first = first_key(view)
    assert_true(Bool(first))
    var bytes = first.take()
    var expected = key_bytes(UInt32(0x80000000))
    for i in range(4):
        assert_equal(bytes[i], expected[i])
    var following = next_key(view, Span(bytes))
    var last = following.take()
    expected = key_bytes(UInt32(0xffffffff))
    for i in range(4):
        assert_equal(last[i], expected[i])
    var end = next_key(view, Span(last))
    assert_true(not end)
    # Owned first result survives subsequent calls and is independently mutable.
    bytes[0] = 0x41
    assert_equal(last[0], UInt8(0xff))
    assert_equal(calls(view, UInt32(19)), UInt64(3))
    view.close()
    obj.close()


def test_delete_exact_flags_and_missing_is_error() raises:
    var obj = loaded()
    var view = obj.map("values")
    var key = key_bytes(UInt32(0x89abcdef))
    scenario(view, UInt32(20))
    delete(view, Span(key), UInt64(0x80000000ffffffff))
    scenario(view, UInt32(11))
    var captured = LmbError(0, 0, 0, "")
    var refused = False
    try:
        delete(view, Span(key))
    except e:
        captured = e^
        refused = True
    assert_true(refused)
    scenario(view, UInt32(0))
    delete(view, Span(key))
    assert_equal(captured.operation, UInt32(18))
    assert_equal(captured.domain, UInt32(3))
    assert_equal(captured.code, Int32(-2))
    assert_true(captured.message.byte_length() > 0)
    view.close()
    obj.close()


def test_terminal_diagnostic_mismatch_raises() raises:
    var obj = loaded()
    var view = obj.map("values")
    for number, code, domain in [(UInt32(12), Int32(-1), UInt32(3)),
                                 (UInt32(13), Int32(-4093), UInt32(3)),
                                 (UInt32(14), Int32(-2), UInt32(4)),
                                 (UInt32(15), Int32(-2), UInt32(4)),
                                 (UInt32(16), Int32(-2), UInt32(4)),
                                 (UInt32(17), Int32(-2), UInt32(4))]:
        scenario(view, number)
        var refused = False
        try:
            var unexpected = first_key(view)
            _ = unexpected^
        except e:
            assert_equal(e.operation, UInt32(19))
            assert_equal(e.domain, domain)
            assert_equal(e.code, code)
            refused = True
        assert_true(refused)
    scenario(view, UInt32(10))
    var empty = first_key(view)
    assert_true(not empty)
    scenario(view, UInt32(0))
    view._name = "absent"
    var refused = False
    try:
        var unexpected = first_key(view)
        _ = unexpected^
    except e:
        assert_equal(e.operation, UInt32(5))
        assert_equal(e.domain, UInt32(4))
        assert_equal(e.code, Int32(-2))
        refused = True
    assert_true(refused)
    view.close()
    obj.close()


def test_optional_map_key_symbols() raises:
    var data = Path(getenv("LMB_GENERIC_MAPS_FIXTURE")).read_bytes()
    var obj = Object.open_with_lib(Span(data), getenv("LMB_GENERIC_OBJECTONLY_LIB"))
    obj.load()
    var view = obj.map("values")
    var info = view.info()
    assert_equal(info.key_size, UInt32(4))
    var key = key_bytes(UInt32(0))
    for operation in [UInt32(18), UInt32(19), UInt32(190)]:
        var refused = False
        try:
            if operation == 18:
                delete(view, Span(key))
            elif operation == 19:
                var unexpected = first_key(view)
                _ = unexpected^
            else:
                var unexpected = next_key(view, Span(key))
                _ = unexpected^
        except e:
            assert_equal(e.operation, UInt32(18) if operation == 18 else UInt32(19))
            assert_equal(e.domain, UInt32(4))
            assert_equal(e.code, Int32(-38))
            refused = True
        assert_true(refused)
    view.close()
    obj.close()


def test_map_key_parent_move_release_and_error_capture() raises:
    var obj = loaded()
    var view = obj.map("values")
    var moved = obj^
    var retained = view^
    var refused = False
    try:
        moved.close()
    except e:
        assert_equal(e.code, Int32(-16))
        refused = True
    assert_true(refused)
    moved.release()
    var first = first_key(retained)
    assert_true(Bool(first))
    var key = first.take()
    delete(retained, Span(key))
    assert_equal(closes(retained), UInt64(0))
    retained.close()
    retained.close()
    assert_equal(closes(retained), UInt64(1))
    moved.close()
    var before = calls(retained, UInt32(19))
    refused = False
    try:
        var unexpected = first_key(retained)
        _ = unexpected^
    except e:
        assert_equal(e.operation, UInt32(17))
        assert_equal(e.code, Int32(-22))
        refused = True
    assert_true(refused)
    assert_equal(calls(retained, UInt32(19)), before)


def test_stale_and_invalid_current_precede_native_entry() raises:
    var data = Path(getenv("LMB_GENERIC_MAPS_FIXTURE")).read_bytes()
    var obj = Object.open_with_lib(Span(data), getenv("LMB_GENERIC_TESTFAKE_LIB"))
    var view = obj.map("values")
    obj.configure_program("packet_control", AUTOLOAD_DISABLE)
    var key = key_bytes(UInt32(0))
    for operation in [UInt32(18), UInt32(19)]:
        var before = calls(view, operation)
        var refused = False
        try:
            if operation == 18:
                delete(view, Span(key))
            else:
                var unexpected = next_key(view, Span(key))
                _ = unexpected^
        except e:
            assert_equal(e.operation, UInt32(17))
            assert_equal(e.code, Int32(-116))
            refused = True
        assert_true(refused)
        assert_equal(calls(view, operation), before)
    view.close()
    obj.close()
    var valid = loaded()
    var current = valid.map("values")
    for size in [0, 3, 5]:
        var wrong = List[UInt8](length=size, fill=0)
        var before = calls(current, UInt32(19))
        var refused = False
        try:
            var unexpected = next_key(current, Span(wrong))
            _ = unexpected^
        except e:
            assert_equal(e.operation, UInt32(19))
            assert_equal(e.domain, UInt32(4))
            assert_equal(e.code, Int32(-22))
            refused = True
        assert_true(refused)
        assert_equal(calls(current, UInt32(19)), before)
    current.close()
    valid.close()


def test_scalar_pointer_abi_sentinels() raises:
    var obj = loaded()
    var view = obj.map("values")
    var query = _query_name(view._name, UInt32(19))
    var key = key_bytes(UInt32(0x89abcdef))
    var output = List[UInt8](length=8, fill=0xa5)
    var destination = Span(output)
    var current = Span(key)
    var needed = UInt64(0xfedcba9876543210)
    var before = calls(view, UInt32(0))
    var rc = view._lib[].object_map_next_key(
        view._handle, Pointer(to=query), UInt32(1), current.unsafe_ptr(), UInt64(4),
        destination.unsafe_ptr(), UInt64(0), Pointer(to=needed),
    )
    assert_equal(rc, Int32(-28))
    assert_equal(needed, UInt64(4))
    for i in range(8):
        assert_equal(output[i], UInt8(0xa5))
    needed = 0xfedcba9876543210
    rc = view._lib[].object_map_next_key(
        view._handle, Pointer(to=query), UInt32(0xffffffff), current.unsafe_ptr(), UInt64(0),
        destination.unsafe_ptr(), UInt64(8), Pointer(to=needed),
    )
    assert_equal(rc, Int32(-22))
    assert_equal(needed, UInt64(0xfedcba9876543210))
    rc = view._lib[].object_map_next_key(
        view._handle, Pointer(to=query), UInt32(1), current.unsafe_ptr(), UInt64(4),
        destination.unsafe_ptr(), UInt64(0xffffffffffffffff), Pointer(to=needed),
    )
    assert_equal(rc, Int32(-22))
    assert_equal(needed, UInt64(0xfedcba9876543210))
    assert_equal(calls(view, UInt32(0)), before)
    scenario(view, UInt32(13))
    rc = view._lib[].object_map_next_key(
        view._handle, Pointer(to=query), UInt32(1), current.unsafe_ptr(), UInt64(4),
        destination.unsafe_ptr(), UInt64(8), Pointer(to=needed),
    )
    assert_equal(rc, Int32(-4093))
    assert_equal(needed, UInt64(0))
    for i in range(8):
        assert_equal(output[i], UInt8(0xa5))
    view.close()
    obj.close()


def main() raises:
    var suite = TestSuite()
    suite.test[test_scalar_pointer_abi_sentinels]()
    suite.test[test_null_first_and_exact_current]()
    suite.test[test_delete_exact_flags_and_missing_is_error]()
    suite.test[test_terminal_diagnostic_mismatch_raises]()
    suite.test[test_optional_map_key_symbols]()
    suite.test[test_map_key_parent_move_release_and_error_capture]()
    suite.test[test_stale_and_invalid_current_precede_native_entry]()
    suite^.run()
    print("NOT_RUN generic_map_keys.kernel-runtime: scripted host seam only")
