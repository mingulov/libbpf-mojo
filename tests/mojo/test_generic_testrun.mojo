# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Typed program test-run boundary checks over the retained public view."""
from std.os import getenv
from std.pathlib import Path
from std.testing import TestSuite, assert_equal, assert_true
from libbpf_mojo._ffi import AUTOLOAD_DISABLE
from libbpf_mojo.object import Object, ProgramView
from libbpf_mojo.program import ProgramTestResult, test_run


def open_object(path: String) raises -> Object:
    var data = Path(getenv("LMB_GENERIC_MAPS_FIXTURE")).read_bytes()
    var obj = Object.open_with_lib(Span(data), path)
    var reset = obj._lib[]._handle.get_function[NoneType]("lmb_test_generic_reset")
    reset()
    return obj^


def loaded() raises -> Object:
    var obj = open_object(getenv("LMB_GENERIC_TESTFAKE_LIB"))
    obj.load()
    return obj^


def scenario(mut view: ProgramView, number: UInt32) raises:
    var f = view._lib[]._handle.get_function[NoneType]("lmb_test_generic_scenario")
    f(number)


def calls(mut view: ProgramView, operation: UInt32) raises -> UInt64:
    var f = view._lib[]._handle.get_function[UInt64]("lmb_test_generic_call_count")
    return f(operation)


def closes(mut view: ProgramView) raises -> UInt64:
    var f = view._lib[]._handle.get_function[UInt64]("lmb_test_generic_close_count")
    return f()


def packet_bytes() -> List[UInt8]:
    var result = List[UInt8](length=61, fill=0)
    for i in range(61):
        result[i] = UInt8(i * 3 + 7)
    return result^


def context_bytes() -> List[UInt8]:
    var result = List[UInt8](length=24, fill=0)
    for i in range(24):
        result[i] = UInt8(0xc0 - i)
    return result^


def verify(result: ProgramTestResult, packet: Span[mut=False, UInt8, _], context: Span[mut=False, UInt8, _]) raises:
    assert_equal(result.retval, UInt32(2))
    assert_equal(result.data_actual, UInt64(37))
    assert_equal(result.ctx_actual, UInt64(16))
    assert_equal(result.duration_ns, UInt64(123))
    for i in range(len(packet)):
        var expected = UInt8(0xa5)
        if i < 37:
            expected = UInt8(0x5b + i * 3)
        assert_equal(packet[i], expected)
    for i in range(len(context)):
        var expected = UInt8(0xa5)
        if i < 16:
            expected = UInt8(0x9d - i * 7)
        assert_equal(context[i], expected)


def test_independent_fields_and_tails() raises:
    var obj = loaded()
    var view = obj.program("packet_control")
    var packet = packet_bytes()
    var context = context_bytes()
    var data_out = List[UInt8](length=97, fill=0xa5)
    var ctx_out = List[UInt8](length=40, fill=0xa5)
    var result = test_run(view, Span(packet), Span(context), Span(data_out), Span(ctx_out), UInt64(2))
    var copy = result.copy()
    verify(copy, Span(data_out), Span(ctx_out))
    assert_equal(calls(view, UInt32(9)), UInt64(1))
    view.close()
    obj.close()
    assert_equal(closes(view), UInt64(1))


def test_native_failures_and_overflow_preserve_outputs() raises:
    var obj = loaded()
    var view = obj.program("packet_control")
    var packet = packet_bytes()
    var context = context_bytes()
    for number, code, domain in [(UInt32(3), Int32(-28), UInt32(3)),
                                (UInt32(4), Int32(-4), UInt32(3)),
                                (UInt32(5), Int32(-75), UInt32(4))]:
        scenario(view, number)
        var data_out = List[UInt8](length=97, fill=0xa5)
        var ctx_out = List[UInt8](length=40, fill=0xa5)
        var before = calls(view, UInt32(9))
        var refused = False
        try:
            var result = test_run(view, Span(packet), Span(context), Span(data_out), Span(ctx_out))
            _ = result^
        except e:
            assert_equal(e.operation, UInt32(9))
            assert_equal(e.domain, domain)
            assert_equal(e.code, code)
            refused = True
        assert_true(refused)
        assert_equal(calls(view, UInt32(9)), before + 1)
        for byte in data_out:
            assert_equal(byte, UInt8(0xa5))
        for byte in ctx_out:
            assert_equal(byte, UInt8(0xa5))
    view.close()
    obj.close()


def test_omitted_outputs_and_zero_inputs() raises:
    var obj = loaded()
    var view = obj.program("packet_control")
    var packet = packet_bytes()
    var context = context_bytes()
    var empty = List[UInt8]()
    var empty_data_out = List[UInt8]()
    var empty_ctx_out = List[UInt8]()
    scenario(view, UInt32(6))
    var result = test_run(view, Span(packet), Span(context), Span(empty_data_out), Span(empty_ctx_out))
    assert_equal(result.retval, UInt32(2))
    assert_equal(result.data_actual, UInt64(37))
    assert_equal(result.ctx_actual, UInt64(0))
    assert_equal(result.duration_ns, UInt64(123))
    scenario(view, UInt32(7))
    result = test_run(view, Span(empty), Span(empty), Span(empty_data_out), Span(empty_ctx_out))
    assert_equal(result.data_actual, UInt64(11))
    assert_equal(result.ctx_actual, UInt64(0))
    view.close()
    obj.close()


def test_input_output_alias_snapshot() raises:
    var obj = loaded()
    var view = obj.program("packet_control")
    var packet = packet_bytes()
    var context = context_bytes()
    var data_out = List[UInt8](length=97, fill=0xa5)
    var ctx_out = List[UInt8](length=40, fill=0xa5)
    for i in range(61):
        data_out[i] = packet[i]
    for i in range(24):
        ctx_out[i] = context[i]
    var data_span = Span(data_out)
    var ctx_span = Span(ctx_out)
    # Deliberate native alias test: both lists remain alive and unmoved through
    # this call. The bridge snapshots inputs before any output write. Erasing
    # just these test input origins lets us exercise that C contract explicitly.
    var input_data = Span(unsafe_ptr=data_span.unsafe_ptr().as_imm().as_unsafe_any_origin(), length=61)
    var input_ctx = Span(unsafe_ptr=ctx_span.unsafe_ptr().as_imm().as_unsafe_any_origin(), length=24)
    var result = test_run(view, input_data, input_ctx, data_span, ctx_span)
    assert_equal(result.data_actual, UInt64(37))
    for i in range(37):
        assert_equal(data_out[i], UInt8(0x5b + i * 3))
    for i in range(37, 61):
        assert_equal(data_out[i], packet[i])
    for i in range(61, 97):
        assert_equal(data_out[i], UInt8(0xa5))
    for i in range(16):
        assert_equal(ctx_out[i], UInt8(0x9d - i * 7))
    for i in range(16, 24):
        assert_equal(ctx_out[i], context[i])
    view.close()
    obj.close()


def test_lifetime_moves_and_child_first() raises:
    var obj = loaded()
    var view = obj.program("packet_control")
    var second = obj.map("counter")
    var moved = obj^
    var moved_view = view^
    moved.release()
    scenario(moved_view, UInt32(7))
    var empty = List[UInt8]()
    var empty_data_out = List[UInt8]()
    var empty_ctx_out = List[UInt8]()
    var result = test_run(moved_view, Span(empty), Span(empty), Span(empty_data_out), Span(empty_ctx_out))
    assert_equal(result.data_actual, UInt64(11))
    moved_view.close()
    moved_view.close()
    assert_equal(closes(moved_view), UInt64(0))
    second.close()
    assert_equal(closes(moved_view), UInt64(1))
    moved.close()
    var child_first = loaded()
    var child = child_first.program("packet_control")
    child.close()
    assert_equal(closes(child), UInt64(0))
    child_first.close()
    assert_equal(closes(child), UInt64(1))


def from_owner_scope() raises -> ProgramView:
    var obj = loaded()
    return obj.program("packet_control")


def test_scope_and_generation_before_execution() raises:
    var view = from_owner_scope()
    scenario(view, UInt32(7))
    var empty = List[UInt8]()
    var empty_data_out = List[UInt8]()
    var empty_ctx_out = List[UInt8]()
    var result = test_run(view, Span(empty), Span(empty), Span(empty_data_out), Span(empty_ctx_out))
    assert_equal(result.data_actual, UInt64(11))
    view.close()
    var obj = open_object(getenv("LMB_GENERIC_TESTFAKE_LIB"))
    var stale = obj.program("packet_control")
    obj.configure_program("packet_control", AUTOLOAD_DISABLE)
    var sentinel = List[UInt8](length=97, fill=0xa5)
    for closed in [False, True]:
        if closed:
            stale.close()
        var refused = False
        try:
            var absent = test_run(stale, Span(empty), Span(empty), Span(sentinel), Span(empty_ctx_out))
            _ = absent^
        except e:
            assert_equal(e.operation, UInt32(17))
            assert_equal(e.code, Int32(-22) if closed else Int32(-116))
            refused = True
        assert_true(refused)
        assert_equal(calls(stale, UInt32(9)), UInt64(0))
        for byte in sentinel:
            assert_equal(byte, UInt8(0xa5))
    obj.close()
    var old_obj = open_object(getenv("LMB_GENERIC_OBJECTONLY_LIB"))
    old_obj.load()
    var older = old_obj.program("packet_control")
    var refused = False
    try:
        var absent = test_run(older, Span(empty), Span(empty), Span(empty_data_out), Span(empty_ctx_out))
        _ = absent^
    except e:
        assert_equal(e.operation, UInt32(9))
        assert_equal(e.domain, UInt32(4))
        assert_equal(e.code, Int32(-38))
        refused = True
    assert_true(refused)
    older.close()
    old_obj.close()


def main() raises:
    var suite = TestSuite()
    suite.test[test_independent_fields_and_tails]()
    suite.test[test_native_failures_and_overflow_preserve_outputs]()
    suite.test[test_omitted_outputs_and_zero_inputs]()
    suite.test[test_input_output_alias_snapshot]()
    suite.test[test_lifetime_moves_and_child_first]()
    suite.test[test_scope_and_generation_before_execution]()
    suite^.run()
    print("NOT_RUN generic_testrun.kernel-runtime: scripted Mojo FFI evidence only")
