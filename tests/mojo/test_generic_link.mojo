# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Owned generic links over the actual bridge's bounded host seams."""
from std.os import getenv
from std.pathlib import Path
from std.testing import TestSuite, assert_equal, assert_true
from libbpf_mojo._ffi import AUTOLOAD_DISABLE, AttachOptionsV1, GenericLib, GenericSpanV1
from libbpf_mojo.link import Link, attach_tracepoint
from libbpf_mojo.object import Object, ProgramView


def move_link(var link: Link) -> Link:
    return link^


def loaded(path: String = "") raises -> Object:
    var data = Path(getenv("LMB_GENERIC_EVENTS_FIXTURE")).read_bytes()
    var library = path.copy()
    if library.byte_length() == 0:
        library = getenv("LMB_EVENTS_TESTFAKE_LIB")
    var object = Object.open_with_lib(Span(data), library)
    var reset = object._lib[]._handle.get_function[NoneType]("lmb_events_reset")
    reset()
    object.load()
    return object^


def scenario(mut view: ProgramView, number: UInt32) raises:
    var control = view._lib[]._handle.get_function[NoneType]("lmb_events_scenario")
    control(number)


def query(mut link: Link, number: UInt32) raises -> UInt64:
    var control = link._lib[]._handle.get_function[UInt64]("lmb_events_call_count")
    return control(number)


def child_from_parent_scope() raises -> Link:
    var object = loaded()
    var program = object.program("on_getpid")
    return attach_tracepoint(program, "syscalls", "sys_enter_getpid")


def child_destructor_scope(mut program: ProgramView) raises:
    var child = attach_tracepoint(program, "syscalls", "sys_enter_getpid")
    assert_true(not child.is_closed())


def test_parent_and_library_outlive_scope() raises:
    var link = child_from_parent_scope()
    assert_equal(query(link, 1), UInt64(1))
    assert_equal(query(link, 8), UInt64(0))
    var moved = move_link(link^)
    assert_true(not moved.is_closed())
    moved.close()
    assert_true(moved.is_closed())
    assert_equal(query(moved, 2), UInt64(1))
    assert_equal(query(moved, 8), UInt64(1))
    moved.close()
    assert_equal(query(moved, 2), UInt64(1))
    assert_equal(query(moved, 19), UInt64(0))


def test_options_errors_and_destructor() raises:
    var object = loaded()
    var program = object.program("on_getpid")
    var anchor = attach_tracepoint(program, "syscalls", "sys_enter_getpid")
    var before = query(anchor, 1)
    for category, event, flags in [(String("syscalls"), String("sys_enter_getpid"), UInt32(1)),
                                   (String(""), String("sys_enter_getpid"), UInt32(0)),
                                   (String("syscalls"), String(""), UInt32(0))]:
        var refused = False
        try:
            var absent = attach_tracepoint(program, category, event, flags)
            _ = absent^
        except e:
            assert_equal(e.operation, UInt32(10))
            assert_equal(e.domain, UInt32(4))
            assert_equal(e.code, Int32(-22))
            refused = True
        assert_true(refused)
    assert_equal(query(anchor, 1), before)
    scenario(program, 7)
    var retained = False
    try:
        var absent = attach_tracepoint(program, "syscalls", "sys_enter_getpid")
        _ = absent^
    except e:
        assert_equal(e.operation, UInt32(10))
        assert_equal(e.domain, UInt32(2))
        assert_equal(e.code, Int32(-5))
        var saved = e.copy()
        scenario(program, 0)
        var sibling = attach_tracepoint(program, "syscalls", "sys_enter_getpid")
        sibling.close()
        assert_equal(saved.operation, UInt32(10))
        assert_equal(saved.domain, UInt32(2))
        assert_equal(saved.code, Int32(-5))
        assert_true(saved.message.byte_length() > 0)
        retained = True
    assert_true(retained)
    scenario(program, 8)
    var refused = False
    try:
        anchor.close()
    except e:
        assert_equal(e.operation, UInt32(11))
        assert_equal(e.domain, UInt32(2))
        assert_equal(e.code, Int32(-5))
        assert_true(anchor.is_closed())
        refused = True
    assert_true(refused)
    anchor.close()
    assert_equal(query(anchor, 2), UInt64(2))
    scenario(program, 0)
    child_destructor_scope(program)
    assert_equal(query(anchor, 2), UInt64(3))
    program.close()
    object.release()
    assert_equal(query(anchor, 8), UInt64(1))


def test_stale_closed_and_missing_operations() raises:
    var data = Path(getenv("LMB_GENERIC_EVENTS_FIXTURE")).read_bytes()
    var object = Object.open_with_lib(Span(data), getenv("LMB_EVENTS_TESTFAKE_LIB"))
    var reset = object._lib[]._handle.get_function[NoneType]("lmb_events_reset")
    reset()
    var stale = object.program("on_getpid")
    object.configure_program("on_getpid", AUTOLOAD_DISABLE)
    for closed in [False, True]:
        if closed:
            stale.close()
        var refused = False
        try:
            var absent = attach_tracepoint(stale, "syscalls", "sys_enter_getpid")
            _ = absent^
        except e:
            assert_equal(e.operation, UInt32(17))
            assert_equal(e.domain, UInt32(4))
            var expected = Int32(-116)
            if closed:
                expected = -22
            assert_equal(e.code, expected)
            refused = True
        assert_true(refused)
    var count = object._lib[]._handle.get_function[UInt64]("lmb_events_call_count")
    assert_equal(count(UInt32(24)), UInt64(0))
    object.close()
    for key in [String("LMB_EVENTS_NO_EVENTS_LIB"), String("LMB_EVENTS_NO_ATTACH_LIB"),
                String("LMB_EVENTS_NO_LINK_CLOSE_LIB")]:
        var older = loaded(getenv(key))
        var program = older.program("on_getpid")
        var refused = False
        try:
            var absent = attach_tracepoint(program, "syscalls", "sys_enter_getpid")
            _ = absent^
        except e:
            assert_equal(e.operation, UInt32(10))
            assert_equal(e.domain, UInt32(4))
            assert_equal(e.code, Int32(-38))
            refused = True
        assert_true(refused)
        var older_count = older._lib[]._handle.get_function[UInt64]("lmb_events_call_count")
        assert_equal(older_count(UInt32(24)), UInt64(0))
        assert_equal(older_count(UInt32(1)), UInt64(0))
        program.close()
        older.close()


def test_optional_ffi_operation_identity() raises:
    for operation, key in [(UInt32(10), String("LMB_EVENTS_NO_ATTACH_LIB")),
                           (UInt32(11), String("LMB_EVENTS_NO_LINK_CLOSE_LIB"))]:
        var library = GenericLib(getenv(key))
        var handle = UInt64(0)
        var options = AttachOptionsV1(1, 72, GenericSpanV1(0, 0), 1, 0,
                                      GenericSpanV1(0, 0), GenericSpanV1(0, 0), 0)
        var refused = False
        try:
            if operation == 10:
                _ = library.object_attach(0, Pointer(to=options), Pointer(to=handle))
            else:
                _ = library.close_link(Pointer(to=handle))
        except e:
            assert_equal(e.operation, operation)
            assert_equal(e.domain, UInt32(4))
            assert_equal(e.code, Int32(-38))
            refused = True
        assert_true(refused)
        assert_equal(handle, UInt64(0))


def main() raises:
    var suite = TestSuite()
    suite.test[test_parent_and_library_outlive_scope]()
    suite.test[test_options_errors_and_destructor]()
    suite.test[test_stale_closed_and_missing_operations]()
    suite.test[test_optional_ffi_operation_identity]()
    suite^.run()
    print("NOT_RUN generic_link.kernel-attachment: host forwarding and ownership only")
