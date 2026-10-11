# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Real generic object owners and retained views, without kernel loading."""
from std.os import getenv, listdir
from std.pathlib import Path
from std.testing import TestSuite, assert_equal, assert_false, assert_true
from libbpf_mojo._ffi import AUTOLOAD_DISABLE, AUTOLOAD_ENABLE
from libbpf_mojo.error import EBUSY, EINVAL, ENOSYS
from libbpf_mojo.object import Object, ObjectOptions, ProgramView, MapView


def elf() raises -> List[UInt8]:
    return Path(getenv("LMB_GENERIC_FIXTURE")).read_bytes()


def open_object() raises -> Object:
    var data = elf()
    return Object.open_with_lib(Span(data), getenv("LMB_NATIVE_LIB"))


def test_open_metadata() raises:
    var data = elf()
    var obj = Object.open_with_lib(Span(data), getenv("LMB_NATIVE_LIB"))
    data[0] = 0
    var view = obj.program(String("first"))
    var meta = view.info()
    assert_equal(meta.prog_type, UInt32(1))
    assert_true(meta.insn_count > 0)
    assert_equal(meta.generation, UInt64(0))
    assert_true(meta.autoload)
    assert_equal(len(meta.log), 0)
    view.close()
    obj.close()
    assert_true(obj.is_closed())


def test_parent_release_view() raises:
    var obj = open_object()
    var view = obj.program(String("first"))
    var busy = False
    try:
        obj.close()
    except e:
        assert_equal(e.operation, UInt32(6))
        assert_equal(e.domain, UInt32(4))
        assert_equal(e.code, EBUSY)
        busy = True
    assert_true(busy)
    assert_false(obj.is_closed())
    obj.release()
    assert_true(obj.is_closed())
    var meta = view.info()
    assert_true(meta.autoload)
    view.close()
    view.close()


def retained_from_scope() raises -> ProgramView:
    var obj = open_object()
    return obj.program(String("first"))


def test_view_library_lifetime() raises:
    var view = retained_from_scope()
    var meta = view.info()
    assert_true(meta.insn_count > 0)
    view.close()


def test_parent_and_view_moves() raises:
    var obj = open_object()
    var view = obj.program(String("second"))
    var moved = obj^
    var moved_view = view^
    var meta = moved_view.info()
    assert_true(meta.autoload)
    moved_view.close()
    moved.close()


def test_stale_generation() raises:
    var obj = open_object()
    var view = obj.program(String("first"))
    obj.configure_program(String("first"), AUTOLOAD_DISABLE)
    var stale = False
    try:
        var meta = view.info()
        _ = meta^
    except e:
        assert_equal(e.operation, UInt32(17))
        assert_equal(e.domain, UInt32(4))
        assert_equal(e.code, Int32(-116))
        stale = True
    assert_true(stale)
    view.close()
    var current = obj.program(String("first"))
    var meta = current.info()
    assert_false(meta.autoload)
    assert_equal(meta.generation, UInt64(1))
    current.close()
    obj.configure_program(String("first"), AUTOLOAD_ENABLE)
    obj.close()


def test_map_load_gate() raises:
    var obj = open_object()
    var view = obj.map(String("counter"))
    obj.release()
    var gated = False
    try:
        var info = view.info()
        _ = info^
    except e:
        assert_equal(e.operation, UInt32(5))
        assert_equal(e.domain, UInt32(4))
        assert_equal(e.code, EINVAL)
        gated = True
    assert_true(gated)
    view.close()


def test_parse_and_missing_symbols() raises:
    var garbage = List[UInt8](length=64, fill=UInt8(0))
    var failed = False
    try:
        var obj = Object.open_with_lib(Span(garbage), getenv("LMB_NATIVE_LIB"))
        _ = obj^
    except e:
        assert_equal(e.operation, UInt32(1))
        assert_equal(e.domain, UInt32(2))
        assert_true(e.code < 0)
        failed = True
    assert_true(failed)
    var data = elf()
    failed = False
    try:
        var obj = Object.open_with_lib(Span(data), getenv("LMB_STUB_LIB"))
        _ = obj^
    except e:
        assert_equal(e.domain, UInt32(4))
        assert_equal(e.code, ENOSYS)
        failed = True
    assert_true(failed)


def test_nomap_and_fd_stability() raises:
    var baseline = len(listdir("/proc/self/fd"))
    var data = Path(getenv("LMB_GENERIC_NOMAP_FIXTURE")).read_bytes()
    for _ in range(64):
        var obj = Object.open_with_lib(Span(data), getenv("LMB_NATIVE_LIB"))
        var view = obj.program(String("first"))
        obj.release()
        var meta = view.info()
        assert_true(meta.insn_count > 0)
        view.close()
    assert_equal(len(listdir("/proc/self/fd")), baseline)


def test_empty_map_name() raises:
    var obj = open_object()
    var refused = False
    try:
        var view = obj.map(String(""))
        view.close()
    except e:
        assert_equal(e.operation, UInt32(5))
        assert_equal(e.domain, UInt32(4))
        assert_equal(e.code, EINVAL)
        refused = True
    assert_true(refused)
    obj.close()


def main() raises:
    var suite = TestSuite()
    suite.test[test_open_metadata]()
    suite.test[test_parent_release_view]()
    suite.test[test_view_library_lifetime]()
    suite.test[test_parent_and_view_moves]()
    suite.test[test_stale_generation]()
    suite.test[test_map_load_gate]()
    suite.test[test_parse_and_missing_symbols]()
    suite.test[test_nomap_and_fd_stability]()
    suite.test[test_empty_map_name]()
    suite^.run()
