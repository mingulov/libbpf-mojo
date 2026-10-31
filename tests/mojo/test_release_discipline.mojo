# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Release discipline: every public close path releases at most once.

Explicit close nulls the handle through the native cell, so the later
destructor is a no-op; dropping an unclosed owner or view releases
exactly once. A double release would corrupt the native refcount and
abort on the repeated destroy, so each case below repeats the
close/drop order many times inside one process.
"""
from std.os import getenv, listdir
from std.pathlib import Path
from std.testing import TestSuite, assert_equal, assert_false, assert_true
from libbpf_mojo.object import Object, MapView, ProgramView


def elf() raises -> List[UInt8]:
    return Path(getenv("LMB_GENERIC_FIXTURE")).read_bytes()


def open_object() raises -> Object:
    var data = elf()
    return Object.open_with_lib(Span(data), getenv("LMB_NATIVE_LIB"))


def drop_unclosed_program_view() raises:
    var obj = open_object()
    var view = obj.program(String("first"))
    _ = view^
    _ = obj^


def drop_unclosed_map_view() raises:
    var obj = open_object()
    var view = obj.map(String("counter"))
    _ = view^
    _ = obj^


def test_explicit_close_then_drop() raises:
    var baseline = len(listdir("/proc/self/fd"))
    for _ in range(64):
        var obj = open_object()
        var program = obj.program(String("first"))
        var view = obj.map(String("counter"))
        program.close()
        view.close()
        obj.close()
        assert_true(obj.is_closed())
    assert_equal(len(listdir("/proc/self/fd")), baseline)


def test_gc_releases_unclosed() raises:
    var baseline = len(listdir("/proc/self/fd"))
    for _ in range(64):
        drop_unclosed_program_view()
        drop_unclosed_map_view()
    assert_equal(len(listdir("/proc/self/fd")), baseline)


def test_double_close_is_quiet() raises:
    var baseline = len(listdir("/proc/self/fd"))
    for _ in range(64):
        var obj = open_object()
        var view = obj.program(String("first"))
        view.close()
        view.close()
        obj.close()
        obj.close()
        assert_true(obj.is_closed())
    assert_equal(len(listdir("/proc/self/fd")), baseline)


def test_map_view_close_then_drop() raises:
    var baseline = len(listdir("/proc/self/fd"))
    for _ in range(64):
        var obj = open_object()
        var view = obj.map(String("counter"))
        view.close()
        obj.close()
        assert_true(obj.is_closed())
    assert_equal(len(listdir("/proc/self/fd")), baseline)


def main() raises:
    var suite = TestSuite()
    suite.test[test_explicit_close_then_drop]()
    suite.test[test_gc_releases_unclosed]()
    suite.test[test_double_close_is_quiet]()
    suite.test[test_map_view_close_then_drop]()
    suite^.run()
