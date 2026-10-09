# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

"""Generic symbol optionality and v1 consumer compatibility.

The eleven v1 operations stay sufficient: ``NativeLib`` constructs
against the current library, and generic entry points are never
mandatory for it. ``GenericLib`` presence queries report what a
library provides without raising, so old consumers keep working
before and after the generic implementation lands.
"""
from std.sys import exit
from std.testing import TestSuite, assert_equal, assert_false, assert_true

from libbpf_mojo._ffi import (
    GenericLib,
    NativeLib,
    generic_symbol_names,
)
from testutil import native_lib_path, stub_lib_path


def count_present(mut lib: GenericLib, names: List[String]) -> Int:
    """Count resolvable names through one presence-query handle."""
    var n = 0
    for name in names:
        if lib.has_symbol(name.copy()):
            n += 1
    return n


def test_v1_sufficient() raises:
    """The current library still satisfies the eleven v1 operations."""
    var lib = NativeLib(native_lib_path())
    _ = lib^


def test_presence_controls() raises:
    """Presence queries answer true, false, and partial correctly."""
    var lib = GenericLib(native_lib_path())
    assert_true(lib.has_symbol(String("lmb_open")))
    assert_false(lib.has_symbol(String("lmb_no_such_symbol")))
    var names = generic_symbol_names()
    assert_equal(len(names), 20)
    # Two handles to one library agree exactly (deterministic query).
    var again = GenericLib(native_lib_path())
    for name in names:
        assert_equal(
            lib.has_symbol(name.copy()), again.has_symbol(name.copy())
        )
    var present = count_present(lib, names)
    print("generic symbols present: " + String(present) + " of 20")


def test_stub_never_requires_generic() raises:
    """A partial library fails only on its missing v1 operation."""
    var stub = stub_lib_path()
    var msg = String("")
    var raised = False
    try:
        var lib = NativeLib(stub)
        _ = lib^
    except e:
        msg = e.message.copy()
        raised = True
    assert_true(raised)
    assert_equal(msg, String("incomplete native library: lmb_close"))
    # The same handle answers generic presence without raising.
    var gen = GenericLib(stub)
    assert_true(gen.has_symbol(String("lmb_open")))
    assert_false(gen.has_symbol(String("lmb_close")))
    var names = generic_symbol_names()
    var present = count_present(gen, names)
    print("stub generic symbols present: " + String(present))


def run() raises -> Int:
    var suite = TestSuite()
    suite.test[test_v1_sufficient]()
    suite.test[test_presence_controls]()
    suite.test[test_stub_never_requires_generic]()
    suite^.run()
    return 0


def main() raises:
    var code = run()
    if code != 0:
        exit(code)
