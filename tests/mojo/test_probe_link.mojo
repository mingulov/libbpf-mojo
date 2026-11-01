# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Probe ownership and typed calls over guarded native adaptation."""
from std.os import getenv
from std.pathlib import Path
from std.testing import TestSuite, assert_equal, assert_true
from libbpf_mojo.link import attach_kprobe, attach_kretprobe, attachment_capability, Link
from libbpf_mojo.object import Object
from libbpf_mojo.session import AttachSpec


def owner() raises -> Object:
    var data = Path(getenv("LMB_PROBE_FIXTURE")).read_bytes()
    var object = Object.open_with_lib(Span(data), getenv("LMB_EVENTS_TESTFAKE_LIB"))
    var reset = object._lib[]._handle.get_function[NoneType]("lmb_events_reset")
    reset()
    object.load()
    return object^


def scoped_link(retprobe: Bool) raises -> Link:
    var object = owner()
    var program = object.program("probe_return" if retprobe else "probe_entry")
    if retprobe:
        return attach_kretprobe(program, "lmb_test_target")
    return attach_kprobe(program, "lmb_test_target")


def test_probe_ownership_and_metadata() raises:
    for retprobe in [False, True]:
        var link = scoped_link(retprobe)
        var moved = link^
        var query = moved._lib[]._handle.get_function[UInt64]("lmb_events_call_count")
        assert_equal(query(UInt32(1)), UInt64(1))
        assert_equal(query(UInt32(8)), UInt64(0))
        moved.close()
        assert_true(moved.is_closed())
        assert_equal(query(UInt32(2)), UInt64(1))
        assert_equal(query(UInt32(8)), UInt64(1))
        moved.close()
        assert_equal(query(UInt32(2)), UInt64(1))
        assert_equal(query(UInt32(19)), UInt64(0))
        var spec = AttachSpec.kretprobe("probe_return", "target") if retprobe else AttachSpec.kprobe("probe_entry", "target")
        assert_equal(spec.kind, UInt32(4 if retprobe else 3))
        assert_equal(spec.target_a, "target")
        assert_equal(spec.target_b, "")
        var capability = attachment_capability(spec.kind)
        assert_equal(capability.minimum_kernel, "6.0")
        assert_true(capability.requires_btf)
        assert_true(capability.requires_symbol)
        assert_equal(capability.qualification, "unqualified")


def test_probe_failures_preserve_diagnostic_and_ownership() raises:
    for retprobe in [False, True]:
        var object = owner()
        var program = object.program("probe_return" if retprobe else "probe_entry")
        var scenario = object._lib[]._handle.get_function[NoneType]("lmb_events_scenario")
        var query = object._lib[]._handle.get_function[UInt64]("lmb_events_call_count")
        scenario(UInt32(7))
        var refused = False
        try:
            var link = attach_kretprobe(program, "lmb_test_target") if retprobe else attach_kprobe(program, "lmb_test_target")
            _ = link^
        except error:
            refused = True
            assert_equal(error.operation, UInt32(10))
            assert_equal(error.domain, UInt32(2))
            assert_equal(error.code, Int32(-5))
        assert_true(refused)
        assert_equal(query(UInt32(1)), UInt64(1))
        assert_equal(query(UInt32(23)), UInt64(0))
        assert_equal(query(UInt32(19)), UInt64(0))


def test_capability_unknown_refused() raises:
    for kind in [UInt32(0), UInt32(5), UInt32(0xffffffff)]:
        var refused = False
        try:
            _ = attachment_capability(kind)
        except error:
            refused = True
            assert_equal(error.operation, UInt32(10))
            assert_equal(error.domain, UInt32(4))
            assert_equal(error.code, Int32(-22))
        assert_true(refused)
    for kind in [UInt32(1), UInt32(2)]:
        var capability = attachment_capability(kind)
        assert_equal(capability.minimum_kernel, "6.0")
        assert_true(capability.requires_btf)
        assert_equal(capability.requires_symbol, kind == 2)


def test_probe_symbol_refusals() raises:
    for retprobe in [False, True]:
        var object = owner()
        var program = object.program("probe_return" if retprobe else "probe_entry")
        var query = object._lib[]._handle.get_function[UInt64]("lmb_events_call_count")
        for symbol in ["target\nforeign", "target argument", "target+0x1", "0xffffffff", "module::target"]:
            var refused = False
            try:
                var link = attach_kretprobe(program, symbol) if retprobe else attach_kprobe(program, symbol)
                _ = link^
            except error:
                refused = True
                assert_equal(error.operation, UInt32(10))
                assert_equal(error.domain, UInt32(4))
                assert_equal(error.code, Int32(-22))
            assert_true(refused)
            assert_equal(query(UInt32(1)), UInt64(0))
            assert_equal(query(UInt32(23)), UInt64(0))


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
    print("NOT_RUN probe_link.kernel-attachment: host adaptation and ownership only")
