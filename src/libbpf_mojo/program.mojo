# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Explicit XDP test-run over a retained program view and borrowed spans."""
from libbpf_mojo._ffi import (
    GENERIC_OP_TEST_RUN, GENERIC_OP_VIEW_CHECK, GenericSpanV1,
    GenericOutSpanV1, TestOptionsV1, TestResultV1,
)
from libbpf_mojo.error import LmbError
from libbpf_mojo.object import ProgramView, _query_name, capture_generic_error


@fieldwise_init
struct ProgramTestResult(Copyable):
    """Independent native values, constructed only after successful copyback."""
    var retval: UInt32
    var data_actual: UInt64
    var ctx_actual: UInt64
    var duration_ns: UInt64


def test_run(
    mut view: ProgramView,
    packet: Span[mut=False, UInt8, _],
    context: Span[mut=False, UInt8, _],
    packet_out: Span[mut=True, UInt8, _],
    context_out: Span[mut=True, UInt8, _],
    repeat: UInt64 = 1,
) raises LmbError -> ProgramTestResult:
    """Run once; omitted outputs are explicit empty mutable spans.

    The native adapter snapshots inputs and preserves both outputs on error.
    Their actual lengths remain independent, including for omitted outputs.
    """
    var rc = view._lib[].object_generation_check(view._handle, view._generation)
    if rc != 0:
        raise capture_generic_error(view._lib[], GENERIC_OP_VIEW_CHECK, rc)
    var query = _query_name(view._name, GENERIC_OP_TEST_RUN)
    var options = TestOptionsV1(
        1, 88,
        GenericSpanV1(UInt64(packet.unsafe_ptr()), UInt64(len(packet))),
        GenericOutSpanV1(UInt64(packet_out.unsafe_ptr()), UInt64(len(packet_out))),
        GenericSpanV1(UInt64(context.unsafe_ptr()), UInt64(len(context))),
        GenericOutSpanV1(UInt64(context_out.unsafe_ptr()), UInt64(len(context_out))),
        repeat, 0,
    )
    var result = TestResultV1(1, 40, 0, 0, 0, 0, 0)
    rc = view._lib[].program_test_run(
        view._handle, Pointer(to=query), Pointer(to=options), Pointer(to=result)
    )
    if rc != 0:
        raise capture_generic_error(view._lib[], GENERIC_OP_TEST_RUN, rc)
    return ProgramTestResult(
        result.retval, result.data_actual, result.ctx_actual, result.duration_ns
    )
