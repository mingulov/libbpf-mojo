# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Explicit tracepoint and kernel probe attachment with move-only native link ownership."""
from std.memory import ArcPointer
from libbpf_mojo._ffi import (
    ATTACH_FAMILY_TRACEPOINT, ATTACH_FAMILY_KPROBE, ATTACH_FAMILY_KRETPROBE, AttachOptionsV1, GenericLib, GenericSpanV1,
    GENERIC_OP_ATTACH, GENERIC_OP_LINK_CLOSE, GENERIC_OP_VIEW_CHECK, GENERIC_DOMAIN_BRIDGE,
)
from libbpf_mojo.error import LmbError, EINVAL
from libbpf_mojo.object import ProgramView, capture_generic_error


struct Link(Movable):
    """One link and its originating dynamic library; never duplicable."""
    var _lib: ArcPointer[GenericLib]
    var _handle: UInt64

    def __init__(
        out self, mut program: ProgramView, category: String, event: String,
        flags: UInt32 = 0, *, family: UInt32 = ATTACH_FAMILY_TRACEPOINT,
    ) raises LmbError:
        var rc = program._lib[].object_generation_check(program._handle, program._generation)
        if rc != 0:
            raise capture_generic_error(program._lib[], GENERIC_OP_VIEW_CHECK, rc)
        program._lib[].require_link()
        var name = program._name.as_bytes()
        var category_bytes = category.as_bytes()
        var event_bytes = event.as_bytes()
        var options = AttachOptionsV1(
            1, 72, GenericSpanV1(UInt64(name.unsafe_ptr()), UInt64(len(name))),
            family, flags,
            GenericSpanV1(UInt64(category_bytes.unsafe_ptr()), UInt64(len(category_bytes))),
            GenericSpanV1(UInt64(event_bytes.unsafe_ptr()), UInt64(len(event_bytes))), 0,
        )
        var handle = UInt64(0)
        rc = program._lib[].object_attach(program._handle, Pointer(to=options), Pointer(to=handle))
        if rc != 0:
            raise capture_generic_error(program._lib[], GENERIC_OP_ATTACH, rc)
        self._lib = program._lib.copy()
        self._handle = handle

    def __init__(out self, *, deinit move: Self):
        self._lib = move._lib^
        self._handle = move._handle

    def __deinit__(deinit self):
        if self._handle != 0:
            var handle = self._handle
            try:
                _ = self._lib[].close_link(Pointer(to=handle))
            except e:
                # Destructors cannot raise. A teardown failure stays in
                # the native last-error record; only the observation here
                # is dropped.
                pass

    def is_closed(self) -> Bool:
        return self._handle == 0

    def close(mut self) raises LmbError:
        """Expose teardown failure while retaining the native null result."""
        if self._handle == 0:
            return
        var handle = self._handle
        var rc = self._lib[].close_link(Pointer(to=handle))
        if rc != 0:
            var error = capture_generic_error(self._lib[], GENERIC_OP_LINK_CLOSE, rc)
            self._handle = handle
            raise error^
        self._handle = handle


def attach_tracepoint(
    mut program: ProgramView, category: String, event: String,
    flags: UInt32 = 0,
) raises LmbError -> Link:
    """Attach one explicit site; loading remains the caller's operation."""
    return Link(program, category, event, flags)


def attach_kprobe(mut program: ProgramView, symbol: String) raises LmbError -> Link:
    """Attach one entry probe; symbol resolution and permission remain native."""
    return Link(program, symbol, "", family=ATTACH_FAMILY_KPROBE)


def attach_kretprobe(mut program: ProgramView, symbol: String) raises LmbError -> Link:
    """Attach one return probe; the link retains its object and library."""
    return Link(program, symbol, "", family=ATTACH_FAMILY_KRETPROBE)


@fieldwise_init
struct AttachmentCapability(Copyable):
    """Declarative library eligibility, never an observation of this kernel."""
    var minimum_kernel: String
    var requires_btf: Bool
    var requires_symbol: Bool
    var qualification: String


def attachment_capability(kind: UInt32) raises LmbError -> AttachmentCapability:
    """Session kinds 1..4; generic family 2 remains reserved."""
    if kind < 1 or kind > 4:
        raise LmbError(GENERIC_OP_ATTACH, GENERIC_DOMAIN_BRIDGE, EINVAL, "unknown attachment capability")
    return AttachmentCapability("6.0", True, kind != 1, "unqualified")
