# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Move-only generic ring consumers with borrowed mutable destinations."""
from std.memory import ArcPointer
from libbpf_mojo._ffi import (
    BufferOptionsV1, BufferStatsV1, GenericLib, GenericSpanV1, MAX_FRAME_BYTES,
    GENERIC_DOMAIN_BRIDGE, GENERIC_OP_BUFFER_OPEN, GENERIC_OP_BUFFER_POLL,
    GENERIC_OP_BUFFER_CLOSE, GENERIC_OP_BUFFER_STATS, GENERIC_OP_VIEW_CHECK,
)
from libbpf_mojo.batch import POLL_BATCH, POLL_TIMEOUT, POLL_SHORT, POLL_ERROR
from libbpf_mojo.error import EINVAL, ENOSPC, LmbError
from libbpf_mojo.object import MapView, capture_generic_error


@fieldwise_init
struct BufferPollResult(Copyable):
    """One-frame/empty/short/error outcome with an owned diagnostic."""
    var kind: UInt32
    var used: UInt64
    var needed: UInt64
    var error: LmbError

    def is_frame(self) -> Bool:
        return self.kind == POLL_BATCH

    def is_empty(self) -> Bool:
        return self.kind == POLL_TIMEOUT

    def is_short(self) -> Bool:
        return self.kind == POLL_SHORT

    def is_error(self) -> Bool:
        return self.kind == POLL_ERROR


@fieldwise_init
struct BufferStats(Copyable):
    """Transport counters for one ring consumer."""

    var received: UInt64
    var delivered: UInt64
    var staged: UInt64
    var malformed: UInt64
    var dropped: UInt64


struct Buffer(Movable):
    """One native ring reader; its native reference retains the parent."""
    var _lib: ArcPointer[GenericLib]
    var _handle: UInt64
    var _parent: UInt64
    var _generation: UInt64

    def __init__(
        out self, mut ring: MapView, max_raw_bytes: UInt32 = 4096,
        stage_slots: UInt32 = 1, flags: UInt32 = 0,
    ) raises LmbError:
        var rc = ring._lib[].object_generation_check(ring._handle, ring._generation)
        if rc != 0:
            raise capture_generic_error(ring._lib[], GENERIC_OP_VIEW_CHECK, rc)
        ring._lib[].require_buffer()
        var name = ring._name.as_bytes()
        var options = BufferOptionsV1(
            1, 40, GenericSpanV1(UInt64(name.unsafe_ptr()), UInt64(len(name))),
            max_raw_bytes, stage_slots, flags, 0,
        )
        var handle = UInt64(0)
        rc = ring._lib[].open_buffer(ring._handle, Pointer(to=options), Pointer(to=handle))
        if rc != 0:
            raise capture_generic_error(ring._lib[], GENERIC_OP_BUFFER_OPEN, rc)
        self._lib = ring._lib.copy()
        self._handle = handle
        self._parent = ring._handle
        self._generation = ring._generation

    def __init__(out self, *, deinit move: Self):
        self._lib = move._lib^
        self._handle = move._handle
        self._parent = move._parent
        self._generation = move._generation

    def __deinit__(deinit self):
        if self._handle != 0:
            var handle = self._handle
            try:
                _ = self._lib[].close_buffer(Pointer(to=handle))
            except e:
                pass

    def is_closed(self) -> Bool:
        return self._handle == 0

    def close(mut self) raises LmbError:
        """Teardown stays available independently of generation checks."""
        if self._handle == 0:
            return
        var handle = self._handle
        var rc = self._lib[].close_buffer(Pointer(to=handle))
        if rc != 0:
            var error = capture_generic_error(self._lib[], GENERIC_OP_BUFFER_CLOSE, rc)
            self._handle = handle
            if handle == 0:
                self._parent = 0
                self._generation = 0
            raise error^
        self._handle = handle
        if handle == 0:
            self._parent = 0
            self._generation = 0

    def poll(
        mut self, dst: Span[mut=True, UInt8, _], timeout_ms: Int32 = 0,
    ) -> BufferPollResult:
        """Poll with caller storage, without resizing, retry or retained spans."""
        if self._handle == 0:
            return BufferPollResult(POLL_ERROR, 0, 0, LmbError(
                GENERIC_OP_BUFFER_POLL, GENERIC_DOMAIN_BRIDGE, EINVAL, "buffer is closed"))
        try:
            var rc = self._lib[].object_generation_check(self._parent, self._generation)
            if rc != 0:
                return BufferPollResult(POLL_ERROR, 0, 0,
                    capture_generic_error(self._lib[], GENERIC_OP_VIEW_CHECK, rc))
            var used = UInt64(0)
            var needed = UInt64(0)
            rc = self._lib[].poll_buffer(self._handle, dst.unsafe_ptr(), UInt64(len(dst)),
                                        timeout_ms, Pointer(to=used), Pointer(to=needed))
            if rc != 0:
                var error = capture_generic_error(self._lib[], GENERIC_OP_BUFFER_POLL, rc)
                var kind = POLL_ERROR
                if (rc == ENOSPC and error.operation == GENERIC_OP_BUFFER_POLL
                        and error.domain == GENERIC_DOMAIN_BRIDGE and error.code == ENOSPC
                        and used == 0 and needed >= 9 and needed <= UInt64(MAX_FRAME_BYTES)
                        and needed > UInt64(len(dst))):
                    kind = POLL_SHORT
                return BufferPollResult(kind, used, needed, error^)
            var kind = POLL_TIMEOUT
            if used != 0:
                kind = POLL_BATCH
            return BufferPollResult(kind, used, needed, LmbError(0, 0, 0, ""))
        except e:
            return BufferPollResult(POLL_ERROR, 0, 0, e.copy())

    def stats(mut self) raises LmbError -> BufferStats:
        """Snapshot this consumer's transport counters without polling."""
        if self._handle == 0:
            raise LmbError(
                GENERIC_OP_BUFFER_STATS, GENERIC_DOMAIN_BRIDGE, EINVAL,
                "buffer is closed")
        var rc = self._lib[].object_generation_check(self._parent, self._generation)
        if rc != 0:
            raise capture_generic_error(self._lib[], GENERIC_OP_VIEW_CHECK, rc)
        var out = BufferStatsV1(
            UInt32(1),
            UInt32(48),
            UInt64(0),
            UInt64(0),
            UInt64(0),
            UInt64(0),
            UInt64(0),
        )
        rc = self._lib[].buffer_stats(self._handle, Pointer(to=out))
        if rc != 0:
            raise capture_generic_error(self._lib[], GENERIC_OP_BUFFER_STATS, rc)
        return BufferStats(
            out.received,
            out.delivered,
            out.staged,
            out.malformed,
            out.dropped,
        )


def open_ring(
    mut ring: MapView, max_raw_bytes: UInt32 = 4096,
    stage_slots: UInt32 = 1, flags: UInt32 = 0,
) raises LmbError -> Buffer:
    """Create a consumer for an explicitly loaded named ring map."""
    return Buffer(ring, max_raw_bytes, stage_slots, flags)
