# SPDX-License-Identifier: GPL-3.0-or-later

"""Poll results and frame decoding.

A poll delivers at most one frame; the batch data stays in the
caller's destination buffer and decoding copies payload bytes into
owned ``Frame`` values, so no borrowed record escapes its owner.
Decoding reads bytes only and never casts input to a native struct,
so unaligned input decodes identically.
"""
from libbpf_mojo._ffi import (
    DOMAIN_BRIDGE,
    FRAME_HEADER_SIZE,
    FRAME_VERSION,
    MAX_FRAME_BYTES,
    OP_POLL,
    read_u16_le,
    read_u32_le,
    read_u8_le,
)
from libbpf_mojo.error import EBADMSG, EINVAL, LmbError

comptime POLL_TIMEOUT = UInt32(0)
comptime POLL_BATCH = UInt32(1)
comptime POLL_SHORT = UInt32(2)
comptime POLL_ERROR = UInt32(3)


@fieldwise_init
struct PollResult(Copyable):
    """One poll outcome: batch, timeout, short, or structured error."""

    var kind: UInt32
    var written: UInt32
    var required: UInt32
    var error: LmbError

    def is_batch(ref self) -> Bool:
        return self.kind == POLL_BATCH

    def is_timeout(ref self) -> Bool:
        return self.kind == POLL_TIMEOUT

    def is_short(ref self) -> Bool:
        return self.kind == POLL_SHORT

    def is_error(ref self) -> Bool:
        return self.kind == POLL_ERROR


@fieldwise_init
struct Frame(Copyable):
    """One decoded frame with an owned payload copy.

    ``flags`` always decodes to zero: v1 reserves the field and
    nonzero values are rejected as corrupt.
    """

    var total_len: UInt32
    var version: UInt16
    var flags: UInt16
    var payload: List[UInt8]


def decode_frame(
    data: Span[UInt8, _], start: Int, count: UInt32
) raises LmbError -> Frame:
    """Decode one frame at ``start`` spanning ``count`` valid bytes."""
    var total = len(data)
    var need = Int(count)
    if need < Int(FRAME_HEADER_SIZE):
        raise LmbError(
            OP_POLL, DOMAIN_BRIDGE, EBADMSG, String("frame too short")
        )
    if start < 0 or start > total or need > total - start:
        raise LmbError(
            OP_POLL, DOMAIN_BRIDGE, EINVAL,
            String("frame out of range"),
        )
    if count > MAX_FRAME_BYTES:
        raise LmbError(
            OP_POLL, DOMAIN_BRIDGE, EBADMSG, String("frame too long")
        )
    var base = data.unsafe_ptr().unsafe_offset(start)
    var payload_len = read_u32_le(base, 0)
    var version = read_u16_le(base, 4)
    var flags = read_u16_le(base, 6)
    if version != FRAME_VERSION:
        raise LmbError(
            OP_POLL, DOMAIN_BRIDGE, EBADMSG,
            String("frame version mismatch"),
        )
    if flags != 0:
        raise LmbError(
            OP_POLL, DOMAIN_BRIDGE, EBADMSG,
            String("frame reserved bytes nonzero"),
        )
    if payload_len == 0 or payload_len != count - FRAME_HEADER_SIZE:
        raise LmbError(
            OP_POLL, DOMAIN_BRIDGE, EBADMSG,
            String("frame length mismatch"),
        )
    var payload = List[UInt8]()
    for i in range(Int(payload_len)):
        payload.append(UInt8(read_u8_le(base, 8 + i)))
    return Frame(count, UInt16(version), UInt16(flags), payload^)
