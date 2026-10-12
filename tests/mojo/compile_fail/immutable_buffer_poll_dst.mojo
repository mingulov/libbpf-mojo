# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# CHECK: cannot be converted from 'Span[UInt8, origin_of(data)]' to 'Span[UInt8, dst.origin]'
from libbpf_mojo.buffer import Buffer, BufferPollResult


def poll_immutable(mut buffer: Buffer, data: List[UInt8]) -> BufferPollResult:
    return buffer.poll(Span(data))


def main():
    pass
