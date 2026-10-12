# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# CHECK: mutable
from libbpf_mojo.buffer import Buffer, BufferPollResult


def poll_immutable(mut buffer: Buffer, data: List[UInt8]) -> BufferPollResult:
    return buffer.poll(Span(data))


def main():
    pass
