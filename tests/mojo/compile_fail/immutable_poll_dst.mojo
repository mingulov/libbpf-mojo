# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

"""Compile-fail fixture: poll needs a mutable destination.

# CHECK: mutable

The native call writes the frame through the destination, so an
immutable borrow must not reach it. This file must NOT compile.
"""
from libbpf_mojo.batch import PollResult
from libbpf_mojo.session import Session
from testutil import must_close, must_open, read_fixture_elf


def poll_imm(var s: Session, data: List[UInt8]) raises -> PollResult:
    var res = s.poll(data, 0, UInt32(0), Int32(0))
    must_close(s^)
    return res^


def main() raises:
    var elf = read_fixture_elf()
    var s = must_open(Span(elf))
    var zone = List[UInt8](length=24, fill=UInt8(0))
    var res = poll_imm(s^, zone)
    print(res.is_error())
