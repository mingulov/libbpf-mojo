# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

"""Compile-fail fixture: a Session cannot be used after transfer.

# CHECK: use of uninitialized value

Ownership moves with `^`; the source must not be usable again.
This file must NOT compile.
"""
from libbpf_mojo.session import Session
from testutil import must_close, must_open, read_fixture_elf


def main() raises:
    var elf = read_fixture_elf()
    var s = must_open(Span(elf))
    var t = s^
    try:
        var st = s.stats()
    except e:
        print("caught")
    must_close(t^)
