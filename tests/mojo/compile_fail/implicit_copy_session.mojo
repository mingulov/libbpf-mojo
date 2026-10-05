"""Compile-fail fixture: a Session cannot be implicitly copied.

# CHECK: cannot be implicitly copied

The session owns its native handle and library; copies would
double-close. This file must NOT compile.
"""
from libbpf_mojo.session import Session
from testutil import must_close, must_open, read_fixture_elf


def main() raises:
    var elf = read_fixture_elf()
    var s = must_open(Span(elf))
    var s2 = s
    must_close(s^)
