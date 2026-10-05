"""Compile-fail fixture: a Session has no copy method.

# CHECK: no attribute 'copy'

Copying would duplicate the native handle owner. This file must
NOT compile.
"""
from libbpf_mojo.session import Session
from testutil import must_close, must_open, read_fixture_elf


def main() raises:
    var elf = read_fixture_elf()
    var s = must_open(Span(elf))
    var s3 = s.copy()
    must_close(s^)
