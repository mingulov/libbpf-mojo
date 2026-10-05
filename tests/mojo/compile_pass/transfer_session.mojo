"""Compile-pass fixture: transferring a Session works.

Ownership moves with `^`; the new owner uses and closes the
session. This file must compile and run cleanly.
"""
from libbpf_mojo.session import BridgeStats, Session
from testutil import must_close, must_open, read_fixture_elf


def use(var s: Session) raises -> Session:
    var st: BridgeStats
    try:
        st = s.stats()
    except e:
        raise Error("stats failed")
    print("received:", st.received)
    return s^


def main() raises:
    var elf = read_fixture_elf()
    var s = must_open(Span(elf))
    var t = use(s^)
    must_close(t^)
    print("transfer ok")
