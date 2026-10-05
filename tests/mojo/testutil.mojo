"""Shared helpers for the Mojo boundary tests (test-only).

`TestFake` drives the synthetic input switch in the test-support
library. Sessions under test are only borrowed, never owned, so no
native handle escapes its `Session` owner.
"""
from std.ffi import OwnedDLHandle
from std.os import getenv
from std.pathlib import Path
from std.testing import assert_true

from libbpf_mojo._ffi import read_u64_le
from libbpf_mojo.batch import PollResult
from libbpf_mojo.error import LmbError
from libbpf_mojo.session import Session


def native_lib_path() raises -> String:
    return getenv("LMB_NATIVE_LIB")


def testfake_lib_path() raises -> String:
    return getenv("LMB_TESTFAKE_LIB")


def fixture_path() raises -> String:
    return getenv("LMB_FIXTURE")


def read_fixture_elf() raises -> List[UInt8]:
    return Path(fixture_path()).read_bytes()


def must_open(elf: Span[UInt8, _]) raises -> Session:
    """Open a fixture session or fail the test with the structure."""
    try:
        var s = Session.open(elf, String("events"), UInt32(4096))
        return s^
    except e:
        raise Error("open failed: " + String(e))


def must_close(var s: Session) raises:
    """Close a session or fail the test with the structure."""
    try:
        s.close()
    except e:
        raise Error("close failed: " + String(e))


struct TestFake(Movable):
    """Test-only driver for the synthetic input switch."""

    var _lib: OwnedDLHandle

    def __init__(out self) raises:
        self._lib = OwnedDLHandle(testfake_lib_path())

    def arm(mut self, session: Session) raises -> Int32:
        var f = self._lib.get_function[Int32](String("lmb_test_fake_arm"))
        return f(session._handle)

    def sample(
        mut self, session: Session, payload: Span[UInt8, _]
    ) raises -> Int32:
        assert_true(len(payload) <= 8192)
        var f = self._lib.get_function[Int32](
            String("lmb_test_fake_sample")
        )
        return f(
            session._handle, payload.unsafe_ptr(),
            UInt32(len(payload)),
        )

    def disarm(mut self, session: Session) raises -> Int32:
        var f = self._lib.get_function[Int32](
            String("lmb_test_fake_disarm")
        )
        return f(session._handle)

    def has_privilege(mut self) raises -> Bool:
        var f = self._lib.get_function[Int32](
            String("lmb_test_has_privilege")
        )
        return f() == 1


def stub_lib_path() raises -> String:
    return getenv("LMB_STUB_LIB")


def poll_guarded(
    mut session: Session,
    mut zone: List[UInt8],
    start: Int,
    capacity: UInt32,
) raises -> PollResult:
    """Poll only while a record is staged.

    The armed test session carries a dummy ring pointer that cannot
    back consumption: polling with an empty stage would crash instead
    of timing out. The guard turns that test bug into a clear
    failure; live timeout coverage belongs to the privileged gate.
    """
    var staged: UInt64
    try:
        var st = session.stats()
        staged = st.staged
    except e:
        raise Error("guard stats failed: " + String(e))
    if staged == 0:
        raise Error("poll with empty stage would hit the dummy ring")
    var res = session.poll(zone, start, capacity, Int32(0))
    return res^


def peak_rss_kb() raises -> Int:
    """Peak resident set in KiB via libc getrusage (no text parsing)."""
    var libc = OwnedDLHandle("libc.so.6")
    var getrusage = libc.get_function[Int32](String("getrusage"))
    var buf = Array[Int8, 144](fill=0)
    var rc = getrusage(Int32(0), Pointer(to=buf))
    if rc != 0:
        raise Error("getrusage failed")
    var p = Pointer(to=buf).unsafe_bitcast[UInt8]()
    return Int(read_u64_le(p, 32))
