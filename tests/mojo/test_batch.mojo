# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

"""Batch decoding: frame parsing, short-buffer retention with guard
bytes, unaligned delivery, and the 100k synthetic bulk run with
markers above 2^53. All native input is synthetic through the
test-support library; no privileges needed.
"""
from std.sys import exit
from std.testing import TestSuite, assert_equal, assert_true

from libbpf_mojo._ffi import (
    DOMAIN_BRIDGE,
    FRAME_HEADER_SIZE,
    FRAME_VERSION,
    MAX_FRAME_BYTES,
    MAX_RAW_BYTES,
    OP_POLL,
)
from libbpf_mojo.batch import POLL_BATCH, POLL_ERROR, POLL_SHORT, POLL_TIMEOUT
from libbpf_mojo.batch import Frame, PollResult, decode_frame
from libbpf_mojo.error import EBADMSG, EINVAL, LmbError
from libbpf_mojo.session import BridgeStats
from testutil import (
    TestFake,
    must_close,
    must_open,
    poll_guarded,
    read_fixture_elf,
)


def must_decode(
    data: Span[UInt8, _], start: Int, count: UInt32
) raises -> Frame:
    try:
        var frame = decode_frame(data, start, count)
        return frame^
    except e:
        raise Error("decode failed: " + String(e))

comptime SEQ_BASE = UInt64(0x20000000000001)


def pattern_byte(i: Int) -> UInt8:
    return UInt8((i * 7 + 3) & 0xFF)


def make_payload(seq: UInt64) -> List[UInt8]:
    var out = List[UInt8]()
    var v = seq
    for _ in range(8):
        out.append(UInt8(v & UInt64(0xFF)))
        v >>= 8
    for i in range(8):
        out.append(pattern_byte(i))
    return out^


def write_frame(mut buf: List[UInt8], start: Int, payload: List[UInt8]):
    var n = UInt32(len(payload))
    buf[start] = UInt8(n & UInt32(0xFF))
    buf[start + 1] = UInt8((n >> 8) & UInt32(0xFF))
    buf[start + 2] = UInt8((n >> 16) & UInt32(0xFF))
    buf[start + 3] = UInt8((n >> 24) & UInt32(0xFF))
    buf[start + 4] = UInt8(FRAME_VERSION & UInt32(0xFF))
    buf[start + 5] = UInt8((FRAME_VERSION >> 8) & UInt32(0xFF))
    buf[start + 6] = UInt8(0)
    buf[start + 7] = UInt8(0)
    for i in range(len(payload)):
        buf[start + 8 + i] = payload[i]


def payload_matches(got: List[UInt8], seq: UInt64) -> Bool:
    if len(got) != 16:
        return False
    var v = UInt64(0)
    for i in range(8):
        v |= UInt64(got[i]) << UInt64(8 * i)
    if v != seq:
        return False
    for i in range(8):
        if got[8 + i] != pattern_byte(i):
            return False
    return True


def test_decode_valid() raises:
    var payload = make_payload(SEQ_BASE)
    var buf = List[UInt8](length=24, fill=UInt8(0))
    write_frame(buf, 0, payload)
    var frame = must_decode(Span(buf), 0, UInt32(24))
    assert_equal(frame.total_len, UInt32(24))
    assert_equal(frame.version, UInt16(1))
    assert_equal(frame.flags, UInt16(0))
    assert_true(payload_matches(frame.payload, SEQ_BASE))


def test_decode_short() raises:
    var buf = List[UInt8](length=7, fill=UInt8(0))
    var code = Int32(0)
    var raised = False
    try:
        var frame = decode_frame(Span(buf), 0, UInt32(7))
    except e:
        code = e.code
        raised = True
    assert_true(raised)
    assert_equal(code, EBADMSG)


def test_decode_version() raises:
    var payload = make_payload(SEQ_BASE)
    var buf = List[UInt8](length=24, fill=UInt8(0))
    write_frame(buf, 0, payload)
    buf[4] = UInt8(2)
    var code = Int32(0)
    var op = UInt32(0)
    var raised = False
    try:
        var frame = decode_frame(Span(buf), 0, UInt32(24))
    except e:
        code = e.code
        op = e.operation
        raised = True
    assert_true(raised)
    assert_equal(op, OP_POLL)
    assert_equal(code, EBADMSG)


def test_decode_reserved() raises:
    for slot in [6, 7]:
        var payload = make_payload(SEQ_BASE)
        var buf = List[UInt8](length=24, fill=UInt8(0))
        write_frame(buf, 0, payload)
        buf[slot] = UInt8(1)
        var code = Int32(0)
        var raised = False
        try:
            var frame = decode_frame(Span(buf), 0, UInt32(24))
        except e:
            code = e.code
            raised = True
        assert_true(raised)
        assert_equal(code, EBADMSG)


def test_decode_length_mismatch() raises:
    var buf = List[UInt8](length=18, fill=UInt8(0))
    buf[0] = UInt8(16)
    buf[4] = UInt8(1)
    var raised = False
    try:
        var frame = decode_frame(Span(buf), 0, UInt32(18))
    except e:
        raised = True
    assert_true(raised)
    var empty = List[UInt8](length=8, fill=UInt8(0))
    empty[4] = UInt8(1)
    var raised2 = False
    try:
        var frame2 = decode_frame(Span(empty), 0, UInt32(8))
    except e:
        raised2 = True
    assert_true(raised2)
    var buf24 = List[UInt8](length=24, fill=UInt8(0))
    var range_code = Int32(0)
    var range_op = UInt32(0)
    var range_raised = False
    try:
        var frame3 = decode_frame(Span(buf24), 16, UInt32(24))
    except e:
        range_code = e.code
        range_op = e.operation
        range_raised = True
    assert_true(range_raised)
    assert_equal(range_op, OP_POLL)
    assert_equal(range_code, EINVAL)


def test_decode_unaligned() raises:
    var payload = make_payload(SEQ_BASE + UInt64(9))
    for start in range(1, 8):
        var buf = List[UInt8](length=32, fill=UInt8(0xA5))
        write_frame(buf, start, payload)
        var frame = must_decode(Span(buf), start, UInt32(24))
        assert_equal(frame.total_len, UInt32(24))
        assert_true(payload_matches(frame.payload, SEQ_BASE + UInt64(9)))


def test_decode_max() raises:
    var payload = List[UInt8]()
    for i in range(Int(MAX_RAW_BYTES)):
        payload.append(pattern_byte(i))
    var buf = List[UInt8](length=Int(MAX_FRAME_BYTES), fill=UInt8(0))
    write_frame(buf, 0, payload)
    var frame = must_decode(Span(buf), 0, MAX_FRAME_BYTES)
    assert_equal(frame.total_len, MAX_FRAME_BYTES)
    assert_equal(len(frame.payload), Int(MAX_RAW_BYTES))
    var same = True
    for i in range(Int(MAX_RAW_BYTES)):
        if frame.payload[i] != pattern_byte(i):
            same = False
            break
    assert_true(same)


def test_pollresult_kinds() raises:
    var err = LmbError(UInt32(4), UInt32(4), Int32(-22), String("x"))
    var timeout = PollResult(POLL_TIMEOUT, UInt32(0), UInt32(0), err.copy())
    assert_true(timeout.is_timeout())
    assert_true(not timeout.is_batch())
    var batch = PollResult(POLL_BATCH, UInt32(24), UInt32(0), err.copy())
    assert_true(batch.is_batch())
    var short = PollResult(POLL_SHORT, UInt32(0), UInt32(24), err.copy())
    assert_true(short.is_short())
    assert_equal(short.required, UInt32(24))
    var failed = PollResult(POLL_ERROR, UInt32(0), UInt32(0), err.copy())
    assert_true(failed.is_error())
    assert_equal(failed.error.code, Int32(-22))


def check_guards(zone: List[UInt8], cap: Int) -> Bool:
    for i in range(16):
        if zone[i] != UInt8(0xA5):
            return False
        if zone[16 + cap + i] != UInt8(0xA5):
            return False
    return True


def check_dst_clean(zone: List[UInt8], cap: Int) -> Bool:
    for i in range(cap):
        if zone[16 + i] != UInt8(0x5A):
            return False
    return True


def prep_zone(mut zone: List[UInt8], cap: Int):
    for i in range(16):
        zone[i] = UInt8(0xA5)
        zone[16 + cap + i] = UInt8(0xA5)
    for i in range(cap):
        zone[16 + i] = UInt8(0x5A)


def test_short_buffer_23_24() raises:
    var elf = read_fixture_elf()
    var s = must_open(Span(elf))
    var fake = TestFake()
    assert_equal(fake.arm(s), Int32(0))
    var disarm_rc: Int32
    try:
        var payload = make_payload(SEQ_BASE)
        assert_equal(fake.sample(s, Span(payload)), Int32(0))
        var zone = List[UInt8](length=16 + 23 + 16, fill=UInt8(0))
        prep_zone(zone, 23)
        var short = poll_guarded(s, zone, 16, UInt32(23))
        assert_true(short.is_short())
        assert_equal(short.written, UInt32(0))
        assert_equal(short.required, UInt32(24))
        assert_true(check_guards(zone, 23))
        assert_true(check_dst_clean(zone, 23))
        var zone2 = List[UInt8](length=24, fill=UInt8(0))
        var got = poll_guarded(s, zone2, 0, UInt32(24))
        assert_true(got.is_batch())
        assert_equal(got.written, UInt32(24))
        assert_equal(got.required, UInt32(0))
        var frame = must_decode(Span(zone2), 0, got.written)
        assert_true(payload_matches(frame.payload, SEQ_BASE))
        var st: BridgeStats
        try:
            st = s.stats()
        except e:
            raise Error("stats failed: " + String(e))
        assert_equal(st.received, UInt64(1))
        assert_equal(st.delivered, UInt64(1))
        assert_equal(st.staged, UInt64(0))
    finally:
        disarm_rc = fake.disarm(s)
    assert_equal(disarm_rc, Int32(0))
    must_close(s^)


def test_malformed_counts() raises:
    var elf = read_fixture_elf()
    var s = must_open(Span(elf))
    var fake = TestFake()
    assert_equal(fake.arm(s), Int32(0))
    var disarm_rc: Int32
    try:
        var big = List[UInt8](length=5000, fill=UInt8(1))
        assert_equal(fake.sample(s, Span(big)), Int32(0))
        var empty = List[UInt8]()
        assert_equal(fake.sample(s, Span(empty)), Int32(0))
        var payload = make_payload(SEQ_BASE)
        assert_equal(fake.sample(s, Span(payload)), Int32(0))
        var zone = List[UInt8](length=24, fill=UInt8(0))
        var got = poll_guarded(s, zone, 0, UInt32(24))
        assert_true(got.is_batch())
        var frame = must_decode(Span(zone), 0, got.written)
        assert_true(payload_matches(frame.payload, SEQ_BASE))
        var st: BridgeStats
        try:
            st = s.stats()
        except e:
            raise Error("stats failed: " + String(e))
        assert_equal(st.received, UInt64(3))
        assert_equal(st.delivered, UInt64(1))
        assert_equal(st.staged, UInt64(0))
        assert_equal(st.malformed, UInt64(2))
        assert_equal(st.dropped, UInt64(0))
    finally:
        disarm_rc = fake.disarm(s)
    assert_equal(disarm_rc, Int32(0))
    must_close(s^)


def bulk_cycle(round: Int) raises:
    var elf = read_fixture_elf()
    var s = must_open(Span(elf))
    var fake = TestFake()
    assert_equal(fake.arm(s), Int32(0))
    var disarm_rc: Int32
    try:
        var zone = List[UInt8](length=24, fill=UInt8(0))
        for i in range(100000):
            var seq = SEQ_BASE + UInt64(i)
            var payload = make_payload(seq)
            assert_equal(fake.sample(s, Span(payload)), Int32(0))
            var res = poll_guarded(s, zone, 0, UInt32(24))
            assert_true(res.is_batch())
            var frame = must_decode(Span(zone), 0, res.written)
            if not payload_matches(frame.payload, seq):
                print("mismatch at round", round, "record", i)
            assert_true(payload_matches(frame.payload, seq))
        var st: BridgeStats
        try:
            st = s.stats()
        except e:
            raise Error("bulk stats failed: " + String(e))
        assert_equal(st.received, UInt64(100000))
        assert_equal(st.delivered, UInt64(100000))
        assert_equal(st.staged, UInt64(0))
        assert_equal(st.malformed, UInt64(0))
        assert_equal(st.dropped, UInt64(0))
        assert_equal(
            st.received,
            st.delivered + st.staged + st.malformed + st.dropped,
        )
    finally:
        disarm_rc = fake.disarm(s)
    assert_equal(disarm_rc, Int32(0))
    must_close(s^)


def test_bulk_100k_twice() raises:
    bulk_cycle(0)
    bulk_cycle(1)


def run() raises -> Int:
    var suite = TestSuite()
    suite.test[test_decode_valid]()
    suite.test[test_decode_short]()
    suite.test[test_decode_version]()
    suite.test[test_decode_reserved]()
    suite.test[test_decode_length_mismatch]()
    suite.test[test_decode_unaligned]()
    suite.test[test_decode_max]()
    suite.test[test_pollresult_kinds]()
    suite.test[test_short_buffer_23_24]()
    suite.test[test_malformed_counts]()
    suite.test[test_bulk_100k_twice]()
    suite^.run()
    return 0


def main() raises:
    var code = run()
    if code != 0:
        exit(code)
