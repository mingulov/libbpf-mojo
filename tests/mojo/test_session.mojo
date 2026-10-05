"""Session ownership, lifecycle, and operation contracts.

Every test runs without privileges except the valid-load branch,
which follows the independent privilege probe deterministically.
"""
from std.sys import exit
from std.testing import TestSuite, assert_equal, assert_false, assert_true

from libbpf_mojo._ffi import (
    ATTACH_TRACEPOINT,
    DOMAIN_BRIDGE,
    DOMAIN_LIBBPF,
    OP_ATTACH,
    OP_LOAD,
    OP_MAP_INFO,
    OP_MAP_READ,
    OP_MAP_WRITE,
    OP_OPEN,
    OP_POLL,
    MapInfoV1,
)
from libbpf_mojo.error import EBUSY, EINVAL, ENOENT, LmbError
from libbpf_mojo.session import (
    AttachSpec,
    BridgeStats,
    MapReadResult,
    Session,
)
from testutil import (
    TestFake,
    must_close,
    must_open,
    peak_rss_kb,
    read_fixture_elf,
)


def test_open_close() raises:
    var elf = read_fixture_elf()
    var s = must_open(Span(elf))
    assert_false(s.is_closed())
    must_close(s^)


def test_double_close() raises:
    var elf = read_fixture_elf()
    var s = must_open(Span(elf))
    try:
        s.close()
        s.close()
    except e:
        raise Error("double close failed: " + String(e))
    assert_true(s.is_closed())
    must_close(s^)


def test_open_invalid_elf() raises:
    var empty = List[UInt8]()
    var op = UInt32(0)
    var code = Int32(0)
    var raised = False
    try:
        var s = Session.open(
            Span(empty), String("events"), UInt32(4096)
        )
        s.close()
    except e:
        op = e.operation
        code = e.code
        raised = True
    assert_true(raised)
    assert_equal(op, OP_OPEN)
    assert_equal(code, EINVAL)


def test_open_invalid_max_raw() raises:
    var elf = read_fixture_elf()
    for raw in [UInt32(0), UInt32(5000)]:
        var code = Int32(0)
        var raised = False
        try:
            var s = Session.open(Span(elf), String("events"), raw)
            s.close()
        except e:
            code = e.code
            raised = True
        assert_true(raised)
        assert_equal(code, EINVAL)


def test_open_invalid_ring() raises:
    var elf = read_fixture_elf()
    var code = Int32(0)
    var raised = False
    try:
        var s = Session.open(Span(elf), String(""), UInt32(4096))
        s.close()
    except e:
        code = e.code
        raised = True
    assert_true(raised)
    assert_equal(code, EINVAL)


def test_open_missing_lib() raises:
    var elf = read_fixture_elf()
    var op = UInt32(0)
    var code = Int32(0)
    var raised = False
    try:
        var s = Session.open_with_lib(
            Span(elf),
            String("events"),
            UInt32(4096),
            String("/nonexistent/liblmb.so"),
        )
        s.close()
    except e:
        op = e.operation
        code = e.code
        raised = True
    assert_true(raised)
    assert_equal(op, OP_OPEN)
    assert_equal(code, ENOENT)


def use_and_return(var s: Session) raises -> Session:
    var st: BridgeStats
    try:
        st = s.stats()
    except e:
        raise Error("stats in helper failed: " + String(e))
    assert_equal(st.received, UInt64(0))
    return s^


def use_twice(var s: Session) raises -> Session:
    var t = use_and_return(s^)
    return use_and_return(t^)


def test_transfer_two_hops() raises:
    var elf = read_fixture_elf()
    var s = must_open(Span(elf))
    s = use_twice(s^)
    assert_false(s.is_closed())
    must_close(s^)


def test_stats_zeros() raises:
    var elf = read_fixture_elf()
    var s = must_open(Span(elf))
    var st: BridgeStats
    try:
        st = s.stats()
    except e:
        raise Error("stats failed: " + String(e))
    assert_equal(st.received, UInt64(0))
    assert_equal(st.delivered, UInt64(0))
    assert_equal(st.staged, UInt64(0))
    assert_equal(st.malformed, UInt64(0))
    assert_equal(st.dropped, UInt64(0))
    assert_equal(st.last_error, Int32(0))
    must_close(s^)


def test_error_preserved_on_success() raises:
    var elf = read_fixture_elf()
    var s = must_open(Span(elf))
    var zone = List[UInt8](length=24, fill=UInt8(0))
    var res = s.poll(zone, 0, UInt32(24), Int32(0))
    assert_true(res.is_error())
    assert_equal(res.error.operation, OP_POLL)
    assert_equal(res.error.domain, DOMAIN_BRIDGE)
    assert_equal(res.error.code, EINVAL)
    var kept: LmbError
    var received: UInt64
    var got_stats: Bool
    try:
        kept = s.last_error()
        var st = s.stats()
        received = st.received
        got_stats = True
    except e:
        raise Error("success path failed: " + String(e))
    assert_true(got_stats)
    assert_equal(received, UInt64(0))
    assert_equal(kept.operation, OP_POLL)
    var again: LmbError
    try:
        again = s.last_error()
    except e:
        raise Error("last_error after success failed")
    assert_equal(again.operation, OP_POLL)
    assert_equal(again.domain, DOMAIN_BRIDGE)
    assert_equal(again.code, EINVAL)
    must_close(s^)


def test_close_then_use() raises:
    var elf = read_fixture_elf()
    var s = must_open(Span(elf))
    try:
        s.close()
    except e:
        raise Error("close failed: " + String(e))
    var zone = List[UInt8](length=24, fill=UInt8(0))
    var res = s.poll(zone, 0, UInt32(24), Int32(0))
    assert_true(res.is_error())
    assert_equal(res.error.code, EINVAL)
    var op = UInt32(0)
    var raised = False
    try:
        var st = s.stats()
    except e:
        op = e.operation
        raised = True
    assert_true(raised)
    assert_equal(op, UInt32(8))
    must_close(s^)


def test_load_garbage() raises:
    var garbage = List[UInt8](length=64, fill=UInt8(0xFF))
    var op = UInt32(0)
    var domain = UInt32(0)
    var code = Int32(0)
    var raised = False
    try:
        var s = Session.open(
            Span(garbage), String("events"), UInt32(4096)
        )
        s.load()
        s.close()
    except e:
        op = e.operation
        domain = e.domain
        code = e.code
        raised = True
    assert_true(raised)
    assert_equal(op, OP_LOAD)
    assert_equal(domain, DOMAIN_LIBBPF)
    assert_true(code != 0)


def test_load_valid_branches_privilege() raises:
    var elf = read_fixture_elf()
    var fake = TestFake()
    var priv = fake.has_privilege()
    print("privileged:", priv)
    var s = must_open(Span(elf))
    if priv:
        var key = List[UInt8](length=4, fill=UInt8(0))
        key[0] = UInt8(0x42)
        var value = List[UInt8]()
        for i in range(8):
            value.append(UInt8(i + 1))
        var second_code = Int32(0)
        var second_raised = False
        try:
            s.load()
            try:
                s.load()
            except e2:
                second_code = e2.code
                second_raised = True
        except e:
            raise Error("privileged load failed: " + String(e))
        assert_true(second_raised)
        assert_equal(second_code, EINVAL)
        var info: MapInfoV1
        try:
            info = s.map_info(String("test_hash"))
        except e:
            raise Error("priv map_info failed: " + String(e))
        assert_equal(info.map_type, UInt32(1))
        assert_equal(info.key_size, UInt32(4))
        assert_equal(info.value_size, UInt32(8))
        assert_equal(info.max_entries, UInt32(64))
        try:
            s.map_write(String("test_hash"), Span(key), Span(value))
        except e:
            raise Error("priv map_write failed: " + String(e))
        var res: MapReadResult
        try:
            res = s.map_read(String("test_hash"), Span(key), UInt32(8))
        except e:
            raise Error("priv map_read failed: " + String(e))
        assert_false(res.is_short())
        assert_equal(res.required, UInt32(0))
        assert_equal(len(res.data), 8)
        for i in range(8):
            assert_equal(res.data[i], value[i])
        var short_res: MapReadResult
        try:
            short_res = s.map_read(
                String("test_hash"), Span(key), UInt32(4)
            )
        except e:
            raise Error("priv short map_read failed: " + String(e))
        assert_true(short_res.is_short())
        assert_equal(short_res.required, UInt32(8))
        assert_equal(len(short_res.data), 0)
        var sites = List[AttachSpec]()
        sites.append(
            AttachSpec(
                String("on_getpid"),
                ATTACH_TRACEPOINT,
                String("syscalls"),
                String("sys_enter_getpid"),
            )
        )
        sites.append(
            AttachSpec(
                String("on_getpid_small"),
                ATTACH_TRACEPOINT,
                String("syscalls"),
                String("sys_enter_getpid"),
            )
        )
        try:
            s.attach(sites)
        except e:
            raise Error("priv attach failed: " + String(e))
        for _ in range(2):
            var busy_code = Int32(0)
            var busy_op = UInt32(0)
            var busy_raised = False
            try:
                s.attach(sites)
            except e:
                busy_code = e.code
                busy_op = e.operation
                busy_raised = True
            assert_true(busy_raised)
            assert_equal(busy_op, OP_ATTACH)
            assert_equal(busy_code, EBUSY)
        try:
            s.detach()
        except e:
            raise Error("priv detach failed: " + String(e))
    else:
        var op = UInt32(0)
        var domain = UInt32(0)
        var code = Int32(0)
        var raised = False
        try:
            s.load()
        except e:
            op = e.operation
            domain = e.domain
            code = e.code
            raised = True
        assert_true(raised)
        assert_equal(op, OP_LOAD)
        assert_equal(domain, DOMAIN_LIBBPF)
        assert_true(code != 0)
        print("unprivileged load code:", code)
    must_close(s^)


def test_attach_unloaded() raises:
    var elf = read_fixture_elf()
    var s = must_open(Span(elf))
    var specs = List[AttachSpec]()
    specs.append(
        AttachSpec(
            String("prog"),
            ATTACH_TRACEPOINT,
            String("syscalls"),
            String("sys_enter_open"),
        )
    )
    specs.append(
        AttachSpec(
            String("prog2"),
            ATTACH_TRACEPOINT,
            String("syscalls"),
            String("sys_enter_close"),
        )
    )
    var op = UInt32(0)
    var raised = False
    try:
        s.attach(specs)
    except e:
        op = e.operation
        raised = True
    assert_true(raised)
    assert_equal(op, OP_ATTACH)
    must_close(s^)


def test_attach_empty() raises:
    var elf = read_fixture_elf()
    var s = must_open(Span(elf))
    var specs = List[AttachSpec]()
    var code = Int32(0)
    var op = UInt32(0)
    var raised = False
    try:
        s.attach(specs)
    except e:
        code = e.code
        op = e.operation
        raised = True
    assert_true(raised)
    assert_equal(op, OP_ATTACH)
    assert_equal(code, EINVAL)
    must_close(s^)


def test_map_unloaded() raises:
    var elf = read_fixture_elf()
    var s = must_open(Span(elf))
    var ops = List[UInt32]()
    try:
        var info = s.map_info(String("events"))
    except e:
        ops.append(e.operation)
    var key = List[UInt8](length=4, fill=UInt8(0))
    try:
        var val = s.map_read(String("events"), Span(key), UInt32(4))
    except e:
        ops.append(e.operation)
    var value = List[UInt8](length=4, fill=UInt8(1))
    try:
        s.map_write(String("events"), Span(key), Span(value))
    except e:
        ops.append(e.operation)
    assert_equal(len(ops), 3)
    assert_equal(ops[0], OP_MAP_INFO)
    assert_equal(ops[1], OP_MAP_READ)
    assert_equal(ops[2], OP_MAP_WRITE)
    must_close(s^)


def test_poll_range_errors() raises:
    var elf = read_fixture_elf()
    var s = must_open(Span(elf))
    var zone = List[UInt8](length=24, fill=UInt8(0))
    var over = s.poll(zone, 0, UInt32(25), Int32(0))
    assert_true(over.is_error())
    assert_equal(over.error.operation, OP_POLL)
    assert_equal(over.error.code, EINVAL)
    var neg = s.poll(zone, -1, UInt32(24), Int32(0))
    assert_true(neg.is_error())
    assert_equal(neg.error.code, EINVAL)
    var huge = s.poll(zone, 0x7FFFFFFFFFFFFFFF, UInt32(24), Int32(0))
    assert_true(huge.is_error())
    assert_equal(huge.error.code, EINVAL)
    must_close(s^)


def test_detach_fresh() raises:
    var elf = read_fixture_elf()
    var s = must_open(Span(elf))
    try:
        s.detach()
    except e:
        raise Error("fresh detach failed: " + String(e))
    must_close(s^)


def test_destruction_no_close() raises:
    var big = List[UInt8]()
    for i in range(1024 * 1024):
        big.append(UInt8(i & 0xFF))
    for _ in range(10):
        var warm_closed: Bool
        try:
            var s = Session.open(
                Span(big), String("events"), UInt32(4096)
            )
            warm_closed = s.is_closed()
        except e:
            raise Error("warmup open failed: " + String(e))
        assert_false(warm_closed)
    var p0 = peak_rss_kb()
    for _ in range(200):
        var cycle_closed: Bool
        try:
            var s = Session.open(
                Span(big), String("events"), UInt32(4096)
            )
            cycle_closed = s.is_closed()
        except e:
            raise Error("cycle open failed: " + String(e))
        assert_false(cycle_closed)
    var p1 = peak_rss_kb()
    print("rss kb before/after:", p0, p1)
    assert_true(p1 - p0 < 20 * 1024)


def run() raises -> Int:
    var suite = TestSuite()
    suite.test[test_open_close]()
    suite.test[test_double_close]()
    suite.test[test_open_invalid_elf]()
    suite.test[test_open_invalid_max_raw]()
    suite.test[test_open_invalid_ring]()
    suite.test[test_open_missing_lib]()
    suite.test[test_transfer_two_hops]()
    suite.test[test_stats_zeros]()
    suite.test[test_error_preserved_on_success]()
    suite.test[test_close_then_use]()
    suite.test[test_poll_range_errors]()
    suite.test[test_load_garbage]()
    suite.test[test_load_valid_branches_privilege]()
    suite.test[test_attach_unloaded]()
    suite.test[test_attach_empty]()
    suite.test[test_map_unloaded]()
    suite.test[test_detach_fresh]()
    suite.test[test_destruction_no_close]()
    suite^.run()
    return 0


def main() raises:
    var code = run()
    if code != 0:
        exit(code)
