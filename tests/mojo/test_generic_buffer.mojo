# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Copied records and ring ownership through the actual pinned reader."""
from std.os import getenv
from std.pathlib import Path
from std.sys import argv
from std.testing import TestSuite, assert_equal, assert_true
from libbpf_mojo._ffi import AUTOLOAD_DISABLE, BufferOptionsV1, BufferStatsV1, GenericLib, GenericSpanV1, read_u64_le
from libbpf_mojo.batch import decode_frame
from libbpf_mojo.buffer import Buffer, BufferPollResult, open_ring
from libbpf_mojo.object import Object, MapView


def move_buffer(var buffer: Buffer) -> Buffer:
    return buffer^


def loaded(path: String = "") raises -> Object:
    var data = Path(getenv("LMB_GENERIC_EVENTS_FIXTURE")).read_bytes()
    var library = path.copy()
    if library.byte_length() == 0:
        library = getenv("LMB_EVENTS_TESTFAKE_LIB")
    var object = Object.open_with_lib(Span(data), library)
    var reset = object._lib[]._handle.get_function[NoneType]("lmb_events_reset")
    reset()
    object.load()
    return object^


def scenario(mut buffer: Buffer, number: UInt32) raises:
    var control = buffer._lib[]._handle.get_function[NoneType]("lmb_events_scenario")
    control(number)


def query(mut buffer: Buffer, number: UInt32) raises -> UInt64:
    var control = buffer._lib[]._handle.get_function[UInt64]("lmb_events_call_count")
    return control(number)


def child_from_parent_scope() raises -> Buffer:
    var object = loaded()
    var control = object._lib[]._handle.get_function[NoneType]("lmb_events_scenario")
    control(UInt32(2))
    var ring = object.map("events")
    return open_ring(ring)


def literal_frame(data: Span[UInt8, _], start: Int) raises:
    var literal = [UInt8(0x10), UInt8(0), UInt8(0), UInt8(0),
                   UInt8(1), UInt8(0), UInt8(0), UInt8(0),
                   UInt8(0x08), UInt8(0x07), UInt8(0x06), UInt8(0x05),
                   UInt8(0x04), UInt8(0x03), UInt8(0x02), UInt8(0x01),
                   UInt8(0xf7), UInt8(0xf8), UInt8(0xf9), UInt8(0xfa),
                   UInt8(0xfb), UInt8(0xfc), UInt8(0xfd), UInt8(0xfe)]
    for i in range(24):
        assert_equal(data[start + i], literal[i])


def test_short_copied_bytes_scope_moves_and_close() raises:
    var original = child_from_parent_scope()
    var buffer = move_buffer(original^)
    assert_equal(query(buffer, 8), UInt64(0))
    assert_equal(query(buffer, 7), UInt64(2))
    scenario(buffer, 5)
    var storage = List[UInt8](length=26, fill=0xa5)
    var destination = Span(storage)
    var saved = buffer.poll(destination[1:24])
    assert_true(saved.is_short())
    assert_equal(saved.used, UInt64(0))
    assert_equal(saved.needed, UInt64(24))
    assert_equal(saved.error.operation, UInt32(13))
    assert_equal(saved.error.domain, UInt32(4))
    assert_equal(saved.error.code, Int32(-28))
    assert_equal(query(buffer, 12), UInt64(1))
    assert_equal(query(buffer, 14), UInt64(1))
    var consumed = query(buffer, 4)
    for capacity in [0, 23, 23]:
        var short = buffer.poll(destination[1:1 + capacity])
        assert_true(short.is_short())
        assert_equal(short.needed, UInt64(24))
        assert_equal(query(buffer, 4), consumed)
        for byte in storage:
            assert_equal(byte, UInt8(0xa5))
    var frame = buffer.poll(destination[1:25])
    assert_true(frame.is_frame())
    assert_equal(frame.used, UInt64(24))
    assert_equal(frame.needed, UInt64(0))
    literal_frame(Span(storage), 1)
    assert_equal(storage[0], UInt8(0xa5))
    assert_equal(storage[25], UInt8(0xa5))
    assert_equal(query(buffer, 13), UInt64(1))
    assert_equal(query(buffer, 14), UInt64(0))
    assert_equal(query(buffer, 4), consumed)
    var decoded = decode_frame(Span(storage), 1, UInt32(frame.used))
    literal_frame(Span(storage), 1)
    for i in range(16):
        assert_equal(decoded.payload[i], storage[i + 9])
    var empty = buffer.poll(destination)
    assert_true(empty.is_empty())
    assert_equal(empty.used, UInt64(0))
    assert_equal(empty.needed, UInt64(0))
    assert_equal(saved.error.operation, UInt32(13))
    assert_equal(saved.error.domain, UInt32(4))
    assert_equal(saved.error.code, Int32(-28))
    assert_true(saved.error.message.byte_length() > 0)
    buffer.close()
    buffer.close()
    assert_true(buffer.is_closed())
    assert_equal(query(buffer, 7), UInt64(0))
    assert_equal(query(buffer, 8), UInt64(1))
    assert_equal(query(buffer, 11), UInt64(1))
    var before = query(buffer, 27)
    var closed = buffer.poll(destination)
    assert_true(closed.is_error())
    assert_equal(closed.error.operation, UInt32(13))
    assert_equal(closed.error.domain, UInt32(4))
    assert_equal(closed.error.code, Int32(-22))
    assert_equal(query(buffer, 27), before)
    scenario(buffer, 10)
    assert_equal(query(buffer, 22), UInt64(0))
    assert_equal(query(buffer, 19), UInt64(0))


def test_prefix_and_error_classification() raises:
    var buffer = child_from_parent_scope()
    scenario(buffer, 3)
    scenario(buffer, 4)
    var output = List[UInt8](length=49, fill=0xa5)
    var zone = Span(output)
    var first = buffer.poll(zone[1:49])
    assert_true(first.is_frame())
    assert_equal(first.used, UInt64(24))
    literal_frame(Span(output), 1)
    var held = buffer.poll(zone[25:48])
    assert_true(held.is_short())
    assert_equal(held.used, UInt64(0))
    assert_equal(held.needed, UInt64(24))
    literal_frame(Span(output), 1)
    for i in range(25, 49):
        assert_equal(output[i], UInt8(0xa5))
    var second = buffer.poll(zone[25:49])
    assert_true(second.is_frame())
    assert_equal(second.used, UInt64(24))
    assert_equal(read_u64_le(zone.unsafe_ptr(), 33), UInt64(0xfedcba9876543210))
    assert_equal(read_u64_le(zone.unsafe_ptr(), 41), UInt64(0x0123456789abcdef))
    assert_equal(query(buffer, 12), UInt64(2))
    assert_equal(query(buffer, 13), UInt64(2))
    var snapshot = output.copy()
    var bad_timeout = buffer.poll(zone, Int32(-2))
    assert_true(bad_timeout.is_error())
    assert_equal(bad_timeout.error.code, Int32(-22))
    scenario(buffer, 1)
    var interrupted = buffer.poll(zone, Int32(17))
    assert_true(interrupted.is_error())
    assert_equal(interrupted.error.operation, UInt32(13))
    assert_equal(interrupted.error.domain, UInt32(1))
    assert_equal(interrupted.error.code, Int32(-4))
    scenario(buffer, 6)
    var native_short_code = buffer.poll(zone)
    assert_true(native_short_code.is_error())
    assert_true(not native_short_code.is_short())
    assert_equal(native_short_code.error.domain, UInt32(2))
    assert_equal(native_short_code.error.code, Int32(-28))
    assert_equal(native_short_code.needed, UInt64(0))
    literal_frame(Span(output), 1)
    for i in range(len(output)):
        assert_equal(output[i], snapshot[i])
    buffer.close()
    scenario(buffer, 10)
    assert_equal(query(buffer, 19), UInt64(0))


def destructor_scope(mut ring: MapView) raises:
    var child = open_ring(ring)
    assert_true(not child.is_closed())


def test_options_stale_missing_and_destructor() raises:
    var object = loaded()
    var control = object._lib[]._handle.get_function[NoneType]("lmb_events_scenario")
    control(UInt32(2))
    var ring = object.map("events")
    var count = object._lib[]._handle.get_function[UInt64]("lmb_events_call_count")
    for maximum, slots, flags in [(UInt32(0), UInt32(1), UInt32(0)),
                                  (UInt32(4097), UInt32(1), UInt32(0)),
                                  (UInt32(4096), UInt32(2), UInt32(0)),
                                  (UInt32(4096), UInt32(1), UInt32(1))]:
        var refused = False
        try:
            var absent = open_ring(ring, maximum, slots, flags)
            _ = absent^
        except e:
            assert_equal(e.operation, UInt32(12))
            assert_equal(e.domain, UInt32(4))
            assert_equal(e.code, Int32(-22))
            refused = True
        assert_true(refused)
    assert_equal(count(UInt32(3)), UInt64(0))
    destructor_scope(ring)
    assert_equal(count(UInt32(11)), UInt64(1))
    assert_equal(count(UInt32(7)), UInt64(0))
    ring.close()
    object.close()
    control(UInt32(10))
    var data = Path(getenv("LMB_GENERIC_EVENTS_FIXTURE")).read_bytes()
    var unconfigured = Object.open_with_lib(Span(data), getenv("LMB_EVENTS_TESTFAKE_LIB"))
    var stale = unconfigured.map("events")
    unconfigured.configure_program("on_getpid", AUTOLOAD_DISABLE)
    for closed in [False, True]:
        if closed:
            stale.close()
        var refused = False
        try:
            var absent = open_ring(stale)
            _ = absent^
        except e:
            assert_equal(e.operation, UInt32(17))
            var code = Int32(-116)
            if closed:
                code = -22
            assert_equal(e.code, code)
            refused = True
        assert_true(refused)
    unconfigured.close()
    for key in [String("LMB_EVENTS_NO_EVENTS_LIB"), String("LMB_EVENTS_NO_BUFFER_OPEN_LIB"),
                String("LMB_EVENTS_NO_BUFFER_POLL_LIB"), String("LMB_EVENTS_NO_BUFFER_CLOSE_LIB")]:
        var older = loaded(getenv(key))
        var view = older.map("events")
        var refused = False
        try:
            var absent = open_ring(view)
            _ = absent^
        except e:
            assert_equal(e.operation, UInt32(12))
            assert_equal(e.domain, UInt32(4))
            assert_equal(e.code, Int32(-38))
            refused = True
        assert_true(refused)
        var older_count = older._lib[]._handle.get_function[UInt64]("lmb_events_call_count")
        assert_equal(older_count(UInt32(26)), UInt64(0))
        assert_equal(older_count(UInt32(3)), UInt64(0))
        view.close()
        older.close()


def test_optional_ffi_operation_identity() raises:
    for operation, key in [(UInt32(12), String("LMB_EVENTS_NO_BUFFER_OPEN_LIB")),
                           (UInt32(13), String("LMB_EVENTS_NO_BUFFER_POLL_LIB")),
                           (UInt32(14), String("LMB_EVENTS_NO_BUFFER_CLOSE_LIB"))]:
        var library = GenericLib(getenv(key))
        var handle = UInt64(0)
        var used = UInt64(0)
        var needed = UInt64(0)
        var empty = List[UInt8]()
        var options = BufferOptionsV1(1, 40, GenericSpanV1(0, 0), 4096, 1, 0, 0)
        var refused = False
        try:
            if operation == 12:
                _ = library.open_buffer(0, Pointer(to=options), Pointer(to=handle))
            elif operation == 13:
                _ = library.poll_buffer(0, Span(empty).unsafe_ptr(), 0, 0,
                                        Pointer(to=used), Pointer(to=needed))
            else:
                _ = library.close_buffer(Pointer(to=handle))
        except e:
            assert_equal(e.operation, operation)
            assert_equal(e.domain, UInt32(4))
            assert_equal(e.code, Int32(-38))
            refused = True
        assert_true(refused)
        assert_equal(handle, UInt64(0))


def test_stats_snapshot_conservation_and_teardown() raises:
    var buffer = child_from_parent_scope()
    var counters = buffer.stats()
    assert_equal(counters.received, UInt64(0))
    assert_equal(counters.delivered, UInt64(0))
    assert_equal(counters.staged, UInt64(0))
    assert_equal(counters.malformed, UInt64(0))
    assert_equal(counters.dropped, UInt64(0))
    scenario(buffer, 3)
    var storage = List[UInt8](length=26, fill=0xa5)
    var destination = Span(storage)
    var short = buffer.poll(destination[1:24])
    assert_true(short.is_short())
    counters = buffer.stats()
    assert_equal(counters.received, UInt64(1))
    assert_equal(counters.delivered, UInt64(0))
    assert_equal(counters.staged, UInt64(1))
    assert_equal(counters.malformed, UInt64(0))
    assert_equal(counters.dropped, UInt64(0))
    var repeat = buffer.stats()
    assert_equal(repeat.received, counters.received)
    assert_equal(repeat.staged, counters.staged)
    var frame = buffer.poll(destination[1:25])
    assert_true(frame.is_frame())
    counters = buffer.stats()
    assert_equal(counters.received, UInt64(1))
    assert_equal(counters.delivered, UInt64(1))
    assert_equal(counters.staged, UInt64(0))
    assert_equal(counters.received, counters.delivered + counters.staged
                 + counters.malformed + counters.dropped)
    buffer.close()
    var refused = False
    try:
        _ = buffer.stats()
    except e:
        assert_equal(e.operation, UInt32(20))
        assert_equal(e.domain, UInt32(4))
        assert_equal(e.code, Int32(-22))
        refused = True
    assert_true(refused)
    scenario(buffer, 10)


def test_stats_optional_symbol() raises:
    var library = getenv("LMB_EVENTS_NO_BUFFER_STATS_LIB")
    var object = loaded(library)
    var control = object._lib[]._handle.get_function[NoneType]("lmb_events_scenario")
    control(UInt32(2))
    var ring = object.map("events")
    var buffer = open_ring(ring)
    assert_true(not buffer.is_closed())
    var refused = False
    try:
        var counters = buffer.stats()
        _ = counters
    except e:
        assert_equal(e.operation, UInt32(20))
        assert_equal(e.domain, UInt32(4))
        assert_equal(e.code, Int32(-38))
        refused = True
    assert_true(refused)
    buffer.close()
    ring.close()
    object.close()
    control(UInt32(10))
    var bare = GenericLib(library)
    var stats_refused = False
    try:
        var record = BufferStatsV1(1, 48, 0, 0, 0, 0, 0)
        _ = bare.buffer_stats(0, Pointer(to=record))
    except e:
        assert_equal(e.operation, UInt32(20))
        assert_equal(e.domain, UInt32(4))
        assert_equal(e.code, Int32(-38))
        stats_refused = True
    assert_true(stats_refused)


def main() raises:
    var args = argv()
    if len(args) > 1:
        var buffer = child_from_parent_scope()
        if args[1] == "reset-live":
            var reset = buffer._lib[]._handle.get_function[NoneType]("lmb_events_reset")
            reset()
        elif args[1] == "end-live":
            scenario(buffer, 10)
        elif args[1] == "begin-live":
            scenario(buffer, 2)
        return
    var suite = TestSuite()
    suite.test[test_short_copied_bytes_scope_moves_and_close]()
    suite.test[test_prefix_and_error_classification]()
    suite.test[test_options_stale_missing_and_destructor]()
    suite.test[test_optional_ffi_operation_identity]()
    suite.test[test_stats_snapshot_conservation_and_teardown]()
    suite.test[test_stats_optional_symbol]()
    suite^.run()
    print("NOT_RUN generic_buffer.kernel-production: actual-reader host mappings only")
