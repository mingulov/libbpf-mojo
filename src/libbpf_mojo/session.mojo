"""Move-only session owner for the native bridge.

A ``Session`` owns its native handle and its native library: the
library provably outlives every call because both die with the
owner, and the owner cannot be duplicated. Dropping a session
without ``close`` still releases the native state exactly once.

Sessions are single-threaded owners: native error records are
thread-local, so each method captures its failure immediately and
a session must not cross threads.
"""
from std.os import getenv

from libbpf_mojo._ffi import (
    DOMAIN_BRIDGE,
    OP_ATTACH,
    OP_CLOSE,
    OP_DETACH,
    OP_LOAD,
    OP_MAP_INFO,
    OP_MAP_READ,
    OP_MAP_WRITE,
    OP_NONE,
    OP_OPEN,
    OP_POLL,
    OP_STATS,
    AttachV1,
    BytesV1,
    ErrorV1,
    MapInfoV1,
    NameV1,
    NativeLib,
    OptionsV1,
    StatsV1,
)
from libbpf_mojo.batch import POLL_BATCH, POLL_ERROR, POLL_SHORT, POLL_TIMEOUT
from libbpf_mojo.batch import PollResult
from libbpf_mojo.error import (
    EINVAL,
    ENOENT,
    ENOSPC,
    EOVERFLOW,
    LmbError,
    message_from_bytes,
)


def checked_u32(n: Int, op: UInt32) raises LmbError -> UInt32:
    """Convert a span length for the ABI without silent narrowing."""
    if n < 0 or n > 0xFFFFFFFF:
        raise LmbError(
            op, DOMAIN_BRIDGE, EOVERFLOW,
            String("length does not fit u32"),
        )
    return UInt32(n)


@fieldwise_init
struct BridgeStats(Copyable):
    """Transport counters for one session."""

    var received: UInt64
    var delivered: UInt64
    var staged: UInt64
    var malformed: UInt64
    var dropped: UInt64
    var last_error: Int32


@fieldwise_init
struct AttachSpec(Copyable):
    """One requested attach site."""

    var program: String
    var kind: UInt32
    var target_a: String
    var target_b: String


@fieldwise_init
struct MapReadResult(Copyable):
    """One map value lookup.

    On success ``data`` holds the value bytes and ``required`` is 0.
    When the capacity was short, ``data`` is empty and ``required``
    carries the needed size.
    """

    var data: List[UInt8]
    var required: UInt32

    def is_short(ref self) -> Bool:
        return self.required != 0


def capture_error(
    mut lib: NativeLib, op: UInt32, rc: Int32
) -> LmbError:
    """Read the stored native record for a failed call.

    Falls back to a synthesized record when inspection itself
    fails, so callers always get a structured error.
    """
    try:
        var err = ErrorV1(
            UInt32(1),
            UInt32(1048),
            UInt32(0),
            UInt32(0),
            Int32(0),
            UInt32(0),
            Array[UInt8, 1024](fill=0),
        )
        var rc2 = lib.last_error(Pointer(to=err))
        if rc2 != 0:
            return LmbError(
                op, DOMAIN_BRIDGE, rc,
                String("last_error unavailable"),
            )
        var count = Int(err.msg_len)
        if count > 1024:
            count = 1024
        if count < 0:
            count = 0
        var raw = List[UInt8]()
        for i in range(count):
            raw.append(err.message[i])
        return LmbError(
            err.operation, err.domain, err.code,
            message_from_bytes(raw),
        )
    except e:
        return LmbError(
            op, DOMAIN_BRIDGE, rc, String("last_error unavailable")
        )


def native_lib_path() raises LmbError -> String:
    """Resolve the native library path from the environment."""
    try:
        var path = getenv("LMB_NATIVE_LIB")
        if path == "":
            raise Error("empty LMB_NATIVE_LIB")
        return path
    except e:
        raise LmbError(
            OP_OPEN, DOMAIN_BRIDGE, ENOENT,
            String("LMB_NATIVE_LIB unusable: ") + String(e),
        )


struct Session(Movable):
    """Move-only owner of one native session plus its library."""

    var _lib: NativeLib
    var _handle: UInt64

    def __init__(
        out self,
        elf: Span[UInt8, _],
        ring: String,
        max_raw_bytes: UInt32,
        lib_path: String,
    ) raises LmbError:
        """Open a session, acquiring a fresh native handle.

        This is the only construction path besides moves: there is
        no raw-handle adoption, so two owners can never free one
        native allocation.
        """
        var lib = NativeLib(lib_path)
        var ring_bytes = ring.as_bytes()
        var ring_addr = UInt64(ring_bytes.unsafe_ptr())
        var ring_len = checked_u32(len(ring_bytes), OP_OPEN)
        var ring_field = BytesV1(ring_addr, ring_len, UInt32(0))
        var opts = OptionsV1(
            UInt32(1),
            UInt32(40),
            ring_field.copy(),
            max_raw_bytes,
            UInt32(1),
            UInt32(0),
            UInt32(0),
        )
        var cell = UInt64(0)
        var rc = lib.open_session(
            elf.unsafe_ptr(),
            UInt64(len(elf)),
            Pointer(to=opts),
            Pointer(to=cell),
        )
        if rc != 0:
            raise capture_error(lib, OP_OPEN, rc)
        self._lib = lib^
        self._handle = cell

    def __init__(out self, *, deinit move: Self):
        self._lib = move._lib^
        self._handle = move._handle

    def __deinit__(deinit self):
        if self._handle != 0:
            var cell = self._handle
            var lib = self._lib^
            try:
                _ = lib.close_session(Pointer(to=cell))
            except e:
                pass

    def is_closed(ref self) -> Bool:
        return self._handle == 0

    @staticmethod
    def open(
        elf: Span[UInt8, _], ring: String, max_raw_bytes: UInt32
    ) raises LmbError -> Session:
        return Session.open_with_lib(
            elf, ring, max_raw_bytes, native_lib_path()
        )

    @staticmethod
    def open_with_lib(
        elf: Span[UInt8, _],
        ring: String,
        max_raw_bytes: UInt32,
        lib_path: String,
    ) raises LmbError -> Session:
        var s = Session(elf, ring, max_raw_bytes, lib_path)
        return s^

    def load(mut self) raises LmbError:
        var rc = self._lib.load(self._handle)
        if rc != 0:
            raise capture_error(self._lib, OP_LOAD, rc)

    def attach(mut self, specs: List[AttachSpec]) raises LmbError:
        """Attach every site in one native all-or-none transaction."""
        if len(specs) == 0:
            raise LmbError(
                OP_ATTACH, DOMAIN_BRIDGE, EINVAL,
                String("no attach sites"),
            )
        var count = checked_u32(len(specs), OP_ATTACH)
        var natives = List[AttachV1]()
        for spec in specs:
            var prog_bytes = spec.program.as_bytes()
            var a_bytes = spec.target_a.as_bytes()
            var b_bytes = spec.target_b.as_bytes()
            var prog_len = checked_u32(len(prog_bytes), OP_ATTACH)
            var a_len = checked_u32(len(a_bytes), OP_ATTACH)
            var b_len = checked_u32(len(b_bytes), OP_ATTACH)
            var prog_field = BytesV1(
                UInt64(prog_bytes.unsafe_ptr()), prog_len, UInt32(0)
            )
            var a_field = BytesV1(
                UInt64(a_bytes.unsafe_ptr()), a_len, UInt32(0)
            )
            var b_field = BytesV1(
                UInt64(b_bytes.unsafe_ptr()), b_len, UInt32(0)
            )
            var site = AttachV1(
                UInt32(1),
                UInt32(64),
                prog_field.copy(),
                spec.kind,
                UInt32(0),
                a_field.copy(),
                b_field.copy(),
            )
            natives.append(site^)
        var sites_span = Span(natives)
        var rc = self._lib.attach(
            self._handle, sites_span.unsafe_ptr(), count
        )
        if rc != 0:
            raise capture_error(self._lib, OP_ATTACH, rc)

    def poll(
        mut self,
        mut dst: List[UInt8],
        start: Int,
        capacity: UInt32,
        timeout_ms: Int32,
    ) -> PollResult:
        """Poll one frame into a caller-owned mutable destination."""
        var span = Span(dst)
        var total = len(span)
        var cap = Int(capacity)
        if start < 0 or start > total or cap > total - start:
            return PollResult(
                POLL_ERROR,
                UInt32(0),
                UInt32(0),
                LmbError(
                    OP_POLL, DOMAIN_BRIDGE, EINVAL,
                    String("destination out of range"),
                ),
            )
        var written = UInt32(0)
        var required = UInt32(0)
        var rc: Int32
        try:
            rc = self._lib.poll(
                self._handle,
                span.unsafe_ptr().unsafe_offset(start),
                capacity,
                Pointer(to=written),
                Pointer(to=required),
                timeout_ms,
            )
        except e:
            return PollResult(
                POLL_ERROR, UInt32(0), UInt32(0), e.copy()
            )
        if rc == 0 and written != 0:
            return PollResult(
                POLL_BATCH, written, UInt32(0),
                LmbError(
                    OP_POLL, DOMAIN_BRIDGE, Int32(0), String("")
                ),
            )
        if rc == 0:
            return PollResult(
                POLL_TIMEOUT, UInt32(0), UInt32(0),
                LmbError(
                    OP_POLL, DOMAIN_BRIDGE, Int32(0), String("")
                ),
            )
        if rc == ENOSPC:
            return PollResult(
                POLL_SHORT, UInt32(0), required,
                LmbError(
                    OP_POLL, DOMAIN_BRIDGE, Int32(0), String("")
                ),
            )
        return PollResult(
            POLL_ERROR, UInt32(0), UInt32(0),
            capture_error(self._lib, OP_POLL, rc),
        )

    def map_info(mut self, name: String) raises LmbError -> MapInfoV1:
        var name_bytes = name.as_bytes()
        var name_len = checked_u32(len(name_bytes), OP_MAP_INFO)
        var name_field = BytesV1(
            UInt64(name_bytes.unsafe_ptr()), name_len, UInt32(0)
        )
        var query = NameV1(
            UInt32(1),
            UInt32(24),
            name_field.copy(),
        )
        var out = MapInfoV1(
            UInt32(1),
            UInt32(40),
            UInt32(0),
            UInt32(0),
            UInt32(0),
            UInt32(0),
            UInt32(0),
            UInt32(0),
            UInt32(0),
            UInt32(0),
        )
        var rc = self._lib.map_info(
            self._handle,
            Pointer(to=query),
            Pointer(to=out),
        )
        if rc != 0:
            raise capture_error(self._lib, OP_MAP_INFO, rc)
        return out^

    def map_read(
        mut self, name: String, key: Span[UInt8, _], capacity: UInt32
    ) raises LmbError -> MapReadResult:
        var name_bytes = name.as_bytes()
        var name_len = checked_u32(len(name_bytes), OP_MAP_READ)
        var name_field = BytesV1(
            UInt64(name_bytes.unsafe_ptr()), name_len, UInt32(0)
        )
        var query = NameV1(
            UInt32(1),
            UInt32(24),
            name_field.copy(),
        )
        var key_len = checked_u32(len(key), OP_MAP_READ)
        var buf = List[UInt8](length=Int(capacity), fill=UInt8(0))
        var dst_span = Span(buf)
        var required = UInt32(0)
        var rc = self._lib.map_read(
            self._handle,
            Pointer(to=query),
            key.unsafe_ptr(),
            key_len,
            dst_span.unsafe_ptr(),
            capacity,
            Pointer(to=required),
        )
        if rc == ENOSPC:
            var empty = List[UInt8]()
            return MapReadResult(empty^, required)
        if rc != 0:
            raise capture_error(self._lib, OP_MAP_READ, rc)
        var info = self.map_info(name)
        var need = info.value_size
        if info.stride != 0:
            need = info.stride * info.num_cpus
        var data = List[UInt8]()
        for i in range(Int(need)):
            data.append(buf[i])
        return MapReadResult(data^, UInt32(0))

    def map_write(
        mut self,
        name: String,
        key: Span[UInt8, _],
        value: Span[UInt8, _],
    ) raises LmbError:
        var name_bytes = name.as_bytes()
        var name_len = checked_u32(len(name_bytes), OP_MAP_WRITE)
        var name_field = BytesV1(
            UInt64(name_bytes.unsafe_ptr()), name_len, UInt32(0)
        )
        var query = NameV1(
            UInt32(1),
            UInt32(24),
            name_field.copy(),
        )
        var key_len = checked_u32(len(key), OP_MAP_WRITE)
        var value_len = checked_u32(len(value), OP_MAP_WRITE)
        var rc = self._lib.map_write(
            self._handle,
            Pointer(to=query),
            key.unsafe_ptr(),
            key_len,
            value.unsafe_ptr(),
            value_len,
        )
        if rc != 0:
            raise capture_error(self._lib, OP_MAP_WRITE, rc)

    def stats(mut self) raises LmbError -> BridgeStats:
        var out = StatsV1(
            UInt32(1),
            UInt32(56),
            UInt64(0),
            UInt64(0),
            UInt64(0),
            UInt64(0),
            UInt64(0),
            Int32(0),
            UInt32(0),
        )
        var rc = self._lib.stats(
            self._handle, Pointer(to=out)
        )
        if rc != 0:
            raise capture_error(self._lib, OP_STATS, rc)
        return BridgeStats(
            out.received,
            out.delivered,
            out.staged,
            out.malformed,
            out.dropped,
            out.last_error,
        )

    def last_error(mut self) raises LmbError -> LmbError:
        var err = ErrorV1(
            UInt32(1),
            UInt32(1048),
            UInt32(0),
            UInt32(0),
            Int32(0),
            UInt32(0),
            Array[UInt8, 1024](fill=0),
        )
        var rc = self._lib.last_error(Pointer(to=err))
        if rc != 0:
            raise LmbError(
                OP_NONE, DOMAIN_BRIDGE, rc,
                String("last_error unavailable"),
            )
        var count = Int(err.msg_len)
        if count > 1024:
            count = 1024
        if count < 0:
            count = 0
        var raw = List[UInt8]()
        for i in range(count):
            raw.append(err.message[i])
        return LmbError(
            err.operation, err.domain, err.code,
            message_from_bytes(raw),
        )

    def detach(mut self) raises LmbError:
        var rc = self._lib.detach(self._handle)
        if rc != 0:
            raise capture_error(self._lib, OP_DETACH, rc)

    def close(mut self) raises LmbError:
        if self._handle == 0:
            return
        var cell = self._handle
        var rc = self._lib.close_session(
            Pointer(to=cell)
        )
        self._handle = cell
        if rc != 0:
            raise capture_error(self._lib, OP_CLOSE, rc)
