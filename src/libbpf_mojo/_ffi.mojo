"""Byte-exact mirrors of the native ``lmb_*_v1`` ABI structs.

Each mirror matches the C layout (offsets, sizes, alignment) so Mojo can
build request structs and parse response structs in place. Pointers cross
the boundary as ``UInt64`` addresses; conversion to and from ``Pointer``
happens only at the call boundary in the session wrapper.

``NativeLib`` is the single site of ``extern`` calls: every ``lmb_*``
operation is resolved and invoked here, and every argument is
fixed-width. The session wrapper owns a ``NativeLib`` and never calls
C directly.
"""
from std.ffi import OwnedDLHandle
from std.memory import MutPointer

from libbpf_mojo.error import ENOENT, ENOSYS, LmbError

comptime OP_NONE = UInt32(0)
comptime OP_OPEN = UInt32(1)
comptime OP_LOAD = UInt32(2)
comptime OP_ATTACH = UInt32(3)
comptime OP_POLL = UInt32(4)
comptime OP_MAP_INFO = UInt32(5)
comptime OP_MAP_READ = UInt32(6)
comptime OP_MAP_WRITE = UInt32(7)
comptime OP_STATS = UInt32(8)
comptime OP_DETACH = UInt32(9)
comptime OP_CLOSE = UInt32(10)

comptime DOMAIN_NONE = UInt32(0)
comptime DOMAIN_POSIX = UInt32(1)
comptime DOMAIN_LIBBPF = UInt32(2)
comptime DOMAIN_KERNEL = UInt32(3)
comptime DOMAIN_BRIDGE = UInt32(4)

comptime ATTACH_TRACEPOINT = UInt32(1)
comptime ATTACH_TRACING = UInt32(2)

comptime FRAME_HEADER_SIZE = UInt32(8)
comptime FRAME_VERSION = UInt32(1)
comptime MAX_RAW_BYTES = UInt32(4096)
comptime MAX_FRAME_BYTES = UInt32(4104)


@fieldwise_init
struct BytesV1(Copyable):
    """Mirrors ``struct lmb_bytes_v1``: pointer plus length."""

    var ptr: UInt64
    var len: UInt32
    var _pad: UInt32


@fieldwise_init
struct OptionsV1(Copyable):
    """Mirrors ``struct lmb_options_v1``: session open parameters."""

    var abi_version: UInt32
    var struct_size: UInt32
    var ring: BytesV1
    var max_raw_bytes: UInt32
    var stage_slots: UInt32
    var flags: UInt32
    var _reserved: UInt32


@fieldwise_init
struct AttachV1(Copyable):
    """Mirrors ``struct lmb_attach_v1``: one attach site."""

    var abi_version: UInt32
    var struct_size: UInt32
    var program: BytesV1
    var kind: UInt32
    var flags: UInt32
    var target_a: BytesV1
    var target_b: BytesV1


@fieldwise_init
struct NameV1(Copyable):
    """Mirrors ``struct lmb_name_v1``: a named map lookup key."""

    var abi_version: UInt32
    var struct_size: UInt32
    var name: BytesV1


@fieldwise_init
struct MapInfoV1(Copyable):
    """Mirrors ``struct lmb_map_info_v1``: map geometry for access."""

    var abi_version: UInt32
    var struct_size: UInt32
    var map_type: UInt32
    var key_size: UInt32
    var value_size: UInt32
    var max_entries: UInt32
    var map_flags: UInt32
    var num_cpus: UInt32
    var stride: UInt32
    var _reserved: UInt32


@fieldwise_init
struct StatsV1(Copyable):
    """Mirrors ``struct lmb_stats_v1``: transport counters."""

    var abi_version: UInt32
    var struct_size: UInt32
    var received: UInt64
    var delivered: UInt64
    var staged: UInt64
    var malformed: UInt64
    var dropped: UInt64
    var last_error: Int32
    var _reserved: UInt32


@fieldwise_init
struct ErrorV1(Copyable):
    """Mirrors ``struct lmb_error_v1``: last-error detail record."""

    var abi_version: UInt32
    var struct_size: UInt32
    var operation: UInt32
    var domain: UInt32
    var code: Int32
    var msg_len: UInt32
    var message: Array[UInt8, 1024]


def read_u8_le(p: Pointer[UInt8, _], off: Int) -> UInt32:
    """Load one byte at ``off`` and zero-extend it to ``UInt32``."""
    return UInt32(p.unsafe_offset(off).unsafe_load())


def read_u16_le(p: Pointer[UInt8, _], off: Int) -> UInt32:
    """Load a little-endian ``UInt16`` at ``off``, zero-extended."""
    var base = p.unsafe_offset(off)
    var v = UInt32(base.unsafe_load())
    v |= UInt32(base.unsafe_offset(1).unsafe_load()) << 8
    return v


def read_u32_le(p: Pointer[UInt8, _], off: Int) -> UInt32:
    """Load a little-endian ``UInt32`` at byte offset ``off``."""
    var base = p.unsafe_offset(off)
    var v = UInt32(base.unsafe_load())
    v |= UInt32(base.unsafe_offset(1).unsafe_load()) << 8
    v |= UInt32(base.unsafe_offset(2).unsafe_load()) << 16
    v |= UInt32(base.unsafe_offset(3).unsafe_load()) << 24
    return v


def read_u64_le(p: Pointer[UInt8, _], off: Int) -> UInt64:
    """Load a little-endian ``UInt64`` at byte offset ``off``."""
    var base = p.unsafe_offset(off)
    var v = UInt64(base.unsafe_load())
    v |= UInt64(base.unsafe_offset(1).unsafe_load()) << 8
    v |= UInt64(base.unsafe_offset(2).unsafe_load()) << 16
    v |= UInt64(base.unsafe_offset(3).unsafe_load()) << 24
    v |= UInt64(base.unsafe_offset(4).unsafe_load()) << 32
    v |= UInt64(base.unsafe_offset(5).unsafe_load()) << 40
    v |= UInt64(base.unsafe_offset(6).unsafe_load()) << 48
    v |= UInt64(base.unsafe_offset(7).unsafe_load()) << 56
    return v


struct NativeLib(Movable):
    """Owned native library handle and sole ``extern`` call site.

    Every ``lmb_*`` operation is resolved and invoked by exactly one
    method here. Every pointee argument is a ``Pointer``: passing an
    address as ``UInt64`` loses escape information and the optimizer
    may reorder or drop the pointee stores across the call (observed
    as stale struct contents on Mojo 1.1.0). Only the opaque session
    handle crosses as ``UInt64``; it has no Mojo-side pointee.
    """

    var _handle: OwnedDLHandle

    def __init__(out self, path: String) raises LmbError:
        try:
            self._handle = OwnedDLHandle(path)
        except e:
            raise LmbError(
                OP_OPEN, DOMAIN_BRIDGE, ENOENT, String(e)
            )
        self._require(String("lmb_open"))
        self._require(String("lmb_load"))
        self._require(String("lmb_attach"))
        self._require(String("lmb_poll"))
        self._require(String("lmb_map_info"))
        self._require(String("lmb_map_read"))
        self._require(String("lmb_map_write"))
        self._require(String("lmb_stats"))
        self._require(String("lmb_last_error"))
        self._require(String("lmb_detach"))
        self._require(String("lmb_close"))

    def _require(mut self, name: String) raises LmbError:
        """Resolve one mandatory ABI symbol before any handle exists."""
        try:
            _ = self._handle.get_function[Int32](name)
        except e:
            raise LmbError(
                OP_OPEN, DOMAIN_BRIDGE, ENOSYS,
                String("incomplete native library: ") + name,
            )

    def open_session(
        mut self,
        elf: Pointer[UInt8, _],
        elf_len: UInt64,
        opts: Pointer[OptionsV1, _],
        handle_out: MutPointer[UInt64, _],
    ) raises LmbError -> Int32:
        try:
            var f = self._handle.get_function[Int32](
                String("lmb_open")
            )
            return f(elf, elf_len, opts, handle_out)
        except e:
            raise LmbError(
                OP_OPEN, DOMAIN_BRIDGE, ENOSYS,
                String("unresolved lmb_open"),
            )

    def load(mut self, session: UInt64) raises LmbError -> Int32:
        try:
            var f = self._handle.get_function[Int32](
                String("lmb_load")
            )
            return f(session)
        except e:
            raise LmbError(
                OP_LOAD, DOMAIN_BRIDGE, ENOSYS,
                String("unresolved lmb_load"),
            )

    def attach(
        mut self,
        session: UInt64,
        sites: Pointer[AttachV1, _],
        count: UInt32,
    ) raises LmbError -> Int32:
        try:
            var f = self._handle.get_function[Int32](
                String("lmb_attach")
            )
            return f(session, sites, count)
        except e:
            raise LmbError(
                OP_ATTACH, DOMAIN_BRIDGE, ENOSYS,
                String("unresolved lmb_attach"),
            )

    def poll(
        mut self,
        session: UInt64,
        dst: MutPointer[UInt8, _],
        capacity: UInt32,
        written: MutPointer[UInt32, _],
        required: MutPointer[UInt32, _],
        timeout_ms: Int32,
    ) raises LmbError -> Int32:
        try:
            var f = self._handle.get_function[Int32](
                String("lmb_poll")
            )
            return f(
                session, dst, capacity, written, required,
                timeout_ms,
            )
        except e:
            raise LmbError(
                OP_POLL, DOMAIN_BRIDGE, ENOSYS,
                String("unresolved lmb_poll"),
            )

    def map_info(
        mut self,
        session: UInt64,
        name: Pointer[NameV1, _],
        info_out: MutPointer[MapInfoV1, _],
    ) raises LmbError -> Int32:
        try:
            var f = self._handle.get_function[Int32](
                String("lmb_map_info")
            )
            return f(session, name, info_out)
        except e:
            raise LmbError(
                OP_MAP_INFO, DOMAIN_BRIDGE, ENOSYS,
                String("unresolved lmb_map_info"),
            )

    def map_read(
        mut self,
        session: UInt64,
        name: Pointer[NameV1, _],
        key: Pointer[UInt8, _],
        key_bytes: UInt32,
        dst: MutPointer[UInt8, _],
        capacity: UInt32,
        required: MutPointer[UInt32, _],
    ) raises LmbError -> Int32:
        try:
            var f = self._handle.get_function[Int32](
                String("lmb_map_read")
            )
            return f(
                session, name, key, key_bytes, dst, capacity,
                required,
            )
        except e:
            raise LmbError(
                OP_MAP_READ, DOMAIN_BRIDGE, ENOSYS,
                String("unresolved lmb_map_read"),
            )

    def map_write(
        mut self,
        session: UInt64,
        name: Pointer[NameV1, _],
        key: Pointer[UInt8, _],
        key_bytes: UInt32,
        value: Pointer[UInt8, _],
        value_bytes: UInt32,
    ) raises LmbError -> Int32:
        try:
            var f = self._handle.get_function[Int32](
                String("lmb_map_write")
            )
            return f(
                session, name, key, key_bytes, value, value_bytes,
            )
        except e:
            raise LmbError(
                OP_MAP_WRITE, DOMAIN_BRIDGE, ENOSYS,
                String("unresolved lmb_map_write"),
            )

    def stats(
        mut self,
        session: UInt64,
        stats_out: MutPointer[StatsV1, _],
    ) raises LmbError -> Int32:
        try:
            var f = self._handle.get_function[Int32](
                String("lmb_stats")
            )
            return f(session, stats_out)
        except e:
            raise LmbError(
                OP_STATS, DOMAIN_BRIDGE, ENOSYS,
                String("unresolved lmb_stats"),
            )

    def last_error(
        mut self, err_out: MutPointer[ErrorV1, _]
    ) raises LmbError -> Int32:
        try:
            var f = self._handle.get_function[Int32](
                String("lmb_last_error")
            )
            return f(err_out)
        except e:
            raise LmbError(
                OP_NONE, DOMAIN_BRIDGE, ENOSYS,
                String("unresolved lmb_last_error"),
            )

    def detach(mut self, session: UInt64) raises LmbError -> Int32:
        try:
            var f = self._handle.get_function[Int32](
                String("lmb_detach")
            )
            return f(session)
        except e:
            raise LmbError(
                OP_DETACH, DOMAIN_BRIDGE, ENOSYS,
                String("unresolved lmb_detach"),
            )

    def close_session(
        mut self, session: MutPointer[UInt64, _]
    ) raises LmbError -> Int32:
        try:
            var f = self._handle.get_function[Int32](
                String("lmb_close")
            )
            return f(session)
        except e:
            raise LmbError(
                OP_CLOSE, DOMAIN_BRIDGE, ENOSYS,
                String("unresolved lmb_close"),
            )
