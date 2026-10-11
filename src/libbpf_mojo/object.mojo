# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Move-only generic objects and retained metadata views.

Owners and views share one library handle. Views retain native object
references and validate their configuration generation before each use.
All operations use one calling thread; loading never attaches.
"""
from std.memory import ArcPointer
from libbpf_mojo._ffi import (
    AUTOLOAD_UNCHANGED,
    GENERIC_DOMAIN_BRIDGE,
    GENERIC_OP_OBJECT_OPEN,
    GENERIC_OP_OBJECT_CLOSE,
    GENERIC_OP_OBJECT_LOAD,
    GENERIC_OP_PROGRAM_CONFIGURE,
    GENERIC_OP_PROGRAM_INFO,
    GENERIC_OP_MAP_INFO,
    GENERIC_OP_VIEW_REF,
    GENERIC_OP_VIEW_GEN,
    GENERIC_OP_VIEW_CHECK,
    LOG_DISCARD,
    BytesV1,
    NameV1,
    MapInfoV1,
    GenericLib,
    GenericSpanV1,
    GenericOutSpanV1,
    GenericErrorV1,
    ObjectOptionsV1,
    ProgramOptionsV1,
    ProgramInfoV1,
)
from libbpf_mojo.error import LmbError, EINVAL, message_from_bytes
from libbpf_mojo.session import native_lib_path


struct ObjectOptions(Copyable):
    """Owned configuration; custom BTF paths are OS bytes."""

    var name: String
    var custom_btf: List[UInt8]
    var log_level: UInt32
    var log_capacity: UInt64

    def __init__(
        out self,
        name: String = "",
        custom_btf: List[UInt8] = List[UInt8](),
        log_level: UInt32 = LOG_DISCARD,
        log_capacity: UInt64 = 0,
    ):
        self.name = name.copy()
        self.custom_btf = custom_btf.copy()
        self.log_level = log_level
        self.log_capacity = log_capacity


@fieldwise_init
struct ProgramMetadata(Copyable):
    """Current metadata and owned verifier-log bytes."""

    var prog_type: UInt32
    var attach_type: UInt32
    var insn_count: UInt64
    var generation: UInt64
    var autoload: Bool
    var log: List[UInt8]
    var log_actual: UInt64
    var log_truncated: Bool


def capture_generic_error(
    mut lib: GenericLib, op: UInt32, rc: Int32
) -> LmbError:
    """Capture diagnostics immediately, on the caller's thread."""
    try:
        var record = GenericErrorV1(
            1, 1048, 0, 0, 0, 0, Array[UInt8, 1024](fill=0)
        )
        if lib.generic_last_error(Pointer(to=record)) != 0:
            return LmbError(
                op, GENERIC_DOMAIN_BRIDGE, rc, "generic error unavailable"
            )
        var bytes = List[UInt8]()
        for i in range(min(Int(record.msg_len), 1024)):
            bytes.append(record.message[i])
        return LmbError(
            record.operation,
            record.domain,
            record.code,
            message_from_bytes(bytes),
        )
    except e:
        return LmbError(
            op, GENERIC_DOMAIN_BRIDGE, rc, "generic error unavailable"
        )


def _query_name(text: String, op: UInt32) raises LmbError -> NameV1:
    var bytes = text.as_bytes()
    if len(bytes) == 0 or len(bytes) > 256:
        raise LmbError(
            op, GENERIC_DOMAIN_BRIDGE, EINVAL, "name must contain 1 to 256 bytes"
        )
    for byte in bytes:
        if byte == 0:
            raise LmbError(
                op, GENERIC_DOMAIN_BRIDGE, EINVAL, "name contains NUL"
            )
    return NameV1(
        1, 24, BytesV1(UInt64(bytes.unsafe_ptr()), UInt32(len(bytes)), 0)
    )


def _program_metadata(
    mut lib: GenericLib,
    handle: UInt64,
    name: String,
    log_capacity: Int,
) raises LmbError -> ProgramMetadata:
    if log_capacity < 0:
        raise LmbError(
            GENERIC_OP_PROGRAM_INFO,
            GENERIC_DOMAIN_BRIDGE,
            EINVAL,
            "negative log capacity",
        )
    var query = _query_name(name, GENERIC_OP_PROGRAM_INFO)
    var buffer = List[UInt8](length=log_capacity, fill=0)
    var storage = Span(buffer)
    var record = ProgramInfoV1(
        1,
        72,
        0,
        0,
        0,
        0,
        0,
        0,
        GenericOutSpanV1(UInt64(storage.unsafe_ptr()), UInt64(log_capacity)),
        0,
        0,
        0,
    )
    var rc = lib.program_info(handle, Pointer(to=query), Pointer(to=record))
    if rc != 0:
        raise capture_generic_error(lib, GENERIC_OP_PROGRAM_INFO, rc)
    var log = List[UInt8]()
    for i in range(Int(min(record.log_actual, UInt64(log_capacity)))):
        log.append(buffer[i])
    return ProgramMetadata(
        record.prog_type,
        record.attach_type,
        record.insn_count,
        record.generation,
        record.autoload != 0,
        log^,
        record.log_actual,
        record.log_truncated != 0,
    )


struct Object(Movable):
    """An external native owner, movable and never duplicable."""

    var _lib: ArcPointer[GenericLib]
    var _handle: UInt64

    def __init__(
        out self,
        elf: Span[UInt8, _],
        lib_path: String,
        options: ObjectOptions = ObjectOptions(),
    ) raises LmbError:
        var lib = GenericLib(lib_path)
        lib.require_object()
        var name = options.name.as_bytes()
        var btf = Span(options.custom_btf)
        var native = ObjectOptionsV1(
            1,
            64,
            GenericSpanV1(UInt64(name.unsafe_ptr()), UInt64(len(name))),
            GenericSpanV1(UInt64(btf.unsafe_ptr()), UInt64(len(btf))),
            options.log_level,
            0,
            options.log_capacity,
            0,
        )
        var cell = UInt64(0)
        var rc = lib.open_object(
            elf.unsafe_ptr(),
            UInt64(len(elf)),
            Pointer(to=native),
            Pointer(to=cell),
        )
        if rc != 0:
            raise capture_generic_error(lib, GENERIC_OP_OBJECT_OPEN, rc)
        self._lib = ArcPointer[GenericLib](lib^)
        self._handle = cell

    def __init__(out self, *, deinit move: Self):
        self._lib = move._lib^
        self._handle = move._handle

    def __deinit__(deinit self):
        if self._handle != 0:
            var cell = self._handle
            try:
                self._lib[].release_object(Pointer(to=cell))
            except e:
                pass

    @staticmethod
    def open(
        elf: Span[UInt8, _], options: ObjectOptions = ObjectOptions()
    ) raises LmbError -> Object:
        return Object.open_with_lib(elf, native_lib_path(), options)

    @staticmethod
    def open_with_lib(
        elf: Span[UInt8, _],
        lib_path: String,
        options: ObjectOptions = ObjectOptions(),
    ) raises LmbError -> Object:
        return Object(elf, lib_path, options)

    def is_closed(self) -> Bool:
        return self._handle == 0

    def configure_program(
        mut self,
        program: String,
        autoload: UInt32 = AUTOLOAD_UNCHANGED,
        attach_target: String = "",
    ) raises LmbError:
        var program_bytes = program.as_bytes()
        var target_bytes = attach_target.as_bytes()
        var native = ProgramOptionsV1(
            1,
            48,
            GenericSpanV1(
                UInt64(program_bytes.unsafe_ptr()), UInt64(len(program_bytes))
            ),
            GenericSpanV1(
                UInt64(target_bytes.unsafe_ptr()), UInt64(len(target_bytes))
            ),
            autoload,
            0,
        )
        var rc = self._lib[].configure_program(self._handle, Pointer(to=native))
        if rc != 0:
            raise capture_generic_error(
                self._lib[], GENERIC_OP_PROGRAM_CONFIGURE, rc
            )

    def load(mut self) raises LmbError:
        var rc = self._lib[].load_object(self._handle)
        if rc != 0:
            raise capture_generic_error(self._lib[], GENERIC_OP_OBJECT_LOAD, rc)

    def program(mut self, name: String) raises LmbError -> ProgramView:
        return ProgramView(self, name)

    def map(mut self, name: String) raises LmbError -> MapView:
        return MapView(self, name)

    def close(mut self) raises LmbError:
        var cell = self._handle
        var rc = self._lib[].close_object(Pointer(to=cell))
        self._handle = cell
        if rc != 0:
            raise capture_generic_error(
                self._lib[], GENERIC_OP_OBJECT_CLOSE, rc
            )

    def release(mut self):
        var cell = self._handle
        try:
            self._lib[].release_object(Pointer(to=cell))
        except e:
            pass
        self._handle = cell


def _retain_view(mut lib: GenericLib, handle: UInt64) raises LmbError -> UInt64:
    var generation = UInt64(0)
    var rc = lib.object_generation(handle, Pointer(to=generation))
    if rc != 0:
        raise capture_generic_error(lib, GENERIC_OP_VIEW_GEN, rc)
    rc = lib.object_ref(handle)
    if rc != 0:
        raise capture_generic_error(lib, GENERIC_OP_VIEW_REF, rc)
    return generation


struct ProgramView(Movable):
    """A native reference and captured generation for one program."""

    var _lib: ArcPointer[GenericLib]
    var _handle: UInt64
    var _generation: UInt64
    var _name: String

    def __init__(out self, object: Object, name: String) raises LmbError:
        var lib = object._lib.copy()
        _ = _program_metadata(lib[], object._handle, name, 0)
        var generation = _retain_view(lib[], object._handle)
        self._lib = lib^
        self._handle = object._handle
        self._generation = generation
        self._name = name.copy()

    def __init__(out self, *, deinit move: Self):
        self._lib = move._lib^
        self._handle = move._handle
        self._generation = move._generation
        self._name = move._name^

    def __deinit__(deinit self):
        if self._handle != 0:
            try:
                self._lib[].object_unref(self._handle)
            except e:
                pass

    def info(
        mut self, log_capacity: Int = 0
    ) raises LmbError -> ProgramMetadata:
        var rc = self._lib[].object_generation_check(
            self._handle, self._generation
        )
        if rc != 0:
            raise capture_generic_error(self._lib[], GENERIC_OP_VIEW_CHECK, rc)
        return _program_metadata(
            self._lib[], self._handle, self._name, log_capacity
        )

    def close(mut self):
        if self._handle != 0:
            try:
                self._lib[].object_unref(self._handle)
            except e:
                pass
            self._handle = 0


struct MapView(Movable):
    """A retained map name, with generation and load gating."""

    var _lib: ArcPointer[GenericLib]
    var _handle: UInt64
    var _generation: UInt64
    var _name: String

    def __init__(out self, object: Object, name: String) raises LmbError:
        _ = _query_name(name, GENERIC_OP_MAP_INFO)
        var lib = object._lib.copy()
        var generation = _retain_view(lib[], object._handle)
        self._lib = lib^
        self._handle = object._handle
        self._generation = generation
        self._name = name.copy()

    def __init__(out self, *, deinit move: Self):
        self._lib = move._lib^
        self._handle = move._handle
        self._generation = move._generation
        self._name = move._name^

    def __deinit__(deinit self):
        if self._handle != 0:
            try:
                self._lib[].object_unref(self._handle)
            except e:
                pass

    def info(mut self) raises LmbError -> MapInfoV1:
        var rc = self._lib[].object_generation_check(
            self._handle, self._generation
        )
        if rc != 0:
            raise capture_generic_error(self._lib[], GENERIC_OP_VIEW_CHECK, rc)
        var query = _query_name(self._name, GENERIC_OP_MAP_INFO)
        var result = MapInfoV1(1, 40, 0, 0, 0, 0, 0, 0, 0, 0)
        rc = self._lib[].object_map_info(
            self._handle, Pointer(to=query), Pointer(to=result)
        )
        if rc != 0:
            raise capture_generic_error(self._lib[], GENERIC_OP_MAP_INFO, rc)
        return result^

    def close(mut self):
        if self._handle != 0:
            try:
                self._lib[].object_unref(self._handle)
            except e:
                pass
            self._handle = 0
