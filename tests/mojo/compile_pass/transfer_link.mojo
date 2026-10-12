# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
from std.os import getenv
from std.pathlib import Path
from std.testing import assert_true
from libbpf_mojo.object import Object
from libbpf_mojo.link import Link, attach_tracepoint


def transfer(var value: Link) -> Link:
    return value^


def main() raises:
    var data = Path(getenv("LMB_GENERIC_EVENTS_FIXTURE")).read_bytes()
    var object = Object.open_with_lib(Span(data), getenv("LMB_EVENTS_TESTFAKE_LIB"))
    var reset = object._lib[]._handle.get_function[NoneType]("lmb_events_reset")
    reset()
    object.load()
    var original_view = object.program("on_getpid")
    var owner = object^
    var view = original_view^
    owner.release()
    var child = attach_tracepoint(view, "syscalls", "sys_enter_getpid")
    var moved = transfer(child^)
    view.close()
    assert_true(not moved.is_closed())
    moved.close()
    moved.close()
    assert_true(moved.is_closed())
