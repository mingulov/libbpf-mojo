# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
from std.os import getenv
from std.pathlib import Path
from std.testing import assert_true
from libbpf_mojo.object import Object
from libbpf_mojo.buffer import Buffer, open_ring


def transfer(var value: Buffer) -> Buffer:
    return value^


def main() raises:
    var data = Path(getenv("LMB_GENERIC_EVENTS_FIXTURE")).read_bytes()
    var object = Object.open_with_lib(Span(data), getenv("LMB_EVENTS_TESTFAKE_LIB"))
    var reset = object._lib[]._handle.get_function[NoneType]("lmb_events_reset")
    reset()
    var setup = object._lib[]._handle.get_function[NoneType]("lmb_events_scenario")
    setup(UInt32(2))
    object.load()
    var original_view = object.map("events")
    var owner = object^
    var view = original_view^
    owner.release()
    var child = open_ring(view)
    var moved = transfer(child^)
    view.close()
    assert_true(not moved.is_closed())
    moved.close()
    moved.close()
    assert_true(moved.is_closed())
    var finish = moved._lib[]._handle.get_function[NoneType]("lmb_events_scenario")
    finish(UInt32(10))
