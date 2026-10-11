# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
from std.os import getenv
from std.pathlib import Path
from libbpf_mojo.object import Object


def main() raises:
    var elf = Path(getenv("LMB_GENERIC_FIXTURE")).read_bytes()
    var object = Object.open_with_lib(Span(elf), getenv("LMB_NATIVE_LIB"))
    var view = object.program(String("first"))
    var moved = object^
    var moved_view = view^
    moved_view.close()
    moved.close()
