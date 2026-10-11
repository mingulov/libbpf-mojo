# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# CHECK: use of uninitialized value
from libbpf_mojo.object import Object


def transfer(var object: Object):
    var moved = object^
    print(object.is_closed())
    _ = moved^


def main():
    pass
