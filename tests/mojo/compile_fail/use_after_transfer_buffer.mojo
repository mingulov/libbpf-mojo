# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# CHECK: use of uninitialized value
from libbpf_mojo.buffer import Buffer


def transfer(var value: Buffer):
    var moved = value^
    print(value.is_closed())
    _ = moved^


def main():
    pass
