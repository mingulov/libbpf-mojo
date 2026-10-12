# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# CHECK: use of uninitialized value
from libbpf_mojo.link import Link


def transfer(var value: Link):
    var moved = value^
    print(value.is_closed())
    _ = moved^


def main():
    pass
