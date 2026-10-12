# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# CHECK: no attribute 'copy'
from libbpf_mojo.buffer import Buffer


def duplicate(value: Buffer):
    var copied = value.copy()
    _ = copied^


def main():
    pass
