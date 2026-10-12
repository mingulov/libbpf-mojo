# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# CHECK: cannot be implicitly copied
from libbpf_mojo.buffer import Buffer


def duplicate(value: Buffer):
    var copied = value
    _ = copied^


def main():
    pass
