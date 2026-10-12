# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# CHECK: no attribute 'copy'
from libbpf_mojo.link import Link


def duplicate(value: Link):
    var copied = value.copy()
    _ = copied^


def main():
    pass
