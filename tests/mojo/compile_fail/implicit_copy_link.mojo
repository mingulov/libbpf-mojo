# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# CHECK: cannot be implicitly copied
from libbpf_mojo.link import Link


def duplicate(value: Link):
    var copied = value
    _ = copied^


def main():
    pass
