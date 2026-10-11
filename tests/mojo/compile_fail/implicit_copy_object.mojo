# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# CHECK: cannot be implicitly copied
from libbpf_mojo.object import Object


def duplicate(object: Object):
    var copy = object
    _ = copy^


def main():
    pass
