# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# CHECK: no attribute 'copy'
from libbpf_mojo.object import Object


def duplicate(object: Object):
    var copy = object.copy()
    _ = copy^


def main():
    pass
