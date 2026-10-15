# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# CHECK: cannot be implicitly copied
# MUST-REJECT: unrelated syntax must not match CHECK echoed below.
def broken(:  # CHECK: cannot be implicitly copied
