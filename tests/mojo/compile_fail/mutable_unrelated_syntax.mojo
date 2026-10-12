# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# CHECK: mutable
# MUST-REJECT: this file fails for an unrelated syntax error; the matcher
# must reject it because the stripped diagnostic lacks the CHECK token even
# though this file's own name carries that token.
def broken(:
