#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Exercise the shipped compile-fail matcher without a compiler."""

import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class CompileFailMatcherTests(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory(prefix="compile-fail matcher-")
        self.addCleanup(self.scratch.cleanup)
        self.directory = Path(self.scratch.name)
        runner = (ROOT / "tools/test").read_text()
        begin = runner.index("check_compile_fail() {")
        end = runner.index("\n}", begin) + 2
        self.function = self.directory / "matcher.sh"
        self.function.write_text(runner[begin:end] + "\n")
        self.compiler = self.directory / "compiler.sh"
        self.compiler.write_text(
            '#!/usr/bin/env bash\nprintf "%s\\n" "$OUTPUT"\nexit "$COMPILER_EXIT"\n'
        )

    def match(self, output, *, must_reject=False, compiler_exit=1):
        fixture = self.directory / "cannot be implicitly copied.mojo"
        fixture.write_text(
            "# CHECK: cannot be implicitly copied\n"
            + ("# MUST-REJECT: unrelated error\n" if must_reject else "")
        )
        environment = os.environ.copy()
        environment.update(OUTPUT=output.replace("<fixture>", str(fixture)),
                           COMPILER_EXIT=str(compiler_exit))
        result = subprocess.run(
            ["bash", "-c",
             'ROOT="$1"; MOJO=(bash "$2"); source "$3"; '
             'check_compile_fail "$4" "$5"', "matcher",
             str(ROOT), str(self.compiler), str(self.function),
             str(fixture), str(self.directory)],
            env=environment, capture_output=True, text=True,
        )
        return result.returncode

    def test_specific_error_message_is_accepted(self):
        self.assertEqual(self.match(
            "<fixture>:17:14: error: value of type 'Session' cannot be implicitly copied"
        ), 0)

    def test_source_excerpt_cannot_satisfy_check(self):
        self.assertEqual(self.match(
            "<fixture>:3:1: error: unable to locate module 'std'\n"
            '\"\"\"A Session cannot be implicitly copied.\n^\n'
        ), 1)

    def test_check_comment_excerpt_cannot_satisfy_check(self):
        self.assertEqual(self.match(
            "<fixture>:2:1: error: unexpected token\n"
            "# CHECK: cannot be implicitly copied\n^\n"
        ), 1)

    def test_filename_cannot_satisfy_check(self):
        self.assertEqual(self.match("<fixture>:3:1: error: expected expression"), 1)

    def test_unrelated_error_is_rejected(self):
        self.assertEqual(self.match("other.mojo:1:4: error: expected expression"), 1)

    def test_compiler_success_is_rejected(self):
        self.assertEqual(self.match(
            "<fixture>:1:1: error: cannot be implicitly copied", compiler_exit=0
        ), 1)

    def test_must_reject_ignores_source_excerpt(self):
        self.assertEqual(self.match(
            "<fixture>:3:1: error: expected expression\n"
            "# CHECK: cannot be implicitly copied\n^\n", must_reject=True
        ), 0)

    def test_must_reject_refuses_actual_matching_error(self):
        self.assertEqual(self.match(
            "<fixture>:1:1: error: cannot be implicitly copied", must_reject=True
        ), 1)


if __name__ == "__main__":
    unittest.main()
