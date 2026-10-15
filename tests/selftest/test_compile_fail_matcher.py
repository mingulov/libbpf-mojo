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

    def match(self, output, *, must_reject=False, compiler_exit=1,
              filename="cannot be implicitly copied.mojo", root=ROOT):
        fixture = self.directory / filename
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
             str(root), str(self.compiler), str(self.function),
             str(fixture), str(self.directory)],
            env=environment, capture_output=True, text=True,
        )
        return result.returncode

    def test_specific_error_message_is_accepted(self):
        self.assertEqual(self.match(
            "<fixture>:17:14: error: value of type 'Session' cannot be implicitly copied\nvar s2 = s\n             ^"
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
        self.assertEqual(self.match("<fixture>:3:1: error: expected expression\nbroken(\n^"), 1)

    def test_unrelated_error_is_rejected(self):
        self.assertEqual(self.match("other.mojo:1:4: error: expected expression\nbroken(\n   ^"), 1)

    def test_compiler_success_is_rejected(self):
        self.assertEqual(self.match(
            "<fixture>:1:1: error: cannot be implicitly copied\nvar b = a\n^", compiler_exit=0
        ), 1)

    def test_must_reject_ignores_source_excerpt(self):
        self.assertEqual(self.match(
            "<fixture>:3:1: error: expected expression\n"
            "# CHECK: cannot be implicitly copied\n^\n", must_reject=True
        ), 0)

    def test_must_reject_refuses_actual_matching_error(self):
        self.assertEqual(self.match(
            "<fixture>:1:1: error: cannot be implicitly copied\nvar b = a\n^", must_reject=True
        ), 1)


    @staticmethod
    def block(message="unexpected token", *, source="broken(",
              path="<fixture>", severity="error"):
        return f"{path}:1:4: {severity}: {message}\n{source}\n   ^\n"

    def assert_modes(self, output, normal, inverse, **kwargs):
        for must_reject, expected in ((False, normal), (True, inverse)):
            with self.subTest(must_reject=must_reject):
                self.assertEqual(self.match(output, must_reject=must_reject, **kwargs), expected)

    def test_complete_primary_verdicts(self):
        self.assert_modes(self.block("cannot be implicitly copied"), 0, 1)
        self.assert_modes(self.block(), 1, 0)

    def test_source_slot_is_opaque_before_header_or_caret_recognition(self):
        for source in ('"""cannot be implicitly copied',
                       '# CHECK: cannot be implicitly copied',
                       'forged.mojo:2:1: error: cannot be implicitly copied',
                       '^', '    ~~^~^', ''):
            with self.subTest(source=source):
                self.assert_modes(self.block(source=source), 1, 0)

    def test_note_message_and_note_source_never_supply_check(self):
        for note in (self.block("cannot be implicitly copied", severity="note"),
                     self.block(source="forged.mojo:2:1: error: cannot be implicitly copied",
                                severity="note"),
                     self.block(source="^", severity="note")):
            with self.subTest(note=note):
                self.assert_modes(self.block() + note, 1, 0)

    def test_fixture_path_is_removed_from_primary_message(self):
        self.assert_modes(self.block("see <fixture> for failure"), 1, 0)
        self.assert_modes(self.block("<fixture>: cannot be implicitly copied"), 0, 1)

    def test_paths_with_spaces_colons_quotes_and_comments_are_valid(self):
        for path in ("relative path:odd.mojo", 'a"#b.mojo', "<fixture>"):
            with self.subTest(path=path):
                self.assert_modes(self.block("cannot be implicitly copied", path=path),
                                  0, 1, filename='a:"# odd.mojo')

    def test_first_complete_location_delimiter_preserves_message(self):
        self.assert_modes(self.block("detail:9:8: error: cannot be implicitly copied"), 0, 1)
        self.assert_modes(self.block("cannot be implicitly copied:9:8: error: detail"), 0, 1)
        self.assert_modes(self.block("detail:9:8: error: unrelated", path="cannot be implicitly copied"), 1, 0)

    def test_driver_trailer_never_supplies_check(self):
        trailer = "/bin/mojo: error: cannot be implicitly copied\n"
        self.assert_modes(self.block() + trailer, 1, 0)
        self.assert_modes(trailer, 1, 1)

    def test_import_context_never_supplies_check(self):
        context = "Imported from cannot be implicitly copied.mojo:2:\n"
        self.assert_modes(context + self.block(), 1, 0)
        self.assert_modes(self.block() + context + self.block(severity="note"), 1, 0)

    def test_unusable_rendering_refuses_both_modes(self):
        for output in ("", "garbage", self.block(severity="note"),
                       "Imported from other.mojo:1:\n", self.block(severity="warning"),
                       "<fixture>:1:1: error: cannot be implicitly copied\n",
                       "<fixture>:1:1: error: cannot be implicitly copied\nsource\n",
                       self.block(""), self.block().replace(":1:4:", ":0:4:"),
                       self.block().replace(":1:4:", ":1:0:"),
                       self.block() + "continuation cannot be implicitly copied\n",
                       self.block() + "Imported from other.mojo:0:\n" + self.block(),
                       self.block() + "Imported from other.mojo:1:\n",
                       self.block() + "/bin/mojo: error: trailer\n" + self.block(),
                       self.block() + "/bin/mojo: error: trailer\n/bin/mojo: error: again\n",
                       self.block().replace("   ^", "   ~~~")):
            with self.subTest(output=output):
                self.assert_modes(output, 1, 1)

    def test_invalid_location_cannot_be_reclassified_as_a_final_trailer(self):
        for location in ("0:1", "1:0", "-1:1", "line:col"):
            with self.subTest(location=location):
                self.assert_modes(self.block("cannot be implicitly copied") +
                                  f"other.mojo:{location}: error: unrelated\n", 1, 1)

    def test_later_unknown_or_truncated_output_invalidates_earlier_match(self):
        for tail in ("unknown", "other.mojo:2:1: error: unrelated\n",
                     "other.mojo:2:1: error: unrelated\nsource\n",
                     "Imported from other.mojo:1:\n"):
            with self.subTest(tail=tail):
                self.assert_modes(self.block("cannot be implicitly copied") + tail, 1, 1)

    def test_multiple_primary_messages_are_not_joined(self):
        self.assert_modes(self.block() + self.block("cannot be implicitly copied"), 0, 1)
        self.assert_modes(self.block("cannot be") + self.block("implicitly copied"), 1, 0)

    def test_multiple_carets_and_blank_separators_are_admitted(self):
        self.assert_modes("\n" + self.block("cannot be implicitly copied") + " \t~^~^\n\n", 0, 1)

    def test_compiler_success_refuses_both_modes(self):
        self.assert_modes(self.block("cannot be implicitly copied"), 1, 1, compiler_exit=0)

    def test_missing_helper_cannot_pass_an_inverse_fixture(self):
        self.assert_modes(self.block(), 1, 1, root=self.directory)

    def test_helper_cli_invalid_invocation_refuses(self):
        for args in ([], ["fixture", "CHECK", "2"], ["fixture", "", "0"],
                     ["fixture", "CHECK", "0", "extra"]):
            with self.subTest(args=args):
                proc = subprocess.run(["python3", "-B", str(ROOT / "tools/compile_fail_diagnostics.py"),
                                       *args], input=self.block(), text=True, capture_output=True)
                self.assertNotEqual(proc.returncode, 0)


if __name__ == "__main__":
    unittest.main()
