#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""LJ01 probe: Mojo diagnostic-line format classifier plus proposed-contract checks.

Format tests assert observed compiler-log facts; tests marked CONSTRUCTED are
parser controls with hand-built specimens (not observed log lines). Contract
tests exercise the proposed LJ01 verdict policy from the probe report, which
is a policy proposal, not an observed compiler fact. Imports nothing from
``tools/test``.
"""

import re
import unittest

# Fix round 1: the path part starts at column 0 (no leading whitespace:
# observed D1 lines never indent), must not contain Mojo comment/string
# markers (#, ", '), and splits at the FIRST `:line:col: error: `
# delimiter (non-greedy) so repeated delimiters cannot truncate the
# message. A marker-free excerpt shaped exactly like a diagnostic still
# matches: undecidable from line shape alone (see probe report).
LOCATED_ERROR_RE = re.compile(r"^([^#\"'\s][^#\"']*?):(\d+):(\d+): error: (.*)$")

ACCEPT = "ACCEPT"
REJECT = "REJECT"


def extract_located_error_messages(output):
    """Probe classifier: message part of anchored path:line:col: error: lines only."""
    messages = []
    for line in output.splitlines():
        match = LOCATED_ERROR_RE.match(line)
        if match:
            messages.append(match.group(4))
    return messages


def contract_verdict(output, want, *, must_reject=False, compiler_exit=1):
    """Proposed LJ01 message-only contract (probe report section 4, fix round 1).

    Nonzero exit plus substring match of CHECK text over recognized D1
    messages only. Fix round 1 requires at least one recognized
    diagnostic: MUST-REJECT must never ACCEPT by absence of evidence.
    """
    if compiler_exit == 0:
        return REJECT
    messages = extract_located_error_messages(output)
    if not messages:
        return REJECT
    joined = "\n".join(messages)
    if must_reject:
        return REJECT if want in joined else ACCEPT
    return ACCEPT if want in joined else REJECT


class DiagnosticLineFormatProbeTests(unittest.TestCase):
    def test_located_error_line_yields_message(self):
        line = "/w/tests/mojo/compile_fail/implicit_copy_session.mojo:17:14: error: value of type 'Session' cannot be implicitly copied, it does not conform to 'ImplicitlyCopyable'"
        self.assertEqual(
            extract_located_error_messages(line),
            ["value of type 'Session' cannot be implicitly copied, it does not conform to 'ImplicitlyCopyable'"],
        )

    def test_message_preserves_inner_colons(self):
        line = "/w/immutable_buffer_poll_dst.mojo:7:28: error: invalid call to 'poll': value passed to 'dst' cannot be converted"
        self.assertEqual(
            extract_located_error_messages(line),
            ["invalid call to 'poll': value passed to 'dst' cannot be converted"],
        )

    def test_note_line_is_not_located_error(self):
        self.assertEqual(
            extract_located_error_messages("/w/a.mojo:17:14: note: consider transferring the value with '^'"),
            [],
        )

    def test_unlocated_trailer_is_not_located_error(self):
        self.assertEqual(
            extract_located_error_messages("/pixi/envs/default/bin/mojo: error: failed to parse the provided Mojo source module"),
            [],
        )

    def test_source_excerpt_is_not_located_error(self):
        self.assertEqual(extract_located_error_messages("    var s2 = s"), [])
        self.assertEqual(extract_located_error_messages("def broken(:"), [])
        # CONSTRUCTED control: CHECK-comment excerpts occur in the synthetic
        # test_compile_fail_matcher.py controls, not in the cited logs.
        self.assertEqual(extract_located_error_messages("# CHECK: cannot be implicitly copied"), [])
        self.assertEqual(
            extract_located_error_messages('"""Compile-fail fixture: a Session cannot be implicitly copied.'),
            [],
        )

    def test_caret_lines_are_not_located_errors(self):
        self.assertEqual(extract_located_error_messages("^"), [])
        self.assertEqual(extract_located_error_messages("             ^"), [])
        self.assertEqual(extract_located_error_messages("                 ~~~~~^"), [])
        self.assertEqual(extract_located_error_messages("                     ~^"), [])

    def test_continuation_and_imported_from_are_not_located_errors(self):
        self.assertEqual(extract_located_error_messages("If you see this either:"), [])
        self.assertEqual(
            extract_located_error_messages("- Your mojo installation is broken and needs to be reinstalled or"),
            [],
        )
        self.assertEqual(
            extract_located_error_messages("Imported from /w/tests/mojo/compile_fail/a.mojo:10:"),
            [],
        )

    def test_crashpad_notice_is_not_located_error(self):
        self.assertEqual(
            extract_located_error_messages("Failed to initialize Crashpad.  Crash reporting will not be available.  Cause: while locating crashpad handler: unable to locate crashpad handler executable"),
            [],
        )

    def test_real_session_block_yields_single_message(self):
        block = (
            "/w/tests/mojo/compile_fail/implicit_copy_session.mojo:17:14: error: value of type 'Session' cannot be implicitly copied, it does not conform to 'ImplicitlyCopyable'\n"
            "    var s2 = s\n"
            "             ^\n"
            "/w/tests/mojo/compile_fail/implicit_copy_session.mojo:17:14: note: consider transferring the value with '^'\n"
            "    var s2 = s\n"
            "             ^\n"
            "              ^\n"
            "/pixi/envs/default/bin/mojo: error: failed to parse the provided Mojo source module\n"
        )
        messages = extract_located_error_messages(block)
        self.assertEqual(len(messages), 1)
        self.assertIn("cannot be implicitly copied", messages[0])

    def test_real_failed_env_excerpt_excluded(self):
        block = (
            "/w/tests/mojo/compile_fail/implicit_copy_session.mojo:3:1: error: unable to locate module 'std'\n"
            '"""Compile-fail fixture: a Session cannot be implicitly copied.\n'
            "^\n"
        )
        messages = extract_located_error_messages(block)
        self.assertEqual(messages, ["unable to locate module 'std'"])
        self.assertNotIn("cannot be implicitly copied", "\n".join(messages))

    def test_relative_path_parses(self):
        self.assertEqual(
            extract_located_error_messages("src/libbpf_mojo/session.mojo:3:1: error: unable to locate module 'std'"),
            ["unable to locate module 'std'"],
        )

    def test_path_with_spaces_parses(self):
        # CONSTRUCTED control: no cited log has a path with spaces; the
        # specimen is modeled on the shipped self-test fixture name
        # ("cannot be implicitly copied.mojo").
        self.assertEqual(
            extract_located_error_messages("/tmp/cannot be implicitly copied.mojo:17:14: error: value of type 'Session' cannot be implicitly copied"),
            ["value of type 'Session' cannot be implicitly copied"],
        )


    def test_diagnostic_shaped_check_comment_is_not_located_error(self):
        # CONSTRUCTED (fix round 1, finding 1): a CHECK-comment source
        # excerpt whose text is shaped like a diagnostic must not yield a
        # message, alone or replayed after an unrelated genuine error.
        shaped = "# fake.mojo:9:9: error: cannot be implicitly copied"
        self.assertEqual(extract_located_error_messages(shaped), [])
        replay = (
            "other.mojo:1:4: error: expected expression\n" + shaped + "\n"
        )
        messages = extract_located_error_messages(replay)
        self.assertEqual(messages, ["expected expression"])
        self.assertNotIn("cannot be implicitly copied", "\n".join(messages))

    def test_diagnostic_shaped_docstring_is_not_located_error(self):
        # CONSTRUCTED (fix round 1, finding 1): a docstring excerpt
        # beginning with diagnostic-shaped text must not yield a message.
        self.assertEqual(
            extract_located_error_messages(
                '"""fake.mojo:9:9: error: cannot be implicitly copied'
            ),
            [],
        )

    def test_diagnostic_shaped_indented_or_quoted_excerpt_is_not_located_error(self):
        # CONSTRUCTED (fix round 1, finding 1): leading whitespace and
        # string-literal quotes are source markers, never diagnostic shape.
        self.assertEqual(
            extract_located_error_messages(
                "    fake.mojo:1:1: error: cannot be implicitly copied"
            ),
            [],
        )
        self.assertEqual(
            extract_located_error_messages(
                'var x = "fake.mojo:1:1: error: cannot be implicitly copied"'
            ),
            [],
        )

    def test_must_reject_without_recognized_diagnostics_is_rejected(self):
        # Contract policy (fix round 1, finding 2): LJ01 MUST-REJECT needs
        # an unrelated genuine compiler error, so zero recognized
        # diagnostics with exit 1 must REJECT, not ACCEPT by absence.
        self.assertEqual(
            contract_verdict(
                "", "cannot be implicitly copied",
                must_reject=True, compiler_exit=1,
            ),
            REJECT,
        )
        self.assertEqual(
            contract_verdict(
                "    var s2 = s\n             ^\n",
                "cannot be implicitly copied",
                must_reject=True, compiler_exit=1,
            ),
            REJECT,
        )
        # Preserved behavior: unrelated genuine error still ACCEPTs under
        # MUST-REJECT; matching error still REJECTs; empty normal still
        # REJECTs.
        self.assertEqual(
            contract_verdict(
                "other.mojo:1:4: error: expected expression",
                "cannot be implicitly copied",
                must_reject=True, compiler_exit=1,
            ),
            ACCEPT,
        )
        self.assertEqual(
            contract_verdict(
                "a.mojo:1:1: error: cannot be implicitly copied",
                "cannot be implicitly copied",
                must_reject=True, compiler_exit=1,
            ),
            REJECT,
        )
        self.assertEqual(
            contract_verdict(
                "", "cannot be implicitly copied",
                must_reject=False, compiler_exit=1,
            ),
            REJECT,
        )

    def test_repeated_delimiter_splits_at_first(self):
        # CONSTRUCTED (fix round 1, finding 3): when the complete
        # `:line:col: error: ` delimiter repeats, the split must keep the
        # full message, not drop the CHECK-bearing prefix.
        self.assertEqual(
            extract_located_error_messages(
                "a.mojo:1:1: error: cannot be implicitly copied; "
                "b.mojo:2:3: error: expected expression"
            ),
            ["cannot be implicitly copied; b.mojo:2:3: error: expected expression"],
        )

    def test_colon_containing_path_parses(self):
        # CONSTRUCTED (fix round 1, finding 3): ordinary colons in the
        # path (drive-letter style) already parse; only the repeated
        # complete delimiter is ambiguous.
        self.assertEqual(
            extract_located_error_messages(
                "C:\\odd\\a.mojo:1:1: error: boom"
            ),
            ["boom"],
        )


if __name__ == "__main__":
    unittest.main()
