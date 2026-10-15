#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Validate the pinned compiler's rendered compile-fail test diagnostics."""

import re
import sys


_HEADER = re.compile(r"(.+?):[1-9][0-9]*:[1-9][0-9]*: (error|note): (.+)")
_IMPORT = re.compile(r"Imported from .+:[1-9][0-9]*:")
_CARET = re.compile(r"[ \t~^]*\^[ \t~^]*")
_TRAILER = re.compile(r"(.+?): error: .+")
_LOCATION_SUFFIX = re.compile(r":[^:]*:[^:]*$")


def extract_primary_errors(output: str) -> list[str]:
    """Return primary messages only after validating the complete rendering.

    A source excerpt is one opaque physical line, consumed before recognizing
    any carets or subsequent headers. Unknown and incomplete rendering raises
    ValueError, including a stream containing no complete primary error.
    """
    lines = output.split("\n")
    primary = []
    index = 0
    imported = False
    trailer = False
    while index < len(lines):
        line = lines[index]
        if line == "" and not imported:
            index += 1
            continue
        if trailer:
            raise ValueError("content after final driver trailer")
        header = _HEADER.fullmatch(line)
        if header:
            _, severity, message = header.groups()
            if severity == "note" and not primary:
                raise ValueError("note without a preceding primary error")
            # Exactly one physical source line precedes the renderer. Its
            # contents must never be interpreted as diagnostic structure.
            index += 2
            if index >= len(lines) or not _CARET.fullmatch(lines[index]):
                raise ValueError("missing source excerpt or renderer caret")
            while index < len(lines) and _CARET.fullmatch(lines[index]):
                index += 1
            if severity == "error":
                primary.append(message)
            imported = False
        elif not imported and _IMPORT.fullmatch(line):
            imported = True
            index += 1
        elif not imported and primary and _TRAILER.fullmatch(line):
            # A location-shaped suffix with invalid coordinates is not an
            # unlocated driver path. Refuse ambiguous trailer interpretations.
            tool_path = _TRAILER.fullmatch(line).group(1)
            if _LOCATION_SUFFIX.search(tool_path):
                raise ValueError("ambiguous or invalid located header")
            trailer = True
            index += 1
        else:
            raise ValueError("unsupported or incomplete diagnostic rendering")
    if imported or not primary:
        raise ValueError("no complete primary error evidence")
    return primary


def matches_diagnostic(output: str, *, fixture: str, expected: str,
                       must_reject: bool) -> bool:
    """Apply a CHECK to individual primary messages of an admitted rendering."""
    if not fixture or not expected:
        return False
    try:
        messages = extract_primary_errors(output)
    except ValueError:
        return False
    matched = any(expected in message.replace(fixture, "") for message in messages)
    return not matched if must_reject else matched


def main() -> int:
    if len(sys.argv) != 4 or sys.argv[3] not in ("0", "1"):
        print("usage: compile_fail_diagnostics.py FIXTURE CHECK MUST_REJECT(0|1)",
              file=sys.stderr)
        return 2
    accepted = matches_diagnostic(sys.stdin.read(), fixture=sys.argv[1],
                                  expected=sys.argv[2], must_reject=sys.argv[3] == "1")
    return 0 if accepted else 1


if __name__ == "__main__":
    sys.exit(main())
