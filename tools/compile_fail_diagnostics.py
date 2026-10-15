#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Validate the pinned compiler's rendered compile-fail test diagnostics."""

import re
import sys


_SUFFIX = re.compile(r":[1-9][0-9]*:[1-9][0-9]*: (error|note): (.+)")
# Count invalid as well as valid header-shaped boundaries. Otherwise a later
# valid delimiter could hide unsupported severity or coordinates in the path.
_BOUNDARY = re.compile(r":[^:\n]+:[^:\n]+: [^: \n]+: ")
_IMPORT = re.compile(r"Imported from .+:[1-9][0-9]*:")
_CARET = re.compile(r"[ \t~^]*\^[ \t~^]*")
_TRAILER = re.compile(r"(.+?): error: .+")
_LOCATION_SUFFIX = re.compile(r":[^:]*:[^:]*$")


def _located_header(line: str, fixture: str):
    if fixture and line.startswith(fixture + ":"):
        # Exact source identity fixes the boundary even when the filename or
        # message contains another delimiter. Never retry an invalid suffix.
        suffix = _SUFFIX.fullmatch(line[len(fixture):])
        if not suffix:
            raise ValueError("invalid header suffix after known fixture path")
        return suffix.groups()
    boundaries = list(_BOUNDARY.finditer(line))
    if not boundaries:
        return None
    if len(boundaries) != 1 or boundaries[0].start() == 0:
        raise ValueError("ambiguous diagnostic header boundary")
    suffix = _SUFFIX.fullmatch(line[boundaries[0].start():])
    if not suffix:
        raise ValueError("invalid located diagnostic header")
    return suffix.groups()


def _extract_primary_errors(output: str, *, fixture: str) -> list[str]:
    """Read the whole rendering with optional exact fixture-path context.

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
        if _IMPORT.fullmatch(line):
            if imported:
                raise ValueError("import context without a following block")
            imported = True
            index += 1
            continue
        header = _located_header(line, fixture)
        if header:
            severity, message = header
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


def extract_primary_errors(output: str) -> list[str]:
    """Extract unambiguous primary messages without source-identity context.

    Multiple header-shaped boundaries raise ValueError; callers with the exact
    fixture identity use matches_diagnostic to disambiguate that fixture's path.
    """
    return _extract_primary_errors(output, fixture="")


def matches_diagnostic(output: str, *, fixture: str, expected: str,
                       must_reject: bool) -> bool:
    """Apply a CHECK to individual primary messages of an admitted rendering."""
    if not fixture or not expected:
        return False
    try:
        messages = _extract_primary_errors(output, fixture=fixture)
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
