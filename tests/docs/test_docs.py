#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Docs gate: links resolve and text stays public.

Scans README.md, AGENTS.md, the root governance files,
docs/**, and examples/**. Every local link in user-facing
Markdown resolves to a file and, for anchored links, a
heading; backticked Markdown paths resolve beside the doc
or at the repo root; and no document carries placeholder
markers. Exits nonzero on the first failure. Standard
library only.
"""

import glob
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))))

FORBIDDEN = (
    "TODO", "FIXME", "XXX",
)

LINK_RE = re.compile(r"\[[^\]]*\]\(([^)\s]+)\)")
BACKTICK_RE = re.compile(r"`([^`\n]+)`")


def check(name, cond, detail=""):
    if not cond:
        print("FAIL %s %s" % (name, detail))
        sys.exit(1)
    print("ok %s" % name)


def slug(text):
    text = text.strip().lower()
    text = re.sub(r"[^a-z0-9 _-]", "", text)
    return text.replace(" ", "-")


def headings_of(path):
    slugs = set()
    for line in open(path, encoding="utf-8"):
        match = re.match(r"#{1,6}\s+(.*)", line)
        if match:
            title = re.sub(r"`([^`]*)`", r"\1", match.group(1))
            slugs.add(slug(title))
    return slugs


def doc_files():
    found = [os.path.join(ROOT, "README.md"),
             os.path.join(ROOT, "AGENTS.md"),
             os.path.join(ROOT, "SECURITY.md"),
             os.path.join(ROOT, "CONTRIBUTING.md"),
             os.path.join(ROOT, "RELEASING.md"),
             os.path.join(ROOT, "CHANGELOG.md")]
    found += sorted(glob.glob(os.path.join(ROOT, "docs", "**", "*.md"),
                              recursive=True))
    found += sorted(glob.glob(os.path.join(ROOT, "examples", "**",
                                           "*.md"), recursive=True))
    return [path for path in found if os.path.isfile(path)]


def main():
    docs = doc_files()
    check("docs-present", len(docs) >= 8, "%d docs" % len(docs))

    bad_links = []
    bad_markers = []
    for path in docs:
        rel = os.path.relpath(path, ROOT)
        text = open(path, encoding="utf-8").read()
        for token in FORBIDDEN:
            if token in text:
                bad_markers.append("%s: %s" % (rel, token))
        for target in LINK_RE.findall(text):
            if re.match(r"(https?://|mailto:|#)", target):
                continue
            file_part, _, anchor = target.partition("#")
            if not file_part:
                continue
            resolved = os.path.normpath(os.path.join(
                os.path.dirname(path), file_part))
            if not os.path.isfile(resolved):
                bad_links.append("%s -> %s" % (rel, target))
            elif anchor and anchor not in headings_of(resolved):
                bad_links.append("%s -> %s (no heading)" % (rel, target))
        for span in BACKTICK_RE.findall(text):
            if not span.endswith(".md"):
                continue
            if "/" not in span and span in (
                    "README.md", "AGENTS.md", "SECURITY.md",
                    "CONTRIBUTING.md", "RELEASING.md",
                    "CHANGELOG.md"):
                continue
            for base in (os.path.dirname(path), ROOT):
                if os.path.isfile(os.path.join(base, span)):
                    break
            else:
                bad_links.append("%s -> `%s`" % (rel, span))
    check("no-markers", not bad_markers, "; ".join(bad_markers[:5]))
    check("links-resolve", not bad_links, "; ".join(bad_links[:5]))
    print("docs: %d files checked" % len(docs))


if __name__ == "__main__":
    main()
