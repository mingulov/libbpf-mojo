#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Reject vacuous live-gate success using guarded, explicit API responses."""
import os
import subprocess
import sys

binary, fixture, guard = sys.argv[1:]
failures = []
for case, expected, reason in [('blanket', 1, 'FAIL blacklist-control'),
                               ('bridge', 1, 'FAIL blacklisted-symbol'),
                               ('native', 0, 'ok blacklisted-symbol'),
                               ('missing-success', 1, 'FAIL missing-symbol')]:
    env = dict(os.environ, LD_PRELOAD=guard, LMB_GATE_CASE=case)
    result = subprocess.run([binary, fixture, '--blacklist', 'blacklisted_target'],
                            env=env, capture_output=True, text=True, timeout=30)
    valid = result.returncode == expected and reason in result.stdout
    valid = valid and 'control kind=3' in result.stdout and 'control kind=4' in result.stdout
    valid = valid and 'gate-oracle controls=2 negatives=2 live=0' in result.stdout
    if not valid:
        failures.append(case)
        print(case, 'unexpected exit', result.returncode, result.stdout, result.stderr)
    else:
        print('PASS gate oracle', case, 'native exit', result.returncode)
if failures:
    raise SystemExit(1)
print('NOT_RUN kernel: live-gate logic over guarded API responses only')
