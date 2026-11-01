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
for case, expected, reason, controls, closes in [
        ('lockdown-denied', 0, 'ok lockdown-attach', 2, 0),
        ('lockdown-bridge', 1, 'FAIL lockdown-attach', 2, 0),
        ('lockdown-operation', 1, 'FAIL lockdown-attach', 2, 0),
        ('lockdown-code', 1, 'FAIL lockdown-attach', 2, 0),
        ('lockdown-other', 1, 'FAIL lockdown-attach', 2, 0),
        ('lockdown-success', 1, 'FAIL lockdown-attach', 2, 2),
        ('lockdown-load-perm', 0, 'ok lockdown-load', 0, 0),
        ('lockdown-load-access', 0, 'ok lockdown-load', 0, 0),
        ('lockdown-load-bridge', 1, 'FAIL lockdown-load', 0, 0),
        ('lockdown-load-operation', 1, 'FAIL lockdown-load', 0, 0),
        ('lockdown-load-code', 1, 'FAIL lockdown-load', 0, 0),
        ('lockdown-load-other', 1, 'FAIL lockdown-load', 0, 0),
        ('pair-close-error', 1, 'FAIL close-pair', 2, 2)]:
    env = dict(os.environ, LD_PRELOAD=guard, LMB_GATE_CASE=case)
    mode = '--positive' if case == 'pair-close-error' else '--lockdown'
    result = subprocess.run([binary, fixture, mode], env=env,
                            capture_output=True, text=True, timeout=30)
    valid = result.returncode == expected and reason in result.stdout
    valid = valid and f'gate-oracle controls={controls} negatives=0 live=0' in result.stdout
    valid = valid and f'cleanup-oracle closes={closes} object_closes=1 owner_fd_open=0' in result.stdout
    if controls:
        valid = valid and 'control kind=3' in result.stdout and 'control kind=4' in result.stdout
    if closes:
        valid = valid and result.stdout.index('close kind=3') < result.stdout.index('close kind=4')
    if case == 'lockdown-denied':
        valid = valid and 'code=-1 domain=2 operation=10' in result.stdout
        valid = valid and 'code=-13 domain=2 operation=10' in result.stdout
    if case in ('lockdown-load-perm', 'lockdown-load-access'):
        code = -1 if case == 'lockdown-load-perm' else -13
        valid = valid and f'code={code} domain=2 operation=3' in result.stdout
    if case == 'pair-close-error':
        valid = valid and 'ok generic-unload' in result.stdout
    if not valid:
        failures.append(case)
        print(case, 'unexpected exit', result.returncode, result.stdout, result.stderr)
    else:
        print('PASS gate oracle', case, 'native exit', result.returncode)
if failures:
    raise SystemExit(1)
print('NOT_RUN kernel: live-gate logic over guarded API responses only')
