#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Required live-suite status must retain skips and every native outcome."""
import importlib.util
import json
import os
import shlex
import sys
import tempfile
import unittest
from importlib.machinery import SourceFileLoader
from pathlib import Path


class Results(unittest.TestCase):
    def check(self, exits, expected):
        loader=SourceFileLoader('results',str(Path(__file__).resolve().parents[2]/'tools/qualification-results'))
        spec=importlib.util.spec_from_loader(loader.name,loader)
        module=importlib.util.module_from_spec(spec);loader.exec_module(module)
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);(root/'tools').mkdir()
            tool=root/'tools/test'
            tool.write_text('#!/bin/sh\ncase "$1" in\n'+''.join(f'{s}) exit {r};;\n' for s,r in exits.items())+'esac\n')
            tool.chmod(0o755)
            rc=module.run_suites(root,root/'out',list(exits))
            report=json.loads((root/'out/results.json').read_text())
            self.assertEqual(report['status'],expected)
            self.assertEqual(rc,0 if expected=='PASS' else 1)
            self.assertEqual([e['native_exit'] for e in report['lanes']],list(exits.values()))

    def test_all_skips_block(self): self.check(dict(a=77,b=77),'BLOCKED')
    def test_partial_skip_blocks(self): self.check(dict(a=77,b=0),'BLOCKED')
    def test_failure_retains_other_result(self): self.check(dict(a=1,b=0),'FAIL')
    def test_healthy_control(self): self.check(dict(a=0,b=0),'PASS')

class Descendants(unittest.TestCase):
    def test_timeout_reaps_separate_session(self):
        loader=SourceFileLoader('results_owned',str(Path(__file__).resolve().parents[2]/'tools/qualification-results'))
        spec=importlib.util.spec_from_loader(loader.name,loader)
        module=importlib.util.module_from_spec(spec);loader.exec_module(module)
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);(root/'tools').mkdir()
            pidfile=root/'child.pid'
            script="import os,time,pathlib;pathlib.Path(%r).write_text(str(os.getpid()));time.sleep(30)" % str(pidfile)
            tool=root/'tools/test'
            tool.write_text('#!/bin/sh\nsetsid '+shlex.quote(sys.executable)+' -c '+shlex.quote(script)+' &\nwait\n')
            tool.chmod(0o755)
            rc=module.run_suites(root,root/'out',['owned-timeout'],timeouts={'owned-timeout':0.3})
            self.assertEqual(rc,1)
            self.assertFalse((Path('/proc')/pidfile.read_text()).exists())
            receipt=json.loads((root/'out/results.json').read_text())
            self.assertEqual(receipt['lanes'][0]['cleanup']['remaining_owned'],0)



class TermHandler(unittest.TestCase):
    def test_new_detached_child_is_retired_before_continuation(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.check_term(Path(tmp))

    def check_term(self, tmp_path):
        import os, shlex, signal, subprocess, sys
        loader=SourceFileLoader("results_term",str(Path(__file__).resolve().parents[2]/"tools/qualification-results"))
        spec=importlib.util.spec_from_loader(loader.name,loader)
        module=importlib.util.module_from_spec(spec);loader.exec_module(module)
        repo = tmp_path / 'repo'
        (repo / 'tools').mkdir(parents=True)
        childfile = tmp_path / 'term-child.pid'
        later = tmp_path / 'later.started'
        tool = repo / 'tools/test'
        tool.write_text('#!/bin/sh\n'
            'if [ "$1" = later ]; then test ! -e /proc/$(cat ' + shlex.quote(str(childfile)) + ') && touch ' + shlex.quote(str(later)) + '; exit $?; fi\n'
            "trap 'setsid sleep 30 </dev/null >/dev/null 2>&1 & echo $! > " + shlex.quote(str(childfile)) + "; exit 0' TERM\n"
            'while :; do sleep 5; done\n')
        tool.chmod(0o755)
        unrelated = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'])
        try:
            code = module.run_suites(repo, tmp_path / 'out', ['finite', 'later'], {'finite': .2, 'later': 1})
            pid = int(childfile.read_text())
            receipt = json.loads((tmp_path / 'out/results.json').read_text())
            assert code == 1 and receipt['lanes'][0]['timed_out'] is True
            assert not (Path('/proc') / str(pid)).exists()
            assert receipt['lanes'][0]['cleanup']['remaining_owned'] == 0
            assert receipt['lanes'][1]['status'] == 'PASS' and later.exists()
            assert unrelated.poll() is None
        finally:
            if childfile.exists():
                pid = int(childfile.read_text())
                if pid in module._processes():
                    os.kill(pid, signal.SIGKILL)
                try:
                    os.waitpid(pid, 0)
                except ChildProcessError:
                    pass
            unrelated.kill()
            unrelated.wait()

    def test_uncertain_cleanup_blocks_later_lane(self):
        from unittest.mock import patch
        loader=SourceFileLoader('results_uncertain',str(Path(__file__).resolve().parents[2]/'tools/qualification-results'))
        spec=importlib.util.spec_from_loader(loader.name,loader)
        module=importlib.util.module_from_spec(spec);loader.exec_module(module)
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);(root/'tools').mkdir()
            later=root/'later.started'
            tool=root/'tools/test'
            tool.write_text('#!/bin/sh\nif [ "$1" = later ]; then touch '+str(later)+'; else sleep 30; fi\n')
            tool.chmod(0o755)
            terminate=module._terminate_owned
            def uncertain(proc, prior):
                result=terminate(proc, prior)
                result['signal_errors']=1
                return result
            with patch.object(module, '_terminate_owned', uncertain):
                self.assertEqual(module.run_suites(root,root/'out',['finite','later'],{'finite':.2}),1)
            receipt=json.loads((root/'out/results.json').read_text())
            self.assertEqual(receipt['lanes'][1]['status'],'BLOCKED')
            self.assertFalse(later.exists())

if __name__=='__main__':unittest.main()
