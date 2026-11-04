from pathlib import Path
import subprocess
import re
import json
import os
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]

class BundleSmoke(unittest.TestCase):
    def test_shell_syntax(self):
        for path in [ROOT/'install.sh',ROOT/'lib/common.sh',ROOT/'lib/backup-node.sh',ROOT/'monitor-kit/install.sh',ROOT/'monitor-kit/lib/sender.sh']:
            subprocess.run(['bash','-n',str(path)],check=True)

    def test_help_is_readonly(self):
        r=subprocess.run(['bash',str(ROOT/'install.sh'),'help'],capture_output=True,text=True,check=True)
        self.assertIn('wizard',r.stdout)
        self.assertIn('monitor foreign',r.stdout)

    def test_monitor_py_compiles(self):
        for path in [ROOT/'monitor-kit/lib/monitor.py',ROOT/'monitor-kit/lib/receiver.py']:
            subprocess.run(['python3','-m','py_compile',str(path)],check=True)

    def test_panel_compose_validation(self):
        with tempfile.TemporaryDirectory() as tmp:
            base=Path(tmp)
            bindir=base/'bin'; bindir.mkdir()
            stub=bindir/'docker'
            stub.write_text("""#!/bin/sh
if [ "$*" = "compose config -q" ]; then exit 0; fi
if [ "$*" = "compose config --format json" ]; then cat "$COMPOSE_FIXTURE"; exit 0; fi
exit 2
""")
            stub.chmod(0o755)
            fixture=base/'compose.json'
            doc={'services':{'remnanode':{
                'image':'remnawave/node:latest',
                'network_mode':'host',
                'environment':{'NODE_PORT':'2222','SECRET_KEY':'FAKE_TEST_ONLY'},
            }}}
            fixture.write_text(json.dumps(doc))
            env=dict(os.environ,PATH=str(bindir)+os.pathsep+os.environ.get('PATH',''),COMPOSE_FIXTURE=str(fixture))
            cmd=['bash','-c','source "$1"; validate_compose "$2" "$3"','bash',str(ROOT/'install.sh'),tmp,'2222']
            p=subprocess.run(cmd,capture_output=True,text=True,env=env)
            self.assertEqual(p.returncode,0,p.stderr)
            self.assertIn('validated',p.stdout)
            self.assertNotIn('FAKE_TEST_ONLY',p.stdout)
            p=subprocess.run(cmd[:-1]+['2223'],capture_output=True,text=True,env=env)
            self.assertNotEqual(p.returncode,0)
            self.assertIn('mismatch',p.stderr)
            doc['services']['remnanode']['image']='malicious/example:latest'
            fixture.write_text(json.dumps(doc))
            p=subprocess.run(cmd,capture_output=True,text=True,env=env)
            self.assertNotEqual(p.returncode,0)
            self.assertIn('official remnawave/node',p.stderr)

    def test_no_sensitive_actual_bot_token_in_package(self):
        for path in ROOT.rglob('*'):
            if path.is_file() and path.suffix in ('.sh','.md','.txt','.py','.yml','.json'):
                data=path.read_text(errors='ignore')
                self.assertIsNone(re.search(r'\b\d{8,12}:[A-Za-z0-9_-]{30,}\b',data),path)

if __name__=='__main__': unittest.main()
