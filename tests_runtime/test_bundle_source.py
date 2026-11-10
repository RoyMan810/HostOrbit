from pathlib import Path
import subprocess
import tempfile
import unittest

from deploy.build_bundle import committed_source, wheel_lock


class BundleSourceTests(unittest.TestCase):
    def test_git_export_excludes_untracked_and_worktree_changes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            subprocess.run(['git', 'init', '-q', str(root)], check=True)
            subprocess.run(['git', '-C', str(root), 'config', 'user.name', 'fixture'], check=True)
            subprocess.run(['git', '-C', str(root), 'config', 'user.email', 'fixture@example.invalid'], check=True)
            (root / 'app.py').write_text('committed')
            subprocess.run(['git', '-C', str(root), 'add', 'app.py'], check=True)
            subprocess.run(['git', '-C', str(root), 'commit', '-qm', 'fixture'], check=True)
            commit = subprocess.check_output(['git', '-C', str(root), 'rev-parse', 'HEAD'], text=True).strip()
            (root / 'app.py').write_text('changed')
            (root / 'untracked.py').write_text('untracked')
            with committed_source(root, commit) as tree:
                self.assertEqual((tree / 'app.py').read_text(), 'committed')
                self.assertFalse((tree / 'untracked.py').exists())

    def test_dependency_lock_must_cover_every_exact_pin_with_hashes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'deploy').mkdir()
            (root / 'requirements-app.txt').write_text('example==1.0\n')
            lock = root / 'deploy/requirements-wheels.lock'
            lock.write_text('example==1.0 --hash=sha256:' + 'a' * 64 + '\n')
            self.assertEqual(wheel_lock(root), lock)
            for text in ('example==1.1 --hash=sha256:' + 'a' * 64, 'example==1.0', ''):
                lock.write_text(text + '\n')
                with self.subTest(text=text), self.assertRaisesRegex(ValueError, 'WHEEL_LOCK_MISMATCH'):
                    wheel_lock(root)


if __name__ == '__main__':
    unittest.main()
