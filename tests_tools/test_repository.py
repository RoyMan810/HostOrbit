from pathlib import Path
import tempfile
import unittest

from tools.check_repository import dependency_errors, documentation_errors


class RepositoryChecks(unittest.TestCase):
    def test_local_link_missing_target_and_path_escape_are_errors(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "docs").mkdir()
            (root / "docs" / "guide.md").write_text("# Guide\n")
            page = root / "README.md"
            page.write_text("[Guide](docs/guide.md#guide) [Web](https://example.org)\n")
            self.assertEqual(documentation_errors(root), [])
            page.write_text("[Missing](docs/missing.md) [Escape](../outside.md)\n")
            self.assertEqual(len(documentation_errors(root)), 2)

    def test_conflicting_and_unpinned_dependencies_and_missing_includes_fail(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "requirements-app.txt").write_text("example==1.0\n")
            dev = root / "requirements-dev.txt"
            dev.write_text("-r requirements-app.txt\nexample==1.0\n")
            self.assertEqual(dependency_errors(root), [])
            dev.write_text("example==2.0\nunpinned\n-r missing.txt\n")
            self.assertEqual(len(dependency_errors(root)), 3)

    def test_project_dependencies_and_linter_version_must_match_pins(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "requirements-app.txt").write_text("example==1.0\nruff==0.17.3\n")
            (root / "pyproject.toml").write_text(
                '[project]\ndependencies = ["example==2.0"]\n'
                '[tool.ruff]\nrequired-version = "==0.1.0"\n')
            self.assertEqual(len(dependency_errors(root)), 2)
