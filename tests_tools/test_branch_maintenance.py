from copy import deepcopy
from pathlib import Path
import subprocess
import tempfile
import unittest

from tools.prune_merged_branches import candidates, delete_branches


REPOSITORY = "RoyMan810/HostOrbit"


def fixture():
    branch = {"name": "chore/finished", "commit": {"sha": "a" * 40}, "protected": False}
    pr = {"number": 7, "merged_at": "2026-11-07T10:00:00Z", "merge_commit_sha": "b" * 40,
          "head": {"ref": branch["name"], "sha": "a" * 40, "repo": {"full_name": REPOSITORY}},
          "base": {"ref": "main", "repo": {"full_name": REPOSITORY}}}
    return branch, pr


class BranchMaintenanceTests(unittest.TestCase):
    def select(self, branch, pr, opened=(), contains=lambda sha: True):
        return candidates([branch], [pr], opened, repository=REPOSITORY, default="main", contains=contains)

    def test_only_unchanged_merged_temporary_branch_is_selected(self):
        branch, pr = fixture()
        self.assertEqual(self.select(branch, pr), [{"name": "chore/finished", "sha": "a" * 40, "pr": 7}])
        branch["commit"]["sha"] = "c" * 40
        self.assertEqual(self.select(branch, pr), [])

    def test_default_protected_and_long_lived_branches_are_preserved(self):
        for change in ({"name": "main"}, {"protected": True}, {"name": "release"}):
            branch, pr = fixture()
            branch.update(change)
            with self.subTest(change=change):
                self.assertEqual(self.select(branch, pr), [])

    def test_unmerged_foreign_missing_and_unreachable_merge_are_preserved(self):
        branch, original = fixture()
        for change in ({"merged_at": None}, {"merge_commit_sha": None},
                       {"head": {**original["head"], "repo": {"full_name": "someone/fork"}}}):
            pr = deepcopy(original)
            pr.update(change)
            with self.subTest(change=change):
                self.assertEqual(self.select(branch, pr), [])
        self.assertEqual(self.select(branch, original, contains=lambda sha: False), [])

    def test_open_pr_blocks_deletion_even_when_an_older_pr_was_merged(self):
        branch, pr = fixture()
        self.assertEqual(self.select(branch, pr, opened=[pr]), [])

    def test_token_cannot_be_sent_to_a_non_github_remote(self):
        with self.assertRaises(ValueError):
            delete_branches([{"name": "chore/finished", "sha": "a" * 40}],
                            remote="https://example.org/remote.git", token="fixture-only")

    def test_real_git_lease_preserves_a_branch_changed_after_review(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            remote, work = root / "remote.git", root / "work"

            def git(*args):
                return subprocess.check_output(["git", *args], cwd=work if work.exists() else root,
                                               stderr=subprocess.DEVNULL, text=True).strip()

            git("init", "--bare", str(remote))
            git("init", "-b", "main", str(work))
            git("config", "user.email", "fixture@example.invalid")
            git("config", "user.name", "Fixture")
            git("commit", "--allow-empty", "-m", "base")
            reviewed = git("rev-parse", "HEAD")
            git("push", str(remote), "HEAD:refs/heads/chore/finished")
            git("commit", "--allow-empty", "-m", "new work after review")
            latest = git("rev-parse", "HEAD")
            git("push", str(remote), "HEAD:refs/heads/chore/finished")
            with self.assertRaises(subprocess.CalledProcessError):
                delete_branches([{"name": "chore/finished", "sha": reviewed}], remote=str(remote), cwd=work)
            self.assertIn(latest, git("ls-remote", str(remote), "refs/heads/chore/finished"))
            delete_branches([{"name": "chore/finished", "sha": latest}], remote=str(remote), cwd=work)
            self.assertEqual(git("ls-remote", str(remote), "refs/heads/chore/finished"), "")
