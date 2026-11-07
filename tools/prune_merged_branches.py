"""Remove unchanged, merged temporary branches; default mode only lists them."""

import argparse
import base64
import json
import os
import re
import subprocess
import urllib.request


TEMPORARY = re.compile(r"(?:codex|chore|feat|feature|fix|docs|test|dependabot)/[A-Za-z0-9][A-Za-z0-9._/-]{0,200}")
SHA = re.compile(r"[0-9a-f]{40}")


def candidates(branches, closed, opened, *, repository, default, contains):
    active = {p["head"]["ref"] for p in opened if p["head"]["repo"]
              and p["head"]["repo"]["full_name"] == repository}
    result = []
    for branch in branches:
        name, sha = branch["name"], branch["commit"]["sha"]
        if (name == default or branch.get("protected") is not False or name in active
                or not TEMPORARY.fullmatch(name) or not SHA.fullmatch(sha)):
            continue
        for pr in closed:
            head, base = pr["head"], pr["base"]
            merge = pr.get("merge_commit_sha")
            if (pr.get("merged_at") and head["repo"] and head["repo"]["full_name"] == repository
                    and base["repo"]["full_name"] == repository and base["ref"] == default
                    and head["ref"] == name and head["sha"] == sha
                    and isinstance(merge, str) and SHA.fullmatch(merge) and contains(merge)):
                result.append({"name": name, "sha": sha, "pr": pr["number"]})
                break
    return sorted(result, key=lambda item: item["name"])


def delete_branches(selected, *, remote, token=None, cwd=None):
    if not selected:
        return
    env = dict(os.environ, GIT_TERMINAL_PROMPT="0")
    if token:
        if not re.fullmatch(r"https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\.git", remote):
            raise ValueError("Token authentication is restricted to GitHub HTTPS")
        authorization = base64.b64encode(("x-access-token:" + token).encode()).decode()
        env.update(GIT_CONFIG_COUNT="1", GIT_CONFIG_KEY_0="http.https://github.com/.extraheader",
                   GIT_CONFIG_VALUE_0="AUTHORIZATION: basic " + authorization)
    leases = [f"--force-with-lease=refs/heads/{item['name']}:{item['sha']}" for item in selected]
    refs = [f":refs/heads/{item['name']}" for item in selected]
    subprocess.run(["git", "push", "--atomic", "--porcelain", *leases, remote, *refs],
                   check=True, env=env, cwd=cwd, timeout=60)


class GitHub:
    def __init__(self, repository, token):
        self.base = "https://api.github.com/repos/" + repository
        self.token = token

    def get(self, path):
        headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
        if self.token:
            headers["Authorization"] = "Bearer " + self.token
        request = urllib.request.Request(self.base + path, headers=headers)
        with urllib.request.urlopen(request, timeout=20) as response:
            return json.load(response)

    def pages(self, path):
        result = []
        for page in range(1, 101):
            batch = self.get(path + ("&" if "?" in path else "?") + f"per_page=100&page={page}")
            result.extend(batch)
            if len(batch) < 100:
                return result
        raise RuntimeError("Pagination limit reached; no branches deleted")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", default=os.environ.get("GITHUB_REPOSITORY"))
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    if not args.repository or not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", args.repository):
        parser.error("Expected owner/repository")
    token = os.environ.get("GH_TOKEN")
    if args.apply and not token:
        parser.error("Apply requires the repository-scoped job token")
    api = GitHub(args.repository, token)
    default = api.get("")["default_branch"]

    def contains(commit):
        return subprocess.run(["git", "merge-base", "--is-ancestor", commit, "HEAD"],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10).returncode == 0

    selected = candidates(api.pages("/branches"), api.pages("/pulls?state=closed"),
                          api.pages("/pulls?state=open"), repository=args.repository,
                          default=default, contains=contains)
    print(json.dumps({"mode": "apply" if args.apply else "dry-run", "branches": selected}, indent=2), flush=True)
    if args.apply:
        delete_branches(selected, remote=f"https://github.com/{args.repository}.git", token=token)
        remaining = {item["name"] for item in api.pages("/branches")}
        if any(item["name"] in remaining for item in selected):
            raise RuntimeError("Branch deletion could not be verified")
        print(f"Verified deletion of {len(selected)} merged branches", flush=True)


if __name__ == "__main__":
    main()
