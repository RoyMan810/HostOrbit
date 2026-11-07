"""Check local documentation targets and consistent pinned dependencies."""

from pathlib import Path
import re
import sys
import tomllib
from urllib.parse import unquote, urlsplit


LINK = re.compile(r"\[[^\]]*\]\(([^\s)]+)(?:\s+[^)]*)?\)")
PIN = re.compile(r"([A-Za-z0-9_.-]+)==([^\s;]+)")


def normalized(name):
    return re.sub(r"[-_.]+", "-", name).lower()


def documentation_errors(root):
    root = root.resolve()
    files = set(root.glob("*.md"))
    for folder in ("docs", "evidence", ".github"):
        files.update((root / folder).rglob("*.md"))
    errors = []
    for path in sorted(files):
        for target in LINK.findall(path.read_text(encoding="utf-8")):
            parsed = urlsplit(target.strip("<>"))
            if parsed.scheme or parsed.netloc or not parsed.path:
                continue
            destination = (path.parent / unquote(parsed.path)).resolve()
            if not destination.is_relative_to(root) or not destination.exists():
                errors.append(f"{path.relative_to(root)}: missing local link {target}")
    return errors


def dependency_errors(root):
    versions = {}
    errors = []
    for path in sorted(root.glob("requirements-*.txt")):
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("-r "):
                if not (root / line[3:].strip()).is_file():
                    errors.append(f"{path.name}:{number}: missing requirements include")
                continue
            match = PIN.fullmatch(line)
            if not match:
                errors.append(f"{path.name}:{number}: expected an exact version pin")
                continue
            name, version = normalized(match[1]), match[2]
            if name in versions and versions[name] != version:
                errors.append(f"{path.name}:{number}: conflicting {name} versions")
            versions[name] = version
    project_path = root / "pyproject.toml"
    if project_path.exists():
        project = tomllib.loads(project_path.read_text(encoding="utf-8"))
        for dependency in project.get("project", {}).get("dependencies", []):
            match = PIN.fullmatch(dependency)
            if not match or versions.get(normalized(match[1])) != match[2]:
                errors.append(f"pyproject.toml: dependency differs from pins: {dependency}")
        required = project.get("tool", {}).get("ruff", {}).get("required-version")
        if required and required != "==" + versions.get("ruff", ""):
            errors.append("pyproject.toml: Ruff version differs from quality pin")
    return errors


def main():
    root = Path(__file__).resolve().parents[1]
    errors = documentation_errors(root) + dependency_errors(root)
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    print("Repository documentation links and dependency pins passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
