"""Build an installable development bundle; the Ed25519 private key stays outside it."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tomllib

from nacl.signing import SigningKey

from artifact import FIXED_FILES, IMAGE, canonical


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--signing-key", type=Path, required=True, help="32-byte offline Ed25519 seed; never placed in the bundle")
    parser.add_argument("--python-image", required=True)
    args = parser.parse_args(argv)
    root = Path(__file__).resolve().parents[1]
    if sys.version_info[:2] != (3, 13) or re.fullmatch(IMAGE, args.python_image) is None:
        parser.error("Python 3.13 and an official digest-pinned Python image are required")
    output = args.output.absolute()
    if output.exists() or args.signing_key.resolve().is_relative_to(output):
        parser.error("Output must be new and the signing key must be independent")
    seed = args.signing_key.read_bytes()
    if len(seed) != 32:
        parser.error("The Ed25519 seed must be exactly 32 bytes")
    signer = SigningKey(seed)
    source = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root).decode().strip()
    if subprocess.check_output(["git", "status", "--porcelain", "--untracked-files=no"], cwd=root).strip():
        parser.error("Build from a committed source revision")
    version = tomllib.loads((root / "pyproject.toml").read_text())["project"]["version"]
    output.mkdir(mode=0o700, parents=True)
    wheels = output / "wheelhouse"
    wheels.mkdir()
    subprocess.run([sys.executable, "-m", "pip", "download", "--only-binary=:all:", "--dest", str(wheels),
                    "-r", str(root / "requirements-app.txt")], check=True)
    subprocess.run([sys.executable, "-m", "pip", "wheel", "--no-deps", "--wheel-dir", str(wheels), str(root)], check=True)
    for relative in FIXED_FILES - {"requirements-install.txt", "sbom.cdx.json"}:
        path = output / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(root / relative, path)
    # The bundle carries exactly the resolved binary distributions. pip on the
    # host and in the image installs these bytes with hashes and no index.
    locked, components = [], []
    for path in sorted(wheels.glob("*.whl")):
        name, wheel_version, *_ = path.name.split("-")
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        locked.append(f"{name}=={wheel_version} --hash=sha256:{digest}")
        components.append({"type": "library", "name": name, "version": wheel_version,
                           "purl": f"pkg:pypi/{name.lower().replace('_', '-')}@{wheel_version}",
                           "hashes": [{"alg": "SHA-256", "content": digest}]})
    (output / "requirements-install.txt").write_text("\n".join(locked) + "\n", encoding="utf-8")
    sbom = {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
            "metadata": {"component": {"type": "application", "name": "HostOrbit", "version": version},
                         "properties": [{"name": "hostorbit:scope", "value": "Installed Python wheels plus the pinned OCI base; excludes full OS/base image inventory"}]},
            "components": components + [{"type": "container", "name": args.python_image}]}
    (output / "sbom.cdx.json").write_bytes(canonical(sbom))
    files = [{"path": str(path.relative_to(output)), "size": path.stat().st_size,
              "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
             for path in sorted(output.rglob("*")) if path.is_file()]
    value = {"v": 1, "application": "HostOrbit", "version": version, "channel": "development",
             "source_commit": source, "python_image": args.python_image, "platform": "ubuntu-24.04-amd64",
             "python": "3.13", "sqlite_schema": 2, "remote_mutation_enabled": False, "files": files,
             "signing_key_sha256": hashlib.sha256(bytes(signer.verify_key)).hexdigest()}
    data = canonical(value)
    (output / "manifest.json").write_bytes(data)
    (output / "manifest.sig").write_bytes(signer.sign(data).signature)
    print(json.dumps({"bundle": str(output), "manifest_sha256": hashlib.sha256(data).hexdigest(),
                      "signing_key_sha256": value["signing_key_sha256"], "channel": "development"}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
