"""Validate the v2.3 Requirements Registry and evaluate its evidence-based gates."""

import argparse
from dataclasses import dataclass
from datetime import datetime, timedelta
from graphlib import CycleError, TopologicalSorter
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import sys


_STAGES = tuple(f"Stage{number}" for number in range(6))
_MVP = {"MVP", "MVP/BLOCKED", "MVP/PAUSED"}
_POST = {"POST", "POST/OPTIONAL"}
_KINDS = {
    "FUNCTIONAL": r"FR-\d{3}\.\d+",
    "NON_FUNCTIONAL": r"NFR-\d{2}",
    "SAFETY": r"P0-\d+",
    "CONTROL": r"CTRL-B\d{2}",
}
_OUTCOMES = {"NOT_RUN", "PASS", "FAIL"}
_STATES = {"DESIGNED", "IMPLEMENTED", "TESTED_PASS", "TESTED_FAIL", "ACCEPTED"}
_EVIDENCE_DIGESTS = ("build_digest", "manifest_digest", "sbom_digest", "evidence_digest")
_EVIDENCE_TEXT = ("environment", "initial_state", "scenario", "fault_injection", "observation", "reviewer")


class InvalidRegistry(ValueError):
    pass


def _text(record, field, location):
    value = record.get(field)
    if not isinstance(value, str) or not value.strip():
        raise InvalidRegistry(f"{location}.{field}: expected nonempty text")
    return value


def _choice(record, field, choices, location):
    value = _text(record, field, location)
    if value not in choices:
        raise InvalidRegistry(f"{location}.{field}: unsupported value {value!r}")
    return value


def _references(record, field, location, *, allow_empty=False):
    values = record.get(field)
    if not isinstance(values, list) or (not values and not allow_empty):
        raise InvalidRegistry(f"{location}.{field}: expected a list of references")
    if any(not isinstance(value, str) or not value.strip() for value in values):
        raise InvalidRegistry(f"{location}.{field}: invalid reference")
    if len(values) != len(set(values)):
        raise InvalidRegistry(f"{location}.{field}: duplicate reference")
    return values


def _evidence_path(record, location):
    value = _text(record, "evidence_path", location)
    parts = value.split("/")
    if (
        len(parts) < 2 or parts[0] != "evidence"
        or any(part in (".", "..") or not re.fullmatch(r"[a-zA-Z0-9_.-]+", part) for part in parts)
        or PurePosixPath(value).suffix != ".json"
    ):
        raise InvalidRegistry(f"{location}.evidence_path: expected a relative evidence JSON path")
    return value


def _index(registry, field):
    entries = registry.get(field)
    if not isinstance(entries, list) or not entries:
        raise InvalidRegistry(f"{field}: expected records")
    records = {}
    for index, item in enumerate(entries):
        location = f"{field}[{index}]"
        if not isinstance(item, dict):
            raise InvalidRegistry(f"{location}: expected an object")
        identifier = _text(item, "id", location)
        if identifier in records:
            raise InvalidRegistry(f"{field}: duplicate ID {identifier}")
        records[identifier] = item
    return records


def _unique_object(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise InvalidRegistry(f"duplicate JSON field {key!r}")
        obj[key] = value
    return obj


def _read_json(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_unique_object)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise InvalidRegistry(f"{path.name}: {error}") from None


@dataclass(frozen=True)
class Registry:
    requirements: dict[str, dict]
    tests: dict[str, dict]
    gates: dict[str, dict]

    def blockers(self, stage: str, evidence_root: Path) -> list[str]:
        gate = self.gates[stage]
        if stage == "Stage1":
            result = []
            for capability in gate["required_capabilities"]:
                try:
                    _check_capability_evidence(evidence_root, capability)
                except InvalidRegistry as error:
                    result.append(f"{capability}: {error}")
            return result
        if stage in ("Stage0", "Stage2"):
            test_ids = set(gate["required_tests"])
        elif stage == "Stage3":
            releases = set(gate["required_requirement_release"])
            test_ids = {
                test_id
                for item in self.requirements.values()
                if item["release_inclusion"] in releases
                for test_id in item["acceptance_ids"]
            }
        else:
            raise ValueError(f"{stage} has no test-based gate in this validator")

        result = []
        for test_id in sorted(test_ids):
            test = self.tests[test_id]
            if test["status"] != "PASS":
                result.append(f"{test_id}: {test['status']}")
                continue
            try:
                _check_evidence(evidence_root, test)
            except InvalidRegistry as error:
                result.append(f"{test_id}: {error}")
        return result


def validate(data) -> Registry:
    if not isinstance(data, dict) or data.get("schema_version") != "1.0":
        raise InvalidRegistry("unsupported registry schema_version")
    for field in ("spec", "generated_from", "status"):
        _text(data, field, "registry")
    requirements, tests = _index(data, "requirements"), _index(data, "tests")
    for identifier, item in requirements.items():
        kind = _choice(item, "kind", _KINDS, identifier)
        if not re.fullmatch(_KINDS[kind], identifier):
            raise InvalidRegistry(f"{identifier}: ID does not match {kind}")
        release = _choice(item, "release_inclusion", _MVP | _POST, identifier)
        stage = _choice(item, "stage", _STAGES, identifier)
        if (stage in _STAGES[4:]) != (release in _POST):
            raise InvalidRegistry(f"{identifier}: stage and release_inclusion disagree")
        for field in ("description", "owner"):
            _text(item, field, identifier)
        _choice(item, "state", _STATES, identifier)
        _choice(item, "evidence_status", _OUTCOMES, identifier)
        _evidence_path(item, identifier)
        _references(item, "acceptance_ids", identifier)
        _references(item, "dependencies", identifier, allow_empty=True)

    test_paths = set()
    for identifier, item in tests.items():
        if not re.fullmatch(r"AC-[AB]?\d{2}", identifier):
            raise InvalidRegistry(f"{identifier}: invalid acceptance ID")
        _choice(item, "stage", _STAGES, identifier)
        _choice(item, "status", _OUTCOMES, identifier)
        for field in ("assertion", "owner"):
            _text(item, field, identifier)
        path = _evidence_path(item, identifier)
        if path in test_paths:
            raise InvalidRegistry(f"{identifier}: duplicate test evidence_path")
        test_paths.add(path)
        _references(item, "linked_requirements", identifier)

    for identifier, item in requirements.items():
        for test_id in item["acceptance_ids"]:
            if test_id not in tests or identifier not in tests[test_id]["linked_requirements"]:
                raise InvalidRegistry(f"{identifier}: missing reciprocal test {test_id}")
        for dep_id in item["dependencies"]:
            dependency = requirements.get(dep_id)
            if dependency is None:
                raise InvalidRegistry(f"{identifier}: unknown dependency {dep_id}")
            if (
                _STAGES.index(dependency["stage"]) > _STAGES.index(item["stage"])
                or (item["release_inclusion"] == "MVP" and dependency["release_inclusion"] != "MVP")
            ):
                raise InvalidRegistry(f"{identifier}: unreachable dependency {dep_id}")
    for identifier, item in tests.items():
        for requirement_id in item["linked_requirements"]:
            if requirement_id not in requirements or identifier not in requirements[requirement_id]["acceptance_ids"]:
                raise InvalidRegistry(f"{identifier}: missing reciprocal requirement {requirement_id}")
    try:
        tuple(TopologicalSorter({key: item["dependencies"] for key, item in requirements.items()}).static_order())
    except CycleError as error:
        raise InvalidRegistry(f"dependency cycle: {' → '.join(error.args[1])}") from None

    gates = data.get("stage_gates")
    if not isinstance(gates, dict) or gates.keys() != set(_STAGES):
        raise InvalidRegistry("stage_gates: expected exactly Stage0 through Stage5")
    for stage, gate in gates.items():
        if not isinstance(gate, dict):
            raise InvalidRegistry(f"{stage}: expected a gate object")
        field = {
            "Stage0": "required_tests",
            "Stage1": "required_capabilities",
            "Stage2": "required_tests",
        }.get(stage, "required_requirement_release")
        if gate.keys() != {"description", field}:
            raise InvalidRegistry(f"{stage}: expected description and {field}")
        _text(gate, "description", stage)
        if stage in ("Stage0", "Stage2"):
            required = _references(gate, "required_tests", stage)
            for identifier in required:
                if identifier not in tests or tests[identifier]["stage"] != stage:
                    raise InvalidRegistry(f"{stage}: test {identifier} belongs to another or unknown stage")
            controls = {
                test_id
                for item in requirements.values()
                if item["stage"] == stage and item["kind"] == "CONTROL"
                for test_id in item["acceptance_ids"]
                if tests[test_id]["stage"] == stage
            }
            if not controls.issubset(required):
                raise InvalidRegistry(f"{stage}: missing control tests {', '.join(sorted(controls - set(required)))}")
        elif stage == "Stage1":
            _references(gate, "required_capabilities", stage)
        else:
            releases = set(_references(gate, "required_requirement_release", stage))
            expected = {"Stage3": _MVP, "Stage4": _POST, "Stage5": {"POST"}}[stage]
            if releases != expected:
                raise InvalidRegistry(f"{stage}: incomplete or invalid release selection")
    return Registry(requirements, tests, gates)


def evidence_digest(report: dict) -> str:
    payload = {key: value for key, value in report.items() if key != "evidence_digest"}
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _check_evidence(root: Path, test: dict) -> None:
    root = root.resolve()
    path = (root / test["evidence_path"]).resolve()
    if not path.is_relative_to(root / "evidence"):
        raise InvalidRegistry("evidence path escaped its root")
    if not path.is_file():
        raise InvalidRegistry("PASS without an evidence report")
    report = _read_json(path)
    if not isinstance(report, dict) or report.get("test_id") != test["id"] or report.get("outcome") != "PASS":
        raise InvalidRegistry("evidence does not identify this passing test")
    for field in _EVIDENCE_TEXT:
        _text(report, field, "evidence")
    for field in _EVIDENCE_DIGESTS:
        if not re.fullmatch(r"[0-9a-f]{64}", _text(report, field, "evidence")):
            raise InvalidRegistry(f"evidence.{field}: expected SHA-256")
    time = _text(report, "recorded_at_utc", "evidence")
    try:
        timestamp = datetime.fromisoformat(time)
        digest = evidence_digest(report)
    except (ValueError, UnicodeError):
        raise InvalidRegistry("invalid evidence time or encoding") from None
    if timestamp.utcoffset() != timedelta(0) or digest != report["evidence_digest"]:
        raise InvalidRegistry("evidence time or digest does not match")


def _check_capability_evidence(root: Path, capability: str) -> None:
    """Use the canonical Stage1 capability gate, without promoting full MVP AC.

    Reports describe Foundation-only assertions. Their checked source files and
    evidence artifacts must still match; a count of green jobs alone is not a
    capability report. Revalidation is required after changing this code scope.
    """
    if re.fullmatch(r"[a-z][a-z0-9_]{0,63}", capability) is None:
        raise InvalidRegistry("unsafe capability ID")
    current = Path("evidence/revalidation/stage1-current")
    if (root / current).exists() or (root / current).is_symlink():
        path = current / f"{capability}.json"
    else:
        path = Path(f"evidence/capabilities/stage1/{capability}.json")
    descriptor = {"id": "Stage1." + capability, "evidence_path": str(path)}
    _check_evidence(root, descriptor)
    root = root.resolve()
    report = _read_json(root / descriptor["evidence_path"])
    if report.get("capability") != capability or report.get("stage") != "Stage1" or report.get("scope") != "FOUNDATION_ONLY":
        raise InvalidRegistry("capability report scope/binding is invalid")
    for field in ("positive_checks", "negative_checks", "limitations"):
        _references(report, field, "capability evidence")
    source_files = report.get("source_files")
    artifacts = report.get("artifacts")
    if not isinstance(source_files, list) or not source_files:
        raise InvalidRegistry("missing capability source files")
    if not isinstance(artifacts, list) or len(artifacts) < 3:
        raise InvalidRegistry("missing manifest/SBOM/CI evidence artifacts")
    for record in source_files + artifacts:
        if not isinstance(record, dict) or set(record) != {"path", "sha256"}:
            raise InvalidRegistry("invalid capability evidence file record")
        relative = record["path"]
        if (not isinstance(relative, str) or not relative or PurePosixPath(relative).is_absolute()
                or ".." in PurePosixPath(relative).parts or "\\" in relative
                or not isinstance(record["sha256"], str) or re.fullmatch(r"[0-9a-f]{64}", record["sha256"]) is None):
            raise InvalidRegistry("unsafe capability evidence file record")
        path = (root / relative).resolve()
        if not path.is_relative_to(root) or not path.is_file():
            raise InvalidRegistry("capability evidence file is unavailable")
        if hashlib.sha256(path.read_bytes()).hexdigest() != record["sha256"]:
            raise InvalidRegistry("capability source/artifact digest changed")
    if report["manifest_digest"] not in {item["sha256"] for item in artifacts} or report["sbom_digest"] not in {item["sha256"] for item in artifacts}:
        raise InvalidRegistry("manifest/SBOM evidence binding is missing")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("registry", type=Path)
    parser.add_argument("--gate", choices=("Stage0", "Stage1", "Stage2", "Stage3"))
    parser.add_argument("--evidence-root", type=Path)
    args = parser.parse_args(argv)
    try:
        registry = validate(_read_json(args.registry))
    except InvalidRegistry as error:
        print(f"Invalid registry: {error}", file=sys.stderr)
        return 1
    print(f"Registry valid: {len(registry.requirements)} requirements, {len(registry.tests)} tests")
    if args.gate:
        blockers = registry.blockers(args.gate, args.evidence_root or args.registry.parent)
        if blockers:
            print(f"{args.gate} blocked ({len(blockers)}):", file=sys.stderr)
            for reason in blockers:
                print(f"  {reason}", file=sys.stderr)
            return 2
        print(f"{args.gate} passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
