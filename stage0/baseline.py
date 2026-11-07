"""Check the authoritative state machines and Stage 0 list against a local baseline."""

import argparse
import hashlib
import json
from pathlib import Path
import re

from .requirements import InvalidRegistry, _read_json, validate


_MACHINES = {
    "Plan": "DRAFT → PREFLIGHTED → AWAITING_APPROVAL → APPROVED → EXECUTION_CLAIMED → CLOSED",
    "Job": "QUEUED → INTENT_PREPARED → DISPATCHING → EXECUTING → VERIFYING → SUCCEEDED | FAILED | UNKNOWN_OUTCOME | CANCELLED_SAFE",
    "Incident": "OPEN → RECONCILING → RECONCILED_SUCCEEDED | RECONCILED_FAILED | QUARANTINED",
    "Host Admission Gate": "NORMAL → QUIESCING → MAINTENANCE → RESUMING → NORMAL",
}


def _stage0_ids(declaration):
    result = set()
    for expression in re.findall(r"`(AC-[^`]+)`", declaration):
        match = re.fullmatch(r"AC-([AB])(\d{2})\.\.\1(\d{2})", expression)
        if match:
            family, first, last = match.groups()
            if int(first) > int(last):
                raise InvalidRegistry("Stage0: reversed acceptance range")
            values = [f"AC-{family}{i:02d}" for i in range(int(first), int(last) + 1)]
        else:
            first, *rest = expression.split("/")
            values = [first] + [f"AC-{item}" for item in rest]
        if len(values) != len(set(values)) or any(
            not re.fullmatch(r"AC-[AB]\d{2}", item) or item in result for item in values
        ):
            raise InvalidRegistry("Stage0: invalid or duplicate acceptance reference")
        result.update(values)
    return result


def check_baseline(markdown: str, data: dict) -> dict:
    registry = validate(data)
    sections = re.findall(r"^## 40\.[^\n]*\n(.*?)(?=^## |\Z)", markdown, re.M | re.S)
    if len(sections) != 1:
        raise InvalidRegistry("baseline: expected exactly one authoritative section 40")
    section = sections[0]
    for name, expected in _MACHINES.items():
        pattern = rf"^\*\*{re.escape(name)}:\*\* `([^`]+)`"
        matches = re.findall(pattern, markdown, re.M)
        scoped = re.findall(pattern, section, re.M)
        if matches != [expected] or scoped != [expected]:
            raise InvalidRegistry(f"baseline: competing or changed {name} definition requires an ADR")
    declarations = re.findall(r"^\*\*Stage0:\*\* ([^\n]+)", markdown, re.M)
    if len(declarations) != 1 or declarations[0] not in section:
        raise InvalidRegistry("baseline: expected a single Stage0 gate in section 40")
    required = _stage0_ids(declarations[0])
    if required != set(registry.gates["Stage0"]["required_tests"]):
        raise InvalidRegistry("baseline: Stage0 criteria differ from the registry")
    if registry.tests.get("AC-28", {}).get("stage") != "Stage2":
        raise InvalidRegistry("baseline: AC-28 must be accepted at Stage2")
    return {
        "outcome": "PASS", "spec_sha256": hashlib.sha256(markdown.encode("utf-8")).hexdigest(),
        "normative_section": 40, "machines": _MACHINES,
        "stage0_required_tests": sorted(required),
        "job_unknown_is_terminal": True, "incident_is_separate": True,
        "scope": "Document and trace validation; does not certify runtime transitions or Owner truthfulness",
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("markdown", type=Path)
    parser.add_argument("registry", type=Path)
    args = parser.parse_args(argv)
    try:
        result = check_baseline(args.markdown.read_text(encoding="utf-8"), _read_json(args.registry))
    except (OSError, UnicodeError, InvalidRegistry) as error:
        parser.exit(1, f"Baseline invalid: {error}\n")
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
