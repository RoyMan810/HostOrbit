from contextlib import redirect_stderr, redirect_stdout
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest

from stage0.requirements import InvalidRegistry, evidence_digest, main, validate


def fixture():
    def requirement(identifier, kind, stage, test_id, release="MVP"):
        return {
            "id": identifier, "kind": kind, "description": "Fixture requirement",
            "release_inclusion": release, "stage": stage, "owner": "Fixture",
            "acceptance_ids": [test_id], "evidence_path": f"evidence/req/{identifier}.json",
            "state": "DESIGNED", "evidence_status": "NOT_RUN", "dependencies": [],
        }

    def acceptance(identifier, stage, linked):
        return {
            "id": identifier, "stage": stage, "owner": "Fixture", "assertion": "Expected result",
            "evidence_path": f"evidence/tests/{identifier}.json", "status": "NOT_RUN",
            "linked_requirements": [linked],
        }

    return {
        "schema_version": "1.0",
        "spec": "Fixture",
        "generated_from": "Fixture",
        "status": "DESIGNED_NOT_TESTED",
        "requirements": [
            requirement("CTRL-B03", "CONTROL", "Stage0", "AC-B03"),
            requirement("FR-003.1", "FUNCTIONAL", "Stage2", "AC-28"),
            requirement("FR-003.2", "FUNCTIONAL", "Stage4", "AC-29", "POST/OPTIONAL"),
        ],
        "tests": [
            acceptance("AC-B03", "Stage0", "CTRL-B03"),
            acceptance("AC-28", "Stage2", "FR-003.1"),
            acceptance("AC-29", "Stage4", "FR-003.2"),
        ],
        "stage_gates": {
            "Stage0": {"required_tests": ["AC-B03"], "description": "Prototype"},
            "Stage1": {"required_capabilities": ["auth"], "description": "Foundation"},
            "Stage2": {"required_tests": ["AC-28"], "description": "Vertical slice"},
            "Stage3": {"required_requirement_release": ["MVP", "MVP/BLOCKED", "MVP/PAUSED"], "description": "Release"},
            "Stage4": {"required_requirement_release": ["POST", "POST/OPTIONAL"], "description": "Extensions"},
            "Stage5": {"required_requirement_release": ["POST"], "description": "Extensions"},
        },
    }


def passing_report(test_id):
    report = {
        "test_id": test_id, "outcome": "PASS",
        "build_digest": "a" * 64, "manifest_digest": "b" * 64, "sbom_digest": "c" * 64,
        "environment": "Ubuntu lab", "initial_state": "Empty fixture",
        "scenario": "Submit substitute", "fault_injection": "Changed ciphertext",
        "observation": "Substitute rejected", "recorded_at_utc": "2026-01-01T10:00:00Z",
        "reviewer": "Fixture reviewer",
    }
    report["evidence_digest"] = evidence_digest(report)
    return report


class RegistryTests(unittest.TestCase):
    def setUp(self):
        self.directory = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.data = fixture()

    def write_report(self, test, report):
        path = self.directory / test["evidence_path"]
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(report), encoding="utf-8")

    def test_checks_all_required_trace_fields(self):
        for section, field in (
            ("requirements", "description"),
            ("requirements", "stage"),
            ("requirements", "release_inclusion"),
            ("requirements", "dependencies"),
            ("requirements", "owner"),
            ("requirements", "acceptance_ids"),
            ("requirements", "evidence_path"),
            ("tests", "owner"),
            ("tests", "assertion"),
            ("tests", "stage"),
            ("tests", "linked_requirements"),
        ):
            with self.subTest(field=field):
                data = fixture()
                del data[section][0][field]
                with self.assertRaisesRegex(InvalidRegistry, f"\\.{field}:"):
                    validate(data)

    def test_reciprocal_trace_and_unique_ids(self):
        self.data["tests"][0]["linked_requirements"] = ["FR-003.1"]
        with self.assertRaisesRegex(InvalidRegistry, "missing reciprocal test AC-B03"):
            validate(self.data)
        self.data = fixture()
        self.data["requirements"].append(self.data["requirements"][0])
        with self.assertRaisesRegex(InvalidRegistry, "duplicate ID CTRL-B03"):
            validate(self.data)

    def test_unknown_later_or_cyclic_dependencies_fail(self):
        item = self.data["requirements"][0]
        for dependency, expected in (
            ("FR-999.1", "unknown dependency"),
            ("FR-003.1", "unreachable dependency"),
            ("CTRL-B03", "dependency cycle"),
        ):
            with self.subTest(dependency=dependency):
                item["dependencies"] = [dependency]
                with self.assertRaisesRegex(InvalidRegistry, expected):
                    validate(self.data)
        item["dependencies"] = []
        self.data["requirements"][1]["dependencies"] = ["CTRL-B03"]
        validate(self.data)

    def test_detects_ac28_stage_drift_and_competing_gate_shape(self):
        self.data["tests"][1]["stage"] = "Stage1"
        with self.assertRaisesRegex(InvalidRegistry, "Stage2: test AC-28 belongs"):
            validate(self.data)
        self.data["tests"][1]["stage"] = "Stage2"
        self.data["stage_gates"]["Stage0"]["required_capabilities"] = ["second-gate"]
        with self.assertRaisesRegex(InvalidRegistry, "Stage0: expected description and required_tests"):
            validate(self.data)

    def test_omitting_a_mandatory_stage0_control_is_detected(self):
        test = self.data["tests"][1]
        test["stage"] = "Stage0"
        self.data["stage_gates"]["Stage0"]["required_tests"] = ["AC-28"]
        with self.assertRaisesRegex(InvalidRegistry, "Stage0: missing control tests AC-B03"):
            validate(self.data)

    def test_gate_blocks_fail_or_not_run_and_does_not_require_post_mvp(self):
        self.data["tests"][1]["status"] = "FAIL"
        registry = validate(self.data)
        self.assertEqual(registry.blockers("Stage0", self.directory), ["AC-B03: NOT_RUN"])
        self.assertEqual(registry.blockers("Stage2", self.directory), ["AC-28: FAIL"])
        self.assertEqual(registry.blockers("Stage3", self.directory), ["AC-28: FAIL", "AC-B03: NOT_RUN"])
        self.data["stage_gates"]["Stage3"]["required_requirement_release"] = ["MVP"]
        with self.assertRaisesRegex(InvalidRegistry, "incomplete or invalid release"):
            validate(self.data)

    def test_pass_requires_evidence_and_verified_digest(self):
        test = self.data["tests"][0]
        test["status"] = "PASS"
        registry = validate(self.data)
        self.assertEqual(registry.blockers("Stage0", self.directory), ["AC-B03: PASS without an evidence report"])
        report = passing_report(test["id"])
        self.write_report(test, report)
        self.assertEqual(registry.blockers("Stage0", self.directory), [])
        report["observation"] = "Altered after review"
        self.write_report(test, report)
        self.assertEqual(registry.blockers("Stage0", self.directory), ["AC-B03: evidence time or digest does not match"])

    def test_evidence_symlink_cannot_escape(self):
        test = self.data["tests"][0]
        test["status"] = "PASS"
        actual = self.directory / "outside.json"
        actual.write_text(json.dumps(passing_report(test["id"])), encoding="utf-8")
        link = self.directory / test["evidence_path"]
        link.parent.mkdir(parents=True)
        link.symlink_to(actual)
        self.assertEqual(validate(self.data).blockers("Stage0", self.directory), ["AC-B03: evidence path escaped its root"])

    def test_cli_distinguishes_invalid_and_blocked(self):
        path = self.directory / "registry.json"
        path.write_text(json.dumps(self.data), encoding="utf-8")
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            self.assertEqual(main([str(path)]), 0)
            self.assertEqual(main([str(path), "--gate", "Stage0"]), 2)
            path.write_text('{"schema_version": "1.0", "schema_version": "1.0"}', encoding="utf-8")
            self.assertEqual(main([str(path)]), 1)

    def foundation_report(self):
        source = self.directory / "controller.py"
        source.write_text("# checked Foundation fixture\n")
        artifacts = []
        for name in ("source-manifest", "sbom", "ci-observations"):
            path = self.directory / "evidence" / (name + ".json")
            path.parent.mkdir(exist_ok=True)
            path.write_text(json.dumps({"kind": name}))
            artifacts.append({"path": str(path.relative_to(self.directory)), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()})
        report = {**passing_report("Stage1.auth"), "stage": "Stage1", "scope": "FOUNDATION_ONLY", "capability": "auth",
            "positive_checks": ["Local Owner login"], "negative_checks": ["First visitor denied"], "limitations": ["Fixture only"],
            "source_files": [{"path": "controller.py", "sha256": hashlib.sha256(source.read_bytes()).hexdigest()}], "artifacts": artifacts,
            "manifest_digest": artifacts[0]["sha256"], "sbom_digest": artifacts[1]["sha256"]}
        report["evidence_digest"] = evidence_digest(report)
        self.write_report({"evidence_path": "evidence/capabilities/stage1/auth.json"}, report)
        return report

    def test_stage1_uses_only_canonical_capabilities_and_does_not_promote_mvp_tests(self):
        registry = validate(self.data)
        self.assertTrue(registry.blockers("Stage1", self.directory))
        self.foundation_report()
        self.assertEqual(registry.blockers("Stage1", self.directory), [])
        self.assertEqual(registry.blockers("Stage3", self.directory), ["AC-28: NOT_RUN", "AC-B03: NOT_RUN"])

    def test_stage1_current_revalidation_is_required_when_directory_exists(self):
        report = self.foundation_report()
        current = self.directory / "evidence/revalidation/stage1-current"
        current.mkdir(parents=True)
        registry = validate(self.data)
        self.assertTrue(registry.blockers("Stage1", self.directory))
        path = {"evidence_path": "evidence/revalidation/stage1-current/auth.json"}
        self.write_report(path, report)
        self.assertEqual(registry.blockers("Stage1", self.directory), [])
        report["observation"] = "altered current revalidation"
        self.write_report(path, report)
        self.assertTrue(registry.blockers("Stage1", self.directory))
        self.assertTrue((self.directory / "evidence/capabilities/stage1/auth.json").is_file())

    def test_stage1_current_revalidation_cannot_escape_evidence_root(self):
        self.foundation_report()
        current = self.directory / "evidence/revalidation/stage1-current"
        current.parent.mkdir(parents=True)
        current.symlink_to(self.directory / "outside", target_is_directory=True)
        self.assertTrue(validate(self.data).blockers("Stage1", self.directory))

    def test_stage1_requires_negative_checks_and_foundation_scope(self):
        for field, value in (("negative_checks", []), ("scope", "FULL_MVP"), ("outcome", "FAIL"), ("capability", "different")):
            report = self.foundation_report()
            report[field] = value
            report["evidence_digest"] = evidence_digest(report)
            self.write_report({"evidence_path": "evidence/capabilities/stage1/auth.json"}, report)
            with self.subTest(field=field):
                self.assertTrue(validate(self.data).blockers("Stage1", self.directory))

    def test_stage1_rejects_changed_code_or_missing_evidence_artifacts(self):
        report = self.foundation_report()
        (self.directory / "controller.py").write_text("# changed after acceptance\n")
        self.assertTrue(validate(self.data).blockers("Stage1", self.directory))
        report = self.foundation_report()
        (self.directory / report["artifacts"][0]["path"]).unlink()
        self.assertTrue(validate(self.data).blockers("Stage1", self.directory))

    def test_stage1_rejects_tampered_review_or_path_escape(self):
        report = self.foundation_report()
        report["observation"] = "tampered after review"
        self.write_report({"evidence_path": "evidence/capabilities/stage1/auth.json"}, report)
        self.assertTrue(validate(self.data).blockers("Stage1", self.directory))
        report = self.foundation_report()
        report["source_files"][0]["path"] = "../escape"
        report["evidence_digest"] = evidence_digest(report)
        self.write_report({"evidence_path": "evidence/capabilities/stage1/auth.json"}, report)
        self.assertTrue(validate(self.data).blockers("Stage1", self.directory))
