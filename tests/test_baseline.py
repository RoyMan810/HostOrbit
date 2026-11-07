import copy
import unittest

from stage0.baseline import _MACHINES, check_baseline
from stage0.requirements import InvalidRegistry
from test_requirements import fixture


def specification():
    definitions = "\n\n".join(f"**{name}:** `{graph}`" for name, graph in _MACHINES.items())
    return f"## 40. Authority\n\n{definitions}\n\n**Stage0:** `AC-B03`\n\n## 41. Evidence\n"


class BaselineTests(unittest.TestCase):
    def test_matches_the_registry_and_checks_terminal_unknown_separately_from_incident(self):
        result = check_baseline(specification(), fixture())
        self.assertEqual(result["stage0_required_tests"], ["AC-B03"])
        self.assertTrue(result["job_unknown_is_terminal"])
        self.assertTrue(result["incident_is_separate"])

    def test_rejects_missing_or_competing_authority_even_outside_section_40(self):
        original = specification()
        for text in (
            original.replace("## 40.", "## 39."),
            original + "\n**Plan:** `DRAFT → APPROVED`\n",
            original + "\n**Stage0:** `AC-B03`\n",
            original + "\n" + original,
        ):
            with self.subTest(text=text), self.assertRaises(InvalidRegistry):
                check_baseline(text, fixture())

    def test_rejects_terminal_job_return_and_incident_merged_into_job(self):
        for previous, replacement in (
            ("UNKNOWN_OUTCOME | CANCELLED_SAFE", "UNKNOWN_OUTCOME → EXECUTING | CANCELLED_SAFE"),
            ("**Incident:**", "**Job:**"),
            ("MAINTENANCE → RESUMING", "MAINTENANCE → NORMAL → RESUMING"),
        ):
            with self.subTest(previous=previous), self.assertRaises(InvalidRegistry):
                check_baseline(specification().replace(previous, replacement), fixture())

    def test_ranges_and_slash_groups_are_expanded_and_mismatches_fail(self):
        from stage0.baseline import _stage0_ids
        self.assertEqual(
            _stage0_ids('`AC-A01..A03`, `AC-A20`, `AC-B01/B03`'),
            {"AC-A01", "AC-A02", "AC-A03", "AC-A20", "AC-B01", "AC-B03"},
        )
        for declaration in ('`AC-A03..A01`', '`AC-B03/B03`', '`AC-B03`, `AC-B03`', '`AC-typo`'):
            with self.subTest(declaration=declaration), self.assertRaises(InvalidRegistry):
                _stage0_ids(declaration)
        with self.assertRaisesRegex(InvalidRegistry, "criteria differ"):
            check_baseline(specification().replace('`AC-B03`', '`AC-B02/B03`'), copy.deepcopy(fixture()))
