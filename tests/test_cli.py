import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from dwi.__main__ import main
from dwi import json_report, scan_workspace, table_report


class CliTests(unittest.TestCase):
    def test_table_and_json_output_are_available(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            cache = root / ".pytest_cache"
            cache.mkdir()
            (cache / "CACHEDIR.TAG").write_text("Signature: 8a477f597d28d172789f06886806bc55\n", encoding="utf-8")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(main(["scan", str(root)]), 0)
            self.assertIn("PATH", output.getvalue())
            self.assertIn("REGENERABILITY", output.getvalue())
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(main(["scan", str(root), "--json"]), 0)
            parsed = json.loads(output.getvalue())
            self.assertEqual(parsed["summary"]["candidates_discovered"], 1)

    def test_json_finding_schema_exposes_effective_posture_and_audit_fields(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            cache = root / ".pytest_cache"
            cache.mkdir()
            (cache / "CACHEDIR.TAG").write_text("Signature: 8a477f597d28d172789f06886806bc55\n", encoding="utf-8")
            (root / "dist").mkdir()

            report = json.loads(json_report(scan_workspace(root)))
            by_artifact = {finding["artifact"]: finding for finding in report["findings"]}
            required = {
                "artifact", "path", "risk_label", "action_eligibility", "regenerability",
                "candidate_eligibility", "rejection_reason", "size", "summary", "evidence",
                "interpretation", "safety_decision", "rule_trace",
            }
            selected = by_artifact["pytest_cache"]
            rejected = by_artifact["dist"]
            self.assertTrue(required.issubset(selected))
            self.assertTrue(required.issubset(rejected))
            self.assertEqual(selected["candidate_eligibility"], "selected")
            self.assertEqual(selected["risk_label"], "review_required")
            self.assertEqual(selected["action_eligibility"], "requires_review")
            self.assertIsNotNone(selected["safety_decision"])
            self.assertIsNotNone(selected["rule_trace"])
            self.assertEqual(rejected["candidate_eligibility"], "rejected")
            self.assertEqual(rejected["risk_label"], "review_required")
            self.assertEqual(rejected["action_eligibility"], "requires_review")
            self.assertIsNone(rejected["safety_decision"])
            self.assertIsNone(rejected["rule_trace"])
            self.assertTrue(rejected["rejection_reason"])

    def test_reporting_is_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            cache = root / ".pytest_cache"
            cache.mkdir()
            (cache / "CACHEDIR.TAG").write_text("Signature: 8a477f597d28d172789f06886806bc55\n", encoding="utf-8")
            first = scan_workspace(root)
            second = scan_workspace(root)
            self.assertEqual(json_report(first), json_report(second))
            self.assertEqual(table_report(first), table_report(second))

    def test_invalid_root_returns_error(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            errors = io.StringIO()
            with contextlib.redirect_stderr(errors):
                result = main(["scan", str(Path(temporary_directory) / "missing")])
            self.assertEqual(result, 2)
            self.assertIn("workspace root", errors.getvalue())


if __name__ == "__main__":
    unittest.main()
