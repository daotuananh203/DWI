from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from dwi.benchmark import run_benchmarks
from dwi.evaluation import run_readonly_evaluation
from dwi.scan_control import ScanLimits


class EvaluationAndBenchmarkTests(unittest.TestCase):
    def test_readonly_evaluation_is_structured_and_never_mutates(self) -> None:
        with tempfile.TemporaryDirectory(prefix="dwi-evaluation-test-") as temporary:
            root = Path(temporary)
            (root / ".pytest_cache").mkdir()
            (root / ".pytest_cache" / "CACHEDIR.TAG").write_text(
                "Signature: 8a477f597d28d172789f06886806bc55\n",
                encoding="utf-8",
            )
            result = run_readonly_evaluation(
                root=str(root),
                limits=ScanLimits(max_seconds=10, max_nodes=100, max_files=100),
            )
        self.assertTrue(result.read_only)
        self.assertFalse(result.mutation_started)
        self.assertGreaterEqual(result.findings_count, 1)
        self.assertIn("complete", result.root_status_counts)

    def test_synthetic_benchmark_is_bounded_and_reports_scale_metrics(self) -> None:
        result = run_benchmarks((2, 4))
        self.assertTrue(result["synthetic_only"])
        self.assertEqual([row["scale"] for row in result["scales"]], [2, 4])
        self.assertEqual(result["pagination_pages"]["4"], 1)
        for row in result["scales"]:
            self.assertIn("duration_ms", row)
            self.assertIn("peak_memory_bytes", row)
            self.assertIn("termination", row)


if __name__ == "__main__":
    unittest.main()
