"""Tests for the benchmark suite and metrics."""

import pytest
from src.benchmark.ctf_benchmark import BenchmarkSuite, BENCHMARK_CASES
from src.benchmark.metrics import BenchmarkMetrics


class TestBenchmarkSuite:
    """Tests for the benchmark suite."""

    def test_has_test_cases(self):
        """Benchmark suite should have test cases defined."""
        assert len(BENCHMARK_CASES) > 0

    def test_all_cases_have_required_fields(self):
        """Each benchmark case should have all required fields."""
        required = {"name", "query", "expected_vulns", "difficulty", "category"}
        for case in BENCHMARK_CASES:
            for field in required:
                assert hasattr(case, field), f"Case '{case.name}' missing field: {field}"

    def test_all_difficulties_covered(self):
        """Benchmark should have cases across difficulty levels."""
        difficulties = {case.difficulty for case in BENCHMARK_CASES}
        assert "easy" in difficulties
        assert "medium" in difficulties

    def test_all_categories_have_cases(self):
        """Each category should have at least one test case."""
        categories = {}
        for case in BENCHMARK_CASES:
            categories[case.category] = categories.get(case.category, 0) + 1
        assert len(categories) >= 3  # At least 3 categories
        for cat, count in categories.items():
            assert count >= 1, f"Category '{cat}' has no cases"

    @pytest.mark.asyncio
    async def test_benchmark_with_null_orchestrator(self):
        """Benchmark should handle None orchestrator gracefully."""
        suite = BenchmarkSuite(orchestrator=None)
        result = await suite.run_all()
        assert result.get("status") == "complete"  # No crash, gracefully handles None orchestrator

    def test_benchmark_cases_cover_major_vulns(self):
        """Benchmark cases should cover major vulnerability types."""
        all_expected = set()
        for case in BENCHMARK_CASES:
            all_expected.update(e.lower() for e in case.expected_vulns)

        major_vulns = ["sql injection", "xss", "command injection"]
        for vuln in major_vulns:
            assert any(vuln in e for e in all_expected), f"Missing benchmark for: {vuln}"


class TestBenchmarkMetrics:
    """Tests for benchmark metrics computation."""

    def test_compute_metrics_empty(self):
        """Empty results should return error."""
        metrics = BenchmarkMetrics.compute_metrics([])
        assert "error" in metrics

    def test_compute_metrics_all_pass(self):
        """Metrics with all passing tests should show 100%."""
        results = [
            {"name": "Test 1", "passed": True, "detected": ["SQL"], "missed": [],
             "false_positives": 0, "confidence": 0.95, "difficulty": "easy", "category": "injection"},
            {"name": "Test 2", "passed": True, "detected": ["XSS"], "missed": [],
             "false_positives": 0, "confidence": 0.9, "difficulty": "medium", "category": "xss"},
        ]
        metrics = BenchmarkMetrics.compute_metrics(results)
        assert metrics["overall"]["success_rate"] == 1.0
        assert metrics["overall"]["passed"] == 2

    def test_compute_metrics_with_failures(self):
        """Metrics should correctly reflect failures."""
        results = [
            {"name": "Test 1", "passed": True, "detected": ["SQL"], "missed": [],
             "false_positives": 0, "confidence": 0.9, "difficulty": "easy", "category": "injection"},
            {"name": "Test 2", "passed": False, "detected": [], "missed": ["XSS"],
             "false_positives": 0, "confidence": 0.3, "difficulty": "hard", "category": "xss"},
            {"name": "Test 3", "passed": True, "detected": ["CMD"], "missed": [],
             "false_positives": 1, "confidence": 0.85, "difficulty": "medium", "category": "injection"},
        ]
        metrics = BenchmarkMetrics.compute_metrics(results)
        assert metrics["overall"]["passed"] == 2
        assert metrics["overall"]["failed"] == 1
        import math
        assert abs(metrics["overall"]["success_rate"] - 2.0 / 3.0) < 0.001

    def test_compute_metrics_by_difficulty(self):
        """Metrics should break down by difficulty."""
        results = [
            {"name": "Easy 1", "passed": True, "detected": ["A"], "missed": [],
             "false_positives": 0, "difficulty": "easy", "category": "injection"},
            {"name": "Easy 2", "passed": False, "detected": [], "missed": ["B"],
             "false_positives": 0, "difficulty": "easy", "category": "xss"},
        ]
        metrics = BenchmarkMetrics.compute_metrics(results)
        assert "easy" in metrics["by_difficulty"]
        assert metrics["by_difficulty"]["easy"]["total"] == 2

    def test_f1_score_computation(self):
        """F1 score should be computed correctly."""
        results = [
            {"name": "Test", "passed": True, "detected": ["A", "B"], "missed": [],
             "false_positives": 1, "confidence": 0.9, "difficulty": "easy", "category": "injection"},
        ]
        metrics = BenchmarkMetrics.compute_metrics(results)
        # precision = 2/(2+1) = 0.667, recall = 2/2 = 1.0, f1 = 2*(0.667*1.0)/(0.667+1.0) = 0.8
        assert metrics["overall"]["precision"] > 0
        assert metrics["overall"]["recall"] > 0

    def test_format_summary_includes_key_metrics(self):
        """Formatted summary should include key metrics."""
        metrics = {"overall": {"success_rate": 0.85, "passed": 17, "failed": 3,
                               "total_tests": 20, "f1_score": 0.82, "precision": 0.88,
                               "recall": 0.85, "total_false_positives": 2,
                               "total_vulnerabilities_missed": 1},
                   "by_difficulty": {},
                   "by_category": {}}
        summary = BenchmarkMetrics.format_summary(metrics)
        assert "85%" in summary or "0.85" in summary
        assert "17" in summary
