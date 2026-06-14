"""Benchmark Metrics — Scoring and performance evaluation.

Provides:
- Detection rate (true positives)
- False positive rate
- Mean average precision
- Per-category F1 scores
- Confidence calibration
"""

from typing import Dict, List, Any
import math


class BenchmarkMetrics:
    """Compute and report benchmark performance metrics."""

    @staticmethod
    def compute_metrics(results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Compute comprehensive metrics from benchmark results."""
        total = len(results)
        if total == 0:
            return {"error": "No results to evaluate"}

        passed = sum(1 for r in results if r.get("passed"))
        failed = total - passed

        # Compute per-category metrics
        categories = set(r.get("category", "unknown") for r in results)
        category_metrics = {}
        for cat in categories:
            cat_results = [r for r in results if r.get("category") == cat]
            cat_passed = sum(1 for r in cat_results if r.get("passed"))
            cat_total = len(cat_results)

            tp = sum(len(r.get("detected", [])) for r in cat_results)
            fn = sum(len(r.get("missed", [])) for r in cat_results)
            fp = sum(r.get("false_positives", 0) for r in cat_results)

            precision = tp / (tp + fp) if (tp + fp) > 0 else 0
            recall = tp / (tp + fn) if (tp + fn) > 0 else 0
            f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0

            category_metrics[cat] = {
                "total": cat_total,
                "passed": cat_passed,
                "success_rate": round(cat_passed / cat_total, 3) if cat_total > 0 else 0,
                "precision": round(precision, 3),
                "recall": round(recall, 3),
                "f1_score": round(f1, 3),
                "false_positive_rate": round(fp / max(tp + fn, 1), 3),
            }

        # Compute overall metrics
        total_detected = sum(len(r.get("detected", [])) for r in results)
        total_missed = sum(len(r.get("missed", [])) for r in results)
        total_fp = sum(r.get("false_positives", 0) for r in results)
        total_expected = total_detected + total_missed

        overall_precision = total_detected / (total_detected + total_fp) if (total_detected + total_fp) > 0 else 0
        overall_recall = total_detected / total_expected if total_expected > 0 else 0
        overall_f1 = 2 * (overall_precision * overall_recall) / (overall_precision + overall_recall) if (overall_precision + overall_recall) > 0 else 0

        # Confidence calibration (how well confidence correlates with accuracy)
        confidence_errors = [
            abs(r.get("confidence", 0) - (1.0 if r.get("passed") else 0.0))
            for r in results if r.get("confidence") is not None
        ]
        calibration_error = sum(confidence_errors) / len(confidence_errors) if confidence_errors else 0

        # Difficulty analysis
        difficulties = set(r.get("difficulty", "unknown") for r in results)
        difficulty_metrics = {}
        for diff in difficulties:
            diff_results = [r for r in results if r.get("difficulty") == diff]
            diff_passed = sum(1 for r in diff_results if r.get("passed"))
            diff_total = len(diff_results)
            difficulty_metrics[diff] = {
                "total": diff_total,
                "passed": diff_passed,
                "success_rate": round(diff_passed / diff_total, 3) if diff_total > 0 else 0,
            }

        return {
            "overall": {
                "total_tests": total,
                "passed": passed,
                "failed": failed,
                "success_rate": round(passed / total, 3),
                "precision": round(overall_precision, 3),
                "recall": round(overall_recall, 3),
                "f1_score": round(overall_f1, 3),
                "calibration_error": round(calibration_error, 3),
                "total_vulnerabilities_detected": total_detected,
                "total_vulnerabilities_missed": total_missed,
                "total_false_positives": total_fp,
            },
            "by_category": category_metrics,
            "by_difficulty": difficulty_metrics,
        }

    @staticmethod
    def format_summary(metrics: Dict[str, Any]) -> str:
        """Format metrics into a human-readable summary."""
        overall = metrics.get("overall", {})
        lines = [
            "## Benchmark Results",
            "",
            f"**Success Rate:** {overall.get('success_rate', 0):.0%} "
            f"({overall.get('passed', 0)}/{overall.get('total_tests', 0)})",
            f"**F1 Score:** {overall.get('f1_score', 0):.3f}",
            f"**Precision:** {overall.get('precision', 0):.0%}",
            f"**Recall:** {overall.get('recall', 0):.0%}",
            f"**False Positives:** {overall.get('total_false_positives', 0)}",
            f"**Missed:** {overall.get('total_vulnerabilities_missed', 0)}",
            "",
            "### By Difficulty",
        ]

        for diff, data in metrics.get("by_difficulty", {}).items():
            lines.append(
                f"- **{diff.title()}**: {data.get('success_rate', 0):.0%} "
                f"({data.get('passed', 0)}/{data.get('total', 0)})"
            )

        lines.extend(["", "### By Category"])
        for cat, data in metrics.get("by_category", {}).items():
            lines.append(
                f"- **{cat.replace('_', ' ').title()}**: F1={data.get('f1_score', 0):.2f} "
                f"({data.get('success_rate', 0):.0%})"
            )

        return "\n".join(lines)
