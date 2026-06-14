#!/usr/bin/env python3
"""Run benchmarks against the Sentinel multi-agent system.

Usage:
    python scripts/benchmark.py              # Run all benchmarks
    python scripts/benchmark.py --category injection  # Filter by category
    python scripts/benchmark.py --json       # JSON output
    python scripts/benchmark.py --verbose    # Detailed output
"""

import sys
import os
import json
import argparse
import asyncio
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.main import setup_orchestrator
from src.benchmark.ctf_benchmark import BenchmarkSuite
from src.benchmark.metrics import BenchmarkMetrics


async def main():
    parser = argparse.ArgumentParser(description="Run Sentinel benchmarks")
    parser.add_argument("--category", type=str, help="Filter by category")
    parser.add_argument("--json", action="store_true", help="JSON output")
    parser.add_argument("--verbose", action="store_true", help="Detailed output")
    args = parser.parse_args()

    print("\n" + "=" * 60)
    print("🔐 Sentinel Cyber AI — Benchmark Suite")
    print("=" * 60)

    # Initialize the system
    print("\n🔄 Initializing agents...")
    orchestrator = setup_orchestrator()

    # Run benchmarks
    print("🔄 Running benchmark cases...\n")
    suite = BenchmarkSuite(orchestrator)
    results = await suite.run_all()

    # Compute metrics
    metrics = BenchmarkMetrics.compute_metrics(results.get("details", []))
    summary = BenchmarkMetrics.format_summary(metrics)

    if args.json:
        print(json.dumps({"results": results, "metrics": metrics}, indent=2, default=str))
    else:
        print(summary)

        if args.verbose and results.get("details"):
            print("\n### Detailed Results")
            for r in results["details"]:
                status_icon = "✅" if r.get("passed") else "❌"
                print(f"\n{status_icon} **{r.get('name')}** ({r.get('difficulty', 'N/A')})")
                print(f"   Status: {r.get('status', 'N/A')}")
                print(f"   Detected: {', '.join(r.get('detected', [])) or 'None'}")
                if r.get("missed"):
                    print(f"   Missed: {', '.join(r['missed'])}")
                if r.get("false_positives", 0) > 0:
                    print(f"   False positives: {r['false_positives']}")

    return results


if __name__ == "__main__":
    asyncio.run(main())
