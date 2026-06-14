"""CodeQL Tool Integration — Wrapper for CodeQL static analysis.

CodeQL is GitHub's semantic code analysis engine. This tool:
1. Runs CodeQL queries against codebases
2. Parses results into standardized finding format
3. Works with locally installed CodeQL CLI or falls back gracefully
"""

import logging
import subprocess
import json
import os
import tempfile
from typing import Dict, List, Optional, Any
from pathlib import Path

logger = logging.getLogger(__name__)

# Built-in security query suites
CODEQL_QUERIES = {
    "security-extended": "codeql-suites/security-extended",
    "security-and-quality": "codeql-suites/security-and-quality",
    "sql-injection": "ql/src/Security/CWE-089/SqlInjection.ql",
    "xss": "ql/src/Security/CWE-079/Xss.ql",
    "command-injection": "ql/src/Security/CWE-078/CommandInjection.ql",
    "path-traversal": "ql/src/Security/CWE-022/PathTraversal.ql",
}


class CodeQLTool:
    """Wrapper for CodeQL static analysis."""

    def __init__(self, codeql_path: Optional[str] = None):
        self.codeql_path = codeql_path or self._find_codeql()

    def _find_codeql(self) -> Optional[str]:
        """Find CodeQL CLI in PATH or common locations."""
        try:
            result = subprocess.run(
                ["codeql", "--version"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                return "codeql"
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        # Check common install locations
        common_paths = [
            os.path.expanduser("~/codeql/codeql"),
            "/usr/local/bin/codeql",
            "/opt/codeql/codeql",
            "C:\\codeql\\codeql.exe",
        ]
        for path in common_paths:
            if os.path.exists(path):
                return path

        return None

    def is_available(self) -> bool:
        """Check if CodeQL CLI is available."""
        return self.codeql_path is not None

    async def analyze(
        self,
        code_path: str,
        query_suite: str = "security-extended",
        language: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Run CodeQL analysis on a codebase.

        Args:
            code_path: Path to the codebase directory
            query_suite: CodeQL query suite to run
            language: Override language detection

        Returns:
            Analysis results with findings
        """
        if not self.is_available():
            logger.warning("CodeQL not installed — returning empty results")
            return {
                "tool": "codeql",
                "available": False,
                "status": "unavailable",
                "findings": [],
                "error": "CodeQL CLI not found. Install from: https://github.com/github/codeql-cli-binaries",
            }

        with tempfile.TemporaryDirectory() as tmpdir:
            try:
                # Step 1: Create CodeQL database
                db_path = os.path.join(tmpdir, "codeql-db")
                cmd = [
                    self.codeql_path, "database", "create",
                    "--language=" + (language or "auto"),
                    "--source-root=" + code_path,
                    db_path,
                ]
                logger.info(f"Creating CodeQL database: {' '.join(cmd)}")
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
                if result.returncode != 0:
                    return {
                        "tool": "codeql",
                        "status": "error",
                        "findings": [],
                        "error": f"Database creation failed: {result.stderr[:500]}",
                    }

                # Step 2: Run analysis
                results_path = os.path.join(tmpdir, "results.sarif")
                cmd = [
                    self.codeql_path, "database", "analyze",
                    db_path,
                    query_suite,
                    "--format=sarif-latest",
                    "--output=" + results_path,
                ]
                logger.info(f"Running CodeQL analysis: {' '.join(cmd)}")
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)

                # Step 3: Parse results
                if os.path.exists(results_path):
                    with open(results_path, "r") as f:
                        sarif = json.load(f)
                    findings = self._parse_sarif(sarif)
                else:
                    findings = []

                return {
                    "tool": "codeql",
                    "available": True,
                    "status": "success",
                    "findings": findings,
                    "total": len(findings),
                }

            except subprocess.TimeoutExpired:
                return {
                    "tool": "codeql",
                    "status": "timeout",
                    "findings": [],
                    "error": "CodeQL analysis timed out after 10 minutes",
                }
            except Exception as e:
                logger.error(f"CodeQL analysis failed: {e}")
                return {
                    "tool": "codeql",
                    "status": "error",
                    "findings": [],
                    "error": str(e),
                }

    def _parse_sarif(self, sarif: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Parse SARIF format into standardized findings."""
        findings = []
        try:
            for run in sarif.get("runs", []):
                for result in run.get("results", []):
                    finding = {
                        "title": result.get("message", {}).get("text", "CodeQL finding"),
                        "description": result.get("message", {}).get("text", ""),
                        "severity": self._map_severity(
                            result.get("properties", {}).get("problem.severity", "warning")
                        ),
                        "location": self._extract_location(result),
                        "cwe": self._extract_cwe(result),
                        "tool": "codeql",
                    }
                    findings.append(finding)
        except Exception as e:
            logger.warning(f"Error parsing SARIF: {e}")

        return findings

    def _map_severity(self, codeql_severity: str) -> str:
        """Map CodeQL severity to standard severity."""
        mapping = {
            "error": "CRITICAL",
            "warning": "HIGH",
            "recommendation": "MEDIUM",
            "note": "LOW",
        }
        return mapping.get(codeql_severity.lower(), "MEDIUM")

    def _extract_location(self, result: Dict[str, Any]) -> str:
        """Extract location info from CodeQL result."""
        try:
            loc = result.get("locations", [{}])[0].get("physicalLocation", {})
            uri = loc.get("artifactLocation", {}).get("uri", "")
            region = loc.get("region", {})
            start_line = region.get("startLine", "?")
            return f"{uri}:{start_line}" if uri else "Unknown"
        except (IndexError, KeyError):
            return "Unknown"

    def _extract_cwe(self, result: Dict[str, Any]) -> Optional[str]:
        """Extract CWE identifier from CodeQL result."""
        for tag in result.get("properties", {}).get("tags", []):
            if tag.startswith("CWE"):
                return tag
        return None
