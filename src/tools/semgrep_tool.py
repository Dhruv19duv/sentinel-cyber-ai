"""Semgrep Tool Integration — Fast, multi-language static analysis.

Semgrep is a lightweight static analysis tool. This wrapper:
1. Runs Semgrep scans against code or snippets
2. Supports custom rules for zero-day detection
3. Parse results into standardized findings
"""

import logging
import subprocess
import json
import os
from typing import Dict, List, Optional, Any

logger = logging.getLogger(__name__)

# Default Semgrep rules for security scanning
SECURITY_RULES = [
    "p/python",       # Python security rules
    "p/javascript",   # JavaScript security rules
    "p/java",         # Java security rules
    "p/owasp-top-ten", # OWASP Top 10 coverage
]

CUSTOM_RULES = """
rules:
  - id: custom-no-eval
    pattern: eval(...)
    message: "eval() can lead to code injection"
    severity: ERROR
    languages: [python, javascript]

  - id: custom-no-shell-true
    pattern: subprocess.run(..., shell=True, ...)
    message: "shell=True enables command injection"
    severity: ERROR
    languages: [python]

  - id: custom-no-inner-html
    pattern: |
      document.getElementById(...).innerHTML = ...
    message: "innerHTML allows XSS attacks"
    severity: WARNING
    languages: [javascript, typescript]

  - id: custom-no-hardcoded-secrets
    patterns:
      - pattern-regex: (?i)(password|secret|api[_-]?key)\s*[:=]\s*["\'][^"\']{8,}["\']
    message: "Hardcoded secret detected"
    severity: ERROR
    languages: [python, javascript, java, go, rust]

  - id: custom-sql-concatenation
    patterns:
      - pattern: |
          "...$..." + $INPUT
      - pattern-not: |
          "...?"...
    message: "SQL query concatenation leads to injection"
    severity: ERROR
    languages: [python, javascript, java, go]
"""


class SemgrepTool:
    """Wrapper for Semgrep static analysis."""

    def is_available(self) -> bool:
        """Check if semgrep CLI is available."""
        try:
            result = subprocess.run(
                ["semgrep", "--version"],
                capture_output=True, text=True, timeout=10,
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    async def analyze_code(
        self,
        code: str,
        language: Optional[str] = None,
        rules: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Run Semgrep analysis on a code snippet.

        Args:
            code: Source code to analyze
            language: Language hint (auto-detected if not provided)
            rules: Semgrep rules/packs to use

        Returns:
            Analysis results with findings
        """
        if not self.is_available():
            logger.warning("Semgrep not installed — using fallback pattern matching")
            return {
                "tool": "semgrep",
                "available": False,
                "status": "unavailable",
                "findings": [],
                "error": "Semgrep not installed. Install with: pip install semgrep",
            }

        try:
            rules_to_use = rules or SECURITY_RULES

            # Write code to temp file
            import tempfile
            with tempfile.NamedTemporaryFile(
                suffix=f".{language or 'py'}", mode="w", delete=False
            ) as f:
                f.write(code)
                temp_path = f.name

            # Write custom rules
            with tempfile.NamedTemporaryFile(
                suffix=".yaml", mode="w", delete=False
            ) as f:
                f.write(CUSTOM_RULES)
                rules_path = f.name

            # Run semgrep
            cmd = [
                "semgrep",
                "--config=" + rules_path,
                "--json",
                "--no-git-ignore",
                "--quiet",
                temp_path,
            ]

            for rule in rules_to_use:
                cmd.insert(-1, f"--config={rule}")

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

            # Cleanup temp files
            try:
                os.unlink(temp_path)
                os.unlink(rules_path)
            except OSError:
                pass

            if result.returncode in (0, 1):  # 1 means findings found
                parsed = json.loads(result.stdout)
                findings = self._parse_results(parsed)
                return {
                    "tool": "semgrep",
                    "available": True,
                    "status": "success",
                    "findings": findings,
                    "total": len(findings),
                }
            else:
                return {
                    "tool": "semgrep",
                    "status": "error",
                    "findings": [],
                    "error": result.stderr[:500],
                }

        except Exception as e:
            logger.error(f"Semgrep analysis failed: {e}")
            return {
                "tool": "semgrep",
                "status": "error",
                "findings": [],
                "error": str(e),
            }

    def _parse_results(self, semgrep_output: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Parse Semgrep JSON output into standardized findings."""
        findings = []
        for result in semgrep_output.get("results", []):
            finding = {
                "title": result.get("check_id", "Semgrep finding"),
                "description": result.get("extra", {}).get("message", ""),
                "severity": self._map_severity(
                    result.get("extra", {}).get("severity", "WARNING")
                ),
                "location": (
                    f"{result.get('path', 'N/A')}:"
                    f"{result.get('start', {}).get('line', '?')}"
                ),
                "cwe": result.get("extra", {}).get("metadata", {}).get("cwe", None),
                "tool": "semgrep",
            }
            findings.append(finding)

        return findings

    def _map_severity(self, semgrep_severity: str) -> str:
        mapping = {
            "ERROR": "CRITICAL",
            "WARNING": "HIGH",
            "INFO": "MEDIUM",
        }
        return mapping.get(semgrep_severity.upper(), "MEDIUM")
