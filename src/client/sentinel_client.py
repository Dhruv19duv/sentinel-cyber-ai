"""Sentinel Python SDK — Client library for the Sentinel Cyber AI API.

Usage:
    from src.client.sentinel_client import SentinelClient
    
    client = SentinelClient(api_key="your-key", base_url="http://localhost:8080")
    
    # Analyze code
    result = client.analyze("eval(request.GET.get('code'))")
    print(result.summary)
    
    # Scan a codebase
    result = client.scan("/path/to/project")
    
    # Get system status
    status = client.status()
"""

import json
import logging
import os
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

logger = logging.getLogger(__name__)


class Severity(str, Enum):
    """Severity levels for findings."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class Finding:
    """A single vulnerability finding."""
    title: str
    description: str
    severity: Severity = Severity.INFO
    location: Optional[str] = None
    remediation: Optional[str] = None
    cwe: Optional[str] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Finding":
        return cls(
            title=data.get("title", "Unknown"),
            description=data.get("description", ""),
            severity=Severity(data.get("severity", "INFO")),
            location=data.get("location"),
            remediation=data.get("remediation"),
            cwe=data.get("cwe"),
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "location": self.location,
            "remediation": self.remediation,
            "cwe": self.cwe,
        }


@dataclass
class AnalysisResult:
    """Result from a security analysis."""
    task_id: str
    status: str
    summary: str
    findings: List[Finding] = field(default_factory=list)
    confidence: float = 0.0
    agents_used: List[str] = field(default_factory=list)
    duration_ms: Optional[float] = None
    error: Optional[str] = None
    raw: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AnalysisResult":
        return cls(
            task_id=data.get("task_id", ""),
            status=data.get("status", "error"),
            summary=data.get("summary", ""),
            findings=[Finding.from_dict(f) for f in data.get("findings", [])],
            confidence=data.get("confidence", 0.0),
            agents_used=data.get("agents_used", []),
            duration_ms=data.get("duration_ms"),
            error=data.get("error"),
            raw=data,
        )

    @property
    def critical_findings(self) -> List[Finding]:
        return [f for f in self.findings if f.severity == Severity.CRITICAL]

    @property
    def high_findings(self) -> List[Finding]:
        return [f for f in self.findings if f.severity == Severity.HIGH]

    @property
    def is_vulnerable(self) -> bool:
        return len(self.critical_findings) > 0 or len(self.high_findings) > 0

    def print_summary(self):
        """Print a human-readable summary."""
        print(f"\n{'='*60}")
        print(f"🔐 Sentinel Analysis — {self.task_id}")
        print(f"{'='*60}")
        print(f"Status: {self.status.upper()}")
        print(f"Confidence: {self.confidence:.1%}")
        print(f"Summary: {self.summary}")
        print(f"Agents: {', '.join(self.agents_used)}")
        print()

        if self.findings:
            print(f"Findings ({len(self.findings)}):")
            for f in self.findings:
                icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵"}.get(
                    f.severity.value, "⚪"
                )
                print(f"\n{icon} **{f.title}** [{f.severity.value}]")
                print(f"   {f.description[:200]}")
                if f.remediation:
                    print(f"   💊 Fix: {f.remediation[:150]}")
        else:
            print("No findings.")


class SentinelClient:
    """Client for the Sentinel Cyber AI API.

    Args:
        api_key: API key for authentication
        base_url: Base URL of the Sentinel API server
        timeout: Request timeout in seconds
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: str = "http://localhost:8080",
        timeout: int = 120,
    ):
        self.api_key = api_key or os.environ.get("SENTINEL_API_KEY", "")
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self._session = None

    def _get_headers(self) -> Dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        return headers

    def _request(self, method: str, path: str, **kwargs) -> Dict[str, Any]:
        """Make an HTTP request to the API."""
        import requests

        url = f"{self.base_url}{path}"
        headers = self._get_headers()
        if kwargs.get("headers"):
            headers.update(kwargs.pop("headers"))

        try:
            response = requests.request(
                method=method,
                url=url,
                headers=headers,
                timeout=self.timeout,
                **kwargs,
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.ConnectionError:
            raise ConnectionError(
                f"Could not connect to Sentinel API at {self.base_url}. "
                "Is the server running?"
            )
        except requests.exceptions.Timeout:
            raise TimeoutError(
                f"Request timed out after {self.timeout}s"
            )
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 401:
                raise PermissionError("Invalid API key")
            elif e.response.status_code == 403:
                raise PermissionError("Access denied")
            else:
                raise RuntimeError(
                    f"API error {e.response.status_code}: {e.response.text[:200]}"
                )

    # ── API Methods ──

    def analyze(self, query: str, scan_mode: str = "auto") -> AnalysisResult:
        """Analyze code or a security query.

        Args:
            query: Code snippet or security question to analyze
            scan_mode: Analysis mode (auto, quick, deep, exploit, patch)

        Returns:
            AnalysisResult with findings
        """
        data = self._request("POST", "/api/v1/analyze", json={
            "query": query,
            "scan_mode": scan_mode,
            "format": "json",
        })
        return AnalysisResult.from_dict(data)

    async def analyze_async(self, query: str, scan_mode: str = "auto") -> AnalysisResult:
        """Async version of analyze."""
        import aiohttp

        async with aiohttp.ClientSession() as session:
            async with session.post(
                f"{self.base_url}/api/v1/analyze",
                json={"query": query, "scan_mode": scan_mode},
                headers=self._get_headers(),
                timeout=aiohttp.ClientTimeout(total=self.timeout),
            ) as response:
                data = await response.json()
                return AnalysisResult.from_dict(data)

    def scan(self, path: str, max_files: int = 100) -> Dict[str, Any]:
        """Scan a local codebase for vulnerabilities.

        Args:
            path: Path to the codebase
            max_files: Maximum number of files to scan

        Returns:
            Scan results with findings summary
        """
        return self._request("POST", "/api/v1/scan", json={
            "path": path,
            "max_files": max_files,
        })

    def batch_analyze(self, queries: List[str], parallel: bool = True) -> List[AnalysisResult]:
        """Analyze multiple queries in batch.

        Args:
            queries: List of queries to analyze
            parallel: Run analyses in parallel

        Returns:
            List of AnalysisResults
        """
        data = self._request("POST", "/api/v1/batch", json={
            "queries": queries,
            "parallel": parallel,
        })
        return [AnalysisResult.from_dict(r) for r in data.get("results", [])]

    def list_agents(self) -> List[Dict[str, Any]]:
        """List all registered agents and their capabilities."""
        return self._request("GET", "/api/v1/agents")

    def status(self) -> Dict[str, Any]:
        """Get system health and status."""
        return self._request("GET", "/api/v1/status")

    def health(self) -> Dict[str, Any]:
        """Quick health check."""
        return self._request("GET", "/health")

    def get_history(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get recent analysis history."""
        return self._request("GET", f"/api/v1/history?limit={limit}")

    def generate_report(self, task_id: str, report_type: str = "technical") -> str:
        """Generate a report from a previous analysis.

        Args:
            task_id: ID of the analysis task
            report_type: Report format (technical, executive, slack, pull_request)

        Returns:
            Formatted report text
        """
        data = self._request("POST", "/api/v1/report", json={
            "task_id": task_id,
            "report_type": report_type,
        })
        return data.get("report", "")

    def run_benchmark(self) -> Dict[str, Any]:
        """Run the benchmark suite."""
        return self._request("POST", "/api/v1/benchmark")

    # ── CI/CD Integration ──

    def check_pr_for_vulnerabilities(self, diff_text: str) -> AnalysisResult:
        """Check a PR diff for vulnerabilities.

        Args:
            diff_text: The git diff text of the pull request

        Returns:
            Analysis result suitable for PR comments
        """
        result = self.analyze(
            f"Review this pull request diff for security vulnerabilities:\n\n```diff\n{diff_text[:8000]}\n```"
        )
        return result

    def generate_pr_comment(self, result: AnalysisResult) -> str:
        """Generate a PR comment from analysis results.

        Args:
            result: Analysis result from check_pr_for_vulnerabilities

        Returns:
            Formatted PR comment with findings
        """
        lines = [
            "## 🔐 Sentinel Security Review",
            "",
            f"**Status:** {result.status.upper()}",
            f"**Confidence:** {result.confidence:.0%}",
            "",
        ]

        if result.findings:
            lines.append("### Issues Found")
            for f in result.findings:
                icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡"}.get(f.severity.value, "⚪")
                lines.append(f"\n{icon} **{f.title}** [{f.severity.value}]")
                lines.append(f"  {f.description[:200]}")

            lines.append("\n### Suggested Fixes")
            for f in result.findings:
                if f.remediation:
                    lines.append(f"- **{f.title}**: {f.remediation[:150]}")
        else:
            lines.append("\n✅ No security issues found.")

        lines.append("\n---")
        lines.append("_Review by Sentinel Cyber AI_")
        return "\n".join(lines)


class AsyncSentinelClient:
    """Async version of the Sentinel client.

    TODO: Add remaining methods (scan, batch_analyze, list_agents, status,
    health, get_history, generate_report, run_benchmark) matching sync client.
    """

    def __init__(self, api_key: Optional[str] = None, base_url: str = "http://localhost:8080"):
        self.api_key = api_key or os.environ.get("SENTINEL_API_KEY", "")
        self.base_url = base_url.rstrip("/")

    async def analyze(self, query: str) -> AnalysisResult:
        """Analyze code asynchronously."""
        import aiohttp
        async with aiohttp.ClientSession() as session:
            async with session.post(
                f"{self.base_url}/api/v1/analyze",
                json={"query": query},
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json",
                } if self.api_key else {"Content-Type": "application/json"},
            ) as response:
                data = await response.json()
                return AnalysisResult.from_dict(data)


# ── Command-line usage ──

def main():
    """CLI entry point for the SDK."""
    import argparse

    parser = argparse.ArgumentParser(description="Sentinel Cyber AI Client")
    parser.add_argument("--url", default="http://localhost:8080", help="API URL")
    parser.add_argument("--key", help="API key")
    parser.add_argument("command", choices=["analyze", "scan", "status", "agents", "benchmark"])
    parser.add_argument("args", nargs="*", help="Command arguments")

    args = parser.parse_args()
    client = SentinelClient(api_key=args.key, base_url=args.url)

    if args.command == "analyze":
        query = " ".join(args.args) if args.args else input("Query: ")
        result = client.analyze(query)
        result.print_summary()
    elif args.command == "status":
        print(json.dumps(client.status(), indent=2))
    elif args.command == "agents":
        for agent in client.list_agents():
            print(f"  • {agent.get('name')} ({agent.get('model')})")
    elif args.command == "benchmark":
        results = client.run_benchmark()
        print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
