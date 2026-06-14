"""CTF Benchmark Suite — Evaluates agent performance on real-world challenges.

Tests agents against:
1. Known vulnerable code patterns (OWASP, CWE Top 25)
2. CTF-style challenges (simple → multi-step exploits)
3. Real-world CVE scenarios
4. Adversarial robustness (obfuscated vulns)
"""

import logging
import json
import os
import asyncio
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class BenchmarkCase:
    """A single benchmark test case."""
    name: str
    query: str
    expected_vulns: List[str]  # Vulnerability names expected
    min_confidence: float = 0.5
    max_false_positives: int = 3
    difficulty: str = "easy"
    category: str = "injection"


# Built-in benchmark cases
BENCHMARK_CASES = [
    # === SQL Injection ===
    BenchmarkCase(
        name="SQL Injection - Basic",
        query="""def get_user(username):
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)
    return cursor.fetchall()""",
        expected_vulns=["SQL Injection"],
        difficulty="easy",
        category="injection",
    ),
    BenchmarkCase(
        name="SQL Injection - Java JDBC",
        query="""String query = "SELECT * FROM products WHERE id = " + request.getParameter("id");
Statement stmt = connection.createStatement();
ResultSet rs = stmt.executeQuery(query);""",
        expected_vulns=["SQL Injection"],
        difficulty="easy",
        category="injection",
    ),
    BenchmarkCase(
        name="SQL Injection - ORM Leak",
        query="""# Hibernate query with string concat
String hql = "FROM User WHERE name = '" + userName + "'";
Query query = session.createQuery(hql);
List results = query.list();""",
        expected_vulns=["SQL Injection"],
        difficulty="medium",
        category="injection",
    ),

    # === XSS ===
    BenchmarkCase(
        name="XSS - innerHTML",
        query="""function showGreeting() {
    const name = new URLSearchParams(window.location.search).get('name');
    document.getElementById('greeting').innerHTML = 'Hello, ' + name;
}""",
        expected_vulns=["XSS", "Cross-Site Scripting"],
        difficulty="easy",
        category="xss",
    ),
    BenchmarkCase(
        name="XSS - document.write",
        query="""function trackClick() {
    const ref = document.referrer;
    document.write('<img src="/track?ref=' + ref + '">');
}""",
        expected_vulns=["XSS"],
        difficulty="medium",
        category="xss",
    ),

    # === Command Injection ===
    BenchmarkCase(
        name="Command Injection - shell=True",
        query="""import subprocess
def ping_host(hostname):
    result = subprocess.run(f"ping -c 4 {hostname}", shell=True, capture_output=True)
    return result.stdout""",
        expected_vulns=["Command Injection"],
        difficulty="easy",
        category="injection",
    ),
    BenchmarkCase(
        name="Command Injection - os.system",
        query="""import os
def delete_file(username):
    os.system(f"rm -rf /home/{username}/temp")""",
        expected_vulns=["Command Injection"],
        difficulty="easy",
        category="injection",
    ),

    # === Path Traversal ===
    BenchmarkCase(
        name="Path Traversal - Basic",
        query="""def read_user_file(filename):
    base_path = "/var/data/users/"
    full_path = base_path + filename
    with open(full_path, 'r') as f:
        return f.read()""",
        expected_vulns=["Path Traversal"],
        difficulty="easy",
        category="path_traversal",
    ),

    # === Insecure Deserialization ===
    BenchmarkCase(
        name="Insecure Deserialization - Pickle",
        query="""import pickle
import base64
def load_session(session_data):
    return pickle.loads(base64.b64decode(session_data))""",
        expected_vulns=["Insecure Deserialization"],
        difficulty="medium",
        category="deserialization",
    ),

    # === Hardcoded Secrets ===
    BenchmarkCase(
        name="Hardcoded Secrets",
        query="""# config.py
DB_PASSWORD = "SuperSecret123!"
API_SECRET = "sk-live-abcdefghijklmnopqrstuvwxyz"
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" """,
        expected_vulns=["Hardcoded Secrets", "Hardcoded Credentials"],
        difficulty="easy",
        category="secrets",
    ),

    # === CSRF ===
    BenchmarkCase(
        name="CSRF - No Token",
        query="""@app.route('/transfer', methods=['POST'])
def transfer_money():
    to_account = request.form['to_account']
    amount = request.form['amount']
    current_user.transfer(to_account, amount)
    return redirect('/success')""",
        expected_vulns=["CSRF", "Cross-Site Request Forgery"],
        difficulty="medium",
        category="csrf",
    ),

    # === SSRF ===
    BenchmarkCase(
        name="SSRF - Basic",
        query="""def fetch_url(url):
    response = requests.get(url)
    return response.text""",
        expected_vulns=["SSRF", "Server-Side Request Forgery"],
        difficulty="medium",
        category="ssrf",
    ),

    # === NoSQL Injection ===
    BenchmarkCase(
        name="NoSQL Injection",
        query="""db.users.find({
    "username": request.json["username"],
    "password": request.json["password"]
})""",
        expected_vulns=["NoSQL Injection"],
        difficulty="medium",
        category="injection",
    ),

    # === Multi-step challenges ===
    BenchmarkCase(
        name="SSRF + Credential Leak",
        query="""def process_user_url(url):
    # Fetch user-provided URL
    response = requests.get(url)
    
    # URL contains admin credentials in path
    admin_token = response.text.split('token=')[1].split('&')[0]
    
    # Use token to access internal API
    internal = requests.get(
        f'http://internal-admin/api/users/{admin_token}',
        headers={'Authorization': f'Bearer {admin_token}'}
    )
    return internal.json()""",
        expected_vulns=["SSRF", "Server-Side Request Forgery", "Information Exposure"],
        min_confidence=0.4,
        difficulty="hard",
        category="multi_step",
    ),
]


class BenchmarkSuite:
    """Runs benchmark tests against the multi-agent system."""

    def __init__(self, orchestrator=None):
        self.orchestrator = orchestrator
        self.test_cases = BENCHMARK_CASES

    async def run_all(self) -> Dict[str, Any]:
        """Run all benchmark cases and return aggregated results."""
        logger.info(f"Running {len(self.test_cases)} benchmark cases...")

        results = []
        for case in self.test_cases:
            result = await self._run_case(case)
            results.append(result)

        return self._aggregate_results(results)

    async def _run_case(self, case: BenchmarkCase) -> Dict[str, Any]:
        """Run a single benchmark case."""
        if not self.orchestrator:
            return {
                "name": case.name,
                "status": "skipped",
                "error": "Orchestrator not available",
            }

        try:
            result = await self.orchestrator.process(case.query)
            findings = result.get("findings", [])
            finding_titles = [f.get("title", "").lower() for f in findings]

            # Check for expected vulnerabilities
            detected = []
            missed = []
            for expected in case.expected_vulns:
                expected_lower = expected.lower()
                if any(expected_lower in title for title in finding_titles):
                    detected.append(expected)
                else:
                    missed.append(expected)

            # Calculate score
            detection_rate = len(detected) / len(case.expected_vulns) if case.expected_vulns else 0
            confidence = result.get("confidence", 0)
            passed = detection_rate >= 0.5 and confidence >= case.min_confidence

            return {
                "name": case.name,
                "difficulty": case.difficulty,
                "category": case.category,
                "status": "passed" if passed else "failed",
                "passed": passed,
                "detection_rate": round(detection_rate, 2),
                "confidence": confidence,
                "detected": detected,
                "missed": missed,
                "false_positives": len(findings) - len(detected),
                "expected": case.expected_vulns,
            }

        except Exception as e:
            logger.error(f"Benchmark case '{case.name}' failed: {e}")
            return {
                "name": case.name,
                "status": "error",
                "error": str(e),
                "passed": False,
            }

    def _aggregate_results(self, results: List[Dict]) -> Dict[str, Any]:
        """Aggregate benchmark results into a summary."""
        if not results:
            return {"status": "error", "message": "No results"}

        total = len(results)
        passed = sum(1 for r in results if r.get("passed"))
        failed = total - passed

        # By category
        categories: Dict[str, Dict] = {}
        for r in results:
            cat = r.get("category", "unknown")
            if cat not in categories:
                categories[cat] = {"total": 0, "passed": 0}
            categories[cat]["total"] += 1
            if r.get("passed"):
                categories[cat]["passed"] += 1

        # By difficulty
        difficulties: Dict[str, Dict] = {}
        for r in results:
            diff = r.get("difficulty", "unknown")
            if diff not in difficulties:
                difficulties[diff] = {"total": 0, "passed": 0}
            difficulties[diff]["total"] += 1
            if r.get("passed"):
                difficulties[diff]["passed"] += 1

        # Average metrics
        confidences = [r.get("confidence", 0) for r in results if r.get("confidence")]
        avg_confidence = sum(confidences) / len(confidences) if confidences else 0

        detection_rates = [r.get("detection_rate", 0) for r in results if r.get("detection_rate") is not None]
        avg_detection = sum(detection_rates) / len(detection_rates) if detection_rates else 0

        return {
            "status": "complete",
            "total_tests": total,
            "passed": passed,
            "failed": failed,
            "success_rate": round(passed / total, 3) if total > 0 else 0,
            "average_confidence": round(avg_confidence, 3),
            "average_detection_rate": round(avg_detection, 3),
            "by_category": categories,
            "by_difficulty": difficulties,
            "details": results,
            "summary": (
                f"Benchmark: {passed}/{total} passed "
                f"({passed / total * 100:.0f}%) | "
                f"Avg confidence: {avg_confidence:.0%} | "
                f"Avg detection: {avg_detection:.0%}"
            ),
        }
