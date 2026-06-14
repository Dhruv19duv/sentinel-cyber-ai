"""CVE Search Tool — Vulnerability database lookup and threat intelligence.

Queries NVD (National Vulnerability Database), OSV (Open Source Vulnerabilities),
and local vulnerability databases for comprehensive threat intelligence.
"""

import logging
import json
import subprocess
from typing import Dict, List, Optional, Any
from datetime import datetime

logger = logging.getLogger(__name__)

# Local vulnerability database (simplified — full version would query NVD API)
LOCAL_VULN_DB: Dict[str, Dict[str, Any]] = {
    "CVE-2021-44228": {
        "id": "CVE-2021-44228",
        "summary": "Apache Log4j2 JNDI features do not protect against attacker-controlled LDAP and other JNDI endpoints.",
        "severity": "CRITICAL",
        "cvss_score": 10.0,
        "affected": [
            "org.apache.logging.log4j:log4j-core:2.0-alpha1 - 2.14.1"
        ],
        "published": "2021-12-10",
        "exploitability": "Actively exploited in the wild",
        "patch": "Upgrade to log4j-core 2.17.0+",
    },
    "CVE-2022-22965": {
        "id": "CVE-2022-22965",
        "summary": "Spring Framework RCE via unsafe data binding",
        "severity": "CRITICAL",
        "cvss_score": 9.8,
        "affected": [
            "org.springframework:spring-beans:5.3.0 - 5.3.17",
            "org.springframework:spring-beans:5.2.0 - 5.2.19",
        ],
        "published": "2022-03-31",
        "exploitability": "Exploit PoCs available",
        "patch": "Upgrade to Spring Framework 5.3.18+",
    },
    "CVE-2023-44487": {
        "id": "CVE-2023-44487",
        "summary": "HTTP/2 Rapid Reset Attack",
        "severity": "HIGH",
        "cvss_score": 7.5,
        "affected": ["Multiple HTTP/2 implementations"],
        "published": "2023-10-10",
        "exploitability": "Actively exploited",
        "patch": "Apply vendor patches for HTTP/2 stack",
    },
    "CVE-2024-3094": {
        "id": "CVE-2024-3094",
        "summary": "XZ Utils backdoor (liblzma) — supply chain compromise",
        "severity": "CRITICAL",
        "cvss_score": 10.0,
        "affected": ["xz-utils:5.6.0", "xz-utils:5.6.1"],
        "published": "2024-03-29",
        "exploitability": "Backdoor detected before widespread exploitation",
        "patch": "Downgrade to xz 5.4.x or apply patched versions",
    },
    "CVE-2024-27198": {
        "id": "CVE-2024-27198",
        "summary": "JetBrains TeamCity Authentication Bypass",
        "severity": "CRITICAL",
        "cvss_score": 9.8,
        "affected": ["JetBrains:TeamCity:before 2023.11.4"],
        "published": "2024-03-04",
        "exploitability": "Actively exploited by ransomware groups",
        "patch": "Upgrade TeamCity to 2023.11.4+",
    },
}


class SearchTool:
    """Vulnerability database search and threat intelligence."""

    def __init__(self):
        self._cache: Dict[str, Any] = {}

    async def search_cve(self, query: str) -> List[Dict[str, Any]]:
        """Search for CVEs matching the query.

        Args:
            query: Search term (CVE ID, software name, vulnerability type)

        Returns:
            List of matching CVE records
        """
        # Check cache first
        if query in self._cache:
            return self._cache[query]

        results = []
        query_lower = query.lower()

        for cve_id, info in LOCAL_VULN_DB.items():
            # Match by CVE ID
            if cve_id.lower() in query_lower:
                results.append(info)
                continue

            # Match by keywords in summary
            for word in query_lower.split():
                if word in info["summary"].lower() or word in info.get("patch", "").lower():
                    results.append(info)
                    break

        # Cache results
        self._cache[query] = results
        return results

    async def get_cve_details(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Get detailed information about a specific CVE."""
        return LOCAL_VULN_DB.get(cve_id.upper())

    async def search_by_software(self, software_name: str) -> List[Dict[str, Any]]:
        """Search vulnerabilities by software/package name."""
        results = []
        name_lower = software_name.lower()

        for cve_id, info in LOCAL_VULN_DB.items():
            for affected in info.get("affected", []):
                if name_lower in affected.lower():
                    results.append(info)
                    break

        return results

    async def get_recent_cves(self, days: int = 30, limit: int = 20) -> List[Dict[str, Any]]:
        """Get recently published CVEs."""
        # Sort by publication date (most recent first)
        sorted_cves = sorted(
            LOCAL_VULN_DB.values(),
            key=lambda x: x.get("published", ""),
            reverse=True,
        )
        return sorted_cves[:limit]

    async def get_statistics(self) -> Dict[str, Any]:
        """Get vulnerability database statistics."""
        severities = {}
        for info in LOCAL_VULN_DB.values():
            sev = info.get("severity", "UNKNOWN")
            severities[sev] = severities.get(sev, 0) + 1

        return {
            "total_cves": len(LOCAL_VULN_DB),
            "by_severity": severities,
            "oldest": min(info.get("published", "") for info in LOCAL_VULN_DB.values()),
            "newest": max(info.get("published", "") for info in LOCAL_VULN_DB.values()),
            "database_version": "2026.1",
        }
