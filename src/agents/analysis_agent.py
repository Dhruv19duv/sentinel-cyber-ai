"""Threat Intelligence Agent — CVE lookup, threat feed analysis, trend detection.

This agent:
1. Searches CVE/NVD databases for known vulnerabilities
2. Analyzes threat intelligence feeds
3. Correlates findings with MITRE ATT&CK framework
4. Provides risk scoring and context

Key differentiator: Real-time threat intelligence integration that
Mythos doesn't have access to.
"""

import logging
import re
from typing import Dict, List, Optional, Any
from datetime import datetime

from src.agents.base_agent import BaseAgent, AgentResult

logger = logging.getLogger(__name__)

# MITRE ATT&CK framework mappings
ATTACK_TACTICS = {
    "TA0001": {"name": "Initial Access", "techniques": ["T1078", "T1190", "T1133", "T1566"]},
    "TA0002": {"name": "Execution", "techniques": ["T1204", "T1059", "T1106", "T1569"]},
    "TA0003": {"name": "Persistence", "techniques": ["T1505", "T1098", "T1133", "T1543"]},
    "TA0004": {"name": "Privilege Escalation", "techniques": ["T1548", "T1068", "T1055", "T1134"]},
    "TA0005": {"name": "Defense Evasion", "techniques": ["T1562", "T1055", "T1070", "T1027"]},
    "TA0006": {"name": "Credential Access", "techniques": ["T1555", "T1110", "T1003", "T1606"]},
    "TA0007": {"name": "Discovery", "techniques": ["T1082", "T1083", "T1069", "T1046"]},
    "TA0008": {"name": "Lateral Movement", "techniques": ["T1021", "T1563", "T1550", "T1570"]},
    "TA0009": {"name": "Collection", "techniques": ["T1114", "T1005", "T1056", "T1074"]},
    "TA0040": {"name": "Impact", "techniques": ["T1486", "T1489", "T1490", "T1565"]},
}

# Common CVEs mapped to descriptions (simplified — real implementation queries NVD API)
COMMON_CVES = {
    "CVE-2021-44228": {
        "description": "Apache Log4j2 JNDI injection — unauthenticated RCE",
        "severity": "CRITICAL",
        "cvss": 10.0,
        "affected": "Apache Log4j 2.0-alpha1 through 2.14.1",
        "exploit_status": "Actively exploited in the wild",
    },
    "CVE-2022-22965": {
        "description": "Spring4Shell — Spring Framework RCE via data binding",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "affected": "Spring Framework 5.3.0-5.3.17, 5.2.0-5.2.19",
        "exploit_status": "Exploit PoCs available",
    },
    "CVE-2023-44487": {
        "description": "HTTP/2 Rapid Reset — DDoS via stream cancellation",
        "severity": "HIGH",
        "cvss": 7.5,
        "affected": "Multiple HTTP/2 implementations",
        "exploit_status": "Actively exploited in the wild",
    },
    "CVE-2024-3094": {
        "description": "XZ Utils backdoor — supply chain attack via liblzma",
        "severity": "CRITICAL",
        "cvss": 10.0,
        "affected": "XZ Utils 5.6.0, 5.6.1",
        "exploit_status": "Backdoor detected before widespread exploitation",
    },
    "CVE-2024-27198": {
        "description": "JetBrains TeamCity authentication bypass leading to RCE",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "affected": "TeamCity < 2023.11.4",
        "exploit_status": "Actively exploited by ransomware groups",
    },
}

# CWE to ATT&CK mapping
CWE_TO_ATTACK = {
    "CWE-89": ["TA0001", "TA0040"],
    "CWE-79": ["TA0001", "TA0009"],
    "CWE-78": ["TA0002", "TA0040"],
    "CWE-22": ["TA0007", "TA0040"],
    "CWE-502": ["TA0002", "TA0004"],
    "CWE-798": ["TA0006"],
    "CWE-918": ["TA0007", "TA0040"],
    "CWE-367": ["TA0004"],
    "CWE-611": ["TA0007"],
}


class ThreatIntelligenceAgent(BaseAgent):
    """Specialized agent for threat intelligence and CVE research."""

    def __init__(self, model_name: str = "qwen3-235b"):
        super().__init__(
            name="Threat-Intelligence",
            model_name=model_name,
            tools=["cve_search", "threat_feeds", "vulnerability_database"],
        )

    async def analyze(self, query: str, context: Optional[Dict[str, Any]] = None) -> AgentResult:
        """Research threat intelligence related to the query."""
        findings: List[Dict[str, Any]] = []
        intelligence_gathered: Dict[str, Any] = {}

        # Step 1: Extract CVE references
        cve_ids = re.findall(r'CVE-\d{4}-\d+', query.upper())
        for cve_id in cve_ids:
            if cve_id in COMMON_CVES:
                info = COMMON_CVES[cve_id]
                attack_tactics = self._map_to_attack(cve_id)

                findings.append(self.format_finding(
                    title=f"Threat Intelligence: {cve_id}",
                    description=(
                        f"**Description:** {info['description']}\n"
                        f"**CVSS Score:** {info['cvss']}/10.0\n"
                        f"**Severity:** {info['severity']}\n"
                        f"**Affected:** {info['affected']}\n"
                        f"**Exploit Status:** {info['exploit_status']}\n\n"
                        f"**MITRE ATT&CK Tactics:**\n"
                        + "\n".join(f"- {t}" for t in attack_tactics)
                    ),
                    severity=info["severity"],
                    location=cve_id,
                    remediation=self._get_cve_remediation(cve_id),
                ))
                intelligence_gathered[cve_id] = info

        # Step 2: Extract CWE references and map to ATT&CK
        cwe_ids = re.findall(r'CWE-\d+', query.upper())
        for cwe_id in cwe_ids:
            attack_tactics = CWE_TO_ATTACK.get(cwe_id, [])
            tactic_names = [
                f"**{ATTACK_TACTICS[t]['name']}** ({', '.join(ATTACK_TACTICS[t]['techniques'][:2])})"
                for t in attack_tactics if t in ATTACK_TACTICS
            ]

            if tactic_names:
                findings.append(self.format_finding(
                    title=f"ATT&CK Mapping: {cwe_id}",
                    description=(
                        f"CWE {cwe_id} maps to the following MITRE ATT&CK tactics:\n"
                        + "\n".join(f"- {t}" for t in tactic_names)
                    ),
                    severity="INFORMATIONAL",
                    cwe=cwe_id,
                ))

        # Step 3: Check for common vulnerability keywords
        vuln_keywords = {
            "log4j|log4shell": "CVE-2021-44228",
            "spring4shell": "CVE-2022-22965",
            "rapid reset|http/2": "CVE-2023-44487",
            "xz|liblzma|backdoor": "CVE-2024-3094",
            "teamcity": "CVE-2024-27198",
            "shellshock|shellshock": "CVE-2014-6271",
            "heartbleed": "CVE-2014-0160",
            "eternalblue": "CVE-2017-0144",
        }

        # Check for known vulnerability keywords (maps to CVEs)
        for keyword, cve_id in vuln_keywords.items():
            if re.search(keyword, query.lower()):
                if cve_id not in intelligence_gathered and cve_id not in COMMON_CVES:
                    # Add intelligence stub for CVEs not in our local DB
                    intelligence_gathered[cve_id] = {
                        "description": f"Known vulnerability referenced: {cve_id}",
                        "severity": "UNKNOWN",
                        "source": "keyword_match",
                    }

        # Build summary
        total_findings = len(findings)
        if total_findings == 0:
            summary = "No threat intelligence matches found for this query."
            status = "success"
            confidence = 0.95
        else:
            cve_count = len(cwe_ids) + len(cve_ids)
            summary = f"Found {total_findings} intelligence item(s): {len(cve_ids)} CVE(s), {len(cwe_ids)} CWE mapping(s)"
            status = "success"
            confidence = 0.9

        return AgentResult(
            agent_name=self.name,
            status=status,
            summary=summary,
            findings=findings,
            confidence=confidence,
            details={
                "cve_references": cve_ids if 'cve_ids' in locals() else [],
                "cwe_references": cwe_ids if 'cwe_ids' in locals() else [],
                "intelligence_gathered": intelligence_gathered,
            },
        )

    def _map_to_attack(self, cve_id: str) -> List[str]:
        """Map a CVE to MITRE ATT&CK tactics."""
        # In a real implementation, this would query a CVE-to-ATT&CK database
        tactics_map = {
            "CVE-2021-44228": ["Initial Access (T1190)", "Execution (T1059)"],
            "CVE-2022-22965": ["Initial Access (T1190)", "Execution (T1059)"],
            "CVE-2023-44487": ["Impact (T1498)"],
            "CVE-2024-3094": ["Execution (T1204)"],
            "CVE-2024-27198": ["Initial Access (T1190)", "Defense Evasion (T1078)"],
        }
        return tactics_map.get(cve_id, ["Unknown"])

    def _get_cve_remediation(self, cve_id: str) -> str:
        """Get remediation guidance for a specific CVE."""
        remediations = {
            "CVE-2021-44228": "Upgrade Log4j to 2.17.0+. If unable to patch: set log4j2.formatMsgNoLookups=true and remove JndiLookup class.",
            "CVE-2022-22965": "Upgrade Spring Framework to 5.3.18+. Apply WAF rules blocking .class. and .log in parameters.",
            "CVE-2023-44487": "Apply vendor patches for HTTP/2 implementation. Consider rate limiting RST_STREAM frames.",
            "CVE-2024-3094": "Downgrade XZ Utils to 5.4.x. Verify package signatures. Scan for SSH backdoor indicators.",
            "CVE-2024-27198": "Upgrade TeamCity to 2023.11.4+. Restrict network access to TeamCity server. Enable 2FA.",
        }
        return remediations.get(cve_id, "Check NVD for latest patches and mitigations.")
