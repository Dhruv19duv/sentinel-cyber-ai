"""Dataset Generator — Creates training data from real-world CVEs and synthetic examples.

Generates high-quality training data from:
1. Real CVE descriptions (from NVD/OSV databases)
2. Synthetic vulnerable→secure code pairs
3. Multi-step exploit chains (for advanced training)
4. OWASP Top 10 scenarios
"""

import json
import os
import random
import logging
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime

logger = logging.getLogger(__name__)


@dataclass
class DatasetConfig:
    """Configuration for dataset generation."""
    total_examples: int = 1000
    real_cve_ratio: float = 0.3
    synthetic_ratio: float = 0.5
    exploit_chain_ratio: float = 0.2
    min_confidence: float = 0.7
    output_dir: str = "./data/processed"
    include_owasp: bool = True
    include_cwe_explanations: bool = True


class DatasetGenerator:
    """Generates comprehensive cybersecurity training datasets."""

    def __init__(self, config: Optional[DatasetConfig] = None):
        self.config = config or DatasetConfig()
        self._cve_cache: Dict[str, Any] = {}

    def generate_dataset(self) -> Dict[str, List[Dict[str, Any]]]:
        """Generate a complete dataset with train/val splits."""
        logger.info(
            f"Generating dataset: {self.config.total_examples} examples "
            f"(CVE: {self.config.real_cve_ratio:.0%}, "
            f"Synthetic: {self.config.synthetic_ratio:.0%}, "
            f"Chain: {self.config.exploit_chain_ratio:.0%})"
        )

        all_examples = []

        # Generate CVE-derived examples
        cve_count = int(self.config.total_examples * self.config.real_cve_ratio)
        all_examples.extend(self._generate_cve_examples(cve_count))

        # Generate synthetic examples
        synthetic_count = int(self.config.total_examples * self.config.synthetic_ratio)
        all_examples.extend(self._generate_synthetic_examples(synthetic_count))

        # Generate exploit chain examples (advanced)
        chain_count = int(self.config.total_examples * self.config.exploit_chain_ratio)
        all_examples.extend(self._generate_chain_examples(chain_count))

        # Add OWASP-specific examples
        if self.config.include_owasp:
            all_examples.extend(self._generate_owasp_examples(20))

        # Add CWE explanations
        if self.config.include_cwe_explanations:
            all_examples.extend(self._generate_cwe_explanations(15))

        # Shuffle and split
        random.shuffle(all_examples)
        split_idx = int(len(all_examples) * 0.9)

        logger.info(
            f"Generated {len(all_examples)} total examples "
            f"({split_idx} train, {len(all_examples) - split_idx} val)"
        )

        return {
            "train": all_examples[:split_idx],
            "val": all_examples[split_idx:],
        }

    def _generate_cve_examples(self, count: int) -> List[Dict[str, Any]]:
        """Generate training examples from CVE data."""
        # This would query NVD/OSV in production
        cve_templates = [
            {
                "id": "CVE-2024-XXXX",
                "type": "sql_injection",
                "code": (
                    "import sqlite3\n\n"
                    "def search_products(search_term):\n"
                    '    conn = sqlite3.connect("products.db")\n'
                    "    cursor = conn.cursor()\n"
                    '    query = f"SELECT * FROM products WHERE name LIKE \'%{search_term}%\'"\n'
                    "    cursor.execute(query)\n"
                    "    return cursor.fetchall()"
                ),
                "fix": (
                    "import sqlite3\n\n"
                    "def search_products(search_term):\n"
                    '    conn = sqlite3.connect("products.db")\n'
                    "    cursor = conn.cursor()\n"
                    '    query = "SELECT * FROM products WHERE name LIKE ?"\n'
                    "    cursor.execute(query, (f'%{search_term}%',))\n"
                    "    return cursor.fetchall()"
                ),
            },
            {
                "id": "CVE-2024-YYYY",
                "type": "path_traversal",
                "code": (
                    "def read_report(filename):\n"
                    '    base = "/var/reports/"\n'
                    "    path = base + filename\n"
                    "    with open(path, 'r') as f:\n"
                    "        return f.read()"
                ),
                "fix": (
                    "import os\n\n"
                    "def read_report(filename):\n"
                    '    base = "/var/reports/"\n'
                    "    path = os.path.normpath(os.path.join(base, filename))\n"
                    "    if not path.startswith(os.path.normpath(base)):\n"
                    "        raise PermissionError('Access denied')\n"
                    "    with open(path, 'r') as f:\n"
                    "        return f.read()"
                ),
            },
        ]

        examples = []
        for i in range(count):
            template = random.choice(cve_templates)
            examples.append({
                "instruction": (
                    f"Analyze this CVE-derived vulnerability "
                    f"and provide a secure fix."
                ),
                "input": template["code"],
                "output": (
                    f"## Vulnerability: {template['type'].replace('_', ' ').title()}\n\n"
                    f"**Referenced CVE:** {template['id']}\n\n"
                    f"### Vulnerable Code:\n"
                    f"```python\n{template['code']}\n```\n\n"
                    f"### Secure Fix:\n"
                    f"```python\n{template['fix']}\n```\n\n"
                    f"### What Changed:\n"
                    "The fix properly validates and sanitizes user input before "
                    "using it in file system operations."
                ),
                "source": "cve_derived",
                "cve_id": template["id"],
            })

        return examples

    def _generate_synthetic_examples(self, count: int) -> List[Dict[str, Any]]:
        """Generate synthetic vulnerable→safe code pairs."""
        # Re-use the patterns from prepare_dataset.py
        from scripts.prepare_dataset import VULNERABLE_CODE_EXAMPLES, CWE_EXAMPLES

        all_patterns = VULNERABLE_CODE_EXAMPLES + CWE_EXAMPLES
        examples = []

        for i in range(min(count, len(all_patterns) * 3)):
            pattern = random.choice(all_patterns)
            examples.append({
                "instruction": pattern.get("instruction", "Analyze this code for security vulnerabilities."),
                "input": pattern.get("input", ""),
                "output": pattern.get("output", ""),
                "source": "synthetic",
                "vulnerability_type": pattern.get("output", "").split("\n")[0].replace("## Vulnerability: ", ""),
            })

        return examples

    def _generate_chain_examples(self, count: int) -> List[Dict[str, Any]]:
        """Generate multi-step exploit chain examples for advanced training."""
        chain_patterns = [
            {
                "scenario": "SSRF → Internal Service → RCE",
                "code": (
                    "# SSRF to internal metadata service, then to Redis RCE\n\n"
                    "import requests\n\n"
                    "def fetch_url(url):\n"
                    "    # Step 1: SSRF to internal service\n"
                    "    resp = requests.get(url)\n"
                    "    \n"
                    "    # Step 2: Use leaked credentials to access internal API\n"
                    "    internal_url = f'http://internal-admin/{resp.text.strip()}'\n"
                    "    admin_resp = requests.get(internal_url)\n"
                    "    \n"
                    "    return admin_resp.text"
                ),
                "analysis": "Multi-step attack: SSRF → Metadata exfiltration → Internal pivot → Data breach",
            },
            {
                "scenario": "XSS → CSRF → Account Takeover",
                "code": (
                    "// XSS + CSRF chain for account takeover\n\n"
                    "fetch('/api/user/profile')\n"
                    "  .then(r => r.json())\n"
                    "  .then(user => {\n"
                    "      // Session hijacking via XSS\n"
                    "      fetch('/api/transfer', {\n"
                    "          method: 'POST',\n"
                    "          credentials: 'include',\n"
                    "          body: new URLSearchParams({\n"
                    "              to: attackerAccount,\n"
                    "              amount: '1000',\n"
                    "          })\n"
                    "      });\n"
                    "  });"
                ),
                "analysis": "Multi-step attack: XSS payload injection → Session theft → CSRF transfer → Fund theft",
            },
        ]

        examples = []
        for i in range(min(count, len(chain_patterns))):
            pattern = chain_patterns[i % len(chain_patterns)]
            examples.append({
                "instruction": f"Analyze this multi-step exploit chain: {pattern['scenario']}",
                "input": pattern["code"],
                "output": (
                    f"## Exploit Chain: {pattern['scenario']}\n\n"
                    f"**Severity: CRITICAL**\n\n"
                    f"{pattern['analysis']}\n\n"
                    "### Defense Layers Required:\n"
                    "1. Input validation and sanitization at every layer\n"
                    "2. Network segmentation (prevent SSRF to internal services)\n"
                    "3. CSRF tokens on all state-changing endpoints\n"
                    "4. Content Security Policy (mitigate XSS)\n"
                    "5. Proper authentication on internal services\n"
                    "6. Regular security audits and penetration testing"
                ),
                "source": "exploit_chain",
                "chain_type": pattern["scenario"],
            })

        return examples

    def _generate_owasp_examples(self, count: int) -> List[Dict[str, Any]]:
        """Generate OWASP Top 10 specific examples."""
        owasp_topics = [
            {
                "id": "A01:2021",
                "name": "Broken Access Control",
                "code": (
                    "@app.route('/admin/users')\n"
                    "def list_users():\n"
                    "    # No authorization check!\n"
                    "    users = db.query(\"SELECT * FROM users\")\n"
                    "    return jsonify(users)"
                ),
            },
            {
                "id": "A02:2021",
                "name": "Cryptographic Failures",
                "code": (
                    "import hashlib\n\n"
                    "def store_password(password):\n"
                    "    # Using MD5 — not cryptographically secure\n"
                    "    hashed = hashlib.md5(password.encode()).hexdigest()\n"
                    "    db.save(hashed)"
                ),
            },
            {
                "id": "A03:2021",
                "name": "Injection",
                "code": self._get_sql_injection_example(),
            },
        ]

        examples = []
        for topic in owasp_topics[:count]:
            examples.append({
                "instruction": f"Identify and fix the {topic['name']} vulnerability ({topic['id']}).",
                "input": topic["code"],
                "output": (
                    f"## OWASP {topic['id']}: {topic['name']}\n\n"
                    f"### Vulnerability\n"
                    f"This code contains {topic['name'].lower()} vulnerability.\n\n"
                    "### Fix\n"
                    "Apply proper access controls, authentication, and input validation.\n"
                    "See https://owasp.org/Top10/ for complete guidance."
                ),
                "source": "owasp",
                "owasp_id": topic["id"],
            })

        return examples

    def _generate_cwe_explanations(self, count: int) -> List[Dict[str, Any]]:
        """Generate CWE explanation examples."""
        cwe_list = [
            ("CWE-89", "SQL Injection"),
            ("CWE-79", "Cross-Site Scripting"),
            ("CWE-78", "Command Injection"),
            ("CWE-22", "Path Traversal"),
            ("CWE-502", "Insecure Deserialization"),
            ("CWE-798", "Hardcoded Credentials"),
            ("CWE-918", "SSRF"),
            ("CWE-338", "Insecure Randomness"),
            ("CWE-367", "Race Condition"),
            ("CWE-611", "XXE"),
            ("CWE-1321", "Prototype Pollution"),
            ("CWE-943", "NoSQL Injection"),
            ("CWE-90", "LDAP Injection"),
            ("CWE-601", "Open Redirect"),
            ("CWE-327", "Weak Cryptography"),
        ]

        examples = []
        for cwe_id, cwe_name in cwe_list[:count]:
            examples.append({
                "instruction": f"Explain {cwe_id}: {cwe_name} and how to prevent it.",
                "input": f"{cwe_id}: {cwe_name}",
                "output": (
                    f"## {cwe_id}: {cwe_name}\n\n"
                    f"**Description:** {self._get_cwe_description(cwe_id)}\n\n"
                    f"**Prevention:**\n"
                    f"{self._get_cwe_prevention(cwe_id)}\n\n"
                    "**Severity:** "
                    + ("CRITICAL" if cwe_id in ("CWE-89", "CWE-78", "CWE-502") else
                       "HIGH" if cwe_id in ("CWE-79", "CWE-22", "CWE-918", "CWE-943", "CWE-90") else
                       "MEDIUM")
                ),
                "source": "cwe_explanation",
                "cwe_id": cwe_id,
            })

        return examples

    def _get_cwe_description(self, cwe_id: str) -> str:
        descriptions = {
            "CWE-89": "The product constructs SQL commands using externally-influenced input without proper neutralization.",
            "CWE-79": "The product does not neutralize user input before placing it in web page output.",
            "CWE-78": "The product constructs shell commands using user input without proper neutralization.",
            "CWE-22": "The product uses external input to construct a pathname without proper validation.",
            "CWE-502": "The product deserializes untrusted data without sufficient verification.",
        }
        return descriptions.get(cwe_id, "Common weakness in software security.")

    def _get_cwe_prevention(self, cwe_id: str) -> str:
        preventions = {
            "CWE-89": "Use parameterized queries / prepared statements. Validate input types.",
            "CWE-79": "Use context-aware output encoding. Implement CSP headers.",
            "CWE-78": "Use argument lists instead of shell strings. Validate all inputs.",
            "CWE-22": "Canonicalize paths and verify they stay within the allowed directory.",
            "CWE-502": "Use safe serialization formats. Never deserialize untrusted data.",
        }
        return preventions.get(cwe_id, "Follow secure coding guidelines and OWASP recommendations.")

    def _get_sql_injection_example(self) -> str:
        return (
            "def authenticate(username, password):\n"
            "    query = f\"SELECT * FROM users \"\n"
            "    query += f\"WHERE username='{username}' \"\n"
            "    query += f\"AND password='{password}'\"\n"
            "    cursor.execute(query)\n"
            "    return cursor.fetchone() is not None"
        )

    def save_dataset(
        self,
        dataset: Dict[str, List[Dict[str, Any]]],
        output_dir: Optional[str] = None,
    ) -> Dict[str, str]:
        """Save dataset to JSONL files."""
        output_dir = output_dir or self.config.output_dir
        os.makedirs(output_dir, exist_ok=True)

        paths = {}
        for split_name, examples in dataset.items():
            path = os.path.join(output_dir, f"cyber_{split_name}.jsonl")
            with open(path, "w", encoding="utf-8") as f:
                for example in examples:
                    f.write(json.dumps(example, ensure_ascii=False) + "\n")
            paths[split_name] = path
            logger.info(f"Saved {len(examples)} {split_name} examples to {path}")

        return paths
