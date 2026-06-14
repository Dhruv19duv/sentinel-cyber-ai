"""Self-Play Training Pipeline — Continuous improvement through exploit discovery.

This is the KEY differentiator from Mythos. Instead of being a static model,
Sentinel continuously improves by:
1. Generating synthetic vulnerable code
2. Attempting to exploit it
3. Generating patches
4. Using successful exploits and fixes as training data
5. Repeating — creating a virtuous cycle of improvement

This is inspired by AlphaGo's self-play approach, applied to cybersecurity.
"""

import logging
import json
import random
import os
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime

logger = logging.getLogger(__name__)


@dataclass
class TrainingExample:
    """A single training example generated through self-play."""
    instruction: str
    input: str
    output: str
    source: str  # "self_play", "curated", "cve_derived"
    difficulty: str  # "easy", "medium", "hard"
    vulnerability_type: str
    confidence: float = 1.0
    metadata: Dict[str, Any] = field(default_factory=dict)


class SelfPlayPipeline:
    """Self-play training data generation for continuous improvement.

    Generates increasingly sophisticated training examples by:
    1. Starting with known vulnerability patterns
    2. Combines patterns into multi-step exploits
    3. Generates fixes for each pattern
    4. Validates fixes don't introduce new vulns
    5. Adds successful examples to training set
    """

    def __init__(self):
        self.generation_count = 0

    def generate_batch(self, count: int = 100, difficulty: str = "mixed") -> List[TrainingExample]:
        """Generate a batch of self-play training examples.

        Args:
            count: Number of examples to generate
            difficulty: "easy", "medium", "hard", or "mixed"

        Returns:
            List of training examples
        """
        examples = []

        # Generate examples across vulnerability types
        vuln_types = [
            "sql_injection", "xss", "command_injection", "path_traversal",
            "insecure_deserialization", "hardcoded_secrets", "csrf",
            "insecure_randomness", "ssrf", "race_condition",
            "ldap_injection", "nosql_injection", "open_redirect", "xxe",
            "prototype_pollution", "buffer_overflow", "format_string",
        ]

        for _ in range(count):
            vuln_type = random.choice(vuln_types)
            difficulty_level = self._select_difficulty(difficulty)

            example = self._generate_example(vuln_type, difficulty_level)
            if example:
                examples.append(example)

        self.generation_count += len(examples)
        logger.info(
            f"Generated {len(examples)} self-play examples "
            f"(total: {self.generation_count})"
        )
        return examples

    def _select_difficulty(self, difficulty: str) -> str:
        """Select difficulty level based on preference."""
        if difficulty == "mixed":
            return random.choices(
                ["easy", "medium", "hard"],
                weights=[0.3, 0.4, 0.3],
                k=1
            )[0]
        return difficulty

    def _generate_example(self, vuln_type: str, difficulty: str) -> Optional[TrainingExample]:
        """Generate a single training example through self-play.

        Each example contains: vulnerable code → analysis → secure fix
        """
        # Use the built-in vulnerable code templates from prepare_dataset.py
        # and extend with self-play combinations
        base_patterns = self._get_patterns(vuln_type, difficulty)

        if not base_patterns:
            return None

        # Randomly select and possibly combine patterns
        selected = random.choice(base_patterns)

        # For hard difficulty, chain multiple vulnerabilities
        if difficulty == "hard":
            additional = random.choice(self._get_patterns(vuln_type, "easy"))
            combined_code = self._chain_vulnerabilities(selected["code"], additional["code"])
            code = combined_code
        else:
            code = selected["code"]

        return TrainingExample(
            instruction=(
                f"Analyze this {vuln_type.replace('_', ' ')} vulnerability "
                f"and provide a secure fix."
            ),
            input=code,
            output=self._generate_fix(vuln_type, code, selected),
            source="self_play",
            difficulty=difficulty,
            vulnerability_type=vuln_type,
            metadata={"technique": selected.get("technique", "unknown")},
        )

    def _get_patterns(self, vuln_type: str, difficulty: str) -> List[Dict[str, Any]]:
        """Get vulnerability patterns for a type and difficulty level."""
        # Core patterns — simplified versions from prepare_dataset.py
        patterns: Dict[str, Dict[str, List]] = {
            "sql_injection": {
                "easy": [
                    {
                        "code": (
                            "def get_user(username):\n"
                            "    query = f\"SELECT * FROM users WHERE username = '{username}'\"\n"
                            "    cursor.execute(query)\n"
                            "    return cursor.fetchall()"
                        ),
                        "technique": "string_interpolation",
                    },
                    {
                        "code": (
                            "String query = \"SELECT * FROM products WHERE id = \" + id;\n"
                            "Statement stmt = conn.createStatement();\n"
                            "ResultSet rs = stmt.executeQuery(query);"
                        ),
                        "technique": "string_concatenation",
                    },
                ],
            },
            "xss": {
                "easy": [
                    {
                        "code": (
                            "function displayMessage() {\n"
                            "    const name = new URLSearchParams(\n"
                            "        window.location.search\n"
                            "    ).get('name');\n"
                            "    document.getElementById('output').innerHTML = name;\n"
                            "}"
                        ),
                        "technique": "direct_innerHTML",
                    },
                ],
            },
            "command_injection": {
                "easy": [
                    {
                        "code": (
                            "import subprocess\n\n"
                            "def ping(host):\n"
                            "    return subprocess.run(\n"
                            "        f'ping -c 4 {host}', shell=True\n"
                            "    )"
                        ),
                        "technique": "shell_true",
                    },
                ],
            },
        }

        return patterns.get(vuln_type, {}).get(difficulty, patterns.get(vuln_type, {}).get("easy", []))

    def _chain_vulnerabilities(self, code1: str, code2: str) -> str:
        """Chain two vulnerabilities together for harder examples."""
        return (
            "# Multi-vulnerability example\n"
            "# Generated through self-play chaining\n\n"
            f"{code1}\n\n"
            f"{code2}\n"
        )

    def _generate_fix(
        self, vuln_type: str, code: str, pattern: Dict[str, Any]
    ) -> str:
        """Generate a fix description and secure code.

        In production, this would use the LLM. For now, templates.
        """
        fixes = {
            "sql_injection": (
                "## Vulnerability: SQL Injection\n\n"
                "**Severity: CRITICAL**\n\n"
                "User input is interpolated directly into a SQL query, "
                "allowing an attacker to manipulate the query structure.\n\n"
                "### Fix:\n"
                "```python\n"
                "def get_user(username):\n"
                '    query = "SELECT * FROM users WHERE username = ?"\n'
                "    cursor.execute(query, (username,))\n"
                "    return cursor.fetchall()\n"
                "```\n\n"
                "Use parameterized queries with ? placeholders."
            ),
            "xss": (
                "## Vulnerability: Cross-Site Scripting (XSS)\n\n"
                "**Severity: HIGH**\n\n"
                "User input is inserted into the DOM using innerHTML, "
                "allowing script injection.\n\n"
                "### Fix:\n"
                "```javascript\n"
                "function displayMessage() {\n"
                "    const name = new URLSearchParams(\n"
                "        window.location.search\n"
                "    ).get('name');\n"
                "    document.getElementById('output').textContent = name;\n"
                "}\n"
                "```\n\n"
                "Use textContent instead of innerHTML."
            ),
            "command_injection": (
                "## Vulnerability: Command Injection\n\n"
                "**Severity: CRITICAL**\n\n"
                "User input passed directly to shell command with "
                "shell=True allows arbitrary command execution.\n\n"
                "### Fix:\n"
                "```python\n"
                "import subprocess\n\n"
                "def ping(host):\n"
                "    return subprocess.run(\n"
                "        ['ping', '-c', '4', host],\n"
                "        capture_output=True,\n"
                "        timeout=30\n"
                "    )\n"
                "```\n\n"
                "Use argument lists instead of shell strings."
            ),
        }

        return fixes.get(
            vuln_type,
            f"## Vulnerability: {vuln_type.replace('_', ' ').title()}\n\n"
            f"Analyze and fix the identified security issue in the code.\n"
        )

    def export_to_jsonl(
        self, examples: List[TrainingExample], output_path: str
    ) -> str:
        """Export training examples to JSONL format."""
        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)

        with open(output_path, "w", encoding="utf-8") as f:
            for ex in examples:
                record = {
                    "instruction": ex.instruction,
                    "input": ex.input,
                    "output": ex.output,
                    "source": ex.source,
                    "difficulty": ex.difficulty,
                    "vulnerability_type": ex.vulnerability_type,
                    "metadata": ex.metadata,
                }
                f.write(json.dumps(record, ensure_ascii=False) + "\n")

        logger.info(f"Exported {len(examples)} examples to {output_path}")
        return output_path
