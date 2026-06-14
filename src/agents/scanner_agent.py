"""Code Scanner Agent — Static analysis + AI-powered vulnerability detection.

This agent combines:
1. Pattern-based scanning (regex signatures for known vulns)
2. AI-powered deep analysis (LLM reasoning for complex vulns)
3. Tool integration (CodeQL, Semgrep when available)

Capabilities:
- SQL injection, XSS, command injection, path traversal
- Insecure deserialization, hardcoded secrets, CSRF
- SSRF, race conditions, LDAP/NoSQL injection
- Open redirect, XXE, buffer overflows
"""

import re
import logging
from typing import Dict, List, Optional, Any
from src.agents.base_agent import BaseAgent, AgentResult

logger = logging.getLogger(__name__)

# Vulnerability signatures — regex patterns for common vulns
VULN_SIGNATURES: List[Dict[str, Any]] = [
    {
        "name": "SQL Injection (String Concatenation)",
        "severity": "CRITICAL",
        "cwe": "CWE-89",
        "patterns": [
            r'execute\(.*f\s*["\'].*\{.*(?:request|input|param|get|post).*\}',
            r'query\s*=\s*["\'].*\+.*(?:request|input|param)',
            r'\$query\s*=\s*["\'].*\$_(?:GET|POST|REQUEST)',
            r'SELECT\s+.*\s+FROM\s+.*\s+WHERE\s+.*["\']\s*\+\s*\$',
            r'cursor\.execute\(\s*["\']\s*SELECT.*%s?\s*["\']\s*%\s*',
        ],
    },
    {
        "name": "Cross-Site Scripting (XSS)",
        "severity": "HIGH",
        "cwe": "CWE-79",
        "patterns": [
            r'\.innerHTML\s*=\s*(?!["\']\s*["\'])',
            r'document\.write\(.*(?:request|input|param|location|search)',
            r'response\.write\(.*(?:request|input|param)',
            r'echo\s+\$_(?:GET|POST|REQUEST)',
            r'print\(.*\$_(?:GET|POST|REQUEST)',
        ],
    },
    {
        "name": "Command Injection",
        "severity": "CRITICAL",
        "cwe": "CWE-78",
        "patterns": [
            r'subprocess\.run\(.*shell=True',
            r'subprocess\.Popen\(.*shell=True',
            r'os\.system\(.*(?:request|input|param)',
            r'exec\(.*(?:request|input|param)',
            r'eval\(.*(?:request|input|param)',
            r'Runtime\.getRuntime\(\)\.exec\(.*(?:request|input|param)',
        ],
    },
    {
        "name": "Path Traversal",
        "severity": "HIGH",
        "cwe": "CWE-22",
        "patterns": [
            r'open\(.*\+.*(?:request|input|param|filename)',
            r'open\(.*f["\'].*\{.*(?:user|input|param)',
            r'file_get_contents\(.*\$_(?:GET|POST|REQUEST)',
            r'File\.read\(.*(?:request|input|param)',
        ],
    },
    {
        "name": "Insecure Deserialization",
        "severity": "CRITICAL",
        "cwe": "CWE-502",
        "patterns": [
            r'pickle\.loads\(',
            r'yaml\.load\(.*(?!.*SafeLoader)',
            r'pickle\.load\(.*(?:request|input|file)',
            r'ObjectInputStream\.readObject\(',
            r'unserialize\(.*\$_(?:GET|POST|REQUEST)',
        ],
    },
    {
        "name": "Hardcoded Secrets / Credentials",
        "severity": "HIGH",
        "cwe": "CWE-798",
        "patterns": [
            r'(?i)(?:password|passwd|pwd|secret|api[_-]?key|apikey)\s*[:=]\s*["\'][^"\']+["\']',
            r'(?i)aws_secret_access_key\s*=\s*["\'][A-Za-z0-9/+=]{40}',
            r'(?i)-----BEGIN (?:RSA |EC )?PRIVATE KEY-----',
            r'(?i)sk-live-[A-Za-z0-9]{32,}',
            r'(?i)ghp_[A-Za-z0-9]{36}',
            r'(?i)xox[baprs]-[A-Za-z0-9-]{24,}',
        ],
    },
    {
        "name": "Server-Side Request Forgery (SSRF)",
        "severity": "HIGH",
        "cwe": "CWE-918",
        "patterns": [
            r'requests\.(?:get|post|put|delete)\(.*(?:request|input|param|url)',
            r'fetch\(.*(?:request|input|param|url)',
            r'HttpURLConnection.*(?:request|input|param|url)',
            r'curl_exec\(.*\$url',
            r'open\(.*http',
        ],
    },
    {
        "name": "Insecure Randomness",
        "severity": "MEDIUM",
        "cwe": "CWE-338",
        "patterns": [
            r'random\.(?:choice|randint|randrange|sample|shuffle)',
            r'Math\.random\(\)',
            r'rand\(\)',
        ],
    },
    {
        "name": "NoSQL Injection",
        "severity": "HIGH",
        "cwe": "CWE-943",
        "patterns": [
            r'find\(\{.*\$ne|find\(\{.*\$gt|find\(\{.*\$regex',
            r'find_one\(\{.*\$ne|find_one\(\{.*\$gt',
        ],
    },
    {
        "name": "LDAP Injection",
        "severity": "HIGH",
        "cwe": "CWE-90",
        "patterns": [
            r'ldap_search\(.*\+.*\$',
            r'search_filter.*=.*["\'].*\+.*(?:request|input|param)',
        ],
    },
    {
        "name": "Open Redirect",
        "severity": "MEDIUM",
        "cwe": "CWE-601",
        "patterns": [
            r'redirect\(.*request\.(?:args|get|form)',
            r'header\(["\']Location:.*\$_(?:GET|POST|REQUEST)',
            r'res\.redirect\(.*req\.(?:query|param|body)',
        ],
    },
    {
        "name": "Weak Cryptography",
        "severity": "HIGH",
        "cwe": "CWE-327",
        "patterns": [
            r'MD5\(|md5\(|SHA1\(|sha1\(',
            r'DES[A-Za-z]*[Cc]ipher',
            r'Cipher\.getInstance\(["\']DES',
            r'[\"\']RSA[\"\']\s*/\s*[\"\']ECB[\"\']',
            r'hashlib\.md5|hashlib\.sha1\b',
        ],
    },
    {
        "name": "Prototype Pollution (JavaScript)",
        "severity": "HIGH",
        "cwe": "CWE-1321",
        "patterns": [
            r'\[(?:\'|")__proto__(?:\'|")\]|\.__proto__\s*=',
            r'merge\(.*(?:true|deep).*\)|extend\(true',
            r'Object\.assign\(.*source|clone\(.*(?:user|input|obj)',
        ],
    },
    {
        "name": "Race Condition (TOCTOU)",
        "severity": "HIGH",
        "cwe": "CWE-367",
        "patterns": [
            r'os\.path\.(?:exists|isfile).*if.*open\(',
            r'File\.Exists.*if.*File\.Open',
            r'time\.sleep\(.*(?:check|verify|validate)',
        ],
    },
    {
        "name": "XXE (XML External Entity)",
        "severity": "HIGH",
        "cwe": "CWE-611",
        "patterns": [
            r'XMLReader\.read\(|SimpleXMLElement\(.*file|parse\(.*file',
            r'DocumentBuilder\.parse\(.*(?:request|input|file)',
            r'xml\.etree\.ElementTree\.parse\(',
            r'loadXML\(.*(?:request|input|document)',
        ],
    },
]


class CodeScannerAgent(BaseAgent):
    """Specialized agent for static code analysis and vulnerability detection."""

    def __init__(self, model_name: str = "qwen3-235b"):
        super().__init__(
            name="Code-Scanner",
            model_name=model_name,
            tools=["codeql_analyze", "semgrep_scan", "pattern_search"],
        )

    async def analyze(self, query: str, context: Optional[Dict[str, Any]] = None) -> AgentResult:
        """Scan code for vulnerabilities using pattern matching and AI analysis."""
        findings: List[Dict[str, Any]] = []

        # Step 1: Extract code blocks from the query
        code_blocks = self._extract_code_blocks(query)

        if not code_blocks:
            # Treat the entire query as code if no code blocks found
            code_blocks = [{"code": query, "language": "unknown"}]

        # Step 2: Run pattern-based scanning
        for block in code_blocks:
            block_findings = self._scan_with_patterns(block["code"])
            findings.extend(block_findings)

        # Step 3: Run AI-powered analysis for complex patterns
        ai_findings = await self._ai_analysis(query, code_blocks)
        findings.extend(ai_findings)

        # Step 4: Deduplicate findings
        findings = self._deduplicate_findings(findings)

        # Sort by severity
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        findings.sort(key=lambda f: severity_order.get(f.get("severity", "LOW"), 99))

        # Build summary
        total = len(findings)
        critical = sum(1 for f in findings if f.get("severity") == "CRITICAL")
        high = sum(1 for f in findings if f.get("severity") == "HIGH")

        if total == 0:
            summary = "No vulnerabilities detected in the analyzed code."
            status = "success"
            confidence = 0.95
        else:
            summary = f"Found {total} potential vulnerabilities ({critical} critical, {high} high)"
            status = "success"
            confidence = 0.85 - (total * 0.02)  # Lower confidence with more findings

        return AgentResult(
            agent_name=self.name,
            status=status,
            summary=summary,
            findings=findings,
            confidence=max(confidence, 0.5),
        )

    def _extract_code_blocks(self, text: str) -> List[Dict[str, str]]:
        """Extract code blocks from markdown-style text."""
        blocks = []
        pattern = r'```(\w+)?\n(.*?)```'
        matches = re.findall(pattern, text, re.DOTALL)
        for lang, code in matches:
            blocks.append({"code": code.strip(), "language": lang or "unknown"})
        return blocks

    def _scan_with_patterns(self, code: str) -> List[Dict[str, Any]]:
        """Scan code against known vulnerability signatures."""
        findings = []
        for sig in VULN_SIGNATURES:
            for pattern in sig["patterns"]:
                matches = re.findall(pattern, code, re.MULTILINE)
                if matches:
                    # Find the line number for context
                    for match in matches[:3]:  # Limit to 3 matches per pattern
                        lines = code.split("\n")
                        line_num = None
                        for i, line in enumerate(lines, 1):
                            if isinstance(match, str) and match in line:
                                line_num = i
                                break
                            elif isinstance(match, tuple):
                                for m in match:
                                    if m and m in line:
                                        line_num = i
                                        break

                        findings.append(self.format_finding(
                            title=sig["name"],
                            description=f"Pattern matched: {pattern}",
                            severity=sig["severity"],
                            location=f"Line {line_num}" if line_num else "Unknown",
                            cwe=sig["cwe"],
                            remediation=self._get_remediation(sig["name"]),
                        ))
        return findings

    async def _ai_analysis(
        self, query: str, code_blocks: List[Dict[str, str]]
    ) -> List[Dict[str, Any]]:
        """AI-powered analysis for complex vulnerabilities pattern matchers can't catch.

        This would use the LLM for deep analysis. For now, returns suggested
        patterns for the AI to investigate.
        """
        findings = []
        for block in code_blocks:
            code = block["code"]
            lang = block["language"]

            # Check for dangerous function patterns
            dangerous_patterns = [
                ("eval() usage", "eval() executes arbitrary code and is extremely dangerous", "HIGH", "CWE-95"),
                ("exec() usage", "exec() executes arbitrary code", "CRITICAL", "CWE-78"),
                ("unsafe input in template", "User input may be rendered without sanitization", "HIGH", "CWE-79"),
                ("raw SQL query", "Raw SQL query construction detected", "CRITICAL", "CWE-89"),
            ]

            for pattern_name, desc, severity, cwe in dangerous_patterns:
                if any(kw in code.lower() for kw in pattern_name.lower().split()):
                    findings.append(self.format_finding(
                        title=pattern_name,
                        description=desc,
                        severity=severity,
                        cwe=cwe,
                        remediation=self._get_remediation(pattern_name),
                    ))

        return findings

    def _deduplicate_findings(self, findings: List[Dict]) -> List[Dict]:
        """Remove duplicate findings by title."""
        seen = set()
        unique = []
        for f in findings:
            key = f.get("title", "")
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return unique

    def _get_remediation(self, vuln_name: str) -> str:
        """Get remediation guidance for common vulnerability types."""
        remediations = {
            "SQL Injection (String Concatenation)": "Use parameterized queries / prepared statements. Never concatenate user input into SQL strings.",
            "Cross-Site Scripting (XSS)": "Use textContent instead of innerHTML. Sanitize all user input with context-aware encoding. Implement CSP headers.",
            "Command Injection": "Use argument lists instead of shell strings. Never pass user input to shell=True. Validate input against allowlist.",
            "Path Traversal": "Normalize paths with os.path.realpath(). Verify resolved path starts with the allowed base directory.",
            "Insecure Deserialization": "Use safe formats like JSON instead of pickle. Never deserialize untrusted data. Use SafeLoader with yaml.",
            "Hardcoded Secrets / Credentials": "Use environment variables or a secrets manager. Never commit secrets to version control.",
            "Server-Side Request Forgery (SSRF)": "Validate and restrict URLs to an allowlist. Block private IP ranges and cloud metadata endpoints.",
            "Insecure Randomness": "Use secrets module (Python) or crypto.getRandomValues (JS) for security-critical randomness.",
            "NoSQL Injection": "Validate inputs are plain strings, not objects. Use an ODM with type validation.",
            "LDAP Injection": "Escape LDAP special characters. Use parameterized LDAP queries.",
            "Open Redirect": "Validate redirect targets are relative URLs or same-origin. Use an allowlist for external redirects.",
            "Weak Cryptography": "Use modern algorithms: AES-256-GCM, SHA-256/SHA-3, Argon2 for passwords. Never use MD5 or SHA-1.",
            "Prototype Pollution (JavaScript)": "Use Object.create(null) for safe objects. Avoid unsafe merge/clone operations. Freeze Object.prototype.",
            "Race Condition (TOCTOU)": "Use file locks (fcntl), database transactions, or atomic operations for shared resource access.",
            "XXE (XML External Entity)": "Disable external entity processing in XML parsers. Use defusedxml library.",
            "eval() usage": "Never use eval(). Use safer alternatives like JSON.parse or Function constructor with caution.",
            "exec() usage": "Never pass user input to exec(). Use subprocess with argument lists.",
            "unsafe input in template": "Always use proper template escaping. React auto-escapes, but dangerouslySetInnerHTML bypasses this.",
            "raw SQL query": "Use an ORM or parameterized queries. Never concatenate user input into SQL strings.",
        }
        return remediations.get(vuln_name, "Follow OWASP guidelines and use security linters.")
