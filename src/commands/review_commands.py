"""
Review Slash Commands — Ported from Claude Code's code review commands.

Commands:
  /review           — Analyze code for issues and improvements
  /security-review  — Focused security vulnerability analysis
  /bughunter        — Deep bug hunting with exploit analysis
"""

from src.commands.base import PromptCommand

# ── /review ──

review_command = PromptCommand(
    name="review",
    description="Analyze code for issues, bugs, and improvements",
    prompt_template=(
        "You are a senior code reviewer. Review the following code for:\n"
        "1. Logic errors and bugs\n"
        "2. Performance issues\n"
        "3. Code quality and maintainability\n"
        "4. Security vulnerabilities\n"
        "5. Best practices violations\n\n"
        "Code to review:\n```\n{{args}}\n```\n\n"
        "{{context}}\n\n"
        "Provide findings with severity ratings and specific line references."
    ),
    agent_name="Code-Scanner",
    aliases=["r", "audit"],
)

# ── /security-review ──

security_review_command = PromptCommand(
    name="security-review",
    description="Focused security vulnerability analysis",
    prompt_template=(
        "You are a security engineer performing a focused security review. "
        "Analyze this code for:\n"
        "1. Injection vulnerabilities (SQL, NoSQL, command, LDAP)\n"
        "2. Authentication & authorization flaws\n"
        "3. Sensitive data exposure\n"
        "4. XML/YAML external entities\n"
        "5. Broken access control\n"
        "6. Security misconfigurations\n"
        "7. Cross-site scripting (XSS)\n"
        "8. Insecure deserialization\n"
        "9. Using components with known vulnerabilities\n"
        "10. Insufficient logging & monitoring\n\n"
        "Code:\n```\n{{args}}\n```\n\n"
        "{{context}}\n\n"
        "For each finding, include: CWE, severity, description, and remediation."
    ),
    agent_name="Code-Scanner",
    aliases=["sec", "security", "safer"],
)

# ── /bughunter ──

bughunter_command = PromptCommand(
    name="bughunter",
    description="Deep bug hunting with exploit chain analysis",
    prompt_template=(
        "You are an expert bug hunter. Perform deep analysis of this code for:\n"
        "1. Complex logic errors that could lead to security issues\n"
        "2. Race conditions and TOCTOU vulnerabilities\n"
        "3. Memory safety issues (buffer overflow, use-after-free)\n"
        "4. Exploit chain construction (multiple bugs chained)\n"
        "5. Edge cases and boundary conditions\n"
        "6. State machine flaws\n"
        "7. Cryptographic weaknesses\n"
        "8. Side-channel vulnerabilities\n\n"
        "Code:\n```\n{{args}}\n```\n\n"
        "{{context}}\n\n"
        "Focus on finding exploitable bugs, not just surface-level issues."
    ),
    agent_name="Exploit-Analyzer",
    aliases=["bug", "hunt", "exploit"],
)

# ── All review commands ──

REVIEW_COMMANDS = [
    review_command,
    security_review_command,
    bughunter_command,
]
