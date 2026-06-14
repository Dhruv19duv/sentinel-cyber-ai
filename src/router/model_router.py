"""Model Router — MoE-Style Query Routing.

Routes incoming security queries to the most capable agent based on:
- Intent classification (vulnerability, exploit, patch, threat intel, report)
- Required tool access (CodeQL, sandbox, CVE search)
- Model capability matching (reasoning depth, code understanding, multilingual)

This is the "gating network" for our multi-agent MoE system.
"""

import re
import logging
from typing import Dict, List, Optional, Tuple, Any

logger = logging.getLogger(__name__)

# Intent classification patterns — maps keywords to agent capabilities
INTENT_PATTERNS: Dict[str, List[str]] = {
    "vulnerability_detection": [
        r"\b(vulnerab|security flaw|bug|CWE-\d+|CVE-\d{4}|SQL\s*injection|XSS|buffer\s*overflow)\b",
        r"\b(RCE|remote\s*code\s*exec|command\s*inject|path\s*traversal)\b",
        r"\b(unsafe|insecure|dangerous|malicious|backdoor)\b",
        r"\b(analyze|scan|audit|review|inspect|check)\s+(code|app|source|repo)\b",
    ],
    "exploit_analysis": [
        r"\b(exploit|zero.?day|attack\s*vector|payload|shellcode)\b",
        r"\b(bypass|escalat|priv.esc|sandbox\s*escape|RCE)\b",
        r"\b(heap\s*spray|ROP|JIT|ASLR|DEP|CFG|control\s*flow)\b",
        r"\b(chain|trigger|leverag|weaponiz)\b",
    ],
    "patch_generation": [
        r"\b(fix|patch|remediate|mitigat|correct|repair|heal)\b",
        r"\b(secure\s*code|safe\s*impl|best\s*practice)\b",
        r"\b(hardening|sanitize|escape|validate|encode)\b",
        r"\b(rewrite|refactor|replace|upgrade|update)\s+to\s+(fix|secure|safe)\b",
    ],
    "threat_intelligence": [
        r"\b(CVE-\d{4}-\d+|advisory|NVD|mitre|ATT&CK)\b",
        r"\b(threat|intel|feeds|IoCs|indicator\s*of\s*compromise)\b",
        r"\b(campaign|APT|actor|group|nation\s*state)\b",
        r"\b(trend|landscape|evolution|emerging)\b",
    ],
    "report_generation": [
        r"\b(report|summary|overview|documentation|write.?up)\b",
        r"\b(compliance|audit|PCI|SOC2|ISO|HIPAA|GDPR)\b",
        r"\b(dashboard|metric|score|rating|grade)\b",
        r"\b(present|presentation|executive|stakeholder)\b",
    ],
}

# Tool requirements per agent
TOOL_REQUIREMENTS: Dict[str, List[str]] = {
    "Code-Scanner": ["codeql_analyze", "semgrep_scan", "pattern_search"],
    "Exploit-Analyzer": ["sandbox_execute", "binary_analysis", "exploit_database"],
    "Patch-Generator": ["codegen", "validate_patch", "test_runner"],
    "Threat-Intelligence": ["cve_search", "threat_feeds", "vulnerability_database"],
    "Report-Generator": ["report_writer", "markdown_render", "pdf_generate"],
}


def classify_intent(query: str) -> Tuple[str, float]:
    """Classify the intent of a security query and return confidence score.

    Returns:
        Tuple of (intent_name, confidence_0_to_1)
    """
    query_lower = query.lower()
    scores: Dict[str, float] = {}

    for intent, patterns in INTENT_PATTERNS.items():
        score = 0.0
        for pattern in patterns:
            matches = re.findall(pattern, query_lower, re.IGNORECASE)
            score += len(matches) * 0.25  # Each match adds 0.25 confidence
        scores[intent] = min(score, 1.0)

    if not scores or max(scores.values()) == 0:
        return "vulnerability_detection", 0.3  # Default fallback with low confidence

    best_intent = max(scores, key=scores.get)
    return best_intent, scores[best_intent]


def route_query(
    query: str,
    context: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Route a security query to the optimal agent.

    Args:
        query: The user's security query or code to analyze
        context: Optional context about previous queries, file types, etc.

    Returns:
        Routing decision with agent name, confidence, and reasoning
    """
    intent, confidence = classify_intent(query)

    # Map intent to agent
    intent_to_agent = {
        "vulnerability_detection": "Code-Scanner",
        "exploit_analysis": "Exploit-Analyzer",
        "patch_generation": "Patch-Generator",
        "threat_intelligence": "Threat-Intelligence",
        "report_generation": "Report-Generator",
    }

    primary_agent = intent_to_agent.get(intent, "Code-Scanner")

    # Determine if secondary agents are needed (for complex queries)
    secondary_agents: List[str] = []
    if confidence < 0.5 and primary_agent != "Code-Scanner":
        # Low confidence — add Code-Scanner as secondary for initial analysis
        secondary_agents.append("Code-Scanner")

    # Check if query contains code that needs patching
    if re.search(r"(fix|patch|secure|rewrite)\b", query.lower()) and confidence < 0.7:
        if "Patch-Generator" not in secondary_agents:
            secondary_agents.append("Patch-Generator")

    decision = {
        "query": query,
        "intent": intent,
        "confidence": round(confidence, 3),
        "primary_agent": primary_agent,
        "secondary_agents": secondary_agents,
        "tools_required": TOOL_REQUIREMENTS.get(primary_agent, []),
        "reasoning": (
            f"Classified as '{intent}' (confidence: {confidence:.1%}). "
            f"Routing to {primary_agent}"
            + (f" with secondary: {', '.join(secondary_agents)}" if secondary_agents else "")
            + "."
        ),
    }

    logger.info(f"Routing decision: {decision['reasoning']}")
    return decision


def get_available_models() -> List[Dict[str, Any]]:
    """Return the list of available models and their capabilities."""
    return [
        {
            "id": "deepseek-r1-671b",
            "name": "DeepSeek R1",
            "params": "671B (37B active)",
            "type": "MoE",
            "strength": "deep_reasoning",
            "min_vram_gb": 48,
            "license": "MIT",
        },
        {
            "id": "qwen3-235b",
            "name": "Qwen 3 235B",
            "params": "235B (24B active)",
            "type": "MoE",
            "strength": "code_understanding",
            "min_vram_gb": 16,
            "license": "Apache 2.0",
        },
        {
            "id": "mistral-large-675b",
            "name": "Mistral Large 3",
            "params": "675B (41B active)",
            "type": "MoE",
            "strength": "enterprise_security",
            "min_vram_gb": 48,
            "license": "Apache 2.0",
        },
    ]
