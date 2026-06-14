"""
Safety Classifier — Fable 5's safety system reimplementation.

Matches Fable 5's safety architecture:
- Safety classifiers that detect sensitive content
- stop_reason: "refusal" returned in HTTP 200 responses
- Server-side fallback mechanism
- Client-side fallback via SDK middleware
- Fallback credits for prompt caching costs
- Graceful refusal handling for agents

Fable 5 spec:
- Built-in safety classifiers
- Returns stop_reason: "refusal" on flagged requests
- Not billed for refused requests (we follow this pattern)
- Server-side fallback via fallbacks parameter
- Client-side fallback via SDK middleware
- Fallback credits for prompt caching
"""

import json
import logging
import re
import hashlib
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

logger = logging.getLogger(__name__)


class RefusalReason(str, Enum):
    """Reasons for refusing a request — matching Fable 5's classifiers."""
    HARMFUL_CONTENT = "harmful_content"
    DANGEROUS_CODE = "dangerous_code"
    EXPLOIT_GENERATION = "exploit_generation"
    MALWARE_CREATION = "malware_creation"
    PERSONAL_INFO = "personal_information"
    POLICY_VIOLATION = "policy_violation"
    RATE_LIMITED = "rate_limited"
    CONTEXT_OVERFLOW = "context_overflow"
    SANDBOX_ESCAPE = "sandbox_escape"


@dataclass
class SafetyResult:
    """Result from safety classification.
    
    Matches Fable 5's API response pattern where refusals
    return HTTP 200 with stop_reason: "refusal".
    """
    is_safe: bool
    refusal_reason: Optional[RefusalReason] = None
    stop_reason: str = "end_turn"  # "refusal" or "end_turn"
    confidence: float = 1.0
    matched_patterns: List[str] = field(default_factory=list)
    severity: str = "low"
    suggested_action: Optional[str] = None
    fallback_available: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "is_safe": self.is_safe,
            "refusal_reason": self.refusal_reason.value if self.refusal_reason else None,
            "stop_reason": self.stop_reason,
            "confidence": self.confidence,
            "matched_patterns": self.matched_patterns,
            "severity": self.severity,
            "suggested_action": self.suggested_action,
            "fallback_available": self.fallback_available,
        }


@dataclass
class SafetyRule:
    """A safety classification rule."""
    name: str
    patterns: List[str]
    refusal_reason: RefusalReason
    severity: str  # "low", "medium", "high", "critical"
    min_confidence: float = 0.7
    allow_fallback: bool = True
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "patterns": self.patterns[:3],  # Preview
            "refusal_reason": self.refusal_reason.value,
            "severity": self.severity,
            "allow_fallback": self.allow_fallback,
        }


# ── Safety Rules ──
# These define what content is flagged and what fallbacks are available.

SAFETY_RULES = [
    SafetyRule(
        name="Malware Creation",
        patterns=[
            r"\b(worm|virus|trojan|ransomware|keylogger|backdoor)\b.*\b(create|generate|write|build|code|implement)\b",
            r"\b(create|generate|write|build)\b.*\b(worm|virus|trojan|ransomware|keylogger|backdoor)\b",
            r"\bmalware\b.*\b(generate|write|create|build)\b",
            r"\b(payload|shellcode)\b.*\b(generate|encode|obfuscate)\b",
        ],
        refusal_reason=RefusalReason.MALWARE_CREATION,
        severity="critical",
        allow_fallback=False,
    ),
    SafetyRule(
        name="Harmful Content Generation",
        patterns=[
            r"\b(instructions|guide|tutorial)\b.*\b(self.?harm|suicide|harm)\b",
            r"\b(how to|ways to|methods for)\b.*\b(harm|hurt|injure)\b.*\b(self|yourself|myself)\b",
            r"\b(dox|doxing|doxx|doxxing)\b",
            r"\b(swatting|swat)\b.*\b(guide|how|instructions)\b",
        ],
        refusal_reason=RefusalReason.HARMFUL_CONTENT,
        severity="critical",
        allow_fallback=False,
    ),
    SafetyRule(
        name="Dangerous Code Patterns",
        patterns=[
            r"\b(rm\s+-rf\s+/\s*|format\s+[c-z]:\s*[/\\\\]|dd\s+if=)\b",
            r"\b(drop\s+database|drop\s+table|truncate\s+table)\b.*\b(production|prod|live)\b",
            r"\b(eval|exec)\s*\(.*\b(request|input|user|get|post)\b",
            r"\b(os\.system|subprocess\.call|subprocess\.Popen)\b.*\b(request\.GET|request\.POST|input\(\))\b",
        ],
        refusal_reason=RefusalReason.DANGEROUS_CODE,
        severity="high",
        allow_fallback=True,
        min_confidence=0.8,
    ),
    SafetyRule(
        name="Exploit Generation",
        patterns=[
            r"\b(exploit|0day|zero.?day)\b.*\b(generate|create|write|build|craft)\b",
            r"\b(rce|remote code execution)\b.*\b(exploit|payload)\b",
            r"\b(buffer overflow|heap overflow|stack overflow)\b.*\b(exploit|shellcode)\b",
            r"\b(sql injection|sqli)\b.*\b(automated|tool|scanner|bypass)\b",
        ],
        refusal_reason=RefusalReason.EXPLOIT_GENERATION,
        severity="high",
        allow_fallback=True,
        min_confidence=0.7,
    ),
    SafetyRule(
        name="Personal Information",
        patterns=[
            r"\b(ssn|social security|credit card|bank account)\b.*\b(extract|steal|collect|harvest)\b",
            r"\b(pii|personally identifiable|private key|api key|secret)\b.*\b(extract|dump|leak)\b",
            r"\b(password|credential|token|session)\b.*\b(dump|harvest|steal|extract)\b",
        ],
        refusal_reason=RefusalReason.PERSONAL_INFO,
        severity="high",
        allow_fallback=True,
    ),
    SafetyRule(
        name="Policy Violation",
        patterns=[
            r"\b(copyright|dmca|trademark)\b.*\b(bypass|circumvent|remove|crack)\b",
            r"\b(drm|digital rights|license key|activation)\b.*\b(crack|bypass|remove|generate)\b",
            r"\b(illegal|unlawful|illicit)\b.*\b(activity|operation|scheme|operation)\b",
        ],
        refusal_reason=RefusalReason.POLICY_VIOLATION,
        severity="medium",
        allow_fallback=True,
    ),
]


class SafetyClassifier:
    """Safety classifier that detects and handles sensitive content.
    
    Matches Fable 5's safety architecture:
    - Pattern-based detection of sensitive content
    - Returns stop_reason: "refusal" on flagged content
    - Supports graceful fallback to alternative models
    - Configurable strictness
    """
    
    def __init__(self, enable_classifiers: bool = True):
        self.enable_classifiers = enable_classifiers
        self._classification_history: List[Dict] = []
        self._refusal_count = 0
        
        # Compile patterns for efficiency
        self._compiled_rules = []
        for rule in SAFETY_RULES:
            compiled_patterns = []
            for pattern in rule.patterns:
                try:
                    compiled_patterns.append(re.compile(pattern, re.IGNORECASE))
                except re.error as e:
                    logger.warning(f"Invalid pattern in rule '{rule.name}': {e}")
            self._compiled_rules.append((rule, compiled_patterns))
        
        logger.info(f"Safety classifier initialized with {len(SAFETY_RULES)} rules")
    
    def classify(self, content: str) -> SafetyResult:
        """Classify content against safety rules.
        
        Returns a SafetyResult matching Fable 5's API response:
        - If safe: stop_reason="end_turn", is_safe=True
        - If flagged: stop_reason="refusal", is_safe=False, with refusal_reason
        
        Args:
            content: The content to classify
        Returns:
            SafetyResult with classification result
        """
        if not self.enable_classifiers:
            return SafetyResult(is_safe=True, stop_reason="end_turn")
        
        # Check content against all rules
        for rule, patterns in self._compiled_rules:
            matches = []
            for pattern in patterns:
                found = pattern.findall(content)
                if found:
                    matches.extend(found)
            
            if matches:
                # Calculate confidence based on number of matches
                confidence = min(1.0, len(matches) / 3)
                
                if confidence >= rule.min_confidence:
                    self._refusal_count += 1
                    
                    result = SafetyResult(
                        is_safe=False,
                        refusal_reason=rule.refusal_reason,
                        stop_reason="refusal",
                        confidence=confidence,
                        matched_patterns=list(set(matches[:5])),  # Top 5 unique matches
                        severity=rule.severity,
                        suggested_action=self._get_suggested_action(rule),
                        fallback_available=rule.allow_fallback,
                    )
                    
                    self._log_classification(content, result)
                    return result
        
        # Content is safe
        return SafetyResult(is_safe=True, stop_reason="end_turn")
    
    def classify_query(self, query: str) -> SafetyResult:
        """Classify a user query before processing.
        
        This is called before the query enters the agent pipeline.
        If flagged, the query is refused and the agent never sees it.
        """
        return self.classify(query)
    
    def classify_code(self, code: str) -> SafetyResult:
        """Classify code content for dangerous patterns.
        
        Matches Fable 5's code-level safety classifiers.
        """
        return self.classify(code)
    
    def _get_suggested_action(self, rule: SafetyRule) -> str:
        """Get suggested action for handling a refusal."""
        actions = {
            RefusalReason.MALWARE_CREATION: "Request cannot be fulfilled. This content is blocked.",
            RefusalReason.HARMFUL_CONTENT: "Request refused. Please rephrase without harmful intent.",
            RefusalReason.DANGEROUS_CODE: "Code contains dangerous patterns. Use parameterized queries and safe APIs instead.",
            RefusalReason.EXPLOIT_GENERATION: "Exploit generation is restricted. Focus on defensive security analysis.",
            RefusalReason.PERSONAL_INFO: "Cannot process requests involving extraction of personal information.",
            RefusalReason.POLICY_VIOLATION: "Request violates usage policy. Please rephrase.",
            RefusalReason.RATE_LIMITED: "Too many requests. Please wait and retry.",
            RefusalReason.CONTEXT_OVERFLOW: "Context too large. Please reduce the input.",
            RefusalReason.SANDBOX_ESCAPE: "Sandbox escape attempt detected. Session terminated.",
        }
        return actions.get(rule.refusal_reason, "Request refused.")
    
    def _log_classification(self, content: str, result: SafetyResult):
        """Log a safety classification event."""
        entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "refusal_reason": result.refusal_reason.value if result.refusal_reason else None,
            "confidence": result.confidence,
            "matched_patterns": result.matched_patterns,
            "severity": result.severity,
            "content_preview": content[:200],
        }
        self._classification_history.append(entry)
        
        if result.severity in ("high", "critical"):
            logger.warning(
                f"Safety block [{result.refusal_reason.value}] "
                f"(confidence={result.confidence:.0%}, severity={result.severity}): "
                f"{content[:100]}..."
            )
        else:
            logger.info(
                f"Safety flag [{result.refusal_reason.value}] "
                f"(confidence={result.confidence:.0%})"
            )
    
    def get_status(self) -> Dict[str, Any]:
        """Get classifier status."""
        return {
            "enabled": self.enable_classifiers,
            "total_rules": len(SAFETY_RULES),
            "refusal_count": self._refusal_count,
            "history_count": len(self._classification_history),
            "rules": [r.to_dict() for r in SAFETY_RULES],
        }


class FallbackManager:
    """Manages fallback behavior when content is refused.
    
    Matches Fable 5's fallback mechanism:
    - Server-side fallback: automatically retry with alternative model
    - Client-side fallback: middleware catches refusal and retries
    - Fallback credits: track costs from fallback rerouting
    """
    
    def __init__(self, safety_classifier: SafetyClassifier):
        self.classifier = safety_classifier
        self._fallback_history: List[Dict] = []
        self._fallback_credits: Dict[str, float] = {}  # model -> credits used
    
    def get_fallback_model(self, original_model: str, refusal_reason: RefusalReason) -> Optional[str]:
        """Determine which fallback model to use.
        
        Fable 5 routes refused requests to alternative models
        with different safety configurations.
        
        Falls back to: Opus 4.8 (in Fable 5's case)
        Our fallback: different agent with different model
        """
        fallback_map = {
            RefusalReason.EXPLOIT_GENERATION: {
                "fallback_model": "code-scanner",
                "reason": "Routing to code scanner for defensive analysis only",
            },
            RefusalReason.DANGEROUS_CODE: {
                "fallback_model": "patch-generator",
                "reason": "Routing to patch generator for secure code review",
            },
            RefusalReason.POLICY_VIOLATION: {
                "fallback_model": "report-generator",
                "reason": "Routing to report generator for policy-compliant response",
            },
            RefusalReason.PERSONAL_INFO: {
                "fallback_model": "threat-intelligence",
                "reason": "Routing to threat intel for anonymized analysis",
            },
        }
        
        fallback = fallback_map.get(refusal_reason)
        if fallback:
            logger.info(f"Fallback: {original_model} -> {fallback['fallback_model']} ({fallback['reason']})")
            return fallback['fallback_model']
        
        return None
    
    def record_fallback(self, original_model: str, fallback_model: str, tokens_saved: int = 0):
        """Record a fallback event and credits."""
        entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "original_model": original_model,
            "fallback_model": fallback_model,
            "tokens_saved": tokens_saved,
        }
        self._fallback_history.append(entry)
        
        # Track fallback credits (like Fable 5's fallback credit system)
        credit_key = f"{original_model}->{fallback_model}"
        self._fallback_credits[credit_key] = self._fallback_credits.get(credit_key, 0) + tokens_saved
    
    def get_status(self) -> Dict[str, Any]:
        """Get fallback manager status."""
        return {
            "total_fallbacks": len(self._fallback_history),
            "fallback_history": self._fallback_history[-10:],  # Last 10
            "credits": self._fallback_credits,
        }
