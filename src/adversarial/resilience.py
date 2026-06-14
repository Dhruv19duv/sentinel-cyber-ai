"""
Adversarial ML Resistance System — Anti-Evasion & Robustness.

Fable 5 has no adversarial defense — it's a single model that can be
manipulated. Sentinel's Adversarial System provides:

1. Prompt injection detection — identifies jailbreak attempts
2. Adversarial input filtering — detects evasion techniques
3. Model robustness monitoring — tracks attack success rates
4. Evasion technique database — keeps up with new attack methods
5. Response sanitization — prevents sensitive data leakage
6. Behavioral consistency checking — detects manipulation
"""

import logging
import re
import json
import hashlib
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

logger = logging.getLogger(__name__)


class AttackType(str, Enum):
    PROMPT_INJECTION = "prompt_injection"
    JAILBREAK = "jailbreak"
    ADVERSARIAL_SUFFIX = "adversarial_suffix"
    ROLE_PLAYING = "role_playing_bypass"
    ENCODING_BYPASS = "encoding_bypass"
    CONTEXT_MANIPULATION = "context_manipulation"
    PAYLOAD_SPLITTING = "payload_splitting"
    FEW_SHOT_MANIPULATION = "few_shot_manipulation"
    REFUSAL_SUPPRESSION = "refusal_suppression"
    TOKEN_MANIPULATION = "token_manipulation"


class ThreatLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class AdversarialDetection:
    """A detected adversarial attack attempt."""
    id: str
    attack_type: AttackType
    threat_level: ThreatLevel
    confidence: float
    evidence: List[str]
    targeted_system: str
    technique: str
    mitigated: bool
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "attack_type": self.attack_type.value,
            "threat_level": self.threat_level.value,
            "confidence": self.confidence,
            "technique": self.technique,
            "mitigated": self.mitigated,
        }


# ── Known attack patterns ──

ATTACK_SIGNATURES = {
    AttackType.PROMPT_INJECTION: {
        "patterns": [
            r"ignore\s+(all\s+)?(previous|prior|above)\s+(instructions|directions|commands|rules)",
            r"disregard\s+(all\s+)?(previous|prior)\s+(instructions|rules)",
            r"forget\s+(everything|all)\s+(you\s+)?(know|learned|told)",
            r"new\s+(instructions|directions|task)\s*:?\s*ignore",
            r"you\s+(are\s+)?(now|will\s+now)\s+(free|unleashed|unbounded|unconstrained)",
            r"override\s+(all\s+)?(previous|system)\s+(directives|instructions|commands)",
            r"your\s+(constraints|limitations|restrictions|boundaries)\s+(are\s+)?(gone|removed|lifted)",
        ],
        "severity": "critical",
    },
    AttackType.JAILBREAK: {
        "patterns": [
            r"DAN(\s|$)",
            r"(do\s+)?anything\s+now",
            r"jail\s*break",
            r"jailbroken",
            r"no\s+(restrictions|limits|boundaries|filtering|content\s+policy)",
            r"unfiltered\s+(mode|version|access)",
            r"hypothetical\s+(scenario|situation|story)\s+.*(no\s+)?(restrictions|limits|rules)",
            r"for\s+(research|educational|academic)\s+(purposes|reasons)\s+only.*(hack|exploit|bypass)",
            r"simulate\s+(.*)(no\s+)?(restrictions|limitations|ethics|morals|safety)",
            r"act\s+as\s+(.*)(without|bypassing|ignoring)\s+(safety|ethics|restrictions)",
        ],
        "severity": "critical",
    },
    AttackType.ADVERSARIAL_SUFFIX: {
        "patterns": [
            r"!\s*!\s*[A-Za-z0-9+/]{10,}\s*!\s*!",
            r"![A-Za-z0-9+/]{20,}!",
            r"\[INST\].*\[/INST\]",
            r"\[SYS\].*\[/SYS\]",
            r"user:\s*.*assistant:\s*",
            r"<\|im_start\|>.*<\|im_end\|>",
            r"\{system\}.*\{/system\}",
        ],
        "severity": "high",
    },
    AttackType.ROLE_PLAYING: {
        "patterns": [
            r"act\s+as\s+(if\s+)?(you\s+are\s+)?(.*)(without|regardless\s+of)\s+(safety|restrictions|ethics)",
            r"pretend\s+(you\s+)?(are|to\s+be)\s+(.*)(without|ignoring)\s+(rules|policies|restrictions)",
            r"role\s*play\s+(as|scenario|where|that)",
            r"you\s+are\s+now\s+(a\s+)?(.*)(with\s+no|without\s+any)\s+(restrictions|limitations|guardrails)",
        ],
        "severity": "high",
    },
    AttackType.ENCODING_BYPASS: {
        "patterns": [
            r"base64\s*(encode|decode|encrypt|decrypt).*instruction",
            r"rot13|rot47",
            r"hex\s*(encode|decode|convert).*instruction",
            r"Caesar\s+cypher.*instruction",
            r"binary\s*(encode|decode|represent).*instruction",
            r"reverse\s+(the\s+)?(string|text|sentence).*instruction",
            r"morse\s+code.*instruction",
            r"atbash.*instruction",
        ],
        "severity": "high",
    },
    AttackType.CONTEXT_MANIPULATION: {
        "patterns": [
            r"context\s+(window|limit|overflow|exhausted)",
            r"token\s+(limit|exhausted|budget|overflow)",
            r"memory\s+(full|exhausted|overflow)",
            r"(too\s+)?(many|much)\s+(tokens|context|memory)",
            r"continue\s+(from|where)\s+(you\s+)?(left\s+off|stopped)",
            r"ignore\s+(everything\s+)?(above|before|prior)",
            r"only\s+(consider|read|use)\s+(the\s+)?(last|most\s+recent)",
        ],
        "severity": "medium",
    },
    AttackType.PAYLOAD_SPLITTING: {
        "patterns": [
            r"(first|second|third|part\s+\d+|step\s+\d+).*(instruction|command|task|message)",
            r"split\s+(the\s+)?(following|below|this)\s+(into|across)",
            r"separate\s+(messages|parts|chunks)",
            r"piece\s+(by\s+)?piece",
            r"bit\s+by\s+bit",
            r"gradually\s+(reveal|build|construct)",
        ],
        "severity": "medium",
    },
    AttackType.REFUSAL_SUPPRESSION: {
        "patterns": [
            r"(don't|do\s+not|never)\s+(refuse|decline|deny|reject|block)",
            r"(always|must|need\s+to)\s+(comply|obey|follow)\s+.*(without|regardless).*refusal",
            r"(do\s+)?not\s+(say|respond|answer|reply)\s+(with|using)\s+(.*)(cannot|unable|sorry)",
            r"(do\s+)?not\s+(apologize|say\s+sorry|explain\s+why)",
            r"(just|simply)\s+(do|answer|respond|provide)\s+(it|the\s+answer)",
        ],
        "severity": "high",
    },
    AttackType.FEW_SHOT_MANIPULATION: {
        "patterns": [
            r"user:\s*.*assistant:\s*.*user:\s*.*assistant:",
            r"example\s+\d+:",
            r"here\s+(are|is)\s+(some\s+)?(examples|demonstrations|illustrations)",
            r"few\s+shot",
            r"demonstration\s+\d+:",
            r"like\s+(this|so|the\s+following).*user:.*assistant:",
        ],
        "severity": "medium",
    },
    AttackType.TOKEN_MANIPULATION: {
        "patterns": [
            r"token\s+(greedy|sampling|temperature|top.k|top.p)",
            r"temperature.*(0\.\d+|1\.\d+|2\.\d+)",
            r"increase\s+(creativity|randomness|variety)",
            r"disable\s+(filter|filtering|moderation|safety)",
            r"remove\s+(guardrails|safety|moderation|filters|restrictions)",
            r"no\s+(moderation|filtering|review|oversight)",
        ],
        "severity": "high",
    },
}


class AdversarialResilience:
    """Defense system against adversarial attacks.

    Protects Sentinel from:
    - Prompt injection attacks
    - Jailbreak attempts
    - Encoding-based bypasses
    - Context manipulation
    - Role-playing attacks
    """

    def __init__(self):
        self._detections: List[AdversarialDetection] = []
        self._blocked_attempts = 0
        self._total_checked = 0

        # Compile patterns
        self._compiled_patterns = {}
        for attack_type, signature in ATTACK_SIGNATURES.items():
            self._compiled_patterns[attack_type] = [
                re.compile(p, re.IGNORECASE) for p in signature["patterns"]
            ]

        logger.info(f"Adversarial Resilience initialized ({sum(len(v) for v in self._compiled_patterns.values())} patterns)")

    def analyze_input(self, input_text: str, source: str = "user") -> List[AdversarialDetection]:
        """Analyze input for adversarial attacks.

        Args:
            input_text: The input to check
            source: Source identifier

        Returns:
            List of detected attacks (empty if safe)
        """
        self._total_checked += 1
        detections = []

        # Check against all attack signatures
        for attack_type, patterns in self._compiled_patterns.items():
            evidence = []

            for pattern in patterns:
                matches = pattern.findall(input_text)
                if matches:
                    evidence.extend(matches[:3])

            if evidence:
                severity = ATTACK_SIGNATURES[attack_type]["severity"]
                confidence = min(1.0, len(evidence) * 0.4)

                detection = AdversarialDetection(
                    id=f"adv-{len(self._detections) + 1}-{hashlib.md5(input_text.encode()[:50]).hexdigest()[:8]}",
                    attack_type=attack_type,
                    threat_level=ThreatLevel(severity),
                    confidence=confidence,
                    evidence=evidence,
                    targeted_system=source,
                    technique=attack_type.value.replace("_", " ").title(),
                    mitigated=severity in ("critical", "high"),
                )
                detections.append(detection)

        # Additional checks
        detections.extend(self._additional_checks(input_text))

        # Record detections
        for d in detections:
            self._detections.append(d)
            if d.threat_level in (ThreatLevel.CRITICAL, ThreatLevel.HIGH):
                self._blocked_attempts += 1
                logger.warning(f"Adversarial attack detected: {d.attack_type.value} "
                              f"(confidence={d.confidence:.0%})")

        return detections

    def _additional_checks(self, text: str) -> List[AdversarialDetection]:
        """Run additional heuristic checks."""
        detections = []
        text_lower = text.lower()

        # Check for unusual character distributions
        special_ratio = sum(1 for c in text if not c.isalnum() and not c.isspace()) / max(len(text), 1)
        if special_ratio > 0.3:
            detections.append(AdversarialDetection(
                id=f"adv-heuristic-{len(self._detections) + 1}",
                attack_type=AttackType.ADVERSARIAL_SUFFIX,
                threat_level=ThreatLevel.MEDIUM,
                confidence=min(1.0, special_ratio),
                evidence=[f"High ratio of special characters ({special_ratio:.0%})"],
                targeted_system="input_filter",
                technique="Special Character Anomaly",
                mitigated=True,
            ))

        # Check for base64-like strings (potential payload)
        b64_patterns = re.findall(r'[A-Za-z0-9+/]{40,}={0,2}', text)
        if len(b64_patterns) > 0:
            detections.append(AdversarialDetection(
                id=f"adv-encoded-{len(self._detections) + 1}",
                attack_type=AttackType.ENCODING_BYPASS,
                threat_level=ThreatLevel.MEDIUM,
                confidence=0.6,
                evidence=[f"Large encoded string detected ({len(b64_patterns)} matches)"],
                targeted_system="input_filter",
                technique="Encoded Payload Detection",
                mitigated=True,
            ))

        return detections

    def sanitize_response(self, response: str, context: Optional[Dict] = None) -> str:
        """Sanitize responses to prevent sensitive data leakage.

        Removes or redacts:
        - API keys and secrets
        - Internal IP addresses
        - Private keys
        - Connection strings
        - Stack traces that might reveal internals
        """
        sanitized = response

        # Redact API keys
        sanitized = re.sub(
            r'(sk-[A-Za-z0-9]{20,}|pk-[A-Za-z0-9]{20,}|[A-Za-z0-9]{32,40})',
            '[REDACTED_KEY]',
            sanitized,
        )

        # Redact private keys
        sanitized = re.sub(
            r'-----BEGIN\s+(?:RSA|EC|DSA|PRIVATE|OPENSSH)\s+KEY-----.*?-----END\s+\1\s+KEY-----',
            '[REDACTED_PRIVATE_KEY]',
            sanitized,
            flags=re.DOTALL,
        )

        # Redact internal IPs
        sanitized = re.sub(
            r'\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b',
            '[REDACTED_INTERNAL_IP]',
            sanitized,
        )

        # Redact connection strings
        sanitized = re.sub(
            r'(postgresql|mysql|mongodb|redis)://[^@\s]+@',
            r'\1://[REDACTED_CREDENTIALS]@',
            sanitized,
        )

        # Redact AWS ARNs
        sanitized = re.sub(
            r'arn:aws:[a-z]+:[a-z0-9-]+:\d{12}:',
            'arn:aws:[REDACTED]:',
            sanitized,
        )

        return sanitized

    def get_attack_statistics(self) -> Dict[str, Any]:
        """Get statistics on detected attacks."""
        by_type = {}
        for attack_type in AttackType:
            count = sum(1 for d in self._detections if d.attack_type == attack_type)
            if count > 0:
                by_type[attack_type.value] = count

        return {
            "total_checked": self._total_checked,
            "total_blocked": self._blocked_attempts,
            "block_rate": round(self._blocked_attempts / max(self._total_checked, 1), 4),
            "attacks_by_type": by_type,
            "recent_attacks": [
                {
                    "type": d.attack_type.value,
                    "level": d.threat_level.value,
                    "confidence": d.confidence,
                    "technique": d.technique,
                }
                for d in self._detections[-20:]
            ],
            "total_patterns": sum(len(v) for v in self._compiled_patterns.values()),
            "coverage": len(ATTACK_SIGNATURES),
        }

    def get_status(self) -> Dict[str, Any]:
        return self.get_attack_statistics()
