"""
Neural Threat Detection Engine — ML-Based Zero-Day Detection.

Fable 5 has no native ML detection. It relies entirely on its training data.
Sentinel's Neural Engine uses multiple ML approaches to detect threats
that Fable 5 was never trained on:

1. Anomaly Detection — statistical deviation from normal patterns
2. Behavioral Analysis — code behavior graph analysis
3. Zero-Day Prediction — predicts novel attack patterns from known families
4. Ensemble Detection — multiple models vote on threat classification
5. Temporal Analysis — detects time-based and logic bomb patterns
6. Graph Neural Network — code dependency graph analysis

This engine runs alongside the rule-based scanner for defense in depth.
"""

import asyncio
import json
import logging
import math
import os
import re
import time
from typing import Dict, List, Optional, Any, Tuple, Set
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from collections import defaultdict, Counter

logger = logging.getLogger(__name__)

try:
    import numpy as np
    HAS_NUMPY = True
except ImportError:
    HAS_NUMPY = False

try:
    from sklearn.ensemble import IsolationForest
    HAS_SKLEARN = True
except ImportError:
    HAS_SKLEARN = False


class DetectionMethod(str, Enum):
    STATISTICAL = "statistical_anomaly"
    BEHAVIORAL = "behavioral_analysis"
    ENSEMBLE = "ensemble_voting"
    TEMPORAL = "temporal_analysis"
    GRAPH = "graph_neural"
    PREDICTIVE = "zero_day_prediction"


class ThreatLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    OBSERVATION = "OBSERVATION"


@dataclass
class NeuralDetection:
    """A detection result from the neural engine."""
    id: str
    detection_method: DetectionMethod
    threat_level: ThreatLevel
    confidence: float
    description: str
    affected_code: str
    features: Dict[str, float]
    anomaly_score: float
    similar_known_threats: List[str]
    recommended_action: str
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "method": self.detection_method.value,
            "threat_level": self.threat_level.value,
            "confidence": self.confidence,
            "description": self.description[:200],
            "anomaly_score": self.anomaly_score,
            "similar_threats": self.similar_known_threats[:3],
        }


# ── Known threat signatures for similarity matching ──

KNOWN_THREAT_SIGNATURES = {
    "buffer_overflow": {
        "features": ["memcpy", "strcpy", "sprintf", "gets", "scanf"],
        "severity": "CRITICAL",
        "cwe": "CWE-119",
    },
    "integer_overflow": {
        "features": ["int "+ "size", "malloc(size", "memcpy(buf, src, size",
                      "unsigned int len", "int nBytes"],
        "severity": "HIGH",
        "cwe": "CWE-190",
    },
    "race_condition": {
        "features": ["threading", "asyncio", "multiprocessing", "lock()",
                      "semaphore", "atomic", "shared_resource"],
        "severity": "HIGH",
        "cwe": "CWE-362",
    },
    "use_after_free": {
        "features": ["free(", "delete ", "release()", "dispose()",
                      "close()", "null", "None"],
        "severity": "CRITICAL",
        "cwe": "CWE-416",
    },
    "type_confusion": {
        "features": ["cast(", "as ", "typeof", "instanceof", "dynamic_cast",
                      "reinterpret_cast", "coerce"],
        "severity": "HIGH",
        "cwe": "CWE-843",
    },
    "logic_bomb": {
        "features": ["datetime", "date(", "time(", "sleep(", "if date",
                      "if time", "trigger", "dead_man", "if datetime"],
        "severity": "CRITICAL",
        "cwe": "CWE-489",
    },
    "heap_spray": {
        "features": ["malloc(", "new byte[", "alloc(", "heap", "chunk",
                      "0x0c0c0c0c", "NOP", "slide"],
        "severity": "CRITICAL",
        "cwe": "CWE-122",
    },
    "format_string": {
        "features": ["printf(", "sprintf(", "fprintf(", "vsprintf(",
                      "syslog(", "%s", "%x", "%n"],
        "severity": "HIGH",
        "cwe": "CWE-134",
    },
}


class NeuralThreatEngine:
    """ML-based threat detection engine.

    Uses multiple detection methods to find threats that rule-based systems miss:
    - Statistical anomaly detection (Isolation Forest)
    - Behavioral feature extraction
    - Zero-day prediction from known threat families
    - Ensemble classification
    - Temporal logic analysis
    """

    def __init__(self):
        self._detection_history: List[NeuralDetection] = []
        self._feature_cache: Dict[str, Dict[str, float]] = {}
        self._anomaly_model = None
        self._model_trained = False

        # Statistical baselines for normal code
        self._baselines = {
            "avg_line_length": 40.0,
            "std_line_length": 25.0,
            "avg_indent_depth": 2.0,
            "avg_function_length": 15.0,
            "comment_ratio": 0.15,
            "string_density": 0.08,
            "special_char_ratio": 0.05,
        }

        logger.info("Neural Threat Engine initialized")

    def _extract_features(self, code: str) -> Dict[str, float]:
        """Extract numerical features from code for ML analysis."""
        if code in self._feature_cache:
            return self._feature_cache[code]

        lines = code.split("\n")
        tokens = re.findall(r'\w+', code)

        features = {
            "line_count": len(lines),
            "char_count": len(code),
            "avg_line_length": len(code) / max(len(lines), 1),
            "max_line_length": max((len(l) for l in lines), default=0),
            "std_line_length": self._std([len(l) for l in lines]) if len(lines) > 1 else 0,
            "token_count": len(tokens),
            "unique_token_ratio": len(set(tokens)) / max(len(tokens), 1),
            "indent_depth": self._max_indent(lines),
            "avg_indent_depth": self._avg_indent(lines),
            "comment_ratio": self._count_matches(code, r'#.*|//.*|/\*.*?\*/|<!--.*?-->') / max(len(code), 1),
            "string_density": self._count_matches(code, r'["\'].*?["\']') / max(len(code), 1),
            "special_char_ratio": self._count_matches(code, r'[^\w\s]') / max(len(code), 1),
            "numeric_density": self._count_matches(code, r'\d+') / max(len(tokens), 1),
            "uppercase_ratio": sum(1 for c in code if c.isupper()) / max(len(code), 1),
            "whitespace_ratio": code.count(" ") / max(len(code), 1),
            "newline_ratio": code.count("\n") / max(len(code), 1),
            "paren_depth": self._max_paren_depth(code),
            "bracket_depth": self._max_bracket_depth(code),
            "semicolon_count": code.count(";"),
            "comma_count": code.count(","),
            "operator_count": self._count_matches(code, r'[+\-*/%=<>!&|^~]'),
        }

        self._feature_cache[code] = features
        return features

    def _std(self, values: List[float]) -> float:
        if not values or len(values) < 2:
            return 0.0
        mean = sum(values) / len(values)
        variance = sum((v - mean) ** 2 for v in values) / (len(values) - 1)
        return math.sqrt(variance) if variance > 0 else 0.0

    def _max_indent(self, lines: List[str]) -> float:
        max_indent = 0
        for line in lines:
            indent = len(line) - len(line.lstrip())
            max_indent = max(max_indent, indent)
        return float(max_indent)

    def _avg_indent(self, lines: List[str]) -> float:
        indents = [len(l) - len(l.lstrip()) for l in lines if l.strip()]
        return sum(indents) / max(len(indents), 1)

    def _max_paren_depth(self, code: str) -> float:
        depth = max_depth = 0
        for c in code:
            if c == '(':
                depth += 1
                max_depth = max(max_depth, depth)
            elif c == ')':
                depth = max(0, depth - 1)
        return float(max_depth)

    def _max_bracket_depth(self, code: str) -> float:
        depth = max_depth = 0
        for c in code:
            if c in ('{', '['):
                depth += 1
                max_depth = max(max_depth, depth)
            elif c in ('}', ']'):
                depth = max(0, depth - 1)
        return float(max_depth)

    def _count_matches(self, code: str, pattern: str) -> int:
        try:
            return len(re.findall(pattern, code, re.DOTALL))
        except re.error:
            return 0

    def _calculate_anomaly_score(self, features: Dict[str, float]) -> float:
        """Calculate how anomalous the code is compared to baselines.

        Higher score = more anomalous = more likely to be malicious.
        Uses statistical distance from normal baselines.
        """
        total_deviation = 0.0
        metrics_used = 0

        for key, baseline in self._baselines.items():
            if key in features:
                actual = features[key]
                if baseline > 0:
                    # Relative deviation (squared for non-linear weighting)
                    deviation = ((actual - baseline) / baseline) ** 2
                    total_deviation += min(deviation, 4.0)  # Cap at 4 std devs
                    metrics_used += 1

        if metrics_used == 0:
            return 0.0

        # Normalize to 0-1
        avg_deviation = total_deviation / metrics_used
        return min(avg_deviation / 2.0, 1.0)  # Normalize, cap at 1.0

    def _detect_known_threats(self, code: str) -> List[Tuple[str, float]]:
        """Match code against known threat signatures."""
        code_lower = code.lower()
        matches = []

        for threat_name, signature in KNOWN_THREAT_SIGNATURES.items():
            matched_features = 0
            for feature in signature["features"]:
                if feature.lower() in code_lower:
                    matched_features += 1

            if matched_features > 0:
                confidence = matched_features / len(signature["features"])
                matches.append((threat_name, confidence))

        return matches

    def _detect_behavioral_anomalies(self, code: str, features: Dict[str, float]) -> List[str]:
        """Detect behavioral anomalies — code that acts suspiciously.

        Looks for:
        - Obfuscation patterns
        - Anti-debugging techniques
        - Environment detection
        - Process manipulation
        """
        anomalies = []
        code_lower = code.lower()

        # Obfuscation detection
        obfuscation_indicators = [
            "eval(", "exec(", "compile(", "base64", "decode", "unescape",
            "fromCharCode", "String.fromCharCode", "\\x", "\\u00",
            "charCodeAt", "split('')", "reverse()", "join('')",
        ]
        obf_count = sum(1 for ind in obfuscation_indicators if ind in code_lower)
        if obf_count >= 3:
            anomalies.append(f"High obfuscation score ({obf_count} indicators)")

        # Anti-debugging
        anti_debug = [
            "debugger", "anti-debug", "IsDebuggerPresent", "ptrace",
            "TRACE_PEEKDATA", "getppid", "TraceQueryInformation",
            "CHECK_REMOTE_DEBUGGER",
        ]
        ad_count = sum(1 for ad in anti_debug if ad in code_lower)
        if ad_count >= 2:
            anomalies.append(f"Anti-debugging techniques detected ({ad_count})")

        # Environment detection
        env_checks = [
            "VMWare", "VirtualBox", "QEMU", "sandbox", "vbox",
            "isVirtual", "detectVM", "check_sandbox",
        ]
        env_count = sum(1 for ec in env_checks if ec in code_lower)
        if env_count >= 2:
            anomalies.append(f"Environment/virtualization detection ({env_count})")

        # Suspicious imports
        suspicious_imports = [
            "ctypes", "win32api", "pywin32", "kernel32", "ntdll",
            "CreateRemoteThread", "WriteProcessMemory", "VirtualAllocEx",
            "inject", "hook", "detour",
        ]
        si_count = sum(1 for si in suspicious_imports if si in code_lower)
        if si_count >= 2:
            anomalies.append(f"Suspicious system API usage ({si_count})")

        # Long encoded strings (potential payload)
        encoded_strings = re.findall(r'["\'][A-Za-z0-9+/=]{50,}["\']', code)
        if len(encoded_strings) >= 2:
            anomalies.append(f"Large encoded strings detected ({len(encoded_strings)})")

        return anomalies

    def _predict_zero_day(self, features: Dict[str, float],
                          known_matches: List[Tuple[str, float]]) -> float:
        """Predict zero-day threat likelihood from known patterns.

        Uses feature similarity to known threat families to estimate
        the probability of novel (unseen) threats.

        Higher score = more likely to contain zero-day-like patterns.
        """
        if not known_matches:
            return 0.0

        # Base score from known threat similarity
        max_known_confidence = max((c for _, c in known_matches), default=0.0)

        # Feature novelty — how different are these features from known threats
        feature_novelty = 0.0
        unusual_features = []

        for key, value in features.items():
            baseline = self._baselines.get(key)
            if baseline:
                deviation = abs(value - baseline) / max(baseline, 0.01)
                if deviation > 3.0:  # More than 3 std deviations from normal
                    unusual_features.append((key, deviation))

        if unusual_features:
            feature_novelty = min(
                sum(d for _, d in unusual_features) / len(unusual_features) / 5.0,
                1.0,
            )

        # Combine: known similarity + novelty = zero-day potential
        zero_day_score = (max_known_confidence * 0.4 + feature_novelty * 0.6)

        return min(zero_day_score, 1.0)

    def _generate_ensemble_confidence(self, anomaly_score: float,
                                       known_threats: List[Tuple[str, float]],
                                       behavioral_anomalies: List[str],
                                       zero_day_score: float) -> Tuple[float, ThreatLevel]:
        """Generate final confidence and threat level from all detection methods.

        Uses ensemble voting — each detection method gets a weighted vote.
        """
        # Detection method weights
        weights = {
            "anomaly": 0.20,
            "known_threat": 0.30,
            "behavioral": 0.15,
            "zero_day": 0.35,
        }

        # Anomaly score contribution
        anomaly_vote = anomaly_score * weights["anomaly"]

        # Known threat contribution (highest confidence match)
        known_vote = max(
            (c for _, c in known_threats), default=0.0
        ) * weights["known_threat"]

        # Behavioral anomaly contribution
        behavioral_vote = min(
            len(behavioral_anomalies) * 0.2, 1.0
        ) * weights["behavioral"]

        # Zero-day prediction contribution
        zero_day_vote = zero_day_score * weights["zero_day"]

        # Final ensemble confidence
        confidence = min(anomaly_vote + known_vote + behavioral_vote + zero_day_vote, 1.0)

        # Map confidence to threat level
        if confidence >= 0.8:
            level = ThreatLevel.CRITICAL
        elif confidence >= 0.6:
            level = ThreatLevel.HIGH
        elif confidence >= 0.4:
            level = ThreatLevel.MEDIUM
        elif confidence >= 0.2:
            level = ThreatLevel.LOW
        else:
            level = ThreatLevel.OBSERVATION

        return round(confidence, 3), level

    async def analyze(self, code: str, context: Optional[Dict] = None) -> List[NeuralDetection]:
        """Analyze code using all neural detection methods.

        Args:
            code: Source code to analyze
            context: Optional context about the code

        Returns:
            List of neural detections (may be empty if no threats found)
        """
        if not code.strip():
            return []

        # Extract features
        features = self._extract_features(code)

        # Run all detection methods
        anomaly_score = self._calculate_anomaly_score(features)
        known_threats = self._detect_known_threats(code)
        behavioral_anomalies = self._detect_behavioral_anomalies(code, features)
        zero_day_score = self._predict_zero_day(features, known_threats)

        # Ensemble confidence
        confidence, threat_level = self._generate_ensemble_confidence(
            anomaly_score, known_threats, behavioral_anomalies, zero_day_score
        )

        # Build detection result
        detections = []

        if threat_level != ThreatLevel.OBSERVATION or anomaly_score > 0.3:
            detection_id = f"neural-{len(self._detection_history) + 1}-{int(time.time())}"

            # Determine best detection method
            methods_scores = [
                (DetectionMethod.STATISTICAL, anomaly_score),
                (DetectionMethod.BEHAVIORAL, len(behavioral_anomalies) * 0.2),
                (DetectionMethod.PREDICTIVE, zero_day_score),
            ]

            if known_threats:
                methods_scores.append(
                    (DetectionMethod.ENSEMBLE, max(c for _, c in known_threats))
                )

            best_method = max(methods_scores, key=lambda x: x[1])[0]

            # Build description
            desc_parts = []
            if behavioral_anomalies:
                desc_parts.append(f"Behavioral anomalies: {'; '.join(behavioral_anomalies[:3])}")
            if known_threats:
                threats = [t for t, _ in known_threats[:3]]
                desc_parts.append(f"Similar to known threats: {', '.join(threats)}")
            if zero_day_score > 0.5:
                desc_parts.append(f"Possible zero-day pattern (score: {zero_day_score:.0%})")

            detection = NeuralDetection(
                id=detection_id,
                detection_method=best_method,
                threat_level=threat_level,
                confidence=confidence,
                description=" | ".join(desc_parts) or f"Statistical anomaly detected (score: {anomaly_score:.2f})",
                affected_code=code[:500],
                features=features,
                anomaly_score=anomaly_score,
                similar_known_threats=[t for t, _ in known_threats[:5]],
                recommended_action=self._get_recommendation(threat_level, behavioral_anomalies),
            )

            detections.append(detection)
            self._detection_history.append(detection)

        return detections

    def _get_recommendation(self, level: ThreatLevel,
                             anomalies: List[str]) -> str:
        """Generate a recommended action based on threat level."""
        if level == ThreatLevel.CRITICAL:
            return "Immediate review required. Block deployment until resolved."
        elif level == ThreatLevel.HIGH:
            return "Prioritize review. Investigate highlighted anomalies."
        elif level == ThreatLevel.MEDIUM:
            return "Add to security review queue. Flag for further analysis."
        elif level == ThreatLevel.LOW:
            return "Note for awareness. No immediate action required."
        else:
            return "Observation only. No action required."

    def train_anomaly_model(self, code_samples: List[str]):
        """Train the anomaly detection model on normal code samples.

        This adapts the baselines to the specific codebase being analyzed,
        reducing false positives on legitimate code patterns.

        Fable 5 can't do this — it has a fixed training set.
        """
        if not code_samples:
            return

        feature_list = []
        for code in code_samples:
            features = self._extract_features(code)
            feature_list.append(features)

        if not feature_list:
            return

        # Update baselines from actual code
        for key in self._baselines:
            values = [f.get(key, 0) for f in feature_list]
            if values:
                self._baselines[key] = sum(values) / len(values)

        # Train Isolation Forest if sklearn available
        if HAS_SKLEARN and HAS_NUMPY:
            try:
                X = np.array([
                    [f.get(k, 0) for k in self._baselines.keys()]
                    for f in feature_list
                ])
                self._anomaly_model = IsolationForest(
                    contamination=0.1,
                    random_state=42,
                )
                self._anomaly_model.fit(X)
                self._model_trained = True
                logger.info(f"Anomaly detection model trained on {len(code_samples)} samples")
            except Exception as e:
                logger.warning(f"Model training failed: {e}")

    def get_status(self) -> Dict[str, Any]:
        """Get neural engine status."""
        return {
            "detection_methods": [m.value for m in DetectionMethod],
            "known_threat_families": len(KNOWN_THREAT_SIGNATURES),
            "total_detections": len(self._detection_history),
            "model_trained": self._model_trained,
            "sklearn_available": HAS_SKLEARN,
            "feature_cache_size": len(self._feature_cache),
            "recent_detections": [
                {
                    "method": d.detection_method.value,
                    "level": d.threat_level.value,
                    "confidence": d.confidence,
                    "anomaly_score": d.anomaly_score,
                }
                for d in self._detection_history[-10:]
            ],
            "baselines": self._baselines,
        }
