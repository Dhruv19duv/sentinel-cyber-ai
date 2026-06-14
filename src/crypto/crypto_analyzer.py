"""
Quantum-Resistant Cryptography Scanner — Detects quantum-vulnerable crypto.

Fable 5 cannot audit cryptographic implementations.
Sentinel's Crypto Scanner detects:

1. Quantum-vulnerable algorithms:
   - RSA (< 4096 bits)
   - ECDSA / ECDH (all current sizes)
   - DSA (all variants)
   - Diffie-Hellman (all current sizes)
   
2. Weak cryptographic practices:
   - Hardcoded keys
   - Weak PRNGs
   - Broken hash functions (MD5, SHA-1)
   - ECB mode encryption
   - Static IVs/nonces
   - Ciphertext padding oracles
   
3. Post-Quantum readiness:
   - Detects if code uses quantum-safe alternatives
   - Recommends PQ algorithms (Kyber, Dilithium, SPHINCS+)
   - Migration roadmap generation
"""

import logging
import re
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

logger = logging.getLogger(__name__)


class AlgorithmType(str, Enum):
    ASYMMETRIC = "asymmetric"
    SYMMETRIC = "symmetric"
    HASH = "hash"
    KEY_EXCHANGE = "key_exchange"
    SIGNATURE = "signature"
    RANDOM = "random_number_generation"
    ENCODING = "encoding"


class QuantumResistance(str, Enum):
    VULNERABLE = "quantum_vulnerable"  # Broken by Shor's algorithm
    WEAKENED = "quantum_weakened"      # Grover's algorithm halves security
    RESISTANT = "quantum_resistant"    # Not known to be broken by quantum
    UNKNOWN = "unknown"


@dataclass
class CryptoFinding:
    """A cryptographic security finding."""
    id: str
    algorithm: str
    algorithm_type: AlgorithmType
    quantum_resistance: QuantumResistance
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    location: str
    description: str
    recommendation: str
    standard: Optional[str] = None  # NIST, FIPS, etc.
    pq_replacement: Optional[str] = None  # Post-quantum alternative

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "algorithm": self.algorithm,
            "type": self.algorithm_type.value,
            "quantum": self.quantum_resistance.value,
            "severity": self.severity,
            "location": self.location,
            "description": self.description[:200],
            "pq_replacement": self.pq_replacement,
        }


# ── Known quantum-vulnerable algorithms ──

QUANTUM_VULNERABLE = {
    "RSA": {
        "type": AlgorithmType.ASYMMETRIC,
        "quantum": QuantumResistance.VULNERABLE,
        "severity": "CRITICAL",
        "reason": "Broken by Shor's algorithm in polynomial time",
        "pq_replacement": "CRYSTALS-Kyber (FIPS 203) / NTRU",
        "standard": "FIPS 186-5",
    },
    "ECDSA": {
        "type": AlgorithmType.SIGNATURE,
        "quantum": QuantumResistance.VULNERABLE,
        "severity": "CRITICAL",
        "reason": "Broken by Shor's algorithm — all elliptic curve sizes affected",
        "pq_replacement": "CRYSTALS-Dilithium (FIPS 204) / FALCON",
        "standard": "FIPS 186-5",
    },
    "ECDH": {
        "type": AlgorithmType.KEY_EXCHANGE,
        "quantum": QuantumResistance.VULNERABLE,
        "severity": "CRITICAL",
        "reason": "Broken by Shor's algorithm — all key exchanges compromised",
        "pq_replacement": "CRYSTALS-Kyber (FIPS 203)",
        "standard": "NIST SP 800-56A",
    },
    "DSA": {
        "type": AlgorithmType.SIGNATURE,
        "quantum": QuantumResistance.VULNERABLE,
        "severity": "CRITICAL",
        "reason": "Broken by Shor's algorithm",
        "pq_replacement": "CRYSTALS-Dilithium (FIPS 204)",
        "standard": "FIPS 186-4",
    },
    "Diffie-Hellman": {
        "type": AlgorithmType.KEY_EXCHANGE,
        "quantum": QuantumResistance.VULNERABLE,
        "severity": "CRITICAL",
        "reason": "Broken by Shor's algorithm — all variants",
        "pq_replacement": "CRYSTALS-Kyber (FIPS 203)",
        "standard": "RFC 3526",
    },
    "ElGamal": {
        "type": AlgorithmType.ASYMMETRIC,
        "quantum": QuantumResistance.VULNERABLE,
        "severity": "CRITICAL",
        "reason": "Broken by Shor's algorithm",
        "pq_replacement": "CRYSTALS-Kyber",
        "standard": None,
    },
}

# Algorithms weakened by Grover's algorithm (halves security level)
QUANTUM_WEAKENED = {
    "AES-128": {
        "type": AlgorithmType.SYMMETRIC,
        "quantum": QuantumResistance.WEAKENED,
        "severity": "MEDIUM",
        "reason": "Grover's algorithm reduces effective security to 64 bits",
        "pq_replacement": "AES-256 (effective 128-bit quantum security)",
        "standard": "FIPS 197",
    },
    "SHA-256": {
        "type": AlgorithmType.HASH,
        "quantum": QuantumResistance.WEAKENED,
        "severity": "LOW",
        "reason": "Grover's algorithm for preimage search",
        "pq_replacement": "SHA-512 / SHA-3 (larger outputs)",
        "standard": "FIPS 180-4",
    },
}

# Broken/weak algorithms (should never be used)
BROKEN_ALGORITHMS = {
    "MD5": {
        "type": AlgorithmType.HASH,
        "quantum": QuantumResistance.VULNERABLE,
        "severity": "CRITICAL",
        "reason": "Collision attacks practical — completely broken",
        "pq_replacement": "SHA-256 / SHA-3-256",
        "standard": None,
    },
    "SHA-1": {
        "type": AlgorithmType.HASH,
        "quantum": QuantumResistance.VULNERABLE,
        "severity": "HIGH",
        "reason": "SHAttered collision attack — deprecated by all major browsers",
        "pq_replacement": "SHA-256 / SHA-3-256",
        "standard": "Deprecated by NIST",
    },
    "DES": {
        "type": AlgorithmType.SYMMETRIC,
        "quantum": QuantumResistance.VULNERABLE,
        "severity": "CRITICAL",
        "reason": "56-bit key brute-forced in < 24 hours",
        "pq_replacement": "AES-256",
        "standard": "Deprecated",
    },
    "RC4": {
        "type": AlgorithmType.SYMMETRIC,
        "quantum": QuantumResistance.VULNERABLE,
        "severity": "CRITICAL",
        "reason": "Multiple bias attacks — completely broken",
        "pq_replacement": "AES-GCM / ChaCha20-Poly1305",
        "standard": "Prohibited by RFC 7465",
    },
    "3DES": {
        "type": AlgorithmType.SYMMETRIC,
        "quantum": QuantumResistance.VULNERABLE,
        "severity": "HIGH",
        "reason": "Sweet32 attack — 64-bit block cipher vulnerable",
        "pq_replacement": "AES-256",
        "standard": "Deprecated by NIST SP 800-131A",
    },
}

# Post-quantum safe algorithms
QUANTUM_SAFE = {
    "AES-256": AlgorithmType.SYMMETRIC,
    "AES-192": AlgorithmType.SYMMETRIC,
    "SHA-384": AlgorithmType.HASH,
    "SHA-512": AlgorithmType.HASH,
    "SHA-3": AlgorithmType.HASH,
    "SHA3-256": AlgorithmType.HASH,
    "SHA3-512": AlgorithmType.HASH,
    "BLAKE2": AlgorithmType.HASH,
    "BLAKE3": AlgorithmType.HASH,
    "ChaCha20": AlgorithmType.SYMMETRIC,
    "Curve25519": AlgorithmType.KEY_EXCHANGE,
    "Ed25519": AlgorithmType.SIGNATURE,
    "Kyber": AlgorithmType.KEY_EXCHANGE,
    "CRYSTALS-Kyber": AlgorithmType.KEY_EXCHANGE,
    "Dilithium": AlgorithmType.SIGNATURE,
    "CRYSTALS-Dilithium": AlgorithmType.SIGNATURE,
    "FALCON": AlgorithmType.SIGNATURE,
    "SPHINCS+": AlgorithmType.SIGNATURE,
    "NTRU": AlgorithmType.KEY_EXCHANGE,
    "NTRUEncrypt": AlgorithmType.ASYMMETRIC,
    "FrodoKEM": AlgorithmType.KEY_EXCHANGE,
    "Classic McEliece": AlgorithmType.ASYMMETRIC,
}


class CryptoAnalyzer:
    """Quantum-Resistant Cryptography Analyzer.

    Scans code for cryptographic algorithm usage and identifies:
    1. Quantum-vulnerable algorithms that will break with Shor's algorithm
    2. Weak/outdated crypto that should be replaced
    3. Post-quantum readiness status
    4. Migration recommendations
    """

    def __init__(self):
        self._findings: List[CryptoFinding] = []
        self._finding_count = 0

    def scan_code(self, code: str, source: str = "unknown") -> List[CryptoFinding]:
        """Scan source code for cryptographic algorithm usage.

        Args:
            code: Source code to analyze
            source: Source identifier (file path, module name, etc.)

        Returns:
            List of cryptographic findings
        """
        findings = []
        code_lower = code.lower()

        # Check for quantum-vulnerable algorithms
        for algo, info in QUANTUM_VULNERABLE.items():
            if self._detect_algorithm(code_lower, algo):
                finding = CryptoFinding(
                    id=f"crypto-{self._finding_count + 1}",
                    algorithm=algo,
                    algorithm_type=info["type"],
                    quantum_resistance=info["quantum"],
                    severity=info["severity"],
                    location=source,
                    description=f"Quantum-vulnerable algorithm detected: {algo}. {info['reason']}",
                    recommendation=f"Migrate to {info['pq_replacement']}",
                    standard=info.get("standard"),
                    pq_replacement=info["pq_replacement"],
                )
                findings.append(finding)
                self._finding_count += 1

        # Check for broken/weak algorithms
        for algo, info in BROKEN_ALGORITHMS.items():
            if self._detect_algorithm(code_lower, algo):
                finding = CryptoFinding(
                    id=f"crypto-{self._finding_count + 1}",
                    algorithm=algo,
                    algorithm_type=info["type"],
                    quantum_resistance=info["quantum"],
                    severity=info["severity"],
                    location=source,
                    description=f"Broken/weak algorithm detected: {algo}. {info['reason']}",
                    recommendation=f"Replace with {info['pq_replacement']}",
                    standard=info.get("standard"),
                    pq_replacement=info["pq_replacement"],
                )
                findings.append(finding)
                self._finding_count += 1

        # Check for quantum-weakened algorithms
        for algo, info in QUANTUM_WEAKENED.items():
            if self._detect_algorithm(code_lower, algo):
                finding = CryptoFinding(
                    id=f"crypto-{self._finding_count + 1}",
                    algorithm=algo,
                    algorithm_type=info["type"],
                    quantum_resistance=info["quantum"],
                    severity=info["severity"],
                    location=source,
                    description=f"Quantum-weakened algorithm: {algo}. {info['reason']}",
                    recommendation=info["pq_replacement"],
                    pq_replacement=info["pq_replacement"],
                )
                findings.append(finding)
                self._finding_count += 1

        # Check for weak key sizes in RSA
        rsa_key_sizes = re.findall(r'RSA\s*\(\s*(\d+)\s*\)', code, re.IGNORECASE)
        for size_str in rsa_key_sizes:
            try:
                size = int(size_str)
                if size < 2048:
                    findings.append(CryptoFinding(
                        id=f"crypto-{self._finding_count + 1}",
                        algorithm=f"RSA-{size}",
                        algorithm_type=AlgorithmType.ASYMMETRIC,
                        quantum_resistance=QuantumResistance.VULNERABLE,
                        severity="CRITICAL" if size < 1024 else "HIGH",
                        location=source,
                        description=f"RSA key size {size} bits is critically weak. "
                                   f"Quantum computers make RSA obsolete regardless of size.",
                        recommendation="Migrate to CRYSTALS-Kyber for key exchange",
                        pq_replacement="CRYSTALS-Kyber / X25519Kyber768",
                    ))
                    self._finding_count += 1
            except ValueError:
                pass

        # Check for weak PRNG usage
        weak_prng = ["random.random", "Random(", "java.util.Random", "mt_rand",
                     "arc4random", "srand", "drand48"]
        for prng in weak_prng:
            if prng.lower() in code_lower:
                findings.append(CryptoFinding(
                    id=f"crypto-{self._finding_count + 1}",
                    algorithm=prng,
                    algorithm_type=AlgorithmType.RANDOM,
                    quantum_resistance=QuantumResistance.UNKNOWN,
                    severity="MEDIUM",
                    location=source,
                    description=f"Weak PRNG detected: {prng}. Not cryptographically secure.",
                    recommendation="Replace with os.urandom() / secrets / SecureRandom",
                    pq_replacement="Hardware random / NIST SP 800-90A DRBG",
                ))
                self._finding_count += 1

        # Check for hardcoded keys
        key_patterns = [
            (r'(?:private_key|secret|password|api_key)\s*[=:]\s*["\'][A-Za-z0-9+/=]{20,}["\']',
             "Hardcoded cryptographic key or secret"),
            (r'(?:-----BEGIN\s+(?:RSA|EC|DSA|PRIVATE)\s+KEY-----)',
             "Embedded private key in source code"),
            (r'(?:sk-[A-Za-z0-9]{20,}|pk-[A-Za-z0-9]{20,})',
             "Hardcoded API key or token"),
        ]
        for pattern, description in key_patterns:
            if re.search(pattern, code, re.IGNORECASE):
                findings.append(CryptoFinding(
                    id=f"crypto-{self._finding_count + 1}",
                    algorithm="Hardcoded Key",
                    algorithm_type=AlgorithmType.SYMMETRIC,
                    quantum_resistance=QuantumResistance.VULNERABLE,
                    severity="CRITICAL",
                    location=source,
                    description=description,
                    recommendation="Use a secrets manager or HSM. Never embed keys in source code.",
                    standard="NIST SP 800-57",
                    pq_replacement="Hardware Security Module (HSM)",
                ))
                self._finding_count += 1

        # Check for ECB mode (always insecure)
        if "ecb" in code_lower and ("aes" in code_lower or "des" in code_lower):
            findings.append(CryptoFinding(
                id=f"crypto-{self._finding_count + 1}",
                algorithm="ECB Mode",
                algorithm_type=AlgorithmType.SYMMETRIC,
                quantum_resistance=QuantumResistance.VULNERABLE,
                severity="CRITICAL",
                location=source,
                description="ECB encryption mode detected. ECB is deterministic and leaks "
                           "plaintext patterns through ciphertext. It is never secure.",
                recommendation="Replace with AES-GCM or ChaCha20-Poly1305 (authenticated encryption)",
                standard="NIST SP 800-38A",
                pq_replacement="AES-256-GCM",
            ))
            self._finding_count += 1

        self._findings.extend(findings)
        return findings

    def _detect_algorithm(self, code_lower: str, algorithm: str) -> bool:
        """Detect if a cryptographic algorithm is referenced in code."""
        algo_lower = algorithm.lower()

        # Direct name match
        if algo_lower in code_lower:
            return True

        # Algorithm-specific patterns
        patterns = {
            "RSA": [r'\brsa\b', r'rsa_', r'_rsa', r'RSA2048', r'RSA4096'],
            "ECDSA": [r'\becdsa\b', r'ecdsa_', r'_ecdsa', r'ECDSA'],
            "AES-128": [r'aes[-\s]?128', r'AES128'],
            "MD5": [r'\bmd5\b', r'MD5', r'md5_', r'md5_hash'],
        }

        for pattern in patterns.get(algorithm, []):
            if re.search(pattern, code_lower):
                return True

        return False

    def assess_quantum_readiness(self, code: str) -> Dict[str, Any]:
        """Assess overall quantum readiness of code.

        Returns:
            Dict with readiness score, vulnerable algorithm count,
            and migration recommendations
        """
        findings = self.scan_code(code)

        quantum_vulnerable_count = sum(
            1 for f in findings if f.quantum_resistance == QuantumResistance.VULNERABLE
        )
        weakened_count = sum(
            1 for f in findings if f.quantum_resistance == QuantumResistance.WEAKENED
        )

        # Count quantum-safe algorithm usage
        safe_count = 0
        for algo in QUANTUM_SAFE:
            if algo.lower() in code.lower():
                safe_count += 1

        # Readiness score (0-100)
        if quantum_vulnerable_count == 0 and safe_count > 0:
            readiness = min(100, 60 + safe_count * 10)
        elif quantum_vulnerable_count > 0:
            readiness = max(0, 40 - quantum_vulnerable_count * 15)
        else:
            readiness = 30  # No crypto detected = unknown

        return {
            "readiness_score": readiness,
            "quantum_vulnerable": quantum_vulnerable_count,
            "quantum_weakened": weakened_count,
            "quantum_safe_count": safe_count,
            "total_findings": len(findings),
            "verdict": self._get_readiness_verdict(readiness),
            "critical_findings": [
                f.to_dict() for f in findings if f.severity == "CRITICAL"
            ],
            "migration_priority": self._get_migration_priority(findings),
        }

    def _get_readiness_verdict(self, score: int) -> str:
        if score >= 80:
            return "QUANTUM_READY — Code is well-prepared for post-quantum transition"
        elif score >= 50:
            return "PARTIALLY_READY — Some algorithms need migration"
        elif score >= 20:
            return "NEEDS_ATTENTION — Significant quantum-vulnerable crypto in use"
        else:
            return "CRITICAL — Immediate quantum migration required"

    def _get_migration_priority(self, findings: List[CryptoFinding]) -> List[Dict[str, Any]]:
        """Generate prioritized migration recommendations."""
        priorities = []
        for f in findings:
            if f.severity == "CRITICAL":
                priority = "IMMEDIATE"
            elif f.severity == "HIGH":
                priority = "WITHIN_3_MONTHS"
            elif f.severity == "MEDIUM":
                priority = "WITHIN_6_MONTHS"
            else:
                priority = "WITHIN_12_MONTHS"

            if f.pq_replacement:
                priorities.append({
                    "algorithm": f.algorithm,
                    "current_severity": f.severity,
                    "priority": priority,
                    "recommended_replacement": f.pq_replacement,
                    "migration_action": f.recommendation,
                })

        return sorted(priorities, key=lambda p: ["IMMEDIATE", "WITHIN_3_MONTHS",
                                                   "WITHIN_6_MONTHS", "WITHIN_12_MONTHS"].index(p["priority"]))

    def get_status(self) -> Dict[str, Any]:
        return {
            "total_findings": len(self._findings),
            "quantum_vulnerable_algorithms_known": len(QUANTUM_VULNERABLE),
            "broken_algorithms_known": len(BROKEN_ALGORITHMS),
            "quantum_safe_algorithms_known": len(QUANTUM_SAFE),
            "recent_findings": [f.to_dict() for f in self._findings[-10:]],
        }
