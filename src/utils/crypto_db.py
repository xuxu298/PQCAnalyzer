"""Algorithm database loader and lookup engine."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

from src.config import ALGORITHM_DB_PATH
from src.utils.constants import RiskLevel


@dataclass(frozen=True)
class AlgorithmInfo:
    """Information about a cryptographic algorithm from the database."""

    name: str
    type: str
    usage: list[str]
    quantum_vulnerable: bool
    risk_level: RiskLevel
    attack: str
    estimated_break: str
    replacement: list[str]
    migration_priority: int
    note_vi: str
    note_en: str


class AlgorithmDatabase:
    """Loads and queries the algorithm vulnerability database."""

    def __init__(self, db_path: Path | None = None) -> None:
        self._path = db_path or ALGORITHM_DB_PATH
        self._algorithms: dict[str, AlgorithmInfo] = {}
        self._version: str = ""
        self._load()

    def _load(self) -> None:
        with open(self._path) as f:
            data = json.load(f)
        self._version = data.get("version", "unknown")
        for name, info in data["algorithms"].items():
            self._algorithms[name.upper()] = AlgorithmInfo(
                name=name,
                type=info["type"],
                usage=info["usage"],
                quantum_vulnerable=info["quantum_vulnerable"],
                risk_level=RiskLevel(info["risk_level"]),
                attack=info["attack"],
                estimated_break=info["estimated_break"],
                replacement=info["replacement"],
                migration_priority=info["migration_priority"],
                note_vi=info["note_vi"],
                note_en=info["note_en"],
            )

    @property
    def version(self) -> str:
        return self._version

    def lookup(self, algorithm_name: str) -> AlgorithmInfo | None:
        """Look up algorithm by exact name (case-insensitive)."""
        return self._algorithms.get(algorithm_name.upper())

    def classify(self, algorithm_name: str) -> AlgorithmInfo | None:
        """Classify an algorithm, trying fuzzy matching if exact match fails.

        Handles variations like:
        - "sha256WithRSAEncryption" -> RSA-2048
        - "ecdsa-with-SHA384" -> ECDSA-P384
        - "aes-256-gcm" -> AES-256
        - "curve25519" -> X25519
        """
        # Try exact match first
        result = self.lookup(algorithm_name)
        if result:
            return result

        name = algorithm_name.upper().replace("_", "-").replace(" ", "-")

        # RSA patterns
        rsa_match = re.search(r"RSA[- ]?(\d{4})", name)
        if rsa_match:
            return self.lookup(f"RSA-{rsa_match.group(1)}")
        if "RSA" in name and not any(c.isdigit() for c in name):
            return self.lookup("RSA-2048")  # Default RSA assumption

        # ECDSA patterns
        ecdsa_match = re.search(r"ECDSA.*P-?(\d{3})", name)
        if ecdsa_match:
            return self.lookup(f"ECDSA-P{ecdsa_match.group(1)}")
        if "ECDSA" in name:
            return self.lookup("ECDSA-P256")  # Default ECDSA assumption

        # ECDHE patterns
        ecdhe_match = re.search(r"ECDHE.*P-?(\d{3})", name)
        if ecdhe_match:
            return self.lookup(f"ECDHE-P{ecdhe_match.group(1)}")
        if "ECDHE" in name:
            return self.lookup("ECDHE-P256")

        # DH patterns
        dh_match = re.search(r"DHE?[- ]?(\d{4})", name)
        if dh_match:
            return self.lookup(f"DHE-{dh_match.group(1)}")

        # AES patterns
        aes_match = re.search(r"AES[- ]?(\d{3})", name)
        if aes_match:
            return self.lookup(f"AES-{aes_match.group(1)}")

        # SHA patterns
        if "SHA3" in name or "SHA-3" in name:
            return self.lookup("SHA3-256")
        sha_match = re.search(r"SHA[- ]?(\d+)", name)
        if sha_match:
            size = sha_match.group(1)
            return self.lookup(f"SHA-{size}")

        # Hybrid PQ KEMs — match BEFORE plain X25519/P-256 so we don't
        # mis-classify a hybrid as its classical half (false negative).
        is_mlkem = "MLKEM" in name or "ML-KEM" in name
        if is_mlkem and "X25519" in name:
            return self.lookup("X25519MLKEM768")
        if is_mlkem and ("SECP256" in name or "P-256" in name or "P256" in name):
            return self.lookup("SecP256r1MLKEM768")
        if "KYBER" in name and "X25519" in name:
            return self.lookup("X25519Kyber768")

        # Ed25519 / Ed448
        if "ED25519" in name or "CURVE25519" in name:
            if "ECDHE" in name or "KEX" in name or "X25519" in name:
                return self.lookup("X25519")
            return self.lookup("Ed25519")
        if "ED448" in name:
            return self.lookup("Ed448")
        if "X448" in name:
            return self.lookup("X448")
        if "X25519" in name:
            return self.lookup("X25519")

        # ChaCha20
        if "CHACHA20" in name:
            return self.lookup("ChaCha20-Poly1305")

        # 3DES
        if "3DES" in name or "DES-EDE" in name or "DES-CBC3" in name:
            return self.lookup("3DES")

        # DES
        if "DES" in name and "3DES" not in name and "DES-EDE" not in name:
            return self.lookup("DES")

        # RC4
        if "RC4" in name or "ARCFOUR" in name:
            return self.lookup("RC4")

        # MD5
        if "MD5" in name:
            return self.lookup("MD5")

        # HMAC
        hmac_match = re.search(r"HMAC[- ]?(SHA\d+|MD5)", name)
        if hmac_match:
            return self.lookup(f"HMAC-{hmac_match.group(1)}")

        # ML-KEM / ML-DSA
        ml_kem_match = re.search(r"ML[- ]?KEM[- ]?(\d+)", name)
        if ml_kem_match:
            return self.lookup(f"ML-KEM-{ml_kem_match.group(1)}")
        ml_dsa_match = re.search(r"ML[- ]?DSA[- ]?(\d+)", name)
        if ml_dsa_match:
            return self.lookup(f"ML-DSA-{ml_dsa_match.group(1)}")

        return None

    def all_algorithms(self) -> dict[str, AlgorithmInfo]:
        """Return all algorithms in the database."""
        return dict(self._algorithms)

    def quantum_vulnerable(self) -> list[AlgorithmInfo]:
        """Return all quantum-vulnerable algorithms."""
        return [a for a in self._algorithms.values() if a.quantum_vulnerable]

    def quantum_safe(self) -> list[AlgorithmInfo]:
        """Return all quantum-safe algorithms."""
        return [a for a in self._algorithms.values() if not a.quantum_vulnerable]


# Module-level singleton
_db: AlgorithmDatabase | None = None


def get_algorithm_db() -> AlgorithmDatabase:
    """Get the global algorithm database instance."""
    global _db
    if _db is None:
        _db = AlgorithmDatabase()
    return _db
