"""Algorithm classifications, risk levels, and NIST standards constants."""

from __future__ import annotations

import sys

if sys.version_info >= (3, 11):
    from enum import StrEnum
else:
    from enum import Enum

    class StrEnum(str, Enum):
        """Backport of StrEnum for Python < 3.11."""

        pass


class RiskLevel(StrEnum):
    """Quantum vulnerability risk level."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    SAFE = "SAFE"


class AlgorithmType(StrEnum):
    """Type of cryptographic algorithm."""

    ASYMMETRIC = "asymmetric"
    SYMMETRIC = "symmetric"
    HASH = "hash"
    KEM = "kem"
    SIGNATURE = "signature"
    KEY_EXCHANGE = "key_exchange"
    MAC = "mac"


class AlgorithmUsage(StrEnum):
    """How the algorithm is used."""

    KEY_EXCHANGE = "key_exchange"
    SIGNATURE = "signature"
    ENCRYPTION = "encryption"
    AUTHENTICATION = "authentication"
    INTEGRITY = "integrity"
    AEAD = "aead"
    HASHING = "hashing"


class ScanType(StrEnum):
    """Type of scan performed."""

    TLS_ENDPOINT = "tls_endpoint"
    CERTIFICATE = "certificate"
    CONFIG_FILE = "config_file"
    SOURCE_CODE = "source_code"
    VPN_CONFIG = "vpn_config"
    SSH_CONFIG = "ssh_config"


class ScanStatus(StrEnum):
    """Status of a scan operation."""

    SUCCESS = "success"
    ERROR = "error"
    TIMEOUT = "timeout"
    REFUSED = "refused"
    SKIPPED = "skipped"


# TLS protocol versions ordered by preference (newest first)
TLS_VERSIONS = {
    "TLSv1.3": {"secure": True, "note": "Current recommended version"},
    "TLSv1.2": {"secure": True, "note": "Acceptable, prefer TLS 1.3"},
    "TLSv1.1": {"secure": False, "note": "Deprecated, should disable"},
    "TLSv1.0": {"secure": False, "note": "Deprecated, should disable"},
    "SSLv3": {"secure": False, "note": "Broken, must disable immediately"},
    "SSLv2": {"secure": False, "note": "Broken, must disable immediately"},
}

# Migration priority levels
MIGRATION_PRIORITY = {
    0: "No action needed (already PQC-safe)",
    1: "Immediate — quantum vulnerable, internet-facing",
    2: "High — quantum vulnerable, internal but sensitive",
    3: "Medium — needs upgrade but not quantum-critical",
    4: "Low — minor improvement recommended",
    5: "Informational — already adequate",
}

# NIST standards reference
NIST_STANDARDS = {
    "FIPS 203": {
        "name": "ML-KEM (Module-Lattice-Based Key-Encapsulation Mechanism)",
        "algorithms": ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"],
        "type": "KEM",
        "status": "Final Standard",
    },
    "FIPS 204": {
        "name": "ML-DSA (Module-Lattice-Based Digital Signature Algorithm)",
        "algorithms": ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"],
        "type": "Signature",
        "status": "Final Standard",
    },
    "FIPS 205": {
        "name": "SLH-DSA (Stateless Hash-Based Digital Signature Algorithm)",
        "algorithms": [
            "SLH-DSA-SHA2-128s",
            "SLH-DSA-SHA2-128f",
            "SLH-DSA-SHA2-192s",
            "SLH-DSA-SHA2-192f",
            "SLH-DSA-SHA2-256s",
            "SLH-DSA-SHA2-256f",
            "SLH-DSA-SHAKE-128s",
            "SLH-DSA-SHAKE-128f",
            "SLH-DSA-SHAKE-192s",
            "SLH-DSA-SHAKE-192f",
            "SLH-DSA-SHAKE-256s",
            "SLH-DSA-SHAKE-256f",
        ],
        "type": "Signature",
        "status": "Final Standard",
    },
    "FIPS 206": {
        "name": "FN-DSA (FFT over NTRU-Lattice-Based Digital Signature Algorithm)",
        "algorithms": ["FN-DSA-512", "FN-DSA-1024"],
        "type": "Signature",
        "status": "Draft",
    },
}
