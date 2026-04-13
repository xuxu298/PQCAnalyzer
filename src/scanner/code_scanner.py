"""Source code scanner — detect crypto usage patterns in source code."""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from pathlib import Path

from src.scanner.models import Finding, ScanResult, ScanStatus
from src.utils.constants import RiskLevel, ScanType

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class CryptoPattern:
    """A regex pattern that detects crypto usage in source code."""

    language: str
    pattern: str
    component: str
    algorithm: str
    risk_level: RiskLevel
    quantum_vulnerable: bool
    replacement: list[str]
    note: str


# Crypto patterns by language
_PATTERNS: list[CryptoPattern] = [
    # --- Python ---
    CryptoPattern(
        language="python",
        pattern=r"from\s+cryptography\.hazmat\.primitives\.asymmetric\s+import\s+rsa",
        component="Python RSA Import",
        algorithm="RSA",
        risk_level=RiskLevel.CRITICAL,
        quantum_vulnerable=True,
        replacement=["ML-DSA (dilithium)", "ML-KEM (kyber)"],
        note="RSA asymmetric crypto is quantum vulnerable (Shor's algorithm).",
    ),
    CryptoPattern(
        language="python",
        pattern=r"from\s+cryptography\.hazmat\.primitives\.asymmetric\s+import\s+ec\b",
        component="Python ECC Import",
        algorithm="ECDSA/ECDH",
        risk_level=RiskLevel.CRITICAL,
        quantum_vulnerable=True,
        replacement=["ML-DSA (signatures)", "ML-KEM (key exchange)"],
        note="Elliptic curve crypto is quantum vulnerable (Shor's ECDLP variant).",
    ),
    CryptoPattern(
        language="python",
        pattern=r"from\s+cryptography\.hazmat\.primitives\.asymmetric\s+import\s+dh\b",
        component="Python DH Import",
        algorithm="Diffie-Hellman",
        risk_level=RiskLevel.CRITICAL,
        quantum_vulnerable=True,
        replacement=["ML-KEM-768"],
        note="DH key exchange is quantum vulnerable (Shor's algorithm).",
    ),
    CryptoPattern(
        language="python",
        pattern=r"from\s+cryptography\.hazmat\.primitives\.asymmetric\s+import\s+dsa\b",
        component="Python DSA Import",
        algorithm="DSA",
        risk_level=RiskLevel.CRITICAL,
        quantum_vulnerable=True,
        replacement=["ML-DSA-65"],
        note="DSA signatures are quantum vulnerable (Shor's algorithm).",
    ),
    CryptoPattern(
        language="python",
        pattern=r"from\s+cryptography\.hazmat\.primitives\.asymmetric\s+import\s+ed25519",
        component="Python Ed25519 Import",
        algorithm="Ed25519",
        risk_level=RiskLevel.CRITICAL,
        quantum_vulnerable=True,
        replacement=["ML-DSA-44"],
        note="Ed25519 is quantum vulnerable (Shor's algorithm).",
    ),
    CryptoPattern(
        language="python",
        pattern=r"from\s+Crypto\.PublicKey\s+import\s+RSA",
        component="Python PyCryptodome RSA",
        algorithm="RSA",
        risk_level=RiskLevel.CRITICAL,
        quantum_vulnerable=True,
        replacement=["ML-DSA / ML-KEM (liboqs-python)"],
        note="PyCryptodome RSA is quantum vulnerable.",
    ),
    CryptoPattern(
        language="python",
        pattern=r"from\s+Crypto\.PublicKey\s+import\s+(?:DSA|ECC)",
        component="Python PyCryptodome DSA/ECC",
        algorithm="DSA/ECC",
        risk_level=RiskLevel.CRITICAL,
        quantum_vulnerable=True,
        replacement=["ML-DSA (liboqs-python)"],
        note="PyCryptodome DSA/ECC is quantum vulnerable.",
    ),
    CryptoPattern(
        language="python",
        pattern=r"hashlib\.(?:md5|sha1)\s*\(",
        component="Python Weak Hash",
        algorithm="MD5/SHA-1",
        risk_level=RiskLevel.HIGH,
        quantum_vulnerable=False,
        replacement=["hashlib.sha256()", "hashlib.sha3_256()"],
        note="MD5/SHA-1 are cryptographically broken for collision resistance.",
    ),
    CryptoPattern(
        language="python",
        pattern=r"ssl\.PROTOCOL_TLSv1\b|ssl\.PROTOCOL_SSLv",
        component="Python Legacy TLS",
        algorithm="TLS 1.0/1.1 or SSLv3",
        risk_level=RiskLevel.HIGH,
        quantum_vulnerable=False,
        replacement=["ssl.PROTOCOL_TLS_CLIENT with TLS 1.2+"],
        note="Legacy TLS/SSL protocols are deprecated and insecure.",
    ),
    CryptoPattern(
        language="python",
        pattern=r"from\s+Crypto\.Cipher\s+import\s+DES\b",
        component="Python DES Import",
        algorithm="DES",
        risk_level=RiskLevel.CRITICAL,
        quantum_vulnerable=False,
        replacement=["AES-256-GCM"],
        note="DES is completely broken (56-bit key).",
    ),
    CryptoPattern(
        language="python",
        pattern=r"from\s+Crypto\.Cipher\s+import\s+Blowfish",
        component="Python Blowfish Import",
        algorithm="Blowfish",
        risk_level=RiskLevel.HIGH,
        quantum_vulnerable=False,
        replacement=["AES-256-GCM"],
        note="Blowfish is deprecated (64-bit block, Sweet32).",
    ),

    # --- Java ---
    CryptoPattern(
        language="java",
        pattern=r'Cipher\.getInstance\s*\(\s*"RSA[/"]',
        component="Java RSA Cipher",
        algorithm="RSA",
        risk_level=RiskLevel.CRITICAL,
        quantum_vulnerable=True,
        replacement=["ML-KEM (Bouncy Castle PQC)"],
        note="RSA cipher is quantum vulnerable.",
    ),
    CryptoPattern(
        language="java",
        pattern=r'KeyPairGenerator\.getInstance\s*\(\s*"RSA"',
        component="Java RSA KeyPairGenerator",
        algorithm="RSA",
        risk_level=RiskLevel.CRITICAL,
        quantum_vulnerable=True,
        replacement=["ML-KEM / ML-DSA (Bouncy Castle PQC)"],
        note="RSA key generation is quantum vulnerable.",
    ),
    CryptoPattern(
        language="java",
        pattern=r'KeyPairGenerator\.getInstance\s*\(\s*"(?:EC|ECDSA|ECDH)"',
        component="Java EC KeyPairGenerator",
        algorithm="ECDSA/ECDH",
        risk_level=RiskLevel.CRITICAL,
        quantum_vulnerable=True,
        replacement=["ML-DSA / ML-KEM (Bouncy Castle PQC)"],
        note="Elliptic curve key generation is quantum vulnerable.",
    ),
    CryptoPattern(
        language="java",
        pattern=r'Signature\.getInstance\s*\(\s*"(?:SHA\d*withRSA|SHA\d*withECDSA|SHA\d*withDSA)',
        component="Java Quantum-Vulnerable Signature",
        algorithm="RSA/ECDSA/DSA signature",
        risk_level=RiskLevel.CRITICAL,
        quantum_vulnerable=True,
        replacement=["ML-DSA (Bouncy Castle PQC)"],
        note="RSA/ECDSA/DSA signatures are quantum vulnerable.",
    ),
    CryptoPattern(
        language="java",
        pattern=r'KeyAgreement\.getInstance\s*\(\s*"(?:DH|ECDH)"',
        component="Java Key Agreement",
        algorithm="DH/ECDH",
        risk_level=RiskLevel.CRITICAL,
        quantum_vulnerable=True,
        replacement=["ML-KEM (Bouncy Castle PQC)"],
        note="DH/ECDH key agreement is quantum vulnerable.",
    ),
    CryptoPattern(
        language="java",
        pattern=r'Cipher\.getInstance\s*\(\s*"DES[/"]',
        component="Java DES Cipher",
        algorithm="DES",
        risk_level=RiskLevel.CRITICAL,
        quantum_vulnerable=False,
        replacement=["AES/GCM/NoPadding"],
        note="DES is completely broken.",
    ),
    CryptoPattern(
        language="java",
        pattern=r'Cipher\.getInstance\s*\(\s*"DESede[/"]',
        component="Java 3DES Cipher",
        algorithm="3DES",
        risk_level=RiskLevel.HIGH,
        quantum_vulnerable=False,
        replacement=["AES/GCM/NoPadding"],
        note="3DES is deprecated (Sweet32).",
    ),
    CryptoPattern(
        language="java",
        pattern=r'MessageDigest\.getInstance\s*\(\s*"(?:MD5|SHA-1)"',
        component="Java Weak Hash",
        algorithm="MD5/SHA-1",
        risk_level=RiskLevel.HIGH,
        quantum_vulnerable=False,
        replacement=["SHA-256", "SHA-3"],
        note="MD5/SHA-1 are cryptographically broken.",
    ),

    # --- Go ---
    CryptoPattern(
        language="go",
        pattern=r'"crypto/rsa"',
        component="Go RSA Import",
        algorithm="RSA",
        risk_level=RiskLevel.CRITICAL,
        quantum_vulnerable=True,
        replacement=["circl/kem/kyber768", "circl/sign/dilithium"],
        note="crypto/rsa is quantum vulnerable.",
    ),
    CryptoPattern(
        language="go",
        pattern=r'"crypto/ecdsa"',
        component="Go ECDSA Import",
        algorithm="ECDSA",
        risk_level=RiskLevel.CRITICAL,
        quantum_vulnerable=True,
        replacement=["circl/sign/dilithium (ML-DSA)"],
        note="crypto/ecdsa is quantum vulnerable.",
    ),
    CryptoPattern(
        language="go",
        pattern=r'"crypto/ecdh"',
        component="Go ECDH Import",
        algorithm="ECDH",
        risk_level=RiskLevel.CRITICAL,
        quantum_vulnerable=True,
        replacement=["circl/kem/kyber768 (ML-KEM)"],
        note="crypto/ecdh is quantum vulnerable.",
    ),
    CryptoPattern(
        language="go",
        pattern=r'"crypto/dsa"',
        component="Go DSA Import",
        algorithm="DSA",
        risk_level=RiskLevel.CRITICAL,
        quantum_vulnerable=True,
        replacement=["circl/sign/dilithium (ML-DSA)"],
        note="crypto/dsa is quantum vulnerable and deprecated in Go.",
    ),
    CryptoPattern(
        language="go",
        pattern=r'"crypto/ed25519"',
        component="Go Ed25519 Import",
        algorithm="Ed25519",
        risk_level=RiskLevel.CRITICAL,
        quantum_vulnerable=True,
        replacement=["circl/sign/dilithium (ML-DSA)"],
        note="crypto/ed25519 is quantum vulnerable.",
    ),
    CryptoPattern(
        language="go",
        pattern=r'"crypto/des"',
        component="Go DES Import",
        algorithm="DES/3DES",
        risk_level=RiskLevel.CRITICAL,
        quantum_vulnerable=False,
        replacement=["crypto/aes with GCM"],
        note="DES/3DES is broken/deprecated.",
    ),
    CryptoPattern(
        language="go",
        pattern=r'"crypto/rc4"',
        component="Go RC4 Import",
        algorithm="RC4",
        risk_level=RiskLevel.CRITICAL,
        quantum_vulnerable=False,
        replacement=["crypto/aes with GCM", "chacha20poly1305"],
        note="RC4 is completely broken.",
    ),
    CryptoPattern(
        language="go",
        pattern=r'crypto/md5"|crypto/sha1"',
        component="Go Weak Hash Import",
        algorithm="MD5/SHA-1",
        risk_level=RiskLevel.HIGH,
        quantum_vulnerable=False,
        replacement=["crypto/sha256", "crypto/sha3"],
        note="MD5/SHA-1 are cryptographically broken for security use.",
    ),
    CryptoPattern(
        language="go",
        pattern=r'x509\.ParseCertificate|x509\.CreateCertificate',
        component="Go X.509 Operations",
        algorithm="RSA/ECDSA (typical X.509)",
        risk_level=RiskLevel.HIGH,
        quantum_vulnerable=True,
        replacement=["PQC-aware certificate handling (future Go support)"],
        note="X.509 operations typically use RSA/ECDSA which are quantum vulnerable.",
    ),

    # --- JavaScript / Node.js ---
    CryptoPattern(
        language="javascript",
        pattern=r"crypto\.createSign\s*\(\s*['\"](?:RSA-SHA|sha\d+WithRSA)",
        component="Node.js RSA Signing",
        algorithm="RSA signature",
        risk_level=RiskLevel.CRITICAL,
        quantum_vulnerable=True,
        replacement=["PQC signature libraries (liboqs-node)"],
        note="RSA signing is quantum vulnerable.",
    ),
    CryptoPattern(
        language="javascript",
        pattern=r"crypto\.createDiffieHellman|crypto\.createECDH|crypto\.getDiffieHellman",
        component="Node.js DH/ECDH Key Exchange",
        algorithm="DH/ECDH",
        risk_level=RiskLevel.CRITICAL,
        quantum_vulnerable=True,
        replacement=["PQC KEM libraries"],
        note="DH/ECDH key exchange is quantum vulnerable.",
    ),
    CryptoPattern(
        language="javascript",
        pattern=r"crypto\.createCipheriv\s*\(\s*['\"](?:des|des3|des-ede3|bf|blowfish|rc4|rc2)",
        component="Node.js Weak Cipher",
        algorithm="DES/3DES/Blowfish/RC4",
        risk_level=RiskLevel.CRITICAL,
        quantum_vulnerable=False,
        replacement=["aes-256-gcm", "chacha20-poly1305"],
        note="Weak/deprecated cipher in use.",
    ),
    CryptoPattern(
        language="javascript",
        pattern=r"crypto\.createHash\s*\(\s*['\"](?:md5|sha1)['\"]",
        component="Node.js Weak Hash",
        algorithm="MD5/SHA-1",
        risk_level=RiskLevel.HIGH,
        quantum_vulnerable=False,
        replacement=["sha256", "sha3-256"],
        note="MD5/SHA-1 are cryptographically broken.",
    ),

    # --- C/C++ (OpenSSL API) ---
    CryptoPattern(
        language="c",
        pattern=r"\bRSA_generate_key(?:_ex)?\s*\(|\bEVP_PKEY_CTX_set_rsa_keygen_bits\s*\(",
        component="C/C++ RSA Key Generation",
        algorithm="RSA",
        risk_level=RiskLevel.CRITICAL,
        quantum_vulnerable=True,
        replacement=["OQS_KEM_keypair (liboqs)", "EVP_PKEY with OQS provider"],
        note="RSA key generation is quantum vulnerable.",
    ),
    CryptoPattern(
        language="c",
        pattern=r"\bEC_KEY_new_by_curve_name\s*\(|\bEVP_PKEY_CTX_set_ec_paramgen_curve_nid\s*\(",
        component="C/C++ EC Key Operations",
        algorithm="ECDSA/ECDH",
        risk_level=RiskLevel.CRITICAL,
        quantum_vulnerable=True,
        replacement=["OQS_SIG / OQS_KEM (liboqs)"],
        note="Elliptic curve operations are quantum vulnerable.",
    ),
    CryptoPattern(
        language="c",
        pattern=r"\bEVP_des_(?:ecb|cbc|cfb|ofb)\b|\bEVP_des_ede3",
        component="C/C++ DES/3DES",
        algorithm="DES/3DES",
        risk_level=RiskLevel.CRITICAL,
        quantum_vulnerable=False,
        replacement=["EVP_aes_256_gcm()"],
        note="DES/3DES is broken/deprecated.",
    ),
    CryptoPattern(
        language="c",
        pattern=r"\bEVP_md5\s*\(|\bMD5_Init\s*\(",
        component="C/C++ MD5",
        algorithm="MD5",
        risk_level=RiskLevel.HIGH,
        quantum_vulnerable=False,
        replacement=["EVP_sha256()", "EVP_sha3_256()"],
        note="MD5 is cryptographically broken.",
    ),
    CryptoPattern(
        language="c",
        pattern=r"\bEVP_sha1\s*\(|\bSHA1_Init\s*\(",
        component="C/C++ SHA-1",
        algorithm="SHA-1",
        risk_level=RiskLevel.HIGH,
        quantum_vulnerable=False,
        replacement=["EVP_sha256()", "EVP_sha3_256()"],
        note="SHA-1 collision attacks demonstrated.",
    ),
    CryptoPattern(
        language="c",
        pattern=r"\bEVP_rc4\s*\(|\bRC4_set_key\s*\(",
        component="C/C++ RC4",
        algorithm="RC4",
        risk_level=RiskLevel.CRITICAL,
        quantum_vulnerable=False,
        replacement=["EVP_aes_256_gcm()", "EVP_chacha20_poly1305()"],
        note="RC4 is completely broken.",
    ),
    CryptoPattern(
        language="c",
        pattern=r"\bDH_generate_parameters(?:_ex)?\s*\(|\bEVP_PKEY_CTX_set_dh_paramgen_prime_len\s*\(",
        component="C/C++ DH Key Exchange",
        algorithm="Diffie-Hellman",
        risk_level=RiskLevel.CRITICAL,
        quantum_vulnerable=True,
        replacement=["OQS_KEM (liboqs)"],
        note="DH key exchange is quantum vulnerable.",
    ),
]

# Map file extensions to language
_EXTENSION_LANG: dict[str, str] = {
    ".py": "python",
    ".java": "java",
    ".go": "go",
    ".js": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "javascript",
    ".tsx": "javascript",
    ".jsx": "javascript",
    ".c": "c",
    ".cc": "c",
    ".cpp": "c",
    ".cxx": "c",
    ".h": "c",
    ".hh": "c",
    ".hpp": "c",
}

# Directories to skip
_SKIP_DIRS = {
    "node_modules", ".git", "__pycache__", ".tox", ".venv", "venv",
    "env", ".env", "vendor", "dist", "build", ".mypy_cache",
    ".pytest_cache", ".eggs", "egg-info",
}


class CodeScanner:
    """Scan source code files for crypto usage patterns."""

    def scan_file(self, filepath: str) -> ScanResult:
        """Scan a single source file for crypto patterns."""
        result = ScanResult(target=filepath, scan_type=ScanType.SOURCE_CODE)
        path = Path(filepath)

        if not path.exists():
            result.status = ScanStatus.ERROR
            result.error_message = f"File not found: {filepath}"
            return result

        ext = path.suffix.lower()
        language = _EXTENSION_LANG.get(ext)
        if not language:
            result.status = ScanStatus.SKIPPED
            result.error_message = f"Unsupported file type: {ext}"
            return result

        try:
            content = path.read_text(errors="replace")
            result.findings = self._scan_content(content, language, filepath)
            result.status = ScanStatus.SUCCESS
            result.metadata = {"language": language, "lines": content.count("\n") + 1}
        except Exception as e:
            result.status = ScanStatus.ERROR
            result.error_message = str(e)
            logger.error("Error scanning source file %s: %s", filepath, e)

        result.finalize()
        return result

    def scan_directory(
        self, dirpath: str, recursive: bool = True,
    ) -> list[ScanResult]:
        """Scan a directory for source files with crypto patterns."""
        results: list[ScanResult] = []
        root = Path(dirpath)

        if not root.is_dir():
            result = ScanResult(target=dirpath, scan_type=ScanType.SOURCE_CODE)
            result.status = ScanStatus.ERROR
            result.error_message = f"Not a directory: {dirpath}"
            results.append(result)
            return results

        pattern = "**/*" if recursive else "*"
        for path in sorted(root.glob(pattern)):
            if not path.is_file():
                continue
            # Skip excluded directories
            if any(skip in path.parts for skip in _SKIP_DIRS):
                continue
            ext = path.suffix.lower()
            if ext not in _EXTENSION_LANG:
                continue

            result = self.scan_file(str(path))
            if result.findings:
                results.append(result)

        return results

    def _scan_content(
        self, content: str, language: str, filepath: str,
    ) -> list[Finding]:
        """Scan file content against crypto patterns for the given language."""
        findings: list[Finding] = []
        lines = content.splitlines()

        # Get patterns for this language
        patterns = [p for p in _PATTERNS if p.language == language]

        for pattern in patterns:
            compiled = re.compile(pattern.pattern)
            for line_no, line in enumerate(lines, start=1):
                if compiled.search(line):
                    findings.append(Finding(
                        component=pattern.component,
                        algorithm=pattern.algorithm,
                        risk_level=pattern.risk_level,
                        quantum_vulnerable=pattern.quantum_vulnerable,
                        location=f"{filepath}:{line_no}",
                        replacement=list(pattern.replacement),
                        migration_priority=1 if pattern.quantum_vulnerable else 2,
                        note=pattern.note,
                    ))
                    # Only report first match per pattern per file to reduce noise
                    break

        return findings
