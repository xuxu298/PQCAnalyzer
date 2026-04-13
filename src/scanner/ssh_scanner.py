"""SSH configuration scanner — parse sshd_config and ssh_config."""

from __future__ import annotations

import logging
import re
from pathlib import Path

from src.scanner.models import Finding, ScanResult, ScanStatus
from src.utils.constants import RiskLevel, ScanType
from src.utils.crypto_db import get_algorithm_db

logger = logging.getLogger(__name__)

# SSH algorithms known to be quantum-vulnerable or classically weak
_WEAK_KEX: dict[str, tuple[RiskLevel, str]] = {
    "diffie-hellman-group1-sha1": (
        RiskLevel.CRITICAL,
        "DH-1024 with SHA-1, both classically and quantum vulnerable",
    ),
    "diffie-hellman-group14-sha1": (
        RiskLevel.HIGH,
        "DH-2048 with SHA-1, quantum vulnerable",
    ),
    "diffie-hellman-group14-sha256": (
        RiskLevel.HIGH,
        "DH-2048, quantum vulnerable (Shor's algorithm)",
    ),
    "diffie-hellman-group16-sha512": (
        RiskLevel.HIGH,
        "DH-4096, quantum vulnerable (Shor's algorithm)",
    ),
    "diffie-hellman-group18-sha512": (
        RiskLevel.HIGH,
        "DH-8192, quantum vulnerable despite large key (Shor's algorithm)",
    ),
    "diffie-hellman-group-exchange-sha1": (
        RiskLevel.HIGH,
        "DH group exchange with SHA-1, quantum vulnerable",
    ),
    "diffie-hellman-group-exchange-sha256": (
        RiskLevel.HIGH,
        "DH group exchange, quantum vulnerable (Shor's algorithm)",
    ),
    "ecdh-sha2-nistp256": (
        RiskLevel.HIGH,
        "ECDH P-256, quantum vulnerable (Shor's ECDLP variant)",
    ),
    "ecdh-sha2-nistp384": (
        RiskLevel.HIGH,
        "ECDH P-384, quantum vulnerable (Shor's ECDLP variant)",
    ),
    "ecdh-sha2-nistp521": (
        RiskLevel.HIGH,
        "ECDH P-521, quantum vulnerable (Shor's ECDLP variant)",
    ),
    "curve25519-sha256": (
        RiskLevel.HIGH,
        "Curve25519, quantum vulnerable (Shor's ECDLP variant). Best classical choice but not post-quantum safe.",
    ),
    "curve25519-sha256@libssh.org": (
        RiskLevel.HIGH,
        "Curve25519, quantum vulnerable. Best classical choice but not post-quantum safe.",
    ),
}

_WEAK_HOST_KEY: dict[str, tuple[RiskLevel, str]] = {
    "ssh-rsa": (RiskLevel.CRITICAL, "RSA host key, quantum vulnerable"),
    "ssh-dss": (RiskLevel.CRITICAL, "DSA host key, classically and quantum vulnerable"),
    "ecdsa-sha2-nistp256": (RiskLevel.CRITICAL, "ECDSA P-256 host key, quantum vulnerable"),
    "ecdsa-sha2-nistp384": (RiskLevel.CRITICAL, "ECDSA P-384 host key, quantum vulnerable"),
    "ecdsa-sha2-nistp521": (RiskLevel.CRITICAL, "ECDSA P-521 host key, quantum vulnerable"),
    "ssh-ed25519": (RiskLevel.CRITICAL, "Ed25519 host key, quantum vulnerable"),
}

_WEAK_CIPHERS: dict[str, tuple[RiskLevel, str]] = {
    "3des-cbc": (RiskLevel.HIGH, "3DES is deprecated (Sweet32 attack)"),
    "aes128-cbc": (RiskLevel.MEDIUM, "AES-128-CBC: CBC mode vulnerable to padding attacks, AES-128 quantum-weak"),
    "aes192-cbc": (RiskLevel.LOW, "AES-192-CBC: CBC mode, consider using CTR/GCM"),
    "aes256-cbc": (RiskLevel.LOW, "AES-256-CBC: CBC mode, consider using CTR/GCM"),
    "arcfour": (RiskLevel.CRITICAL, "RC4 is completely broken"),
    "arcfour128": (RiskLevel.CRITICAL, "RC4 is completely broken"),
    "arcfour256": (RiskLevel.CRITICAL, "RC4 is completely broken"),
    "blowfish-cbc": (RiskLevel.HIGH, "Blowfish is deprecated, 64-bit block size"),
    "cast128-cbc": (RiskLevel.HIGH, "CAST-128 is deprecated, 64-bit block size"),
    "aes128-ctr": (RiskLevel.MEDIUM, "AES-128: reduced to 64-bit security post-quantum"),
    "aes128-gcm@openssh.com": (RiskLevel.MEDIUM, "AES-128: reduced to 64-bit security post-quantum"),
}

_WEAK_MACS: dict[str, tuple[RiskLevel, str]] = {
    "hmac-md5": (RiskLevel.HIGH, "MD5 is broken"),
    "hmac-md5-96": (RiskLevel.HIGH, "MD5 is broken"),
    "hmac-sha1": (RiskLevel.MEDIUM, "SHA-1 has collision weakness"),
    "hmac-sha1-96": (RiskLevel.MEDIUM, "SHA-1 has collision weakness"),
    "umac-64@openssh.com": (RiskLevel.MEDIUM, "64-bit MAC tag is short"),
}


class SSHScanner:
    """Scan SSH configuration files for quantum-vulnerable algorithms."""

    def scan_file(self, filepath: str) -> ScanResult:
        """Scan an sshd_config or ssh_config file.

        Args:
            filepath: Path to SSH config file.

        Returns:
            ScanResult with findings.
        """
        result = ScanResult(target=filepath, scan_type=ScanType.SSH_CONFIG)
        path = Path(filepath)

        if not path.exists():
            result.status = ScanStatus.ERROR
            result.error_message = f"File not found: {filepath}"
            return result

        try:
            content = path.read_text(errors="replace")
            config = self._parse_ssh_config(content)
            result.findings = self._analyze(config, filepath)
            result.status = ScanStatus.SUCCESS
            result.metadata = {"config_directives": config}
        except Exception as e:
            result.status = ScanStatus.ERROR
            result.error_message = str(e)
            logger.error("Error scanning SSH config %s: %s", filepath, e)

        result.finalize()
        return result

    def _parse_ssh_config(self, content: str) -> dict[str, list[str]]:
        """Parse SSH config into directive -> values mapping."""
        config: dict[str, list[str]] = {}

        directives_of_interest = [
            "KexAlgorithms",
            "HostKeyAlgorithms",
            "PubkeyAcceptedAlgorithms",
            "PubkeyAcceptedKeyTypes",  # older name
            "Ciphers",
            "MACs",
            "HostKey",
        ]

        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            # Handle "Directive value1,value2" format
            for directive in directives_of_interest:
                match = re.match(
                    rf"^{directive}\s+(.+)$", line, re.IGNORECASE
                )
                if match:
                    values = [
                        v.strip()
                        for v in match.group(1).split(",")
                        if v.strip()
                    ]
                    key = directive.lower()
                    # HostKey can appear multiple times, accumulate values
                    if key in config:
                        config[key].extend(values)
                    else:
                        config[key] = values
                    break

        return config

    def _analyze(
        self, config: dict[str, list[str]], filepath: str
    ) -> list[Finding]:
        """Analyze parsed SSH config for weak algorithms."""
        findings: list[Finding] = []

        # Check KexAlgorithms
        kex_algos = config.get("kexalgorithms", [])
        for algo in kex_algos:
            algo_lower = algo.lower()
            if algo_lower in _WEAK_KEX:
                risk, note = _WEAK_KEX[algo_lower]
                findings.append(Finding(
                    component="SSH Key Exchange",
                    algorithm=algo,
                    risk_level=risk,
                    quantum_vulnerable=True,
                    location=f"{filepath}, KexAlgorithms",
                    replacement=["sntrup761x25519-sha512@openssh.com (hybrid PQ)"],
                    migration_priority=1 if risk == RiskLevel.CRITICAL else 2,
                    note=note,
                ))

        # Check HostKeyAlgorithms / PubkeyAcceptedAlgorithms
        host_key_algos = (
            config.get("hostkeyalgorithms", [])
            + config.get("pubkeyacceptedalgorithms", [])
            + config.get("pubkeyacceptedkeytypes", [])
        )
        seen_host_keys: set[str] = set()
        for algo in host_key_algos:
            algo_lower = algo.lower()
            if algo_lower in _WEAK_HOST_KEY and algo_lower not in seen_host_keys:
                seen_host_keys.add(algo_lower)
                risk, note = _WEAK_HOST_KEY[algo_lower]
                findings.append(Finding(
                    component="SSH Host Key",
                    algorithm=algo,
                    risk_level=risk,
                    quantum_vulnerable=True,
                    location=f"{filepath}, HostKeyAlgorithms",
                    replacement=["ssh-ed25519 (best classical)", "PQ host keys (when available)"],
                    migration_priority=1,
                    note=note,
                ))

        # Check Ciphers
        ciphers = config.get("ciphers", [])
        for cipher in ciphers:
            cipher_lower = cipher.lower()
            if cipher_lower in _WEAK_CIPHERS:
                risk, note = _WEAK_CIPHERS[cipher_lower]
                findings.append(Finding(
                    component="SSH Cipher",
                    algorithm=cipher,
                    risk_level=risk,
                    quantum_vulnerable=False,  # Symmetric ciphers are not directly quantum-vulnerable
                    location=f"{filepath}, Ciphers",
                    replacement=["aes256-gcm@openssh.com", "chacha20-poly1305@openssh.com"],
                    migration_priority=2 if risk in (RiskLevel.CRITICAL, RiskLevel.HIGH) else 3,
                    note=note,
                ))

        # Check MACs
        macs = config.get("macs", [])
        for mac in macs:
            mac_lower = mac.lower()
            if mac_lower in _WEAK_MACS:
                risk, note = _WEAK_MACS[mac_lower]
                findings.append(Finding(
                    component="SSH MAC",
                    algorithm=mac,
                    risk_level=risk,
                    quantum_vulnerable=False,
                    location=f"{filepath}, MACs",
                    replacement=["hmac-sha2-256-etm@openssh.com", "hmac-sha2-512-etm@openssh.com"],
                    migration_priority=3,
                    note=note,
                ))

        # Check HostKey directives for key type inference
        host_keys = config.get("hostkey", [])
        for key_path in host_keys:
            key_lower = key_path.lower()
            if "rsa" in key_lower:
                findings.append(Finding(
                    component="SSH Host Key File",
                    algorithm="RSA host key",
                    risk_level=RiskLevel.CRITICAL,
                    quantum_vulnerable=True,
                    location=f"{filepath}, HostKey {key_path}",
                    replacement=["Ed25519 host key (best classical)", "PQ host keys (when available)"],
                    migration_priority=1,
                    note="RSA host key is quantum vulnerable",
                ))
            elif "dsa" in key_lower:
                findings.append(Finding(
                    component="SSH Host Key File",
                    algorithm="DSA host key",
                    risk_level=RiskLevel.CRITICAL,
                    quantum_vulnerable=True,
                    location=f"{filepath}, HostKey {key_path}",
                    replacement=["Ed25519 host key"],
                    migration_priority=1,
                    note="DSA host key is classically and quantum vulnerable",
                ))

        # If no directives found, note that defaults are in use
        if not config:
            findings.append(Finding(
                component="SSH Configuration",
                algorithm="Default configuration",
                risk_level=RiskLevel.MEDIUM,
                quantum_vulnerable=True,
                location=f"{filepath}",
                replacement=["Explicitly configure KexAlgorithms, Ciphers, MACs"],
                migration_priority=3,
                note="No explicit crypto configuration found. Default OpenSSH settings include quantum-vulnerable algorithms.",
            ))

        return findings
