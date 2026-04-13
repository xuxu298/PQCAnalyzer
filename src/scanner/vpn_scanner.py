"""VPN configuration scanner — parse OpenVPN, WireGuard, IPSec configs."""

from __future__ import annotations

import logging
import re
from pathlib import Path

from src.scanner.models import Finding, ScanResult, ScanStatus
from src.utils.constants import RiskLevel, ScanType

logger = logging.getLogger(__name__)


# --- OpenVPN analysis tables ---

_OPENVPN_CIPHER_RISK: dict[str, tuple[RiskLevel, bool, str]] = {
    # cipher -> (risk, quantum_vulnerable, note)
    "bf-cbc": (RiskLevel.CRITICAL, False, "Blowfish is deprecated, 64-bit block (Sweet32)"),
    "des-cbc": (RiskLevel.CRITICAL, False, "DES is completely broken"),
    "des-ede3-cbc": (RiskLevel.HIGH, False, "3DES is deprecated, 64-bit block (Sweet32)"),
    "rc2-cbc": (RiskLevel.CRITICAL, False, "RC2 is broken"),
    "cast5-cbc": (RiskLevel.HIGH, False, "CAST5 is deprecated, 64-bit block"),
    "aes-128-cbc": (RiskLevel.MEDIUM, False, "AES-128 reduced to 64-bit security post-quantum, CBC mode"),
    "aes-192-cbc": (RiskLevel.LOW, False, "AES-192-CBC: consider GCM mode"),
    "aes-256-cbc": (RiskLevel.LOW, False, "AES-256-CBC: consider GCM mode for AEAD"),
    "aes-128-gcm": (RiskLevel.MEDIUM, False, "AES-128-GCM: reduced to 64-bit security post-quantum"),
    "aes-256-gcm": (RiskLevel.SAFE, False, "AES-256-GCM: quantum safe symmetric AEAD"),
    "chacha20-poly1305": (RiskLevel.SAFE, False, "ChaCha20-Poly1305: quantum safe symmetric AEAD"),
}

_OPENVPN_AUTH_RISK: dict[str, tuple[RiskLevel, str]] = {
    # auth digest -> (risk, note)
    "md5": (RiskLevel.CRITICAL, "MD5 is broken, collision attacks feasible"),
    "sha1": (RiskLevel.HIGH, "SHA-1 collision attacks demonstrated (SHAttered)"),
    "md4": (RiskLevel.CRITICAL, "MD4 is completely broken"),
    "rmd160": (RiskLevel.MEDIUM, "RIPEMD-160: limited security margin, prefer SHA-256+"),
    "sha224": (RiskLevel.LOW, "SHA-224: adequate but prefer SHA-256+"),
    "sha256": (RiskLevel.SAFE, "SHA-256: quantum safe hash"),
    "sha384": (RiskLevel.SAFE, "SHA-384: quantum safe hash"),
    "sha512": (RiskLevel.SAFE, "SHA-512: quantum safe hash"),
}

_OPENVPN_TLS_CIPHER_RISK: dict[str, tuple[RiskLevel, bool, str]] = {
    # Patterns for tls-cipher kex component
    "rsa": (RiskLevel.CRITICAL, True, "RSA key exchange is quantum vulnerable, no forward secrecy"),
    "dhe": (RiskLevel.HIGH, True, "DHE is quantum vulnerable (Shor's algorithm)"),
    "ecdhe": (RiskLevel.HIGH, True, "ECDHE is quantum vulnerable (Shor's ECDLP variant)"),
}


# --- WireGuard analysis ---

_WIREGUARD_CRYPTO = {
    "Curve25519": {
        "component": "WireGuard Key Exchange",
        "risk": RiskLevel.HIGH,
        "quantum_vulnerable": True,
        "note": "Curve25519 ECDH is quantum vulnerable (Shor's ECDLP variant). WireGuard has no PQC option yet.",
        "replacement": ["ML-KEM-768 (when WireGuard supports PQC)", "Rosenpass (PQC WireGuard wrapper)"],
    },
    "ChaCha20-Poly1305": {
        "component": "WireGuard Encryption",
        "risk": RiskLevel.SAFE,
        "quantum_vulnerable": False,
        "note": "ChaCha20-Poly1305 with 256-bit key is quantum safe.",
        "replacement": [],
    },
    "BLAKE2s": {
        "component": "WireGuard Hash/MAC",
        "risk": RiskLevel.SAFE,
        "quantum_vulnerable": False,
        "note": "BLAKE2s: quantum safe hash function.",
        "replacement": [],
    },
}


# --- IPSec/IKEv2 analysis tables ---

_IPSEC_KEX_RISK: dict[str, tuple[RiskLevel, bool, str, list[str]]] = {
    # group name/number -> (risk, qv, note, replacement)
    "modp768": (RiskLevel.CRITICAL, True, "DH-768 is classically and quantum broken", ["ML-KEM-768"]),
    "modp1024": (RiskLevel.CRITICAL, True, "DH-1024 is classically weak and quantum vulnerable", ["ML-KEM-768"]),
    "modp1536": (RiskLevel.CRITICAL, True, "DH-1536 is classically weak and quantum vulnerable", ["ML-KEM-768"]),
    "modp2048": (RiskLevel.HIGH, True, "DH-2048 is quantum vulnerable (Shor's algorithm)", ["ML-KEM-768"]),
    "modp3072": (RiskLevel.HIGH, True, "DH-3072 is quantum vulnerable (Shor's algorithm)", ["ML-KEM-768"]),
    "modp4096": (RiskLevel.HIGH, True, "DH-4096 is quantum vulnerable (Shor's algorithm)", ["ML-KEM-1024"]),
    "modp6144": (RiskLevel.HIGH, True, "DH-6144 is quantum vulnerable (Shor's algorithm)", ["ML-KEM-1024"]),
    "modp8192": (RiskLevel.HIGH, True, "DH-8192 is quantum vulnerable despite large key (Shor's algorithm)", ["ML-KEM-1024"]),
    "ecp256": (RiskLevel.HIGH, True, "ECDH P-256 is quantum vulnerable (Shor's ECDLP)", ["ML-KEM-768"]),
    "ecp384": (RiskLevel.HIGH, True, "ECDH P-384 is quantum vulnerable (Shor's ECDLP)", ["ML-KEM-768"]),
    "ecp521": (RiskLevel.HIGH, True, "ECDH P-521 is quantum vulnerable (Shor's ECDLP)", ["ML-KEM-1024"]),
    "curve25519": (RiskLevel.HIGH, True, "Curve25519 is quantum vulnerable (Shor's ECDLP)", ["ML-KEM-768"]),
}

_IPSEC_ENC_RISK: dict[str, tuple[RiskLevel, bool, str]] = {
    "des": (RiskLevel.CRITICAL, False, "DES is completely broken"),
    "3des": (RiskLevel.HIGH, False, "3DES is deprecated, 64-bit block (Sweet32)"),
    "blowfish": (RiskLevel.HIGH, False, "Blowfish is deprecated, 64-bit block"),
    "cast128": (RiskLevel.HIGH, False, "CAST-128 is deprecated, 64-bit block"),
    "aes128": (RiskLevel.MEDIUM, False, "AES-128 reduced to 64-bit security post-quantum"),
    "aes192": (RiskLevel.LOW, False, "AES-192: adequate post-quantum"),
    "aes256": (RiskLevel.SAFE, False, "AES-256: quantum safe"),
    "aes128gcm16": (RiskLevel.MEDIUM, False, "AES-128-GCM: reduced to 64-bit security post-quantum"),
    "aes256gcm16": (RiskLevel.SAFE, False, "AES-256-GCM: quantum safe AEAD"),
    "chacha20poly1305": (RiskLevel.SAFE, False, "ChaCha20-Poly1305: quantum safe AEAD"),
}

_IPSEC_AUTH_RISK: dict[str, tuple[RiskLevel, str]] = {
    "md5": (RiskLevel.CRITICAL, "MD5 is broken"),
    "sha1": (RiskLevel.HIGH, "SHA-1 collision attacks demonstrated"),
    "sha256": (RiskLevel.SAFE, "SHA-256: quantum safe"),
    "sha384": (RiskLevel.SAFE, "SHA-384: quantum safe"),
    "sha512": (RiskLevel.SAFE, "SHA-512: quantum safe"),
    "sha2_256": (RiskLevel.SAFE, "SHA-256: quantum safe"),
    "sha2_384": (RiskLevel.SAFE, "SHA-384: quantum safe"),
    "sha2_512": (RiskLevel.SAFE, "SHA-512: quantum safe"),
}

# Common DH group number -> name mapping
_DH_GROUP_MAP: dict[str, str] = {
    "1": "modp768", "2": "modp1024", "5": "modp1536",
    "14": "modp2048", "15": "modp3072", "16": "modp4096",
    "17": "modp6144", "18": "modp8192",
    "19": "ecp256", "20": "ecp384", "21": "ecp521",
    "31": "curve25519",
}


class VPNScanner:
    """Scan VPN configuration files for quantum-vulnerable algorithms."""

    def scan_file(self, filepath: str) -> ScanResult:
        """Scan a VPN config file, auto-detecting type."""
        result = ScanResult(target=filepath, scan_type=ScanType.VPN_CONFIG)
        path = Path(filepath)

        if not path.exists():
            result.status = ScanStatus.ERROR
            result.error_message = f"File not found: {filepath}"
            return result

        try:
            content = path.read_text(errors="replace")
            vpn_type = self._detect_vpn_type(content, filepath)

            if vpn_type == "openvpn":
                result.findings = self._analyze_openvpn(content, filepath)
            elif vpn_type == "wireguard":
                result.findings = self._analyze_wireguard(content, filepath)
            elif vpn_type == "ipsec":
                result.findings = self._analyze_ipsec(content, filepath)
            else:
                result.status = ScanStatus.SKIPPED
                result.error_message = f"Could not detect VPN config type for: {filepath}"
                return result

            result.status = ScanStatus.SUCCESS
            result.metadata = {"vpn_type": vpn_type}
        except Exception as e:
            result.status = ScanStatus.ERROR
            result.error_message = str(e)
            logger.error("Error scanning VPN config %s: %s", filepath, e)

        result.finalize()
        return result

    def _detect_vpn_type(self, content: str, filepath: str) -> str | None:
        """Detect VPN config type from content and filename."""
        name_lower = Path(filepath).name.lower()
        content_lower = content.lower()

        # WireGuard detection
        if name_lower.endswith(".conf") and (
            "[interface]" in content_lower and "[peer]" in content_lower
        ):
            return "wireguard"
        if "privatekey" in content_lower and "allowedips" in content_lower:
            return "wireguard"

        # OpenVPN detection
        openvpn_markers = ["remote ", "dev tun", "dev tap", "proto udp", "proto tcp",
                           "cipher ", "auth ", "tls-cipher", "ca ", "client", "server"]
        if any(m in content_lower for m in openvpn_markers):
            if name_lower.endswith((".ovpn", ".conf")) or sum(1 for m in openvpn_markers if m in content_lower) >= 3:
                return "openvpn"

        # IPSec detection (strongSwan, Libreswan, racoon)
        ipsec_markers = ["ike=", "esp=", "conn ", "phase1", "phase2",
                         "ikev2=", "keyexchange=", "ipsec.conf"]
        if any(m in content_lower for m in ipsec_markers):
            return "ipsec"
        if name_lower in ("ipsec.conf", "ipsec.secrets") or "racoon" in name_lower:
            return "ipsec"

        return None

    # --- OpenVPN ---

    def _analyze_openvpn(self, content: str, filepath: str) -> list[Finding]:
        """Analyze OpenVPN config."""
        findings: list[Finding] = []
        config = self._parse_openvpn(content)

        # Analyze cipher directive
        cipher = config.get("cipher", "").lower()
        if cipher:
            if cipher in _OPENVPN_CIPHER_RISK:
                risk, qv, note = _OPENVPN_CIPHER_RISK[cipher]
                findings.append(Finding(
                    component="OpenVPN Cipher",
                    algorithm=cipher.upper(),
                    risk_level=risk,
                    quantum_vulnerable=qv,
                    location=f"{filepath}, cipher directive",
                    replacement=["AES-256-GCM", "ChaCha20-Poly1305"],
                    migration_priority=1 if risk == RiskLevel.CRITICAL else 2,
                    note=note,
                ))
            else:
                findings.append(Finding(
                    component="OpenVPN Cipher",
                    algorithm=cipher.upper(),
                    risk_level=RiskLevel.MEDIUM,
                    quantum_vulnerable=False,
                    location=f"{filepath}, cipher directive",
                    replacement=["AES-256-GCM"],
                    migration_priority=3,
                    note=f"Unknown cipher '{cipher}', review recommended",
                ))

        # Analyze data-ciphers / ncp-ciphers
        for directive_name in ("data-ciphers", "ncp-ciphers"):
            ciphers_str = config.get(directive_name, "")
            if ciphers_str:
                for c in ciphers_str.split(":"):
                    c = c.strip().lower()
                    if c and c in _OPENVPN_CIPHER_RISK:
                        risk, qv, note = _OPENVPN_CIPHER_RISK[c]
                        if risk in (RiskLevel.CRITICAL, RiskLevel.HIGH, RiskLevel.MEDIUM):
                            findings.append(Finding(
                                component="OpenVPN Data Cipher",
                                algorithm=c.upper(),
                                risk_level=risk,
                                quantum_vulnerable=qv,
                                location=f"{filepath}, {directive_name}",
                                replacement=["AES-256-GCM", "ChaCha20-Poly1305"],
                                migration_priority=2,
                                note=note,
                            ))

        # Analyze auth digest
        auth = config.get("auth", "").lower()
        if auth and auth in _OPENVPN_AUTH_RISK:
            risk, note = _OPENVPN_AUTH_RISK[auth]
            if risk in (RiskLevel.CRITICAL, RiskLevel.HIGH, RiskLevel.MEDIUM):
                findings.append(Finding(
                    component="OpenVPN Auth Digest",
                    algorithm=auth.upper(),
                    risk_level=risk,
                    quantum_vulnerable=False,
                    location=f"{filepath}, auth directive",
                    replacement=["SHA-256", "SHA-384", "SHA-512"],
                    migration_priority=2,
                    note=note,
                ))

        # Analyze tls-cipher for key exchange
        tls_cipher = config.get("tls-cipher", "")
        if tls_cipher:
            findings.extend(self._analyze_openvpn_tls_cipher(tls_cipher, filepath))

        # Analyze tls-ciphersuites (TLS 1.3)
        tls13_suites = config.get("tls-ciphersuites", "")
        if tls13_suites:
            # TLS 1.3 suites use ECDHE by default, still quantum vulnerable kex
            findings.append(Finding(
                component="OpenVPN TLS 1.3 Key Exchange",
                algorithm="ECDHE (implicit in TLS 1.3)",
                risk_level=RiskLevel.HIGH,
                quantum_vulnerable=True,
                location=f"{filepath}, tls-ciphersuites",
                replacement=["X25519Kyber768 hybrid (when OpenVPN supports PQC)"],
                migration_priority=2,
                note="TLS 1.3 cipher suites use ECDHE key exchange which is quantum vulnerable.",
            ))

        # Check CA/cert/key presence (informational)
        ca = config.get("ca", "")
        cert = config.get("cert", "")
        if ca or cert:
            findings.append(Finding(
                component="OpenVPN PKI",
                algorithm="RSA/ECDSA certificates (check CA)",
                risk_level=RiskLevel.HIGH,
                quantum_vulnerable=True,
                location=f"{filepath}, ca/cert directives",
                replacement=["ML-DSA-65 certificates (when CA supports PQC)"],
                migration_priority=2,
                note="OpenVPN PKI typically uses RSA or ECDSA certificates, both quantum vulnerable. "
                     "Verify certificate algorithms with cert_analyzer.",
            ))

        # If no cipher found, warn about defaults
        if not cipher and not config.get("data-ciphers") and not config.get("ncp-ciphers"):
            findings.append(Finding(
                component="OpenVPN Cipher",
                algorithm="BF-CBC (default)",
                risk_level=RiskLevel.CRITICAL,
                quantum_vulnerable=False,
                location=f"{filepath}, no cipher directive",
                replacement=["AES-256-GCM"],
                migration_priority=1,
                note="No cipher specified. OpenVPN defaults to BF-CBC (Blowfish) which is deprecated.",
            ))

        return findings

    def _parse_openvpn(self, content: str) -> dict[str, str]:
        """Parse OpenVPN config into directive -> value mapping."""
        config: dict[str, str] = {}
        directives = [
            "cipher", "auth", "tls-cipher", "tls-ciphersuites",
            "data-ciphers", "ncp-ciphers", "ca", "cert", "key",
            "tls-auth", "tls-crypt", "remote", "proto", "dev",
        ]
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith(("#", ";", "<")):
                continue
            for directive in directives:
                match = re.match(rf"^{re.escape(directive)}\s+(.+)$", line, re.IGNORECASE)
                if match:
                    config[directive.lower()] = match.group(1).strip().strip("'\"")
                    break
        return config

    def _analyze_openvpn_tls_cipher(self, tls_cipher: str, filepath: str) -> list[Finding]:
        """Analyze OpenVPN tls-cipher directive for key exchange algorithms."""
        findings: list[Finding] = []
        seen: set[str] = set()

        for suite in tls_cipher.split(":"):
            suite_upper = suite.strip().upper()
            if not suite_upper:
                continue

            # Check key exchange component
            if "RSA" in suite_upper and "kex:rsa" not in seen:
                seen.add("kex:rsa")
                findings.append(Finding(
                    component="OpenVPN TLS Key Exchange",
                    algorithm="RSA key exchange",
                    risk_level=RiskLevel.CRITICAL,
                    quantum_vulnerable=True,
                    location=f"{filepath}, tls-cipher: {suite.strip()}",
                    replacement=["ECDHE-based suites", "PQC hybrid key exchange (future)"],
                    migration_priority=1,
                    note="RSA key exchange is quantum vulnerable and provides no forward secrecy.",
                ))
            elif "DHE" in suite_upper and "ECDHE" not in suite_upper and "kex:dhe" not in seen:
                seen.add("kex:dhe")
                findings.append(Finding(
                    component="OpenVPN TLS Key Exchange",
                    algorithm="DHE key exchange",
                    risk_level=RiskLevel.HIGH,
                    quantum_vulnerable=True,
                    location=f"{filepath}, tls-cipher: {suite.strip()}",
                    replacement=["ECDHE (better classical)", "PQC hybrid (future)"],
                    migration_priority=2,
                    note="DHE is quantum vulnerable (Shor's algorithm).",
                ))
            elif "ECDHE" in suite_upper and "kex:ecdhe" not in seen:
                seen.add("kex:ecdhe")
                findings.append(Finding(
                    component="OpenVPN TLS Key Exchange",
                    algorithm="ECDHE key exchange",
                    risk_level=RiskLevel.HIGH,
                    quantum_vulnerable=True,
                    location=f"{filepath}, tls-cipher",
                    replacement=["X25519Kyber768 hybrid (when available)"],
                    migration_priority=2,
                    note="ECDHE is quantum vulnerable (Shor's ECDLP variant). Best classical choice but not PQC safe.",
                ))

        return findings

    # --- WireGuard ---

    def _analyze_wireguard(self, content: str, filepath: str) -> list[Finding]:
        """Analyze WireGuard config.

        WireGuard uses a fixed crypto stack: Curve25519, ChaCha20-Poly1305, BLAKE2s, SipHash24.
        No configurability — always report the same findings.
        """
        findings: list[Finding] = []

        for algo_name, info in _WIREGUARD_CRYPTO.items():
            findings.append(Finding(
                component=info["component"],
                algorithm=algo_name,
                risk_level=info["risk"],
                quantum_vulnerable=info["quantum_vulnerable"],
                location=f"{filepath}, WireGuard fixed crypto stack",
                replacement=info["replacement"],
                migration_priority=1 if info["quantum_vulnerable"] else 5,
                note=info["note"],
            ))

        # Count peers for context
        peer_count = len(re.findall(r"^\[Peer\]", content, re.MULTILINE | re.IGNORECASE))
        if peer_count > 0:
            findings[0].note += f" ({peer_count} peer(s) configured)"

        return findings

    # --- IPSec / IKEv2 ---

    def _analyze_ipsec(self, content: str, filepath: str) -> list[Finding]:
        """Analyze IPSec/IKEv2 config (strongSwan/Libreswan format)."""
        findings: list[Finding] = []
        connections = self._parse_ipsec_connections(content)

        for conn_name, conn_config in connections.items():
            # Analyze ike= (Phase 1 / IKE SA)
            ike_str = conn_config.get("ike", "")
            if ike_str:
                findings.extend(self._analyze_ipsec_proposal(
                    ike_str, filepath, conn_name, phase="IKE (Phase 1)"
                ))

            # Analyze esp= (Phase 2 / Child SA)
            esp_str = conn_config.get("esp", "")
            if esp_str:
                findings.extend(self._analyze_ipsec_proposal(
                    esp_str, filepath, conn_name, phase="ESP (Phase 2)"
                ))

            # Check keyexchange type
            kex_type = conn_config.get("keyexchange", "")
            if kex_type.lower() == "ikev1":
                findings.append(Finding(
                    component=f"IPSec [{conn_name}] Protocol",
                    algorithm="IKEv1",
                    risk_level=RiskLevel.HIGH,
                    quantum_vulnerable=True,
                    location=f"{filepath}, conn {conn_name}, keyexchange",
                    replacement=["IKEv2"],
                    migration_priority=2,
                    note="IKEv1 is deprecated. Upgrade to IKEv2.",
                ))

        # If no connections with crypto found, check for global defaults
        if not connections:
            findings.append(Finding(
                component="IPSec Configuration",
                algorithm="Default configuration",
                risk_level=RiskLevel.MEDIUM,
                quantum_vulnerable=True,
                location=filepath,
                replacement=["Explicitly configure ike= and esp= proposals"],
                migration_priority=3,
                note="No explicit IPSec crypto proposals found. Defaults may include quantum-vulnerable algorithms.",
            ))

        return findings

    def _parse_ipsec_connections(self, content: str) -> dict[str, dict[str, str]]:
        """Parse IPSec config into connection name -> settings mapping."""
        connections: dict[str, dict[str, str]] = {}
        current_conn: str | None = None

        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            # Connection header: conn <name>
            conn_match = re.match(r"^conn\s+(\S+)", line, re.IGNORECASE)
            if conn_match:
                current_conn = conn_match.group(1)
                connections[current_conn] = {}
                continue

            # Key=value inside a connection block
            if current_conn:
                kv_match = re.match(r"^\s*(\w[\w-]*)\s*=\s*(.+)$", line)
                if kv_match:
                    key = kv_match.group(1).lower()
                    value = kv_match.group(2).strip()
                    connections[current_conn][key] = value
                elif not line.startswith((" ", "\t")):
                    # No indentation — probably a new section
                    if re.match(r"^(conn|config|ca)\s+", line, re.IGNORECASE):
                        current_conn = None

        return connections

    def _analyze_ipsec_proposal(
        self, proposal_str: str, filepath: str, conn_name: str, phase: str,
    ) -> list[Finding]:
        """Analyze an IPSec ike= or esp= proposal string."""
        findings: list[Finding] = []
        seen_kex: set[str] = set()
        seen_enc: set[str] = set()

        # Proposals separated by comma, components by dash
        for proposal in proposal_str.split(","):
            proposal = proposal.strip().lower()
            if not proposal:
                continue

            parts = proposal.split("-")

            for part in parts:
                part = part.strip()

                # Check encryption
                if part in _IPSEC_ENC_RISK and part not in seen_enc:
                    seen_enc.add(part)
                    risk, qv, note = _IPSEC_ENC_RISK[part]
                    if risk != RiskLevel.SAFE:
                        findings.append(Finding(
                            component=f"IPSec [{conn_name}] {phase} Encryption",
                            algorithm=part.upper(),
                            risk_level=risk,
                            quantum_vulnerable=qv,
                            location=f"{filepath}, conn {conn_name}",
                            replacement=["AES-256-GCM", "ChaCha20-Poly1305"],
                            migration_priority=2 if risk in (RiskLevel.CRITICAL, RiskLevel.HIGH) else 3,
                            note=note,
                        ))

                # Check auth/integrity
                if part in _IPSEC_AUTH_RISK:
                    risk, note = _IPSEC_AUTH_RISK[part]
                    if risk != RiskLevel.SAFE:
                        findings.append(Finding(
                            component=f"IPSec [{conn_name}] {phase} Integrity",
                            algorithm=part.upper(),
                            risk_level=risk,
                            quantum_vulnerable=False,
                            location=f"{filepath}, conn {conn_name}",
                            replacement=["SHA-256", "SHA-384", "SHA-512"],
                            migration_priority=2 if risk == RiskLevel.CRITICAL else 3,
                            note=note,
                        ))

                # Check DH groups (kex)
                kex_name = _DH_GROUP_MAP.get(part, part)
                if kex_name in _IPSEC_KEX_RISK and kex_name not in seen_kex:
                    seen_kex.add(kex_name)
                    risk, qv, note, replacement = _IPSEC_KEX_RISK[kex_name]
                    findings.append(Finding(
                        component=f"IPSec [{conn_name}] {phase} Key Exchange",
                        algorithm=kex_name.upper(),
                        risk_level=risk,
                        quantum_vulnerable=qv,
                        location=f"{filepath}, conn {conn_name}",
                        replacement=replacement,
                        migration_priority=1,
                        note=note,
                    ))

            # Also try matching multi-part encryption names
            for enc_name in _IPSEC_ENC_RISK:
                if enc_name in proposal and enc_name not in seen_enc:
                    seen_enc.add(enc_name)
                    risk, qv, note = _IPSEC_ENC_RISK[enc_name]
                    if risk != RiskLevel.SAFE:
                        findings.append(Finding(
                            component=f"IPSec [{conn_name}] {phase} Encryption",
                            algorithm=enc_name.upper(),
                            risk_level=risk,
                            quantum_vulnerable=qv,
                            location=f"{filepath}, conn {conn_name}",
                            replacement=["AES-256-GCM", "ChaCha20-Poly1305"],
                            migration_priority=2 if risk in (RiskLevel.CRITICAL, RiskLevel.HIGH) else 3,
                            note=note,
                        ))

        return findings
