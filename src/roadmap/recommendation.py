"""Recommendation engine — suggest PQC migration actions for findings."""

from __future__ import annotations

from dataclasses import dataclass, field

from src.scanner.models import Finding


@dataclass
class Recommendation:
    """A migration recommendation for a finding."""

    finding_algorithm: str = ""
    finding_component: str = ""
    replace_with: str = ""
    effort: str = "Medium"
    risk: str = "Low"
    timeline_phase: int = 1
    steps: list[str] = field(default_factory=list)
    note: str = ""

    def to_dict(self) -> dict:
        return {
            "finding_algorithm": self.finding_algorithm,
            "finding_component": self.finding_component,
            "replace_with": self.replace_with,
            "effort": self.effort,
            "risk": self.risk,
            "timeline_phase": self.timeline_phase,
            "steps": self.steps,
            "note": self.note,
        }


# Recommendation templates keyed by (component_keyword, algorithm_keyword)
_RECOMMENDATIONS: list[dict] = [
    # TLS key exchange
    {
        "match_component": ["TLS Key Exchange"],
        "match_algorithm": ["ECDHE", "DHE", "RSA key exchange", "X25519", "Curve25519"],
        "replace_with": "ML-KEM-768 (hybrid X25519Kyber768)",
        "effort": "Low-Medium",
        "risk": "Low (hybrid mode backward compatible)",
        "phase": 1,
        "steps": [
            "Verify server supports TLS 1.3",
            "Enable X25519Kyber768 hybrid key exchange in server config",
            "Test with clients that support hybrid KEM",
            "Monitor handshake latency and success rate",
            "Disable classical-only key exchange after validation",
        ],
    },
    # RSA certificates
    {
        "match_component": ["Certificate", "Cert"],
        "match_algorithm": ["RSA"],
        "replace_with": "ML-DSA-65 certificate (when CA supports PQC)",
        "effort": "Medium-High",
        "risk": "Medium (CA ecosystem not fully ready)",
        "phase": 2,
        "steps": [
            "Check if CA provider issues PQC or hybrid certificates",
            "Request hybrid certificate (RSA + ML-DSA) if available",
            "Test certificate chain validation with clients",
            "Deploy dual-certificate setup (classical + PQC)",
            "Full migration when CA ecosystem matures",
        ],
    },
    # ECDSA certificates
    {
        "match_component": ["Certificate", "Cert"],
        "match_algorithm": ["ECDSA", "ECC"],
        "replace_with": "ML-DSA-44 or ML-DSA-65 certificate",
        "effort": "Medium-High",
        "risk": "Medium",
        "phase": 2,
        "steps": [
            "Inventory all ECDSA certificates and their expiry dates",
            "Plan renewal with PQC-capable CA",
            "Test hybrid certificates in staging",
            "Deploy during next certificate renewal cycle",
        ],
    },
    # SSH key exchange
    {
        "match_component": ["SSH Key Exchange", "SSH"],
        "match_algorithm": ["diffie-hellman", "ecdh", "curve25519"],
        "replace_with": "sntrup761x25519-sha512@openssh.com (hybrid PQ)",
        "effort": "Low",
        "risk": "Low",
        "phase": 1,
        "steps": [
            "Verify OpenSSH version >= 9.0 (supports sntrup761)",
            "Update KexAlgorithms in sshd_config to prefer sntrup761x25519",
            "Test SSH connectivity from all clients",
            "Deploy to production servers",
        ],
    },
    # SSH host keys
    {
        "match_component": ["SSH Host Key"],
        "match_algorithm": ["RSA", "ECDSA", "DSA", "Ed25519"],
        "replace_with": "PQ host keys (when OpenSSH supports ML-DSA)",
        "effort": "Low",
        "risk": "Low",
        "phase": 1,
        "steps": [
            "Generate Ed25519 host key (best classical option)",
            "Prefer Ed25519 in HostKeyAlgorithms",
            "Remove DSA host keys completely",
            "Monitor for PQ host key support in OpenSSH",
        ],
    },
    # Weak ciphers (DES, 3DES, RC4, Blowfish)
    {
        "match_component": ["Cipher", "Encryption"],
        "match_algorithm": ["DES", "3DES", "RC4", "Blowfish", "BF-CBC", "CAST"],
        "replace_with": "AES-256-GCM or ChaCha20-Poly1305",
        "effort": "Low",
        "risk": "Low",
        "phase": 1,
        "steps": [
            "Disable weak cipher in server/application config",
            "Enable AES-256-GCM and ChaCha20-Poly1305",
            "Verify client compatibility",
            "Remove weak cipher from allowed list",
        ],
    },
    # AES-128 upgrade
    {
        "match_component": ["Cipher", "Encryption"],
        "match_algorithm": ["AES-128", "AES128"],
        "replace_with": "AES-256-GCM",
        "effort": "Low",
        "risk": "Low",
        "phase": 1,
        "steps": [
            "Update cipher configuration to prefer AES-256",
            "Remove AES-128 from allowed ciphers where possible",
            "Test performance impact (minimal for modern hardware)",
        ],
    },
    # Weak hashes (MD5, SHA-1)
    {
        "match_component": ["Hash", "MAC", "Auth", "Digest"],
        "match_algorithm": ["MD5", "SHA-1", "SHA1"],
        "replace_with": "SHA-256 or SHA-3-256",
        "effort": "Low",
        "risk": "Low",
        "phase": 1,
        "steps": [
            "Replace MD5/SHA-1 with SHA-256 in application code",
            "Update HMAC configurations to use SHA-256+",
            "Verify no signature verification depends on SHA-1",
        ],
    },
    # OpenVPN PKI
    {
        "match_component": ["OpenVPN PKI", "OpenVPN"],
        "match_algorithm": ["RSA", "ECDSA", "certificate"],
        "replace_with": "PQC-aware PKI (when OpenVPN supports it)",
        "effort": "High",
        "risk": "Medium",
        "phase": 2,
        "steps": [
            "Verify CA certificate algorithms (use cert_analyzer)",
            "Plan CA re-key with PQC algorithms when supported",
            "Enable tls-crypt for additional protection layer",
            "Consider WireGuard + Rosenpass for PQC VPN",
        ],
    },
    # WireGuard
    {
        "match_component": ["WireGuard"],
        "match_algorithm": ["Curve25519"],
        "replace_with": "Rosenpass (PQC WireGuard wrapper) or ML-KEM when supported",
        "effort": "Medium",
        "risk": "Medium",
        "phase": 2,
        "steps": [
            "Evaluate Rosenpass as PQC layer on top of WireGuard",
            "Test Rosenpass in staging environment",
            "Monitor WireGuard project for native PQC support",
            "Deploy Rosenpass or wait for native PQC integration",
        ],
    },
    # IPSec
    {
        "match_component": ["IPSec"],
        "match_algorithm": ["MODP", "ECP", "DH", "modp"],
        "replace_with": "PQC IPSec proposals (when strongSwan supports ML-KEM)",
        "effort": "Medium-High",
        "risk": "Medium",
        "phase": 2,
        "steps": [
            "Upgrade to strongSwan >= 6.0 (PQC support)",
            "Configure PQC proposals in ike= and esp= directives",
            "Test interoperability with peer VPN devices",
            "Migrate to IKEv2 if still using IKEv1",
        ],
    },
    # Source code crypto
    {
        "match_component": ["Python", "Java", "Go", "Node", "C/C++"],
        "match_algorithm": ["RSA", "ECDSA", "ECDH", "DH", "DSA", "Ed25519"],
        "replace_with": "PQC libraries (liboqs, Bouncy Castle PQC, circl)",
        "effort": "High",
        "risk": "Medium",
        "phase": 2,
        "steps": [
            "Inventory all crypto usage in codebase",
            "Identify PQC library for your language/framework",
            "Create abstraction layer for crypto operations",
            "Implement PQC alternatives behind feature flags",
            "Test thoroughly in staging",
            "Gradual rollout to production",
        ],
    },
]


def recommend(finding: Finding) -> Recommendation:
    """Generate a recommendation for a finding."""
    for tmpl in _RECOMMENDATIONS:
        component_match = any(
            kw.lower() in finding.component.lower()
            for kw in tmpl["match_component"]
        )
        algorithm_match = any(
            kw.lower() in finding.algorithm.lower()
            for kw in tmpl["match_algorithm"]
        )
        if component_match and algorithm_match:
            return Recommendation(
                finding_algorithm=finding.algorithm,
                finding_component=finding.component,
                replace_with=tmpl["replace_with"],
                effort=tmpl["effort"],
                risk=tmpl["risk"],
                timeline_phase=tmpl["phase"],
                steps=list(tmpl["steps"]),
            )

    # Default recommendation
    replacement_str = ", ".join(finding.replacement[:2]) if finding.replacement else "Review and upgrade"
    return Recommendation(
        finding_algorithm=finding.algorithm,
        finding_component=finding.component,
        replace_with=replacement_str,
        effort="Medium",
        risk="Medium",
        timeline_phase=2,
        steps=[
            f"Review {finding.component} using {finding.algorithm}",
            "Identify PQC replacement",
            "Test in staging environment",
            "Deploy to production",
        ],
    )


def recommend_all(findings: list[Finding]) -> list[Recommendation]:
    """Generate recommendations for all findings."""
    return [recommend(f) for f in findings]
