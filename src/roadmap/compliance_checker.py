"""Compliance checker — verify against NIST and Vietnam BCY guidelines."""

from __future__ import annotations

from src.roadmap.models import ComplianceStatus
from src.scanner.models import Finding
from src.utils.constants import RiskLevel


def check_compliance(findings: list[Finding]) -> list[ComplianceStatus]:
    """Check findings against compliance standards.

    Currently checks:
    - NIST SP 800-208 (commercial NSA suite replacement)
    - NIST FIPS 203/204/205 readiness
    - CNSS Policy 15 (quantum-safe timelines)
    - Vietnam Ban Co Yeu (when guidelines available)
    """
    statuses: list[ComplianceStatus] = []

    statuses.extend(_check_nist_pqc_readiness(findings))
    statuses.extend(_check_deprecated_algorithms(findings))
    statuses.extend(_check_key_lengths(findings))
    statuses.extend(_check_vietnam_bcy(findings))

    return statuses


def _check_nist_pqc_readiness(findings: list[Finding]) -> list[ComplianceStatus]:
    """Check readiness for NIST PQC standards (FIPS 203, 204, 205)."""
    statuses: list[ComplianceStatus] = []

    # Check if any quantum-vulnerable key exchange is in use
    qv_kex = [f for f in findings
              if f.quantum_vulnerable
              and any(kw in f.component.lower() for kw in ["key exchange", "kex", "kem"])]

    if qv_kex:
        statuses.append(ComplianceStatus(
            standard="NIST FIPS 203 (ML-KEM)",
            requirement="Transition to ML-KEM for key encapsulation",
            status="non_compliant",
            details=f"{len(qv_kex)} quantum-vulnerable key exchange(s) found. "
                    "ML-KEM (Kyber) should replace RSA/ECDH/DH key exchange.",
            remediation="Enable ML-KEM-768 or hybrid X25519Kyber768 key exchange.",
        ))
    else:
        statuses.append(ComplianceStatus(
            standard="NIST FIPS 203 (ML-KEM)",
            requirement="Transition to ML-KEM for key encapsulation",
            status="compliant" if not any(f.quantum_vulnerable for f in findings) else "partial",
            details="No quantum-vulnerable key exchange detected.",
        ))

    # Check signatures
    qv_sig = [f for f in findings
              if f.quantum_vulnerable
              and any(kw in f.component.lower()
                     for kw in ["signature", "certificate", "cert", "sign", "host key"])]

    if qv_sig:
        statuses.append(ComplianceStatus(
            standard="NIST FIPS 204 (ML-DSA)",
            requirement="Transition to ML-DSA for digital signatures",
            status="non_compliant",
            details=f"{len(qv_sig)} quantum-vulnerable signature/certificate(s) found. "
                    "ML-DSA (Dilithium) should replace RSA/ECDSA/DSA signatures.",
            remediation="Plan certificate migration to ML-DSA when CA ecosystem supports it.",
        ))
    else:
        statuses.append(ComplianceStatus(
            standard="NIST FIPS 204 (ML-DSA)",
            requirement="Transition to ML-DSA for digital signatures",
            status="compliant" if not any(f.quantum_vulnerable for f in findings) else "partial",
            details="No quantum-vulnerable signatures detected.",
        ))

    return statuses


def _check_deprecated_algorithms(findings: list[Finding]) -> list[ComplianceStatus]:
    """Check for deprecated algorithms per NIST SP 800-131A."""
    deprecated = {"DES", "3DES", "RC4", "MD5", "SHA-1", "SHA1", "DSA",
                  "BF-CBC", "BLOWFISH", "ARCFOUR", "CAST"}

    found_deprecated = [
        f for f in findings
        if any(d.lower() in f.algorithm.lower() for d in deprecated)
    ]

    if found_deprecated:
        algos = set(f.algorithm for f in found_deprecated)
        return [ComplianceStatus(
            standard="NIST SP 800-131A",
            requirement="Remove deprecated cryptographic algorithms",
            status="non_compliant",
            details=f"Deprecated algorithms in use: {', '.join(sorted(algos))}",
            remediation="Replace with approved alternatives (AES-256, SHA-256+, RSA-2048+/ECDSA-P256+).",
        )]
    return [ComplianceStatus(
        standard="NIST SP 800-131A",
        requirement="Remove deprecated cryptographic algorithms",
        status="compliant",
        details="No deprecated algorithms detected.",
    )]


def _check_key_lengths(findings: list[Finding]) -> list[ComplianceStatus]:
    """Check minimum key lengths per NIST SP 800-57."""
    short_key_issues = []
    for f in findings:
        algo = f.algorithm.upper()
        if "RSA-1024" in algo or "RSA-512" in algo:
            short_key_issues.append(f"RSA key too short: {f.algorithm}")
        if "DH-768" in algo or "DH-1024" in algo or "MODP768" in algo or "MODP1024" in algo:
            short_key_issues.append(f"DH group too small: {f.algorithm}")

    if short_key_issues:
        return [ComplianceStatus(
            standard="NIST SP 800-57",
            requirement="Minimum cryptographic key lengths",
            status="non_compliant",
            details="; ".join(short_key_issues),
            remediation="Use minimum RSA-2048, DH-2048, ECDSA-P256.",
        )]
    return [ComplianceStatus(
        standard="NIST SP 800-57",
        requirement="Minimum cryptographic key lengths",
        status="compliant",
        details="All key lengths meet minimum requirements.",
    )]


def _check_vietnam_bcy(findings: list[Finding]) -> list[ComplianceStatus]:
    """Check against Vietnam Ban Co Yeu (Government Cipher Committee) guidelines.

    Note: Vietnam's specific PQC migration guidelines are still being developed.
    This checks against known general requirements.
    """
    qv_findings = [f for f in findings if f.quantum_vulnerable]
    critical = [f for f in findings
                if (f.risk_level == RiskLevel.CRITICAL
                    if isinstance(f.risk_level, RiskLevel)
                    else f.risk_level == "CRITICAL")]

    status = "compliant"
    details = "No critical issues detected."
    remediation = ""

    if critical:
        status = "non_compliant"
        details = (f"{len(critical)} critical finding(s), {len(qv_findings)} quantum-vulnerable. "
                   "Vietnamese government systems should prioritize PQC migration "
                   "per Ban Co Yeu guidance on cryptographic modernization.")
        remediation = ("Follow NIST PQC timeline. Begin hybrid deployment for internet-facing services. "
                      "Coordinate with Ban Co Yeu for compliance verification.")
    elif qv_findings:
        status = "partial"
        details = (f"{len(qv_findings)} quantum-vulnerable finding(s). "
                   "Plan migration per PQC readiness timeline.")
        remediation = "Begin PQC readiness assessment and migration planning."

    return [ComplianceStatus(
        standard="Vietnam Ban Co Yeu - Cryptographic Modernization",
        requirement="PQC readiness for government and critical infrastructure",
        status=status,
        details=details,
        remediation=remediation,
    )]
