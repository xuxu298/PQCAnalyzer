"""Risk scoring engine — compute risk scores for scanner findings."""

from __future__ import annotations

from src.scanner.models import Finding
from src.roadmap.models import RiskScore
from src.utils.constants import RiskLevel


# Vulnerability weights by risk level
VULNERABILITY_WEIGHTS: dict[RiskLevel, int] = {
    RiskLevel.CRITICAL: 10,
    RiskLevel.HIGH: 8,
    RiskLevel.MEDIUM: 5,
    RiskLevel.LOW: 2,
    RiskLevel.SAFE: 0,
}

# Exposure factor based on component type
EXPOSURE_FACTORS: dict[str, int] = {
    # Internet-facing = 3
    "TLS": 3,
    "Certificate": 3,
    "HTTPS": 3,
    # Internal network = 2
    "SSH": 2,
    "VPN": 2,
    "OpenVPN": 2,
    "WireGuard": 2,
    "IPSec": 2,
    # Source code / config = 1-2
    "Config": 1,
    "Code": 1,
    "Source": 1,
}

# Data sensitivity keywords
SENSITIVITY_KEYWORDS: dict[str, int] = {
    # Top Secret = 5
    "key": 4,
    "private": 4,
    "secret": 4,
    "credential": 5,
    # Confidential = 3
    "certificate": 3,
    "signature": 3,
    "auth": 3,
    # Internal = 2
    "cipher": 2,
    "encryption": 2,
    "hash": 2,
    "mac": 2,
    # Public = 1
    "public": 1,
}


def score_finding(
    finding: Finding,
    exposure_factor: int | None = None,
    data_sensitivity: int | None = None,
    harvest_now_risk: int | None = None,
) -> RiskScore:
    """Compute risk score for a single finding.

    Args:
        finding: Scanner finding to score.
        exposure_factor: Override auto-detected exposure (1-3).
        data_sensitivity: Override auto-detected sensitivity (1-5).
        harvest_now_risk: Override harvest-now-decrypt-later risk (1-3).

    Returns:
        RiskScore with computed total.
    """
    risk = RiskScore(
        finding_algorithm=finding.algorithm,
        finding_component=finding.component,
        finding_location=finding.location,
    )

    # Vulnerability weight
    risk_level = finding.risk_level
    if isinstance(risk_level, str):
        risk_level = RiskLevel(risk_level)
    risk.vulnerability_weight = VULNERABILITY_WEIGHTS.get(risk_level, 0)

    # Exposure factor
    if exposure_factor is not None:
        risk.exposure_factor = exposure_factor
    else:
        risk.exposure_factor = _detect_exposure(finding)

    # Data sensitivity
    if data_sensitivity is not None:
        risk.data_sensitivity = data_sensitivity
    else:
        risk.data_sensitivity = _detect_sensitivity(finding)

    # Harvest-now-decrypt-later risk
    if harvest_now_risk is not None:
        risk.harvest_now_risk = harvest_now_risk
    else:
        risk.harvest_now_risk = _detect_harvest_risk(finding)

    risk.compute()
    return risk


def score_findings(
    findings: list[Finding],
    exposure_factor: int | None = None,
    data_sensitivity: int | None = None,
    harvest_now_risk: int | None = None,
) -> list[RiskScore]:
    """Score a list of findings, sorted by total score descending."""
    scores = [
        score_finding(f, exposure_factor, data_sensitivity, harvest_now_risk)
        for f in findings
    ]
    scores.sort(key=lambda s: s.total_score, reverse=True)
    return scores


def _detect_exposure(finding: Finding) -> int:
    """Auto-detect exposure factor from finding component."""
    component_upper = finding.component.upper()
    for keyword, factor in EXPOSURE_FACTORS.items():
        if keyword.upper() in component_upper:
            return factor
    return 2  # default: internal


def _detect_sensitivity(finding: Finding) -> int:
    """Auto-detect data sensitivity from finding details."""
    text = f"{finding.component} {finding.algorithm} {finding.note}".lower()
    max_sensitivity = 1
    for keyword, sensitivity in SENSITIVITY_KEYWORDS.items():
        if keyword in text:
            max_sensitivity = max(max_sensitivity, sensitivity)
    return max_sensitivity


def _detect_harvest_risk(finding: Finding) -> int:
    """Auto-detect harvest-now-decrypt-later risk.

    Key exchange and encryption are high HNDL risk.
    Signatures and hashes are lower.
    """
    if not finding.quantum_vulnerable:
        return 1  # not quantum vulnerable, no HNDL risk

    component_lower = finding.component.lower()
    algo_lower = finding.algorithm.lower()

    # Key exchange = highest HNDL risk (data can be captured and decrypted later)
    if any(kw in component_lower for kw in ("key exchange", "kex", "kem", "ecdh", "dh")):
        return 3
    if any(kw in algo_lower for kw in ("ecdhe", "dhe", "x25519", "curve25519")):
        return 3

    # Certificates/signatures = medium HNDL risk (forgery, not decryption)
    if any(kw in component_lower for kw in ("certificate", "signature", "sign", "auth")):
        return 2
    if any(kw in algo_lower for kw in ("rsa", "ecdsa", "dsa", "ed25519")):
        return 2

    return 1
