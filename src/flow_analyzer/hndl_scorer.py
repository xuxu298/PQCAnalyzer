"""Harvest-Now-Decrypt-Later (HNDL) scorer.

Formula (per spec §2.3.6):

    HNDL_Score = 100 * V * S * R * E

    V = vulnerability component (0-1) — how breakable the kex is under Shor/Grover
    S = sensitivity component    (0-1) — data sensitivity weight
    R = retention component      (0-1) — how long the data stays valuable
    E = exposure factor          (0-1) — log-scaled volume sigmoid

    Risk bands:
        >= 60 CRITICAL | >= 40 HIGH | >= 20 MEDIUM | >= 5 LOW | < 5 SAFE

Inspired by Kagai 2025 "A Temporal HNDL Risk Model" (MDPI Future Internet 6/4/100)
but simplified: we drop Mosca-window time decay because reports are point-in-time.
"""

from __future__ import annotations

import math

from src.flow_analyzer.models import (
    RETENTION_WEIGHT,
    SENSITIVITY_WEIGHT,
    CryptoPrimitive,
    Flow,
    HNDLScore,
    RiskBand,
)

# Mapping kex_algorithm → vulnerability weight.
# Grounded in Shor (breaks RSA/ECDHE/DH) and Grover (sqrt for symmetric).
KEX_VULNERABILITY: dict[str, float] = {
    # Classical asymmetric — Shor-breakable
    "RSA": 1.0,
    "RSA-1024": 1.0,
    "RSA-2048": 1.0,
    "RSA-3072": 1.0,
    "RSA-4096": 1.0,
    "DHE": 0.95,
    "DH": 0.95,
    "ffdhe2048": 0.95,
    "ffdhe3072": 0.95,
    "ffdhe4096": 0.95,
    "ECDHE": 0.9,
    "ECDHE-P256": 0.9,
    "ECDHE-P384": 0.9,
    "ECDHE-P521": 0.9,
    "secp256r1": 0.9,
    "secp384r1": 0.9,
    "secp521r1": 0.9,
    "x25519": 0.9,
    "X25519": 0.9,
    "x448": 0.9,
    # Hybrid PQC — safe under current state-of-the-art (classical side still hedges)
    "X25519MLKEM768": 0.1,
    "X25519Kyber768Draft00": 0.1,
    "SecP256r1Kyber768Draft00": 0.1,
    "SecP384r1Kyber768Draft00": 0.1,
    "sntrup761x25519-sha512@openssh.com": 0.1,
    "mlkem768x25519-sha256": 0.1,
    "mlkem768nistp256-sha256": 0.1,
    "mlkem1024nistp384-sha384": 0.1,
    # Pure PQC
    "MLKEM512": 0.05,
    "MLKEM768": 0.0,
    "MLKEM1024": 0.0,
    "ML-KEM-512": 0.05,
    "ML-KEM-768": 0.0,
    "ML-KEM-1024": 0.0,
}


def _vulnerability(crypto: CryptoPrimitive | None) -> float:
    """Vulnerability component V. Unknown crypto defaults to 0.9 (classical-assumed)."""
    if crypto is None:
        return 0.9
    if crypto.is_pure_pqc:
        return 0.0
    if crypto.is_hybrid_pqc:
        return 0.1
    if crypto.kex_algorithm:
        # Exact lookup first
        if crypto.kex_algorithm in KEX_VULNERABILITY:
            return KEX_VULNERABILITY[crypto.kex_algorithm]
        # Prefix/substring match (e.g., "ECDHE-secp256r1")
        upper = crypto.kex_algorithm.upper()
        for key, weight in KEX_VULNERABILITY.items():
            if key.upper() in upper:
                return weight
    return 0.9


def _exposure(bytes_total: int) -> float:
    """E = min(1, log10(bytes + 1) / 10). 1 GB ≈ 0.9, 1 MB ≈ 0.6, 1 KB ≈ 0.3, 0 B = 0."""
    if bytes_total <= 0:
        return 0.0
    return min(1.0, math.log10(bytes_total + 1) / 10.0)


def _risk_band(overall: float) -> RiskBand:
    if overall >= 60.0:
        return RiskBand.CRITICAL
    if overall >= 40.0:
        return RiskBand.HIGH
    if overall >= 20.0:
        return RiskBand.MEDIUM
    if overall >= 5.0:
        return RiskBand.LOW
    return RiskBand.SAFE


def _rationale(
    flow: Flow, crypto: CryptoPrimitive | None, v: float, s: float, r: float, e: float
) -> str:
    kex = crypto.kex_algorithm if crypto and crypto.kex_algorithm else "unknown"
    pqc_state = "pure-PQC" if crypto and crypto.is_pure_pqc else (
        "hybrid-PQC" if crypto and crypto.is_hybrid_pqc else "classical"
    )
    gb = flow.bytes_total / (1024 * 1024 * 1024)
    vol = f"{gb:.2f} GB" if gb >= 1 else f"{flow.bytes_total / 1024:.1f} KB"
    return (
        f"kex={kex} ({pqc_state}, V={v:.2f}), "
        f"sensitivity={flow.sensitivity.value} (S={s:.2f}), "
        f"retention={flow.retention.value} (R={r:.2f}), "
        f"volume={vol} (E={e:.2f})"
    )


def _recommendation(crypto: CryptoPrimitive | None, risk: RiskBand) -> str:
    if risk == RiskBand.SAFE:
        return "On track — no action required."
    if crypto and crypto.is_hybrid_pqc:
        return "Already hybrid-PQC; monitor for pure-PQC upgrade path."
    if risk in (RiskBand.CRITICAL, RiskBand.HIGH):
        return (
            "Migrate this endpoint to hybrid KEX (X25519MLKEM768 for TLS, "
            "mlkem768x25519-sha256 for SSH). Prioritise before 2028."
        )
    return "Plan migration to PQC hybrid in next maintenance window."


def score_hndl(flow: Flow, crypto: CryptoPrimitive | None = None) -> HNDLScore:
    """Compute HNDLScore for a single flow.

    `crypto` defaults to `flow.crypto` when not provided — allows callers to
    override e.g. when re-scoring with updated classification.
    """
    c = crypto if crypto is not None else flow.crypto

    v = _vulnerability(c)
    s = SENSITIVITY_WEIGHT[flow.sensitivity]
    r = RETENTION_WEIGHT[flow.retention]
    e = _exposure(flow.bytes_total)

    overall = 100.0 * v * s * r * e
    # Clamp for safety — the multiplication should never exceed 100 given inputs ≤ 1.
    overall = max(0.0, min(100.0, overall))
    band = _risk_band(overall)

    return HNDLScore(
        overall=overall,
        risk_level=band,
        vulnerability_component=v,
        sensitivity_component=s,
        retention_component=r,
        volume_factor=e,
        rationale=_rationale(flow, c, v, s, r, e),
        recommended_action=_recommendation(c, band),
    )
