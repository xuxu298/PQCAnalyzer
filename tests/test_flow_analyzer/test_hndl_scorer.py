"""HNDL scoring — per-component unit + realistic integration cases."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from src.flow_analyzer.hndl_scorer import _exposure, _risk_band, _vulnerability, score_hndl
from src.flow_analyzer.models import (
    CryptoPrimitive,
    DataSensitivity,
    Flow,
    Protocol,
    RetentionClass,
    RiskBand,
)


def _flow(
    *,
    crypto: CryptoPrimitive | None = None,
    sensitivity: DataSensitivity = DataSensitivity.INTERNAL,
    retention: RetentionClass = RetentionClass.SHORT,
    bytes_total: int = 1_000_000,
    dst_port: int = 443,
) -> Flow:
    now = datetime.now(tz=timezone.utc)
    return Flow(
        src_ip="10.0.0.1", dst_ip="10.0.1.1",
        src_port=12345, dst_port=dst_port,
        transport="tcp", protocol=Protocol.TLS_1_3,
        first_seen=now, last_seen=now,
        bytes_total=bytes_total,
        crypto=crypto,
        sensitivity=sensitivity,
        retention=retention,
    )


# --- Component: V ---

def test_vulnerability_unknown_crypto_defaults_high() -> None:
    assert _vulnerability(None) == pytest.approx(0.9, abs=0.05)


def test_vulnerability_rsa_is_maximum() -> None:
    assert _vulnerability(CryptoPrimitive(kex_algorithm="RSA-2048")) == 1.0


def test_vulnerability_x25519_is_shor_breakable() -> None:
    assert _vulnerability(CryptoPrimitive(kex_algorithm="x25519")) == 0.9


def test_vulnerability_hybrid_pqc_is_low() -> None:
    cp = CryptoPrimitive(kex_algorithm="X25519MLKEM768", is_hybrid_pqc=True)
    assert _vulnerability(cp) == pytest.approx(0.1)


def test_vulnerability_pure_pqc_is_zero() -> None:
    cp = CryptoPrimitive(kex_algorithm="ML-KEM-768", is_pure_pqc=True)
    assert _vulnerability(cp) == 0.0


# --- Component: E ---

def test_exposure_monotonic_in_bytes() -> None:
    assert _exposure(0) == 0.0
    assert _exposure(1_000) < _exposure(1_000_000) < _exposure(1_000_000_000)


def test_exposure_caps_at_1() -> None:
    assert _exposure(10**20) == 1.0


# --- Risk band mapping ---

@pytest.mark.parametrize(
    ("score", "band"),
    [
        (80.0, RiskBand.CRITICAL),
        (60.0, RiskBand.CRITICAL),
        (59.9, RiskBand.HIGH),
        (40.0, RiskBand.HIGH),
        (30.0, RiskBand.MEDIUM),
        (20.0, RiskBand.MEDIUM),
        (10.0, RiskBand.LOW),
        (4.9, RiskBand.SAFE),
        (0.0, RiskBand.SAFE),
    ],
)
def test_risk_band_thresholds(score: float, band: RiskBand) -> None:
    assert _risk_band(score) == band


# --- End-to-end: canonical cases ---

def test_score_critical_medical_rsa() -> None:
    """Medical data over RSA-2048 with 1 GB traffic → CRITICAL."""
    crypto = CryptoPrimitive(kex_algorithm="RSA-2048", is_hybrid_pqc=False)
    flow = _flow(
        crypto=crypto,
        sensitivity=DataSensitivity.SECRET,
        retention=RetentionClass.LIFETIME,
        bytes_total=1_000_000_000,
    )
    score = score_hndl(flow)
    assert score.risk_level == RiskBand.CRITICAL
    assert score.overall >= 60.0


def test_score_safe_pqc_hybrid_public() -> None:
    """Public data over hybrid PQC → SAFE."""
    crypto = CryptoPrimitive(
        kex_algorithm="X25519MLKEM768", is_hybrid_pqc=True,
        symmetric_cipher="AES-256-GCM",
    )
    flow = _flow(
        crypto=crypto,
        sensitivity=DataSensitivity.PUBLIC,
        retention=RetentionClass.EPHEMERAL,
        bytes_total=10_000,
    )
    score = score_hndl(flow)
    assert score.risk_level in (RiskBand.SAFE, RiskBand.LOW)
    assert score.overall < 10.0


def test_score_zero_bytes_is_safe() -> None:
    crypto = CryptoPrimitive(kex_algorithm="RSA-2048")
    flow = _flow(
        crypto=crypto,
        sensitivity=DataSensitivity.SECRET,
        retention=RetentionClass.LIFETIME,
        bytes_total=0,
    )
    score = score_hndl(flow)
    assert score.overall == 0.0
    assert score.risk_level == RiskBand.SAFE


def test_score_recommendation_mentions_migration_on_high_risk() -> None:
    flow = _flow(
        crypto=CryptoPrimitive(kex_algorithm="RSA-2048"),
        sensitivity=DataSensitivity.RESTRICTED,
        retention=RetentionClass.LONG,
        bytes_total=500_000_000,
    )
    score = score_hndl(flow)
    assert "migrat" in score.recommended_action.lower() or score.risk_level == RiskBand.SAFE


def test_score_rationale_mentions_components() -> None:
    flow = _flow(crypto=CryptoPrimitive(kex_algorithm="ECDHE"))
    score = score_hndl(flow)
    for token in ("kex=", "sensitivity=", "retention=", "volume="):
        assert token in score.rationale
