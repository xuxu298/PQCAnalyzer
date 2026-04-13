"""Tests for risk scoring engine."""

import pytest

from src.roadmap.risk_scorer import score_finding, score_findings, VULNERABILITY_WEIGHTS
from src.scanner.models import Finding
from src.utils.constants import RiskLevel


@pytest.fixture
def critical_tls_finding():
    return Finding(
        component="TLS Key Exchange",
        algorithm="ECDHE-P256",
        risk_level=RiskLevel.CRITICAL,
        quantum_vulnerable=True,
        location="example.vn:443",
        replacement=["ML-KEM-768"],
        migration_priority=1,
        note="ECDHE quantum vulnerable",
    )


@pytest.fixture
def medium_cipher_finding():
    return Finding(
        component="SSH Cipher",
        algorithm="AES-128-CTR",
        risk_level=RiskLevel.MEDIUM,
        quantum_vulnerable=False,
        location="/etc/ssh/sshd_config",
        replacement=["AES-256-GCM"],
        migration_priority=3,
    )


class TestRiskScoring:
    def test_vulnerability_weight(self, critical_tls_finding):
        score = score_finding(critical_tls_finding)
        assert score.vulnerability_weight == VULNERABILITY_WEIGHTS[RiskLevel.CRITICAL]
        assert score.vulnerability_weight == 10

    def test_auto_exposure_tls(self, critical_tls_finding):
        score = score_finding(critical_tls_finding)
        assert score.exposure_factor == 3  # TLS = internet-facing

    def test_auto_exposure_ssh(self, medium_cipher_finding):
        score = score_finding(medium_cipher_finding)
        assert score.exposure_factor == 2  # SSH = internal

    def test_manual_exposure_override(self, critical_tls_finding):
        score = score_finding(critical_tls_finding, exposure_factor=1)
        assert score.exposure_factor == 1

    def test_harvest_now_risk_kex(self, critical_tls_finding):
        score = score_finding(critical_tls_finding)
        assert score.harvest_now_risk == 3  # Key exchange = highest HNDL risk

    def test_harvest_now_risk_non_qv(self, medium_cipher_finding):
        score = score_finding(medium_cipher_finding)
        assert score.harvest_now_risk == 1  # Non-quantum-vulnerable

    def test_total_score_computation(self, critical_tls_finding):
        score = score_finding(critical_tls_finding)
        expected = (
            score.vulnerability_weight
            * score.exposure_factor
            * score.data_sensitivity
            * score.harvest_now_risk
        )
        assert score.total_score == expected
        assert score.total_score > 0

    def test_safe_finding_zero_score(self):
        finding = Finding(
            component="Encryption",
            algorithm="AES-256-GCM",
            risk_level=RiskLevel.SAFE,
            quantum_vulnerable=False,
            location="test",
        )
        score = score_finding(finding)
        assert score.total_score == 0

    def test_score_findings_sorted(self, critical_tls_finding, medium_cipher_finding):
        scores = score_findings([medium_cipher_finding, critical_tls_finding])
        assert len(scores) == 2
        assert scores[0].total_score >= scores[1].total_score

    def test_to_dict(self, critical_tls_finding):
        score = score_finding(critical_tls_finding)
        d = score.to_dict()
        assert "algorithm" in d
        assert "total_score" in d
        assert d["total_score"] > 0
