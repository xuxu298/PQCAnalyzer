"""Tests for recommendation engine."""

import pytest

from src.roadmap.recommendation import recommend, recommend_all
from src.scanner.models import Finding
from src.utils.constants import RiskLevel


class TestRecommendation:
    def test_tls_kex_recommendation(self):
        finding = Finding(
            component="TLS Key Exchange",
            algorithm="ECDHE-P256",
            risk_level=RiskLevel.HIGH,
            quantum_vulnerable=True,
            location="example.vn:443",
        )
        rec = recommend(finding)
        assert "ML-KEM" in rec.replace_with or "Kyber" in rec.replace_with
        assert len(rec.steps) > 0
        assert rec.timeline_phase == 1

    def test_ssh_kex_recommendation(self):
        finding = Finding(
            component="SSH Key Exchange",
            algorithm="curve25519-sha256",
            risk_level=RiskLevel.HIGH,
            quantum_vulnerable=True,
            location="/etc/ssh/sshd_config",
        )
        rec = recommend(finding)
        assert "sntrup761" in rec.replace_with
        assert rec.timeline_phase == 1

    def test_weak_cipher_recommendation(self):
        finding = Finding(
            component="SSH Cipher",
            algorithm="3des-cbc",
            risk_level=RiskLevel.HIGH,
            quantum_vulnerable=False,
            location="/etc/ssh/sshd_config",
        )
        rec = recommend(finding)
        assert "AES-256" in rec.replace_with or "ChaCha20" in rec.replace_with

    def test_certificate_recommendation(self):
        finding = Finding(
            component="Certificate Signature",
            algorithm="RSA-2048",
            risk_level=RiskLevel.CRITICAL,
            quantum_vulnerable=True,
            location="example.vn cert",
        )
        rec = recommend(finding)
        assert "ML-DSA" in rec.replace_with
        assert rec.timeline_phase >= 2

    def test_wireguard_recommendation(self):
        finding = Finding(
            component="WireGuard Key Exchange",
            algorithm="Curve25519",
            risk_level=RiskLevel.HIGH,
            quantum_vulnerable=True,
            location="wg0.conf",
        )
        rec = recommend(finding)
        assert "Rosenpass" in rec.replace_with or "ML-KEM" in rec.replace_with

    def test_code_recommendation(self):
        finding = Finding(
            component="Python RSA Import",
            algorithm="RSA",
            risk_level=RiskLevel.CRITICAL,
            quantum_vulnerable=True,
            location="app.py:10",
        )
        rec = recommend(finding)
        assert "liboqs" in rec.replace_with or "PQC" in rec.replace_with

    def test_default_recommendation(self):
        finding = Finding(
            component="Unknown Component",
            algorithm="UnknownAlgo",
            risk_level=RiskLevel.MEDIUM,
            quantum_vulnerable=False,
            location="unknown",
            replacement=["SomeReplacement"],
        )
        rec = recommend(finding)
        assert rec.replace_with != ""
        assert len(rec.steps) > 0

    def test_recommend_all(self):
        findings = [
            Finding(component="TLS Key Exchange", algorithm="ECDHE-P256",
                    risk_level=RiskLevel.HIGH, quantum_vulnerable=True, location="test"),
            Finding(component="SSH Cipher", algorithm="3des-cbc",
                    risk_level=RiskLevel.HIGH, quantum_vulnerable=False, location="test"),
        ]
        recs = recommend_all(findings)
        assert len(recs) == 2

    def test_recommendation_to_dict(self):
        finding = Finding(
            component="TLS Key Exchange", algorithm="DHE-2048",
            risk_level=RiskLevel.HIGH, quantum_vulnerable=True, location="test",
        )
        rec = recommend(finding)
        d = rec.to_dict()
        assert "replace_with" in d
        assert "steps" in d
        assert "effort" in d
