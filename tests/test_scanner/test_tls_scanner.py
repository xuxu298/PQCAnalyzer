"""Tests for the TLS cipher-suite parser."""

from __future__ import annotations

from src.scanner.models import TLSConnectionInfo, TLSInfo
from src.scanner.tls_scanner import TLSScanner
from src.utils.constants import RiskLevel


def _parse(suite: str, protocol: str, negotiated_group: str | None = None) -> TLSConnectionInfo:
    info = TLSConnectionInfo(cipher_suite=suite, protocol_version=protocol)
    TLSScanner()._parse_cipher_suite(info, negotiated_group)
    return info


class TestParseCipherSuiteTLS12:
    def test_ecdhe_rsa(self):
        info = _parse("ECDHE-RSA-AES256-GCM-SHA384", "TLSv1.2")
        assert info.key_exchange == "ECDHE"
        assert info.authentication == "RSA"
        assert info.bulk_cipher == "AES-256-GCM"
        assert info.mac_algorithm == "SHA-384"

    def test_ecdhe_ecdsa(self):
        info = _parse("ECDHE-ECDSA-CHACHA20-POLY1305", "TLSv1.2")
        assert info.key_exchange == "ECDHE"
        assert info.authentication == "ECDSA"
        assert info.bulk_cipher == "ChaCha20-Poly1305"

    def test_static_rsa(self):
        info = _parse("AES256-SHA256", "TLSv1.2")
        # No ECDHE/DHE in suite
        assert info.key_exchange == ""

    def test_dhe(self):
        info = _parse("DHE-RSA-AES128-GCM-SHA256", "TLSv1.2")
        assert info.key_exchange == "DHE"


class TestParseCipherSuiteTLS13:
    """TLS 1.3 cipher suites DO NOT encode key exchange.

    Regression: prior to the fix, _parse_cipher_suite returned an empty
    key_exchange for all TLS 1.3 connections because "ECDHE"/"DHE"/"RSA"
    substrings are absent. Now we default to ECDHE (TLS 1.3 mandates
    (EC)DHE) so the scanner produces a quantum-vulnerable finding.
    """

    def test_aes256_gcm_defaults_to_ecdhe(self):
        info = _parse("TLS_AES_256_GCM_SHA384", "TLSv1.3")
        assert info.key_exchange == "ECDHE"
        assert info.bulk_cipher == "AES-256-GCM"
        assert info.mac_algorithm == "SHA-384"

    def test_chacha20_defaults_to_ecdhe(self):
        info = _parse("TLS_CHACHA20_POLY1305_SHA256", "TLSv1.3")
        assert info.key_exchange == "ECDHE"
        assert info.bulk_cipher == "ChaCha20-Poly1305"

    def test_aes128_gcm_defaults_to_ecdhe(self):
        info = _parse("TLS_AES_128_GCM_SHA256", "TLSv1.3")
        assert info.key_exchange == "ECDHE"
        assert info.bulk_cipher == "AES-128-GCM"

    def test_negotiated_group_overrides_default(self):
        """When stdlib exposes the group (Python 3.13+), prefer it."""
        info = _parse("TLS_AES_256_GCM_SHA384", "TLSv1.3", negotiated_group="X25519")
        assert info.key_exchange == "X25519"

    def test_hybrid_pqc_group(self):
        """Hybrid PQC groups (e.g. X25519MLKEM768) should be reported verbatim."""
        info = _parse(
            "TLS_AES_256_GCM_SHA384", "TLSv1.3", negotiated_group="X25519MLKEM768"
        )
        assert info.key_exchange == "X25519MLKEM768"


class TestAnalyzeHybridPQ:
    """End-to-end: hybrid PQ kex must produce a PQ-safe finding, not vulnerable."""

    def _analyze(self, group: str):
        info = TLSConnectionInfo(
            cipher_suite="TLS_AES_256_GCM_SHA384",
            protocol_version="TLSv1.3",
            supported_protocols=["TLSv1.3"],
        )
        TLSScanner()._parse_cipher_suite(info, negotiated_group=group)
        return TLSScanner()._analyze(info, "example.com:443")

    def test_x25519mlkem768_is_pq_safe(self):
        findings = self._analyze("X25519MLKEM768")
        kex = [f for f in findings if f.component == TLSInfo.KEY_EXCHANGE]
        assert len(kex) == 1
        assert kex[0].algorithm == "X25519MLKEM768"
        assert kex[0].quantum_vulnerable is False
        assert kex[0].risk_level == RiskLevel.SAFE

    def test_plain_x25519_still_vulnerable(self):
        """Regression guard: classical X25519 must still be flagged."""
        findings = self._analyze("X25519")
        kex = [f for f in findings if f.component == TLSInfo.KEY_EXCHANGE]
        assert len(kex) == 1
        assert kex[0].quantum_vulnerable is True
