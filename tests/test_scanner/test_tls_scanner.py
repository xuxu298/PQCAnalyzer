"""Tests for the TLS cipher-suite parser."""

from __future__ import annotations

from src.scanner.models import TLSConnectionInfo
from src.scanner.tls_scanner import TLSScanner


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
