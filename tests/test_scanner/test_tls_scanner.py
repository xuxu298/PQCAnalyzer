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


class TestDetectionMode:
    """The kex finding carries a detection_mode label distinguishing
    traffic-observed (HNDL) from server-capability (operator-grade) risk.
    This is the split-label commitment from the vrc-005 thread.
    """

    def _analyze_with_mode(self, group: str, mode: str):
        info = TLSConnectionInfo(
            cipher_suite="TLS_AES_256_GCM_SHA384",
            protocol_version="TLSv1.3",
            supported_protocols=["TLSv1.3"],
            detection_mode=mode,
        )
        TLSScanner()._parse_cipher_suite(info, negotiated_group=group)
        return TLSScanner()._analyze(info, "example.com:443")

    def _kex(self, findings):
        return next(f for f in findings if f.component == TLSInfo.KEY_EXCHANGE)

    def test_unset_mode_defaults_to_passive(self):
        findings = self._analyze_with_mode("X25519", mode="")
        assert self._kex(findings).detection_mode == "passive"

    def test_active_declined_preserved(self):
        findings = self._analyze_with_mode("X25519", mode="active_declined")
        assert self._kex(findings).detection_mode == "active_declined"

    def test_active_supported_preserved(self):
        findings = self._analyze_with_mode("X25519MLKEM768", mode="active_supported")
        kex = self._kex(findings)
        assert kex.detection_mode == "active_supported"
        assert kex.risk_level == RiskLevel.SAFE

    def test_non_tls_finding_has_empty_mode(self):
        """Cert / cipher / MAC findings don't carry a detection_mode."""
        findings = self._analyze_with_mode("X25519", mode="active_declined")
        non_kex = [f for f in findings if f.component != TLSInfo.KEY_EXCHANGE]
        for f in non_kex:
            assert f.detection_mode == ""

    def test_to_dict_omits_empty_mode(self):
        """Serialization is backward-compat: no detection_mode key when unset."""
        findings = self._analyze_with_mode("X25519", mode="")
        non_kex = next(f for f in findings if f.component != TLSInfo.KEY_EXCHANGE)
        assert "detection_mode" not in non_kex.to_dict()
        kex = self._kex(findings)
        assert kex.to_dict()["detection_mode"] == "passive"


class TestProbePqGroupsBranches:
    """_probe_pq_groups must set info.detection_mode correctly for each
    ProbeResult outcome, so downstream findings carry the right label.
    """

    def _run(self, monkeypatch, result_or_exc):
        from src.scanner import tls_scanner as ts

        def fake_probe(host, port, timeout=5.0):
            if isinstance(result_or_exc, Exception):
                raise result_or_exc
            return result_or_exc

        monkeypatch.setattr(ts, "probe_x25519mlkem768", fake_probe)
        info = TLSConnectionInfo(key_exchange="ECDHE")
        ts.TLSScanner()._probe_pq_groups(info, "example.com", 443, 5.0)
        return info

    def test_supported_promotes_kex_and_marks_active_supported(self, monkeypatch):
        from src.scanner.pq_probe import ProbeResult

        info = self._run(
            monkeypatch, ProbeResult(selected_group="X25519MLKEM768", supported=True)
        )
        assert info.detection_mode == "active_supported"
        assert info.key_exchange == "X25519MLKEM768"

    def test_declined_marks_active_declined(self, monkeypatch):
        from src.scanner.pq_probe import ProbeResult

        info = self._run(
            monkeypatch, ProbeResult(selected_group="X25519", supported=False)
        )
        assert info.detection_mode == "active_declined"
        assert info.key_exchange == "ECDHE"  # not promoted

    def test_probe_error_marks_passive(self, monkeypatch):
        from src.scanner.pq_probe import ProbeResult

        info = self._run(
            monkeypatch,
            ProbeResult(selected_group=None, supported=False, error="timeout"),
        )
        assert info.detection_mode == "passive"

    def test_probe_exception_marks_passive(self, monkeypatch):
        info = self._run(monkeypatch, RuntimeError("socket boom"))
        assert info.detection_mode == "passive"
