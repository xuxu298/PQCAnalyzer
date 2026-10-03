"""Tests for the TLS cipher-suite parser."""

from __future__ import annotations

import pytest

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


def _leaf_der(
    key,
    days_valid: int = 365,
    cn: str = "app.example.com",
    issuer_key=None,
    issuer_cn: str | None = None,
) -> bytes:
    import datetime as dt

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.x509.oid import NameOID

    now = dt.datetime.now(dt.timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn or cn)])
    signer = issuer_key or key
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=days_valid))
        .sign(signer, None if _is_eddsa(signer) else hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.DER)


def _is_eddsa(key) -> bool:
    from cryptography.hazmat.primitives.asymmetric import ed448, ed25519

    return isinstance(key, (ed25519.Ed25519PrivateKey, ed448.Ed448PrivateKey))


def _rsa_key():
    from cryptography.hazmat.primitives.asymmetric import rsa

    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


class TestLeafCertAnalysis:
    """The endpoint scan must assess the server cert, not just the cipher suite."""

    def _findings(self, *ders: bytes):
        info = TLSConnectionInfo(
            protocol_version="TLSv1.3",
            cipher_suite="TLS_AES_256_GCM_SHA384",
            key_exchange="ECDHE",
            cert_chain_der=list(ders),
        )
        return TLSScanner()._analyze(info, "app.example.com:443")

    def test_rsa_leaf_reports_key_and_signature(self):
        findings = self._findings(_leaf_der(_rsa_key()))
        by_component = {f.component: f for f in findings}
        assert by_component[TLSInfo.CERT_PUBLIC_KEY].algorithm == "RSA-2048"
        assert by_component[TLSInfo.CERT_PUBLIC_KEY].quantum_vulnerable
        assert by_component[TLSInfo.CERT_SIGNATURE].algorithm == "RSA-SHA256"

    def test_ecdsa_leaf_reports_curve(self):
        from cryptography.hazmat.primitives.asymmetric import ec

        findings = self._findings(_leaf_der(ec.generate_private_key(ec.SECP256R1())))
        key = next(f for f in findings if f.component == TLSInfo.CERT_PUBLIC_KEY)
        assert key.algorithm.startswith("ECDSA-secp256r1")
        assert key.quantum_vulnerable

    def test_ed25519_leaf_is_quantum_vulnerable(self):
        from cryptography.hazmat.primitives.asymmetric import ed25519

        findings = self._findings(_leaf_der(ed25519.Ed25519PrivateKey.generate()))
        key = next(f for f in findings if f.component == TLSInfo.CERT_PUBLIC_KEY)
        assert key.algorithm.startswith("Ed25519")
        assert key.quantum_vulnerable

    def test_intermediate_in_chain_is_assessed(self):
        ca_key = _rsa_key()
        leaf = _leaf_der(_rsa_key(), issuer_key=ca_key, issuer_cn="Issuing CA")
        intermediate = _leaf_der(
            ca_key, cn="Issuing CA", issuer_key=_rsa_key(), issuer_cn="Root CA",
        )
        findings = self._findings(leaf, intermediate)
        keys = [f for f in findings if f.component == TLSInfo.CERT_PUBLIC_KEY]
        assert len(keys) == 2
        assert "leaf cert" in keys[0].location
        # last cert sent is not self-signed, so it is an intermediate, not a root
        assert "intermediate cert" in keys[1].location

    def test_bad_intermediate_does_not_hide_leaf(self):
        findings = self._findings(_leaf_der(_rsa_key()), b"\x30\x03junk")
        assert any(f.component == TLSInfo.CERT_PUBLIC_KEY for f in findings)

    def test_expiring_soon_flagged(self):
        findings = self._findings(_leaf_der(_rsa_key(), days_valid=10))
        assert any(f.algorithm == "Expiring soon" for f in findings)

    def test_valid_cert_not_flagged_expiring(self):
        findings = self._findings(_leaf_der(_rsa_key()))
        assert not any(f.algorithm == "Expiring soon" for f in findings)

    def test_malformed_der_keeps_cipher_findings(self):
        findings = self._findings(b"\x30\x03not-a-cert")
        assert not any(f.component == TLSInfo.CERT_PUBLIC_KEY for f in findings)
        assert any(f.component == TLSInfo.KEY_EXCHANGE for f in findings)

    def test_live_handshake_captures_leaf_der(self, tmp_path, monkeypatch):
        # Regression: getpeercert() is {} under CERT_NONE, so the cert used
        # to be invisible to the endpoint scan.
        import socket
        import ssl
        import threading

        from cryptography.hazmat.primitives import serialization

        from src.config import ScanConfig

        key = _rsa_key()
        der = _leaf_der(key, cn="localhost")
        cert_pem = tmp_path / "c.pem"
        key_pem = tmp_path / "k.pem"
        cert_pem.write_text(ssl.DER_cert_to_PEM_cert(der))
        key_pem.write_bytes(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ))
        server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_ctx.load_cert_chain(cert_pem, key_pem)

        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(8)
        listener.settimeout(5)
        port = listener.getsockname()[1]

        def serve():
            while True:
                try:
                    conn, _ = listener.accept()
                except OSError:
                    return
                try:
                    with server_ctx.wrap_socket(conn, server_side=True) as tls:
                        tls.recv(1)
                except (ssl.SSLError, OSError):
                    pass

        threading.Thread(target=serve, daemon=True).start()
        try:
            from src.scanner import tls_scanner as ts

            def no_probe(*args, **kwargs):
                raise OSError("probe disabled in test")

            monkeypatch.setattr(ts, "probe_x25519mlkem768", no_probe)
            scanner = TLSScanner(config=ScanConfig(timeout_ms=3000))
            info = scanner._connect_and_extract("127.0.0.1", port)
        finally:
            listener.close()
        assert info.cert_chain_der[0] == der


class TestChainRobustness:
    """Regressions from the 03/10 review of the chain analysis."""

    RSA_OID = bytes.fromhex("06092a864886f70d010101")       # rsaEncryption
    MLDSA65_OID = bytes.fromhex("0609608648016503040312")    # id-ml-dsa-65

    def _analyze(self, *ders):
        from src.scanner.cert_analyzer import CertAnalyzer

        return CertAnalyzer().analyze_chain_bytes(list(ders), source="h.example:443")

    def test_pq_key_cert_is_reported_not_fatal(self):
        inter = _leaf_der(_rsa_key(), cn="PQ CA", issuer_key=_rsa_key(), issuer_cn="Root")
        assert inter.count(self.RSA_OID) == 1
        pq = inter.replace(self.RSA_OID, self.MLDSA65_OID)
        infos, findings = self._analyze(_leaf_der(_rsa_key()), pq)
        assert len(infos) == 2
        keys = [f.algorithm for f in findings if f.component == TLSInfo.CERT_PUBLIC_KEY]
        assert "ML-DSA-65" in keys

    def test_duplicate_cert_assessed_once(self):
        leaf = _leaf_der(_rsa_key())
        infos, _ = self._analyze(leaf, leaf)
        assert len(infos) == 1

    def test_unparseable_leaf_keeps_positions(self):
        ca_key = _rsa_key()
        inter = _leaf_der(ca_key, cn="CA", issuer_key=_rsa_key(), issuer_cn="Root")
        infos, _ = self._analyze(b"\x30\x03bad", inter)
        assert [i.chain_position for i in infos] == ["intermediate"]

    def test_root_self_signature_not_assessed(self):
        root_key = _rsa_key()
        root = _leaf_der(root_key, cn="Root")
        leaf = _leaf_der(_rsa_key(), issuer_key=root_key, issuer_cn="Root")
        _, findings = self._analyze(leaf, root)
        root_findings = [f for f in findings if "root cert" in f.location]
        assert root_findings and all(f.component != TLSInfo.CERT_SIGNATURE for f in root_findings)

    def test_expired_intermediate_is_not_critical(self):
        import datetime as dt

        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.x509.oid import NameOID

        key = _rsa_key()
        now = dt.datetime.now(dt.timezone.utc)
        expired = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Old Cross-sign")]))
            .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Older Root")]))
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(days=900))
            .not_valid_after(now - dt.timedelta(days=10))
            .sign(_rsa_key(), hashes.SHA256())
        ).public_bytes(serialization.Encoding.DER)
        _, findings = self._analyze(_leaf_der(_rsa_key()), expired)
        exp = [f for f in findings if f.algorithm == "Expired"]
        assert exp and exp[0].risk_level != RiskLevel.CRITICAL

    @pytest.mark.parametrize("sig,flagged", [
        ("RSA-SHA1", "SHA-1"), ("sha1WithRSAEncryption", "SHA-1"), ("RSA-MD5", "MD5"),
        ("RSA-SHA256", None), ("ECDSA-SHA384", None),
    ])
    def test_weak_signature_hash_flagged(self, sig, flagged):
        from src.scanner.cert_analyzer import CertAnalyzer
        from src.scanner.models import CertificateInfo

        info = CertificateInfo(
            subject={"commonName": "legacy.example"}, public_key_algorithm="RSA",
            public_key_size=2048, signature_algorithm=sig, chain_position="leaf",
        )
        names = [f.algorithm for f in CertAnalyzer()._assess_cert(info, "h:443")]
        if flagged:
            assert f"{flagged} signature hash" in names
        else:
            assert not any("signature hash" in n for n in names)

    def test_peer_chain_accepts_313_bytes_form(self):
        der = _leaf_der(_rsa_key())

        class FakeSock:
            def get_unverified_chain(self):
                return [der]

        assert TLSScanner._peer_chain_der(FakeSock()) == [der]
