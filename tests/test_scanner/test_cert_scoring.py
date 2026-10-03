"""Certificate scoring: authentication is planned, key exchange is urgent.

A Shor-breakable certificate is HIGH (leaf, own CA) or LOW (public CA, which
the customer cannot change); classical key exchange — the part harvest-now-
decrypt-later attacks today — is CRITICAL.
"""

from __future__ import annotations

import datetime as dt

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

import src.scanner.cert_analyzer as ca_mod
from src.scanner.cert_analyzer import CertAnalyzer, authentication_risk
from src.scanner.models import TLSConnectionInfo, TLSInfo
from src.scanner.tls_scanner import TLSScanner
from src.utils.constants import RiskLevel
from src.utils.crypto_db import get_algorithm_db


def _name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _cert(cn, key, signer, issuer_cn, *, ca):
    now = dt.datetime.now(dt.timezone.utc)
    return (
        x509.CertificateBuilder()
        .subject_name(_name(cn)).issuer_name(_name(issuer_cn))
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now).not_valid_after(now + dt.timedelta(days=90))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
        .sign(signer, hashes.SHA256())
    )


def _der(cert):
    return cert.public_bytes(serialization.Encoding.DER)


@pytest.fixture
def pki():
    """Root → intermediate → leaf, all ECDSA P-256."""
    root_key, inter_key, leaf_key = (ec.generate_private_key(ec.SECP256R1()) for _ in range(3))
    root = _cert("Test Root", root_key, root_key, "Test Root", ca=True)
    inter = _cert("Test Issuing CA", inter_key, root_key, "Test Root", ca=True)
    leaf = _cert("app.example.com", leaf_key, inter_key, "Test Issuing CA", ca=False)
    return root, inter, leaf


def _trust(monkeypatch, *roots):
    by_subject: dict[bytes, tuple] = {}
    for r in roots:
        by_subject[r.subject.public_bytes()] = (*by_subject.get(r.subject.public_bytes(), ()), r)
    store = (frozenset(r.fingerprint(hashes.SHA256()) for r in roots), by_subject)
    monkeypatch.setattr(ca_mod, "_public_trust_store", lambda: store)


def _by_cn(findings):
    out: dict[str, list] = {}
    for f in findings:
        cn = f.location.split("CN=")[1].split(",")[0]
        out.setdefault(cn, []).append(f)
    return out


def test_classical_key_exchange_is_critical():
    db = get_algorithm_db()
    for name in ("X25519", "ECDHE-P256", "ECDHE-P384", "X448", "DHE-2048"):
        assert db.classify(name).risk_level == RiskLevel.CRITICAL, name
    assert db.classify("X25519MLKEM768").risk_level == RiskLevel.SAFE


def test_no_withdrawn_kyber_draft_recommended():
    db = get_algorithm_db()
    for name in ("X25519", "ECDHE-P256", "ECDHE-P384", "DHE-2048"):
        assert "X25519Kyber768" not in db.classify(name).replacement


def test_aes128_follows_nist_ir_8547():
    info = get_algorithm_db().classify("AES-128-GCM")
    assert info.risk_level == RiskLevel.LOW
    assert "64-bit" not in info.note_en


def test_authentication_risk_rules():
    def rule(name, risk=RiskLevel.CRITICAL, vulnerable=True, *, ca=False, public=False):
        return authentication_risk(name, risk, vulnerable, is_ca=ca, public_ca=public)

    assert rule("ECDSA-P256")[:2] == (RiskLevel.HIGH, 2)
    assert rule("ECDSA-P256", ca=True)[:2] == (RiskLevel.HIGH, 1)
    assert rule("ECDSA-P256", ca=True, public=True)[:2] == (RiskLevel.LOW, 4)
    # weak even classically, or not Shor-breakable: keep the DB rating
    assert rule("RSA-1024") is None
    assert rule("ML-DSA-65", RiskLevel.SAFE, False) is None


def test_private_pki_chain_is_high_with_ca_first(monkeypatch, pki):
    _trust(monkeypatch)  # empty public store
    root, inter, leaf = pki
    chain = [_der(leaf), _der(inter)]
    _, findings = CertAnalyzer().analyze_chain_bytes(chain, source="app:443")
    by = _by_cn(findings)
    assert {f.risk_level for f in findings} == {RiskLevel.HIGH}
    assert {f.migration_priority for f in by["Test Issuing CA"]} == {1}
    assert {f.migration_priority for f in by["app.example.com"]} == {2}
    assert "Your own CA" in by["Test Issuing CA"][0].note


def test_public_ca_certs_are_low_leaf_stays_high(monkeypatch, pki):
    root, inter, leaf = pki
    _trust(monkeypatch, root)
    chain = [_der(leaf), _der(inter)]
    _, findings = CertAnalyzer().analyze_chain_bytes(chain, source="app:443")
    by = _by_cn(findings)
    assert {f.risk_level for f in by["Test Issuing CA"]} == {RiskLevel.LOW}
    assert "publicly trusted CA" in by["Test Issuing CA"][0].note
    assert {f.risk_level for f in by["app.example.com"]} == {RiskLevel.HIGH}
    assert not any(f.risk_level == RiskLevel.CRITICAL for f in findings)


def test_public_status_propagates_through_cross_signed_intermediates(monkeypatch):
    """Let's Encrypt style: leaf ← YE1 ← Root YE ← X2 (both cross-signed); only X1 is trusted."""
    keys = [ec.generate_private_key(ec.SECP384R1()) for _ in range(5)]
    x1 = _cert("X1", keys[0], keys[0], "X1", ca=True)
    x2 = _cert("X2", keys[1], keys[0], "X1", ca=True)
    ye = _cert("Root YE", keys[2], keys[1], "X2", ca=True)
    ye1 = _cert("YE1", keys[3], keys[2], "Root YE", ca=True)
    leaf = _cert("site.example.com", keys[4], keys[3], "YE1", ca=False)
    _trust(monkeypatch, x1)
    _, findings = CertAnalyzer().analyze_chain_bytes(
        [_der(c) for c in (leaf, ye1, ye, x2)], source="site:443")
    by = _by_cn(findings)
    for cn in ("YE1", "Root YE", "X2"):
        assert {f.risk_level for f in by[cn]} == {RiskLevel.LOW}, cn
    assert {f.risk_level for f in by["site.example.com"]} == {RiskLevel.HIGH}


def test_a_ca_merely_named_like_a_public_root_is_not_public(monkeypatch, pki):
    root, _, _ = pki
    _trust(monkeypatch, root)
    impostor_key = ec.generate_private_key(ec.SECP256R1())
    fake_inter = _cert("Test Issuing CA", impostor_key, impostor_key, "Test Root", ca=True)
    leaf = _cert("x", impostor_key, impostor_key, "Test Issuing CA", ca=False)
    _, findings = CertAnalyzer().analyze_chain_bytes([_der(leaf), _der(fake_inter)], source="x:443")
    assert {f.risk_level for f in _by_cn(findings)["Test Issuing CA"]} == {RiskLevel.HIGH}


def test_classically_weak_leaf_stays_critical(monkeypatch):
    _trust(monkeypatch)
    key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    leaf = _cert("old.example.com", key, key, "old.example.com", ca=False)
    _, findings = CertAnalyzer().analyze_chain_bytes([_der(leaf)], source="old:443")
    key_findings = [f for f in findings if f.component == TLSInfo.CERT_PUBLIC_KEY]
    assert key_findings[0].risk_level == RiskLevel.CRITICAL


@pytest.mark.parametrize("protocol,component", [
    ("TLSv1.3", TLSInfo.HANDSHAKE_HASH),
    ("TLSv1.2", TLSInfo.MAC),
])
def test_suite_hash_label_depends_on_protocol(protocol, component):
    info = TLSConnectionInfo(protocol_version=protocol, mac_algorithm="SHA-256")
    findings = TLSScanner()._analyze(info, "h:443")
    assert [f.component for f in findings if f.algorithm == "SHA-256"] == [component]
