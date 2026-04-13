"""Tests for algorithm database and classification."""

import pytest

from src.utils.constants import RiskLevel
from src.utils.crypto_db import AlgorithmDatabase


@pytest.fixture
def db():
    return AlgorithmDatabase()


class TestAlgorithmDatabase:
    def test_load_algorithms(self, db):
        all_algos = db.all_algorithms()
        assert len(all_algos) >= 30

    def test_version(self, db):
        assert db.version == "1.0.0"

    def test_lookup_exact(self, db):
        info = db.lookup("RSA-2048")
        assert info is not None
        assert info.quantum_vulnerable is True
        assert info.risk_level == RiskLevel.CRITICAL

    def test_lookup_case_insensitive(self, db):
        info = db.lookup("rsa-2048")
        assert info is not None
        assert info.name == "RSA-2048"

    def test_lookup_not_found(self, db):
        assert db.lookup("NONEXISTENT-ALGO") is None

    def test_classify_rsa_variants(self, db):
        assert db.classify("sha256WithRSAEncryption") is not None
        info = db.classify("RSA")
        assert info is not None
        assert "RSA" in info.name

    def test_classify_ecdsa_variants(self, db):
        info = db.classify("ecdsa-with-SHA256")
        assert info is not None

        info2 = db.classify("ECDSA-P384")
        assert info2 is not None
        assert info2.risk_level == RiskLevel.CRITICAL

    def test_classify_aes_variants(self, db):
        info = db.classify("aes-256-gcm")
        assert info is not None
        assert info.risk_level in (RiskLevel.LOW, RiskLevel.SAFE)

        info2 = db.classify("AES-128")
        assert info2 is not None
        assert info2.risk_level == RiskLevel.MEDIUM

    def test_classify_sha_variants(self, db):
        info = db.classify("SHA-256")
        assert info is not None
        assert info.quantum_vulnerable is False

        info2 = db.classify("SHA-1")
        assert info2 is not None
        assert info2.risk_level == RiskLevel.HIGH

    def test_classify_chacha20(self, db):
        info = db.classify("ChaCha20-Poly1305")
        assert info is not None
        assert info.risk_level == RiskLevel.SAFE

    def test_classify_ed25519(self, db):
        info = db.classify("Ed25519")
        assert info is not None
        assert info.quantum_vulnerable is True

    def test_classify_x25519(self, db):
        info = db.classify("X25519")
        assert info is not None
        assert info.quantum_vulnerable is True

    def test_classify_x25519kyber(self, db):
        info = db.classify("X25519Kyber768")
        assert info is not None
        assert info.quantum_vulnerable is False
        assert info.risk_level == RiskLevel.SAFE

    def test_classify_ml_kem(self, db):
        info = db.classify("ML-KEM-768")
        assert info is not None
        assert info.risk_level == RiskLevel.SAFE

    def test_classify_ml_dsa(self, db):
        info = db.classify("ML-DSA-65")
        assert info is not None
        assert info.risk_level == RiskLevel.SAFE

    def test_classify_md5(self, db):
        info = db.classify("MD5")
        assert info is not None
        assert info.risk_level == RiskLevel.CRITICAL

    def test_classify_rc4(self, db):
        info = db.classify("RC4")
        assert info is not None
        assert info.risk_level == RiskLevel.CRITICAL

    def test_classify_3des(self, db):
        info = db.classify("3DES")
        assert info is not None
        assert info.risk_level == RiskLevel.HIGH

        info2 = db.classify("DES-CBC3")
        assert info2 is not None

    def test_quantum_vulnerable_list(self, db):
        vuln = db.quantum_vulnerable()
        assert len(vuln) > 0
        for algo in vuln:
            assert algo.quantum_vulnerable is True

    def test_quantum_safe_list(self, db):
        safe = db.quantum_safe()
        assert len(safe) > 0
        for algo in safe:
            assert algo.quantum_vulnerable is False

    def test_classify_hmac(self, db):
        info = db.classify("HMAC-MD5")
        assert info is not None
        assert info.risk_level == RiskLevel.HIGH

        info2 = db.classify("HMAC-SHA256")
        assert info2 is not None
        assert info2.risk_level == RiskLevel.SAFE
