"""Tests for source code scanner."""

from pathlib import Path

import pytest

from src.scanner.code_scanner import CodeScanner
from src.utils.constants import RiskLevel

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures" / "code"


@pytest.fixture
def scanner():
    return CodeScanner()


class TestPythonScanner:
    def test_finds_rsa_import(self, scanner):
        result = scanner.scan_file(str(FIXTURES_DIR / "sample_python.py"))
        assert result.status.value == "success"

        rsa_findings = [f for f in result.findings if "RSA" in f.algorithm and "Python" in f.component]
        assert len(rsa_findings) > 0
        assert rsa_findings[0].risk_level == RiskLevel.CRITICAL
        assert rsa_findings[0].quantum_vulnerable is True

    def test_finds_ec_import(self, scanner):
        result = scanner.scan_file(str(FIXTURES_DIR / "sample_python.py"))
        ec_findings = [f for f in result.findings if "ECC" in f.component or "ECDSA" in f.algorithm]
        assert len(ec_findings) > 0
        assert ec_findings[0].quantum_vulnerable is True

    def test_finds_weak_hash(self, scanner):
        result = scanner.scan_file(str(FIXTURES_DIR / "sample_python.py"))
        hash_findings = [f for f in result.findings if "Hash" in f.component]
        assert len(hash_findings) > 0

    def test_finds_pycryptodome_rsa(self, scanner):
        result = scanner.scan_file(str(FIXTURES_DIR / "sample_python.py"))
        pycrypto = [f for f in result.findings if "PyCryptodome" in f.component]
        assert len(pycrypto) > 0

    def test_reports_file_line_number(self, scanner):
        result = scanner.scan_file(str(FIXTURES_DIR / "sample_python.py"))
        for f in result.findings:
            assert ":" in f.location
            parts = f.location.rsplit(":", 1)
            assert parts[1].isdigit()


class TestJavaScanner:
    def test_finds_rsa_keygen(self, scanner):
        result = scanner.scan_file(str(FIXTURES_DIR / "sample_java.java"))
        assert result.status.value == "success"

        rsa = [f for f in result.findings if "RSA" in f.algorithm and "KeyPairGenerator" in f.component]
        assert len(rsa) > 0

    def test_finds_rsa_cipher(self, scanner):
        result = scanner.scan_file(str(FIXTURES_DIR / "sample_java.java"))
        cipher = [f for f in result.findings if "Cipher" in f.component and "RSA" in f.algorithm]
        assert len(cipher) > 0

    def test_finds_ecdsa_signature(self, scanner):
        result = scanner.scan_file(str(FIXTURES_DIR / "sample_java.java"))
        sig = [f for f in result.findings if "Signature" in f.component]
        assert len(sig) > 0
        assert sig[0].quantum_vulnerable is True

    def test_finds_des(self, scanner):
        result = scanner.scan_file(str(FIXTURES_DIR / "sample_java.java"))
        des = [f for f in result.findings if f.algorithm == "DES"]
        assert len(des) > 0
        assert des[0].risk_level == RiskLevel.CRITICAL

    def test_finds_md5(self, scanner):
        result = scanner.scan_file(str(FIXTURES_DIR / "sample_java.java"))
        md5 = [f for f in result.findings if "MD5" in f.algorithm]
        assert len(md5) > 0


class TestGoScanner:
    def test_finds_rsa(self, scanner):
        result = scanner.scan_file(str(FIXTURES_DIR / "sample_go.go"))
        assert result.status.value == "success"
        rsa = [f for f in result.findings if "RSA" in f.algorithm]
        assert len(rsa) > 0

    def test_finds_ecdsa(self, scanner):
        result = scanner.scan_file(str(FIXTURES_DIR / "sample_go.go"))
        ecdsa = [f for f in result.findings if "ECDSA" in f.algorithm]
        assert len(ecdsa) > 0

    def test_finds_sha1(self, scanner):
        result = scanner.scan_file(str(FIXTURES_DIR / "sample_go.go"))
        sha1 = [f for f in result.findings if "SHA-1" in f.algorithm or "MD5" in f.algorithm]
        assert len(sha1) > 0

    def test_finds_x509(self, scanner):
        result = scanner.scan_file(str(FIXTURES_DIR / "sample_go.go"))
        x509 = [f for f in result.findings if "X.509" in f.component]
        assert len(x509) > 0


class TestJavaScriptScanner:
    def test_finds_weak_hash(self, scanner):
        result = scanner.scan_file(str(FIXTURES_DIR / "sample_node.js"))
        assert result.status.value == "success"
        hash_f = [f for f in result.findings if "Hash" in f.component]
        assert len(hash_f) > 0

    def test_finds_dh(self, scanner):
        result = scanner.scan_file(str(FIXTURES_DIR / "sample_node.js"))
        dh = [f for f in result.findings if "DH" in f.algorithm or "Key Exchange" in f.component]
        assert len(dh) > 0

    def test_finds_weak_cipher(self, scanner):
        result = scanner.scan_file(str(FIXTURES_DIR / "sample_node.js"))
        cipher = [f for f in result.findings if "Cipher" in f.component]
        assert len(cipher) > 0


class TestCScanner:
    def test_finds_rsa_keygen(self, scanner):
        result = scanner.scan_file(str(FIXTURES_DIR / "sample_c.c"))
        assert result.status.value == "success"
        rsa = [f for f in result.findings if "RSA" in f.algorithm]
        assert len(rsa) > 0

    def test_finds_ec(self, scanner):
        result = scanner.scan_file(str(FIXTURES_DIR / "sample_c.c"))
        ec = [f for f in result.findings if "EC" in f.component]
        assert len(ec) > 0

    def test_finds_md5(self, scanner):
        result = scanner.scan_file(str(FIXTURES_DIR / "sample_c.c"))
        md5 = [f for f in result.findings if "MD5" in f.algorithm]
        assert len(md5) > 0

    def test_finds_des(self, scanner):
        result = scanner.scan_file(str(FIXTURES_DIR / "sample_c.c"))
        des = [f for f in result.findings if "DES" in f.algorithm]
        assert len(des) > 0


class TestCodeScannerEdgeCases:
    def test_file_not_found(self, scanner):
        result = scanner.scan_file("/nonexistent/file.py")
        assert result.status.value == "error"

    def test_unsupported_extension(self, scanner, tmp_path):
        f = tmp_path / "test.txt"
        f.write_text("some text")
        result = scanner.scan_file(str(f))
        assert result.status.value == "skipped"

    def test_no_crypto_in_file(self, scanner, tmp_path):
        f = tmp_path / "clean.py"
        f.write_text("def hello():\n    print('hello')\n")
        result = scanner.scan_file(str(f))
        assert result.status.value == "success"
        assert len(result.findings) == 0

    def test_scan_directory(self, scanner):
        results = scanner.scan_directory(str(FIXTURES_DIR))
        assert len(results) > 0
        # Should find files with crypto patterns
        all_findings = [f for r in results for f in r.findings]
        assert len(all_findings) > 0

    def test_metadata_has_language(self, scanner):
        result = scanner.scan_file(str(FIXTURES_DIR / "sample_python.py"))
        assert result.metadata.get("language") == "python"
        assert result.metadata.get("lines", 0) > 0
