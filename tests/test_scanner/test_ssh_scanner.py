"""Tests for SSH configuration scanner."""

from pathlib import Path

import pytest

from src.scanner.ssh_scanner import SSHScanner
from src.utils.constants import RiskLevel

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures" / "configs"


@pytest.fixture
def scanner():
    return SSHScanner()


class TestSSHScanner:
    def test_scan_weak_config(self, scanner):
        result = scanner.scan_file(str(FIXTURES_DIR / "sshd_config_weak"))
        assert result.status.value == "success"
        assert len(result.findings) > 0

        # Should find weak KEX
        kex_findings = [f for f in result.findings if f.component == "SSH Key Exchange"]
        assert len(kex_findings) > 0

        # Should find DH group1 (CRITICAL)
        dh1 = [f for f in kex_findings if "group1" in f.algorithm]
        assert len(dh1) > 0
        assert dh1[0].risk_level == RiskLevel.CRITICAL

        # Should find weak ciphers
        cipher_findings = [f for f in result.findings if f.component == "SSH Cipher"]
        assert len(cipher_findings) > 0

        # 3des-cbc should be flagged
        des3 = [f for f in cipher_findings if "3des" in f.algorithm.lower()]
        assert len(des3) > 0

        # Should find weak MACs
        mac_findings = [f for f in result.findings if f.component == "SSH MAC"]
        assert len(mac_findings) > 0

        # hmac-md5 should be flagged
        md5 = [f for f in mac_findings if "md5" in f.algorithm.lower()]
        assert len(md5) > 0

        # Should find weak host key files
        hostkey_findings = [
            f for f in result.findings if f.component == "SSH Host Key File"
        ]
        rsa_keys = [f for f in hostkey_findings if "RSA" in f.algorithm]
        assert len(rsa_keys) > 0
        dsa_keys = [f for f in hostkey_findings if "DSA" in f.algorithm]
        assert len(dsa_keys) > 0

    def test_scan_strong_config(self, scanner):
        result = scanner.scan_file(str(FIXTURES_DIR / "sshd_config_strong"))
        assert result.status.value == "success"
        # Strong config should have fewer findings
        # Note: even curve25519 is quantum-vulnerable, so there will be some findings
        critical = [f for f in result.findings if f.risk_level == RiskLevel.CRITICAL]
        # No CRITICAL in ciphers/MACs — the strong config is clean there
        cipher_critical = [
            f for f in critical if f.component == "SSH Cipher"
        ]
        assert len(cipher_critical) == 0

    def test_scan_nonexistent_file(self, scanner):
        result = scanner.scan_file("/nonexistent/sshd_config")
        assert result.status.value == "error"

    def test_all_findings_have_replacement(self, scanner):
        result = scanner.scan_file(str(FIXTURES_DIR / "sshd_config_weak"))
        for finding in result.findings:
            assert len(finding.replacement) > 0, (
                f"Finding for {finding.algorithm} has no replacement suggestion"
            )

    def test_quantum_vulnerable_flag(self, scanner):
        result = scanner.scan_file(str(FIXTURES_DIR / "sshd_config_weak"))
        kex_findings = [f for f in result.findings if f.component == "SSH Key Exchange"]
        for f in kex_findings:
            # All KEX algorithms are quantum-vulnerable
            assert f.quantum_vulnerable is True
