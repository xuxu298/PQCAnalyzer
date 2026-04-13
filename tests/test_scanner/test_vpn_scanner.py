"""Tests for VPN configuration scanner."""

from pathlib import Path

import pytest

from src.scanner.vpn_scanner import VPNScanner
from src.utils.constants import RiskLevel

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures" / "configs"


@pytest.fixture
def scanner():
    return VPNScanner()


class TestVPNTypeDetection:
    def test_detect_openvpn(self, scanner):
        result = scanner.scan_file(str(FIXTURES_DIR / "openvpn_legacy.conf"))
        assert result.metadata.get("vpn_type") == "openvpn"

    def test_detect_wireguard(self, scanner):
        result = scanner.scan_file(str(FIXTURES_DIR / "wireguard.conf"))
        assert result.metadata.get("vpn_type") == "wireguard"

    def test_detect_ipsec(self, scanner):
        result = scanner.scan_file(str(FIXTURES_DIR / "ipsec.conf"))
        assert result.metadata.get("vpn_type") == "ipsec"


class TestOpenVPNScanner:
    def test_legacy_config_finds_weak_cipher(self, scanner):
        result = scanner.scan_file(str(FIXTURES_DIR / "openvpn_legacy.conf"))
        assert result.status.value == "success"

        cipher_findings = [f for f in result.findings if "Cipher" in f.component]
        assert len(cipher_findings) > 0

        # BF-CBC should be CRITICAL
        bf = [f for f in cipher_findings if "BF-CBC" in f.algorithm]
        assert len(bf) > 0
        assert bf[0].risk_level == RiskLevel.CRITICAL

    def test_legacy_config_finds_weak_auth(self, scanner):
        result = scanner.scan_file(str(FIXTURES_DIR / "openvpn_legacy.conf"))
        auth_findings = [f for f in result.findings if "Auth" in f.component]
        assert len(auth_findings) > 0

        sha1 = [f for f in auth_findings if "SHA1" in f.algorithm]
        assert len(sha1) > 0
        assert sha1[0].risk_level == RiskLevel.HIGH

    def test_legacy_config_finds_weak_tls_kex(self, scanner):
        result = scanner.scan_file(str(FIXTURES_DIR / "openvpn_legacy.conf"))
        kex_findings = [f for f in result.findings if "Key Exchange" in f.component]
        assert len(kex_findings) > 0
        assert any(f.quantum_vulnerable for f in kex_findings)

    def test_legacy_config_finds_pki(self, scanner):
        result = scanner.scan_file(str(FIXTURES_DIR / "openvpn_legacy.conf"))
        pki_findings = [f for f in result.findings if "PKI" in f.component]
        assert len(pki_findings) > 0

    def test_modern_config_still_has_quantum_findings(self, scanner):
        result = scanner.scan_file(str(FIXTURES_DIR / "openvpn_modern.conf"))
        assert result.status.value == "success"
        # Even modern OpenVPN uses quantum-vulnerable key exchange
        qv_findings = [f for f in result.findings if f.quantum_vulnerable]
        assert len(qv_findings) > 0

    def test_modern_config_aes128_flagged(self, scanner):
        result = scanner.scan_file(str(FIXTURES_DIR / "openvpn_modern.conf"))
        aes128 = [f for f in result.findings if "AES-128" in f.algorithm]
        assert len(aes128) > 0
        assert aes128[0].risk_level == RiskLevel.MEDIUM


class TestWireGuardScanner:
    def test_wireguard_finds_curve25519(self, scanner):
        result = scanner.scan_file(str(FIXTURES_DIR / "wireguard.conf"))
        assert result.status.value == "success"

        kex = [f for f in result.findings if "Key Exchange" in f.component]
        assert len(kex) > 0
        assert kex[0].algorithm == "Curve25519"
        assert kex[0].quantum_vulnerable is True
        assert kex[0].risk_level == RiskLevel.HIGH

    def test_wireguard_chacha20_safe(self, scanner):
        result = scanner.scan_file(str(FIXTURES_DIR / "wireguard.conf"))
        enc = [f for f in result.findings if "Encryption" in f.component]
        assert len(enc) > 0
        assert enc[0].risk_level == RiskLevel.SAFE
        assert enc[0].quantum_vulnerable is False

    def test_wireguard_peer_count(self, scanner):
        result = scanner.scan_file(str(FIXTURES_DIR / "wireguard.conf"))
        kex = [f for f in result.findings if "Key Exchange" in f.component]
        assert "2 peer(s)" in kex[0].note

    def test_wireguard_reports_all_crypto(self, scanner):
        result = scanner.scan_file(str(FIXTURES_DIR / "wireguard.conf"))
        # Should report Curve25519, ChaCha20-Poly1305, BLAKE2s
        algos = {f.algorithm for f in result.findings}
        assert "Curve25519" in algos
        assert "ChaCha20-Poly1305" in algos
        assert "BLAKE2s" in algos


class TestIPSecScanner:
    def test_ipsec_finds_weak_proposals(self, scanner):
        result = scanner.scan_file(str(FIXTURES_DIR / "ipsec.conf"))
        assert result.status.value == "success"
        assert len(result.findings) > 0

    def test_ipsec_finds_des(self, scanner):
        result = scanner.scan_file(str(FIXTURES_DIR / "ipsec.conf"))
        des_findings = [f for f in result.findings if f.algorithm == "DES"]
        assert len(des_findings) > 0
        assert des_findings[0].risk_level == RiskLevel.CRITICAL

    def test_ipsec_finds_md5(self, scanner):
        result = scanner.scan_file(str(FIXTURES_DIR / "ipsec.conf"))
        md5_findings = [f for f in result.findings if f.algorithm == "MD5"]
        assert len(md5_findings) > 0

    def test_ipsec_finds_weak_dh_groups(self, scanner):
        result = scanner.scan_file(str(FIXTURES_DIR / "ipsec.conf"))
        kex_findings = [f for f in result.findings if "Key Exchange" in f.component]
        assert len(kex_findings) > 0
        assert all(f.quantum_vulnerable for f in kex_findings)

    def test_ipsec_finds_ikev1(self, scanner):
        result = scanner.scan_file(str(FIXTURES_DIR / "ipsec.conf"))
        ikev1 = [f for f in result.findings if "IKEv1" in f.algorithm]
        assert len(ikev1) > 0
        assert ikev1[0].risk_level == RiskLevel.HIGH

    def test_ipsec_connection_names_in_findings(self, scanner):
        result = scanner.scan_file(str(FIXTURES_DIR / "ipsec.conf"))
        components = [f.component for f in result.findings]
        assert any("office-to-dc" in c for c in components)
        assert any("legacy-vpn" in c for c in components)


class TestVPNScannerEdgeCases:
    def test_file_not_found(self, scanner):
        result = scanner.scan_file("/nonexistent/file.conf")
        assert result.status.value == "error"
        assert "not found" in result.error_message.lower()

    def test_unknown_vpn_type(self, scanner, tmp_path):
        f = tmp_path / "random.conf"
        f.write_text("some random content\nnothing vpn related\n")
        result = scanner.scan_file(str(f))
        assert result.status.value == "skipped"

    def test_empty_openvpn_defaults_warning(self, scanner, tmp_path):
        f = tmp_path / "minimal.ovpn"
        f.write_text("client\ndev tun\nremote vpn.example.com 1194\nproto udp\n")
        result = scanner.scan_file(str(f))
        assert result.status.value == "success"
        # Should warn about default BF-CBC
        bf_default = [f_ for f_ in result.findings if "default" in f_.algorithm.lower() or "BF-CBC" in f_.algorithm]
        assert len(bf_default) > 0
