"""Tests for configuration file parser."""

from pathlib import Path

import pytest

from src.scanner.config_parser import ConfigParser
from src.utils.constants import RiskLevel

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures" / "configs"


@pytest.fixture
def parser():
    return ConfigParser()


class TestConfigParser:
    def test_scan_nginx_legacy(self, parser):
        result = parser.scan_file(str(FIXTURES_DIR / "nginx_legacy.conf"))
        assert result.status.value == "success"
        assert len(result.findings) > 0

        # Should find SSLv3
        sslv3 = [f for f in result.findings if "SSLv3" in f.algorithm]
        assert len(sslv3) > 0
        assert sslv3[0].risk_level == RiskLevel.CRITICAL

        # Should find TLS 1.0
        tls10 = [f for f in result.findings if "TLS 1.0" in f.algorithm]
        assert len(tls10) > 0

        # Should find TLS 1.1
        tls11 = [f for f in result.findings if "TLS 1.1" in f.algorithm]
        assert len(tls11) > 0

        # Should find weak ciphers (RC4, 3DES)
        algos = [f.algorithm for f in result.findings]
        assert "RC4" in algos or any("RC4" in a for a in algos)
        assert "3DES" in algos or any("3DES" in a for a in algos)

    def test_scan_nginx_modern(self, parser):
        result = parser.scan_file(str(FIXTURES_DIR / "nginx_modern.conf"))
        assert result.status.value == "success"
        # Modern config should have no/minimal findings
        critical = [f for f in result.findings if f.risk_level == RiskLevel.CRITICAL]
        assert len(critical) == 0

    def test_scan_apache(self, parser):
        result = parser.scan_file(str(FIXTURES_DIR / "apache_default.conf"))
        assert result.status.value == "success"
        # Should find SSLv3 enabled
        sslv3 = [f for f in result.findings if "SSLv3" in f.algorithm]
        assert len(sslv3) > 0

    def test_scan_nonexistent_file(self, parser):
        result = parser.scan_file("/nonexistent/path.conf")
        assert result.status.value == "error"

    def test_scan_directory(self, parser):
        results = parser.scan_directory(str(FIXTURES_DIR))
        # Should find at least the legacy config with issues
        assert len(results) > 0

    def test_config_type_detection(self, parser):
        nginx_content = "server { ssl_protocols TLSv1.2; }"
        assert parser._detect_config_type(nginx_content, "test.conf") == "nginx"

        apache_content = "SSLProtocol all -SSLv2"
        assert parser._detect_config_type(apache_content, "test.conf") == "apache"

    def test_metadata_includes_config_type(self, parser):
        result = parser.scan_file(str(FIXTURES_DIR / "nginx_legacy.conf"))
        assert result.metadata.get("config_type") == "nginx"
