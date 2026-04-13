"""Tests for data models."""

import json

import pytest

from src.scanner.models import Finding, ScanResult, ScanSummary
from src.utils.constants import RiskLevel, ScanStatus, ScanType


class TestFinding:
    def test_to_dict(self):
        f = Finding(
            component="TLS Key Exchange",
            algorithm="ECDHE-P256",
            risk_level=RiskLevel.HIGH,
            quantum_vulnerable=True,
            location="example.vn:443",
            replacement=["ML-KEM-768"],
            migration_priority=1,
        )
        d = f.to_dict()
        assert d["algorithm"] == "ECDHE-P256"
        assert d["risk_level"] == "HIGH"
        assert d["quantum_vulnerable"] is True
        assert d["replacement"] == ["ML-KEM-768"]


class TestScanSummary:
    def test_from_findings(self):
        findings = [
            Finding("A", "RSA-2048", RiskLevel.CRITICAL, True, "loc1"),
            Finding("B", "AES-256", RiskLevel.LOW, False, "loc2"),
            Finding("C", "ECDHE-P256", RiskLevel.HIGH, True, "loc3"),
            Finding("D", "SHA-256", RiskLevel.SAFE, False, "loc4"),
        ]
        summary = ScanSummary.from_findings(findings)
        assert summary.total_findings == 4
        assert summary.critical == 1
        assert summary.high == 1
        assert summary.low == 1
        assert summary.safe == 1
        assert summary.overall_risk == RiskLevel.CRITICAL

    def test_empty_findings(self):
        summary = ScanSummary.from_findings([])
        assert summary.total_findings == 0
        assert summary.overall_risk == RiskLevel.SAFE

    def test_to_dict(self):
        summary = ScanSummary(total_findings=2, critical=1, high=1, overall_risk=RiskLevel.CRITICAL)
        d = summary.to_dict()
        assert d["overall_risk"] == "CRITICAL"


class TestScanResult:
    def test_finalize(self):
        result = ScanResult(target="test:443", scan_type=ScanType.TLS_ENDPOINT)
        result.findings = [
            Finding("A", "RSA-2048", RiskLevel.CRITICAL, True, "loc"),
        ]
        result.finalize()
        assert result.summary is not None
        assert result.summary.critical == 1

    def test_to_dict(self):
        result = ScanResult(target="test:443", scan_type=ScanType.TLS_ENDPOINT)
        result.findings = [
            Finding("A", "RSA-2048", RiskLevel.CRITICAL, True, "loc"),
        ]
        d = result.to_dict()
        assert d["target"] == "test:443"
        assert d["scan_type"] == "tls_endpoint"
        assert "findings" in d
        assert "summary" in d

    def test_to_dict_json_serializable(self):
        result = ScanResult(target="test:443", scan_type=ScanType.TLS_ENDPOINT)
        result.findings = [
            Finding("A", "RSA-2048", RiskLevel.CRITICAL, True, "loc", ["ML-KEM-768"]),
        ]
        # Should not raise
        json_str = json.dumps(result.to_dict())
        assert "RSA-2048" in json_str

    def test_error_result(self):
        result = ScanResult(
            target="bad:443",
            scan_type=ScanType.TLS_ENDPOINT,
            status=ScanStatus.TIMEOUT,
            error_message="Connection timed out",
        )
        d = result.to_dict()
        assert d["status"] == "timeout"
        assert d["error_message"] == "Connection timed out"
