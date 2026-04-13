"""Tests for crypto inventory aggregator."""

import json
import tempfile
from pathlib import Path

import pytest

from src.scanner.inventory import CryptoInventory
from src.scanner.models import Finding, ScanResult
from src.utils.constants import RiskLevel, ScanStatus, ScanType


@pytest.fixture
def sample_inventory():
    inventory = CryptoInventory()

    r1 = ScanResult(target="host1:443", scan_type=ScanType.TLS_ENDPOINT)
    r1.findings = [
        Finding("Key Exchange", "ECDHE-P256", RiskLevel.HIGH, True, "host1:443"),
        Finding("Bulk Cipher", "AES-256", RiskLevel.LOW, False, "host1:443"),
    ]
    r1.finalize()

    r2 = ScanResult(target="host2:443", scan_type=ScanType.TLS_ENDPOINT)
    r2.findings = [
        Finding("Certificate", "RSA-2048", RiskLevel.CRITICAL, True, "host2:443"),
        Finding("Key Exchange", "ECDHE-P256", RiskLevel.HIGH, True, "host2:443"),
    ]
    r2.finalize()

    inventory.add_result(r1)
    inventory.add_result(r2)
    return inventory


class TestCryptoInventory:
    def test_all_findings(self, sample_inventory):
        assert len(sample_inventory.all_findings) == 4

    def test_summary(self, sample_inventory):
        s = sample_inventory.summary
        assert s.total_findings == 4
        assert s.critical == 1
        assert s.high == 2
        assert s.low == 1
        assert s.overall_risk == RiskLevel.CRITICAL

    def test_unique_algorithms(self, sample_inventory):
        algos = sample_inventory.unique_algorithms
        assert "ECDHE-P256" in algos
        assert len(algos["ECDHE-P256"]) == 2  # Found in both hosts

    def test_quantum_vulnerable(self, sample_inventory):
        vuln = sample_inventory.quantum_vulnerable_findings
        assert len(vuln) == 3

    def test_critical_findings(self, sample_inventory):
        critical = sample_inventory.critical_findings
        assert len(critical) == 1
        assert critical[0].algorithm == "RSA-2048"

    def test_findings_by_risk(self, sample_inventory):
        by_risk = sample_inventory.findings_by_risk()
        assert len(by_risk[RiskLevel.CRITICAL]) == 1
        assert len(by_risk[RiskLevel.HIGH]) == 2

    def test_findings_by_target(self, sample_inventory):
        by_target = sample_inventory.findings_by_target()
        assert "host1:443" in by_target
        assert len(by_target["host1:443"]) == 2

    def test_to_json(self, sample_inventory):
        j = sample_inventory.to_json()
        data = json.loads(j)
        assert "inventory_id" in data
        assert "summary" in data
        assert len(data["scan_results"]) == 2

    def test_save_and_load(self, sample_inventory):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name

        sample_inventory.save(path)
        loaded = CryptoInventory.load(path)

        assert len(loaded.all_findings) == 4
        assert loaded.summary.critical == 1
        Path(path).unlink()
