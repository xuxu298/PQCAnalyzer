"""Tests for reporter module."""

import json
import pytest
from pathlib import Path

from src.roadmap.models import MigrationRoadmap, MigrationPhase, MigrationTask, CostEstimate, ComplianceStatus
from src.scanner.models import Finding
from src.utils.constants import RiskLevel


@pytest.fixture
def sample_roadmap():
    cost = CostEstimate(
        total_person_hours=200,
        hourly_rate_vnd=500_000,
    )
    cost.compute()

    return MigrationRoadmap(
        organization="Test Org",
        overall_risk=RiskLevel.HIGH,
        phases=[
            MigrationPhase(
                phase_number=0, name="Assessment", timeline="0-3 months",
                tasks=[], total_effort_hours=0,
            ),
            MigrationPhase(
                phase_number=1, name="Quick Wins", timeline="3-6 months",
                tasks=[
                    MigrationTask(title="Enable hybrid KEX", effort_hours=8, risk_level="low"),
                    MigrationTask(title="Upgrade ciphers", effort_hours=4, risk_level="low"),
                ],
                total_effort_hours=12,
            ),
        ],
        risk_scores=[],
        cost_estimate=cost,
        compliance=[
            ComplianceStatus(
                standard="NIST FIPS 203",
                requirement="ML-KEM transition",
                status="non_compliant",
                details="Quantum-vulnerable KEX found",
            ),
        ],
        total_findings=10,
        critical_findings=3,
        quantum_vulnerable_count=7,
    )


@pytest.fixture
def sample_findings():
    return [
        Finding(
            component="TLS Key Exchange", algorithm="ECDHE-P256",
            risk_level=RiskLevel.CRITICAL, quantum_vulnerable=True,
            location="example.vn:443", replacement=["ML-KEM-768"],
        ),
        Finding(
            component="SSH Cipher", algorithm="AES-128-CTR",
            risk_level=RiskLevel.MEDIUM, quantum_vulnerable=False,
            location="/etc/ssh/sshd_config", replacement=["AES-256-GCM"],
        ),
    ]


class TestHTMLReport:
    def test_generate_html_en(self, sample_roadmap, sample_findings):
        from src.reporter.html_report import generate_html_report
        html = generate_html_report(sample_roadmap, sample_findings, language="en")
        assert "<!DOCTYPE html>" in html
        assert "PQC Readiness" in html
        assert "Test Org" in html
        assert "CRITICAL" in html
        assert "ECDHE-P256" in html

    def test_generate_html_vi(self, sample_roadmap, sample_findings):
        from src.reporter.html_report import generate_html_report
        html = generate_html_report(sample_roadmap, sample_findings, language="vi")
        assert "Đánh giá" in html or "PQC" in html

    def test_save_html(self, sample_roadmap, sample_findings, tmp_path):
        from src.reporter.html_report import generate_html_report, save_html_report
        html = generate_html_report(sample_roadmap, sample_findings)
        path = save_html_report(html, str(tmp_path / "report.html"))
        assert Path(path).exists()
        content = Path(path).read_text()
        assert "<!DOCTYPE html>" in content


class TestJSONExport:
    def test_export_json(self, sample_roadmap, tmp_path):
        from src.reporter.json_export import export_json
        path = export_json(sample_roadmap, str(tmp_path / "report.json"))
        assert Path(path).exists()
        data = json.loads(Path(path).read_text())
        assert "roadmap_id" in data
        assert data["organization"] == "Test Org"

    def test_export_sarif(self, sample_roadmap, tmp_path):
        from src.roadmap.models import RiskScore
        sample_roadmap.risk_scores = [
            RiskScore(
                finding_algorithm="ECDHE-P256",
                finding_component="TLS Key Exchange",
                finding_location="example.vn:443",
                total_score=150,
            ),
        ]
        from src.reporter.json_export import export_sarif
        path = export_sarif(sample_roadmap, str(tmp_path / "report.sarif"))
        assert Path(path).exists()
        data = json.loads(Path(path).read_text())
        assert data["version"] == "2.1.0"
        assert len(data["runs"]) == 1
        assert len(data["runs"][0]["results"]) > 0


class TestExecutiveSummary:
    def test_generate_en(self, sample_roadmap):
        from src.reporter.executive_summary import generate_executive_summary
        summary = generate_executive_summary(sample_roadmap, language="en")
        assert "EXECUTIVE SUMMARY" in summary
        assert "Test Org" in summary
        assert "10" in summary  # total findings

    def test_generate_vi(self, sample_roadmap):
        from src.reporter.executive_summary import generate_executive_summary
        summary = generate_executive_summary(sample_roadmap, language="vi")
        assert "TÓM TẮT ĐIỀU HÀNH" in summary
        assert "Test Org" in summary

    def test_critical_risk_warning(self, sample_roadmap):
        sample_roadmap.overall_risk = RiskLevel.CRITICAL
        from src.reporter.executive_summary import generate_executive_summary
        summary = generate_executive_summary(sample_roadmap, language="en")
        assert "WARNING" in summary or "immediate" in summary.lower()
