"""Tests for priority engine."""

import pytest

from src.roadmap.models import RiskScore
from src.roadmap.priority_engine import assign_phase, build_migration_tasks, build_phases
from src.roadmap.recommendation import recommend_all
from src.roadmap.risk_scorer import score_findings
from src.scanner.models import Finding
from src.utils.constants import RiskLevel


@pytest.fixture
def sample_findings():
    return [
        Finding(
            component="TLS Key Exchange", algorithm="ECDHE-P256",
            risk_level=RiskLevel.CRITICAL, quantum_vulnerable=True,
            location="example.vn:443",
        ),
        Finding(
            component="SSH Cipher", algorithm="3des-cbc",
            risk_level=RiskLevel.HIGH, quantum_vulnerable=False,
            location="/etc/ssh/sshd_config",
        ),
        Finding(
            component="Certificate Signature", algorithm="RSA-2048",
            risk_level=RiskLevel.CRITICAL, quantum_vulnerable=True,
            location="cert CN=example.vn",
        ),
        Finding(
            component="WireGuard Key Exchange", algorithm="Curve25519",
            risk_level=RiskLevel.HIGH, quantum_vulnerable=True,
            location="wg0.conf",
        ),
        Finding(
            component="Python RSA Import", algorithm="RSA",
            risk_level=RiskLevel.CRITICAL, quantum_vulnerable=True,
            location="app.py:10",
        ),
    ]


class TestPhaseAssignment:
    def test_cipher_goes_to_phase1(self):
        finding = Finding(component="SSH Cipher", algorithm="3des-cbc",
                         risk_level=RiskLevel.HIGH, quantum_vulnerable=False, location="test")
        score = RiskScore(total_score=50)
        assert assign_phase(finding, score) == 1

    def test_tls_kex_goes_to_phase1(self):
        finding = Finding(component="TLS Key Exchange", algorithm="ECDHE",
                         risk_level=RiskLevel.HIGH, quantum_vulnerable=True, location="test")
        score = RiskScore(total_score=100)
        assert assign_phase(finding, score) == 1

    def test_certificate_goes_to_phase2_or_3(self):
        finding = Finding(component="Certificate Signature", algorithm="RSA-2048",
                         risk_level=RiskLevel.CRITICAL, quantum_vulnerable=True, location="test")
        score = RiskScore(total_score=100)
        phase = assign_phase(finding, score)
        assert phase in (2, 3)

    def test_vpn_goes_to_phase2(self):
        finding = Finding(component="WireGuard Key Exchange", algorithm="Curve25519",
                         risk_level=RiskLevel.HIGH, quantum_vulnerable=True, location="test")
        score = RiskScore(total_score=80)
        assert assign_phase(finding, score) == 2

    def test_code_goes_to_phase2(self):
        finding = Finding(component="Python RSA Import", algorithm="RSA",
                         risk_level=RiskLevel.CRITICAL, quantum_vulnerable=True, location="test")
        score = RiskScore(total_score=100)
        assert assign_phase(finding, score) == 2

    def test_broken_algo_goes_to_phase1(self):
        finding = Finding(component="Unknown", algorithm="DES",
                         risk_level=RiskLevel.CRITICAL, quantum_vulnerable=False, location="test")
        score = RiskScore(total_score=50)
        assert assign_phase(finding, score) == 1


class TestBuildMigrationTasks:
    def test_builds_tasks(self, sample_findings):
        scores = score_findings(sample_findings)
        recs = recommend_all(sample_findings)
        tasks = build_migration_tasks(sample_findings, scores, recs)
        assert len(tasks) > 0
        assert all(t.title for t in tasks)

    def test_tasks_sorted_by_phase_priority(self, sample_findings):
        scores = score_findings(sample_findings)
        recs = recommend_all(sample_findings)
        tasks = build_migration_tasks(sample_findings, scores, recs)
        for i in range(len(tasks) - 1):
            assert tasks[i].phase <= tasks[i + 1].phase or \
                   (tasks[i].phase == tasks[i + 1].phase and tasks[i].priority <= tasks[i + 1].priority)

    def test_deduplicates_findings(self):
        findings = [
            Finding(component="SSH Cipher", algorithm="3des-cbc",
                    risk_level=RiskLevel.HIGH, quantum_vulnerable=False, location="host1"),
            Finding(component="SSH Cipher", algorithm="3des-cbc",
                    risk_level=RiskLevel.HIGH, quantum_vulnerable=False, location="host2"),
        ]
        scores = score_findings(findings)
        recs = recommend_all(findings)
        tasks = build_migration_tasks(findings, scores, recs)
        assert len(tasks) == 1  # deduplicated


class TestBuildPhases:
    def test_builds_4_phases(self, sample_findings):
        scores = score_findings(sample_findings)
        recs = recommend_all(sample_findings)
        tasks = build_migration_tasks(sample_findings, scores, recs)
        phases = build_phases(tasks)
        assert len(phases) == 4
        assert phases[0].phase_number == 0
        assert phases[3].phase_number == 3

    def test_phase_effort_computed(self, sample_findings):
        scores = score_findings(sample_findings)
        recs = recommend_all(sample_findings)
        tasks = build_migration_tasks(sample_findings, scores, recs)
        phases = build_phases(tasks)
        total_effort = sum(p.total_effort_hours for p in phases)
        assert total_effort > 0
