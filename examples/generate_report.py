#!/usr/bin/env python3
"""Example: Generate a full HTML report from scan findings."""

from src.scanner.models import Finding
from src.utils.constants import RiskLevel
from src.roadmap.risk_scorer import score_findings
from src.roadmap.recommendation import recommend_all
from src.roadmap.priority_engine import build_migration_tasks, build_phases
from src.roadmap.cost_estimator import estimate_cost
from src.roadmap.compliance_checker import check_compliance
from src.roadmap.models import MigrationRoadmap
from src.reporter.html_report import generate_html_report, save_html_report

# Example findings (in production, these come from scanners)
findings = [
    Finding(
        component="TLS Key Exchange", algorithm="ECDHE-P256",
        risk_level=RiskLevel.CRITICAL, quantum_vulnerable=True,
        location="gateway.example.vn:443",
        replacement=["ML-KEM-768", "X25519Kyber768"],
    ),
    Finding(
        component="Certificate Signature", algorithm="RSA-2048",
        risk_level=RiskLevel.CRITICAL, quantum_vulnerable=True,
        location="cert CN=gateway.example.vn",
        replacement=["ML-DSA-65"],
    ),
    Finding(
        component="SSH Cipher", algorithm="3des-cbc",
        risk_level=RiskLevel.HIGH, quantum_vulnerable=False,
        location="/etc/ssh/sshd_config",
        replacement=["AES-256-GCM", "ChaCha20-Poly1305"],
    ),
]

# Build roadmap pipeline
scores = score_findings(findings)
recs = recommend_all(findings)
tasks = build_migration_tasks(findings, scores, recs)
phases = build_phases(tasks)
cost = estimate_cost(phases)
compliance = check_compliance(findings)

roadmap = MigrationRoadmap(
    organization="Example Vietnam Corp",
    overall_risk=RiskLevel.CRITICAL,
    phases=phases,
    risk_scores=scores,
    cost_estimate=cost,
    compliance=compliance,
    total_findings=len(findings),
    critical_findings=sum(1 for f in findings if f.risk_level == RiskLevel.CRITICAL),
    quantum_vulnerable_count=sum(1 for f in findings if f.quantum_vulnerable),
)

# Generate HTML report
html = generate_html_report(roadmap, findings, language="en")
path = save_html_report(html, "output/report_en.html")
print(f"English report: {path}")

html_vi = generate_html_report(roadmap, findings, language="vi")
path_vi = save_html_report(html_vi, "output/report_vi.html")
print(f"Vietnamese report: {path_vi}")
