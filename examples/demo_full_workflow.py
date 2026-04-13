#!/usr/bin/env python3
"""Example: Full end-to-end workflow — scan, analyze, generate roadmap + report.

This demonstrates the complete VN-PQC Analyzer pipeline:
1. Scan config files for cryptographic findings
2. Score risks
3. Generate recommendations
4. Build migration roadmap
5. Estimate costs
6. Check compliance
7. Generate reports (HTML, JSON, SARIF)
"""

import json
from pathlib import Path

from src.scanner.config_parser import parse_nginx_config, parse_apache_config
from src.scanner.ssh_scanner import analyze_ssh_config
from src.scanner.inventory import build_inventory
from src.roadmap.risk_scorer import score_findings
from src.roadmap.recommendation import recommend_all
from src.roadmap.priority_engine import build_migration_tasks, build_phases
from src.roadmap.cost_estimator import estimate_cost, format_vnd
from src.roadmap.compliance_checker import check_compliance
from src.roadmap.models import MigrationRoadmap
from src.roadmap.timeline_generator import generate_timeline
from src.reporter.html_report import generate_html_report, save_html_report
from src.reporter.json_export import export_json, export_sarif
from src.reporter.executive_summary import generate_executive_summary
from src.utils.constants import RiskLevel

# ── Step 1: Scan ─────────────────────────────────────────────
print("=== Step 1: Scanning configurations ===")

all_findings = []

# Scan nginx config (if available)
nginx_conf = Path("/etc/nginx/nginx.conf")
if nginx_conf.exists():
    findings = parse_nginx_config(str(nginx_conf))
    all_findings.extend(findings)
    print(f"  nginx: {len(findings)} findings")

# Scan SSH config (if available)
ssh_conf = Path("/etc/ssh/sshd_config")
if ssh_conf.exists():
    findings = analyze_ssh_config(str(ssh_conf))
    all_findings.extend(findings)
    print(f"  SSH: {len(findings)} findings")

# If no real configs found, use demo data
if not all_findings:
    print("  No config files found, using demo findings...")
    from src.scanner.models import Finding
    all_findings = [
        Finding(component="TLS Key Exchange", algorithm="ECDHE-P256",
                risk_level=RiskLevel.CRITICAL, quantum_vulnerable=True,
                location="demo:443", replacement=["ML-KEM-768"]),
        Finding(component="Certificate Signature", algorithm="RSA-2048",
                risk_level=RiskLevel.CRITICAL, quantum_vulnerable=True,
                location="demo cert", replacement=["ML-DSA-65"]),
        Finding(component="SSH Cipher", algorithm="aes128-ctr",
                risk_level=RiskLevel.MEDIUM, quantum_vulnerable=False,
                location="demo sshd", replacement=["AES-256-GCM"]),
        Finding(component="SSH Key Exchange", algorithm="ecdh-sha2-nistp256",
                risk_level=RiskLevel.HIGH, quantum_vulnerable=True,
                location="demo sshd", replacement=["sntrup761x25519"]),
    ]

print(f"  Total findings: {len(all_findings)}")

# ── Step 2: Risk Scoring ─────────────────────────────────────
print("\n=== Step 2: Scoring risks ===")
scores = score_findings(all_findings)
for s in scores[:3]:
    print(f"  {s.finding_algorithm}: score={s.total_score}")

# ── Step 3: Recommendations ──────────────────────────────────
print("\n=== Step 3: Generating recommendations ===")
recs = recommend_all(all_findings)
for r in recs[:3]:
    print(f"  {r.finding_algorithm} -> {r.replace_with}")

# ── Step 4: Migration Roadmap ────────────────────────────────
print("\n=== Step 4: Building migration roadmap ===")
tasks = build_migration_tasks(all_findings, scores, recs)
phases = build_phases(tasks)
for p in phases:
    print(f"  Phase {p.phase_number}: {p.name} ({p.total_effort_hours}h, {len(p.tasks)} tasks)")

# ── Step 5: Cost Estimation ──────────────────────────────────
print("\n=== Step 5: Estimating costs ===")
cost = estimate_cost(phases)
print(f"  Total hours: {cost.total_person_hours}")
print(f"  Cost range: {format_vnd(cost.cost_range_low_vnd)} - {format_vnd(cost.cost_range_high_vnd)}")
print(f"  Timeline: {cost.timeline_months} months")

# ── Step 6: Compliance Check ─────────────────────────────────
print("\n=== Step 6: Checking compliance ===")
compliance = check_compliance(all_findings)
for c in compliance:
    print(f"  {c.standard}: {c.status} — {c.requirement}")

# ── Step 7: Build Roadmap Model ──────────────────────────────
overall_risk = RiskLevel.CRITICAL if any(f.risk_level == RiskLevel.CRITICAL for f in all_findings) else RiskLevel.HIGH
roadmap = MigrationRoadmap(
    organization="Demo Organization",
    overall_risk=overall_risk,
    phases=phases,
    risk_scores=scores,
    cost_estimate=cost,
    compliance=compliance,
    total_findings=len(all_findings),
    critical_findings=sum(1 for f in all_findings if f.risk_level == RiskLevel.CRITICAL),
    quantum_vulnerable_count=sum(1 for f in all_findings if f.quantum_vulnerable),
)

# ── Step 8: Generate Reports ─────────────────────────────────
print("\n=== Step 7: Generating reports ===")
output_dir = Path("output")
output_dir.mkdir(exist_ok=True)

# HTML
html = generate_html_report(roadmap, all_findings, language="en")
html_path = save_html_report(html, str(output_dir / "report.html"))
print(f"  HTML: {html_path}")

# JSON
json_path = export_json(roadmap, str(output_dir / "report.json"))
print(f"  JSON: {json_path}")

# SARIF
sarif_path = export_sarif(roadmap, str(output_dir / "report.sarif"))
print(f"  SARIF: {sarif_path}")

# Executive Summary
summary = generate_executive_summary(roadmap, language="en")
summary_path = output_dir / "executive_summary.txt"
summary_path.write_text(summary)
print(f"  Summary: {summary_path}")

print("\nDone! Check the 'output/' directory for generated reports.")
