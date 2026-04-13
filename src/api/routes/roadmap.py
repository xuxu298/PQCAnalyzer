"""Roadmap API routes."""

from __future__ import annotations

import json
from pathlib import Path

from fastapi import APIRouter, HTTPException

from src.api.schemas import RoadmapRequest

router = APIRouter()


@router.post("/roadmap/generate")
def generate_roadmap(request: RoadmapRequest):
    """Generate migration roadmap from scan results."""
    from src.roadmap.compliance_checker import check_compliance
    from src.roadmap.cost_estimator import estimate_cost
    from src.roadmap.models import MigrationRoadmap
    from src.roadmap.priority_engine import build_migration_tasks, build_phases
    from src.roadmap.recommendation import recommend_all
    from src.roadmap.risk_scorer import score_findings
    from src.roadmap.timeline_generator import generate_timeline
    from src.scanner.models import Finding
    from src.utils.constants import RiskLevel

    # Get findings from request or file
    findings: list[Finding] = []
    if request.findings:
        for f in request.findings:
            findings.append(Finding(
                component=f.component,
                algorithm=f.algorithm,
                risk_level=RiskLevel(f.risk_level),
                quantum_vulnerable=f.quantum_vulnerable,
                location=f.location,
                replacement=f.replacement,
                migration_priority=f.migration_priority,
                note=f.note,
            ))
    elif request.scan_results_path:
        p = Path(request.scan_results_path)
        if not p.exists():
            raise HTTPException(status_code=404, detail=f"File not found: {request.scan_results_path}")
        data = json.loads(p.read_text())
        for r in data.get("results", []):
            for f_data in r.get("findings", []):
                findings.append(Finding(
                    component=f_data["component"],
                    algorithm=f_data["algorithm"],
                    risk_level=RiskLevel(f_data["risk_level"]),
                    quantum_vulnerable=f_data["quantum_vulnerable"],
                    location=f_data.get("location", ""),
                    replacement=f_data.get("replacement", []),
                    migration_priority=f_data.get("migration_priority", 5),
                    note=f_data.get("note", ""),
                ))

    if not findings:
        raise HTTPException(status_code=400, detail="No findings provided")

    # Score, recommend, build roadmap
    risk_scores = score_findings(
        findings,
        exposure_factor=request.exposure_factor,
        data_sensitivity=request.data_sensitivity,
    )
    recommendations = recommend_all(findings)
    tasks = build_migration_tasks(findings, risk_scores, recommendations)
    phases = build_phases(tasks)
    cost = estimate_cost(phases)
    compliance = check_compliance(findings)
    timeline = generate_timeline(phases)

    # Overall risk
    critical_count = sum(1 for f in findings if f.risk_level == RiskLevel.CRITICAL)
    high_count = sum(1 for f in findings if f.risk_level == RiskLevel.HIGH)
    if critical_count > 0:
        overall = RiskLevel.CRITICAL
    elif high_count > 0:
        overall = RiskLevel.HIGH
    else:
        overall = RiskLevel.MEDIUM

    roadmap = MigrationRoadmap(
        organization=request.organization,
        overall_risk=overall,
        phases=phases,
        risk_scores=risk_scores,
        cost_estimate=cost,
        compliance=compliance,
        total_findings=len(findings),
        critical_findings=critical_count,
        quantum_vulnerable_count=sum(1 for f in findings if f.quantum_vulnerable),
    )

    return roadmap.to_dict()
