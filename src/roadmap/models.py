"""Data models for migration roadmap."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from uuid import uuid4

from src.utils.constants import RiskLevel


@dataclass
class RiskScore:
    """Computed risk score for a finding."""

    finding_algorithm: str = ""
    finding_component: str = ""
    finding_location: str = ""
    vulnerability_weight: int = 0
    exposure_factor: int = 1
    data_sensitivity: int = 1
    harvest_now_risk: int = 1
    total_score: int = 0

    def compute(self) -> int:
        self.total_score = (
            self.vulnerability_weight
            * self.exposure_factor
            * self.data_sensitivity
            * self.harvest_now_risk
        )
        return self.total_score

    def to_dict(self) -> dict:
        return {
            "algorithm": self.finding_algorithm,
            "component": self.finding_component,
            "location": self.finding_location,
            "vulnerability_weight": self.vulnerability_weight,
            "exposure_factor": self.exposure_factor,
            "data_sensitivity": self.data_sensitivity,
            "harvest_now_risk": self.harvest_now_risk,
            "total_score": self.total_score,
        }


@dataclass
class MigrationTask:
    """A single migration task in the roadmap."""

    task_id: str = field(default_factory=lambda: str(uuid4())[:8])
    title: str = ""
    description: str = ""
    phase: int = 0  # 0-3
    phase_name: str = ""
    priority: int = 5  # 1=highest
    risk_score: int = 0
    effort_hours: int = 0
    risk_level: str = "low"  # low/medium/high
    downtime: str = "0"
    affected_components: list[str] = field(default_factory=list)
    steps: list[str] = field(default_factory=list)
    dependencies: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "task_id": self.task_id,
            "title": self.title,
            "description": self.description,
            "phase": self.phase,
            "phase_name": self.phase_name,
            "priority": self.priority,
            "risk_score": self.risk_score,
            "effort_hours": self.effort_hours,
            "risk_level": self.risk_level,
            "downtime": self.downtime,
            "affected_components": self.affected_components,
            "steps": self.steps,
            "dependencies": self.dependencies,
        }


@dataclass
class MigrationPhase:
    """A phase in the migration roadmap."""

    phase_number: int = 0
    name: str = ""
    description: str = ""
    timeline: str = ""
    tasks: list[MigrationTask] = field(default_factory=list)
    total_effort_hours: int = 0

    def to_dict(self) -> dict:
        return {
            "phase": self.phase_number,
            "name": self.name,
            "description": self.description,
            "timeline": self.timeline,
            "tasks": [t.to_dict() for t in self.tasks],
            "total_effort_hours": self.total_effort_hours,
        }


@dataclass
class CostEstimate:
    """Cost estimation for the migration."""

    total_person_hours: int = 0
    hourly_rate_vnd: int = 500_000  # default ~$20/hr Vietnam market
    total_cost_vnd: int = 0
    cost_range_low_vnd: int = 0
    cost_range_high_vnd: int = 0
    timeline_months: int = 0
    breakdown: list[dict] = field(default_factory=list)

    def compute(self) -> None:
        self.total_cost_vnd = self.total_person_hours * self.hourly_rate_vnd
        self.cost_range_low_vnd = int(self.total_cost_vnd * 0.7)
        self.cost_range_high_vnd = int(self.total_cost_vnd * 1.5)

    def to_dict(self) -> dict:
        return {
            "total_person_hours": self.total_person_hours,
            "hourly_rate_vnd": self.hourly_rate_vnd,
            "total_cost_vnd": self.total_cost_vnd,
            "cost_range_low_vnd": self.cost_range_low_vnd,
            "cost_range_high_vnd": self.cost_range_high_vnd,
            "timeline_months": self.timeline_months,
            "breakdown": self.breakdown,
        }


@dataclass
class ComplianceStatus:
    """Compliance check result."""

    standard: str = ""
    requirement: str = ""
    status: str = "not_checked"  # compliant / non_compliant / partial / not_checked
    details: str = ""
    remediation: str = ""

    def to_dict(self) -> dict:
        return {
            "standard": self.standard,
            "requirement": self.requirement,
            "status": self.status,
            "details": self.details,
            "remediation": self.remediation,
        }


@dataclass
class MigrationRoadmap:
    """Complete migration roadmap."""

    roadmap_id: str = field(default_factory=lambda: str(uuid4()))
    timestamp: str = field(default_factory=lambda: datetime.now().astimezone().isoformat())
    organization: str = ""
    scope_summary: str = ""
    overall_risk: RiskLevel = RiskLevel.MEDIUM
    phases: list[MigrationPhase] = field(default_factory=list)
    risk_scores: list[RiskScore] = field(default_factory=list)
    cost_estimate: CostEstimate = field(default_factory=CostEstimate)
    compliance: list[ComplianceStatus] = field(default_factory=list)
    total_findings: int = 0
    critical_findings: int = 0
    quantum_vulnerable_count: int = 0

    def to_dict(self) -> dict:
        return {
            "roadmap_id": self.roadmap_id,
            "timestamp": self.timestamp,
            "organization": self.organization,
            "scope_summary": self.scope_summary,
            "overall_risk": self.overall_risk.value,
            "total_findings": self.total_findings,
            "critical_findings": self.critical_findings,
            "quantum_vulnerable_count": self.quantum_vulnerable_count,
            "phases": [p.to_dict() for p in self.phases],
            "risk_scores": [r.to_dict() for r in self.risk_scores],
            "cost_estimate": self.cost_estimate.to_dict(),
            "compliance": [c.to_dict() for c in self.compliance],
        }
