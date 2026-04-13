"""Priority engine — assign migration phases and priorities to findings."""

from __future__ import annotations

from src.roadmap.models import MigrationPhase, MigrationTask, RiskScore
from src.roadmap.recommendation import Recommendation
from src.scanner.models import Finding
from src.utils.constants import RiskLevel

# Phase definitions
PHASES = [
    MigrationPhase(
        phase_number=0,
        name="Inventory & Assessment",
        description="Run scanners, benchmark PQC on production hardware, define scope.",
        timeline="0-3 months",
    ),
    MigrationPhase(
        phase_number=1,
        name="Quick Wins",
        description="Enable hybrid key exchange, upgrade ciphers, update SSH configs, upgrade AES-128 to AES-256.",
        timeline="3-6 months",
    ),
    MigrationPhase(
        phase_number=2,
        name="Core Migration",
        description="Migrate VPN infrastructure, PKI preparation, application-level crypto changes, test hybrid mode.",
        timeline="6-18 months",
    ),
    MigrationPhase(
        phase_number=3,
        name="Full PQC",
        description="Full PQC certificates, retire classical-only suites, compliance verification, continuous monitoring.",
        timeline="18-36 months",
    ),
]


def assign_phase(finding: Finding, risk_score: RiskScore) -> int:
    """Determine which migration phase a finding belongs to.

    Phase 1: Config-level changes (cipher suites, SSH KEX, TLS settings)
    Phase 2: Infrastructure changes (VPN, PKI, code)
    Phase 3: Full PQC (certificates, retire classical)
    """
    component_lower = finding.component.lower()
    risk = finding.risk_level
    if isinstance(risk, str):
        risk = RiskLevel(risk)

    # Phase 1: Quick wins — config changes, cipher upgrades
    phase1_keywords = ["cipher", "mac", "hash", "ssh key exchange",
                       "ssh host key", "ssh cipher", "ssh mac"]
    if any(kw in component_lower for kw in phase1_keywords):
        return 1

    # Weak/broken algorithms regardless of component -> Phase 1
    algo_lower = finding.algorithm.lower()
    broken_algos = ["des", "3des", "rc4", "md5", "sha-1", "sha1", "blowfish",
                    "bf-cbc", "arcfour"]
    if any(a in algo_lower for a in broken_algos):
        return 1

    # AES-128 -> AES-256 is a quick win
    if "aes-128" in algo_lower or "aes128" in algo_lower:
        return 1

    # TLS key exchange upgrade (enable hybrid) -> Phase 1
    if "key exchange" in component_lower and "tls" in component_lower:
        return 1

    # Certificates, PKI -> Phase 2-3
    if "certificate" in component_lower or "cert" in component_lower:
        if risk == RiskLevel.CRITICAL:
            return 2
        return 3

    # VPN, IPSec -> Phase 2
    if any(kw in component_lower for kw in ["vpn", "openvpn", "wireguard", "ipsec"]):
        return 2

    # Source code changes -> Phase 2
    if any(kw in component_lower for kw in ["python", "java", "go", "node", "c/c++", "code"]):
        return 2

    # Default: use risk score to decide
    if risk_score.total_score >= 100:
        return 1
    elif risk_score.total_score >= 50:
        return 2
    else:
        return 3


def assign_priority(risk_score: RiskScore, phase: int) -> int:
    """Assign priority within a phase (1=highest, 5=lowest)."""
    score = risk_score.total_score

    if score >= 150:
        return 1
    elif score >= 100:
        return 2
    elif score >= 50:
        return 3
    elif score >= 20:
        return 4
    else:
        return 5


def build_migration_tasks(
    findings: list[Finding],
    risk_scores: list[RiskScore],
    recommendations: list[Recommendation],
) -> list[MigrationTask]:
    """Build migration tasks from findings, scores, and recommendations."""
    tasks: list[MigrationTask] = []

    # Build lookup by algorithm+component
    score_map: dict[str, RiskScore] = {}
    for s in risk_scores:
        key = f"{s.finding_algorithm}|{s.finding_component}"
        score_map[key] = s

    rec_map: dict[str, Recommendation] = {}
    for r in recommendations:
        key = f"{r.finding_algorithm}|{r.finding_component}"
        rec_map[key] = r

    # Group similar findings to avoid duplicate tasks
    seen: set[str] = set()

    for finding in findings:
        key = f"{finding.algorithm}|{finding.component}"
        if key in seen:
            continue
        seen.add(key)

        score = score_map.get(key, RiskScore())
        rec = rec_map.get(key)

        phase = rec.timeline_phase if rec else assign_phase(finding, score)
        priority = assign_priority(score, phase)

        task = MigrationTask(
            title=f"Migrate {finding.component}: {finding.algorithm}",
            description=finding.note or f"Upgrade {finding.algorithm} in {finding.component}",
            phase=phase,
            phase_name=PHASES[phase].name if phase < len(PHASES) else "Unknown",
            priority=priority,
            risk_score=score.total_score,
            effort_hours=_estimate_effort(finding, rec),
            risk_level=rec.risk if rec else "medium",
            affected_components=[finding.location],
            steps=rec.steps if rec else [],
        )
        tasks.append(task)

    tasks.sort(key=lambda t: (t.phase, t.priority, -t.risk_score))
    return tasks


def build_phases(tasks: list[MigrationTask]) -> list[MigrationPhase]:
    """Organize tasks into migration phases."""
    phases = [
        MigrationPhase(
            phase_number=p.phase_number,
            name=p.name,
            description=p.description,
            timeline=p.timeline,
        )
        for p in PHASES
    ]

    for task in tasks:
        if 0 <= task.phase < len(phases):
            phases[task.phase].tasks.append(task)

    for phase in phases:
        phase.total_effort_hours = sum(t.effort_hours for t in phase.tasks)

    return phases


def _estimate_effort(finding: Finding, rec: Recommendation | None) -> int:
    """Estimate effort in person-hours for a migration task."""
    component_lower = finding.component.lower()

    # Effort matrix from spec
    if "cipher" in component_lower or "mac" in component_lower:
        return 4  # config update
    if "ssh" in component_lower:
        return 4
    if "tls" in component_lower and "key exchange" in component_lower:
        return 8
    if "certificate" in component_lower:
        return 24
    if "vpn" in component_lower or "openvpn" in component_lower:
        return 40
    if "wireguard" in component_lower:
        return 24
    if "ipsec" in component_lower:
        return 40
    if any(kw in component_lower for kw in ["python", "java", "go", "node", "c/c++"]):
        return 80

    # Default based on risk
    if rec and "high" in rec.effort.lower():
        return 80
    elif rec and "medium" in rec.effort.lower():
        return 40
    return 16
