"""Timeline generator — create migration timeline from phases."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta

from src.roadmap.models import MigrationPhase


@dataclass
class TimelineEntry:
    """A single entry in the timeline."""

    phase: int = 0
    phase_name: str = ""
    start_date: str = ""
    end_date: str = ""
    duration_months: int = 0
    tasks_count: int = 0
    effort_hours: int = 0
    milestones: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "phase": self.phase,
            "phase_name": self.phase_name,
            "start_date": self.start_date,
            "end_date": self.end_date,
            "duration_months": self.duration_months,
            "tasks_count": self.tasks_count,
            "effort_hours": self.effort_hours,
            "milestones": self.milestones,
        }


@dataclass
class Timeline:
    """Complete migration timeline."""

    start_date: str = ""
    end_date: str = ""
    total_months: int = 0
    entries: list[TimelineEntry] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "start_date": self.start_date,
            "end_date": self.end_date,
            "total_months": self.total_months,
            "entries": [e.to_dict() for e in self.entries],
        }


# Phase durations from spec
_PHASE_DURATIONS: dict[int, tuple[int, int]] = {
    # phase -> (start_month_offset, duration_months)
    0: (0, 3),
    1: (3, 3),
    2: (6, 12),
    3: (18, 18),
}

# Milestones per phase
_PHASE_MILESTONES: dict[int, list[str]] = {
    0: [
        "Complete full crypto inventory scan",
        "Run PQC benchmarks on production hardware",
        "Define migration scope and priorities",
    ],
    1: [
        "Enable hybrid key exchange on TLS endpoints",
        "Upgrade cipher suites (remove weak, prefer AES-256)",
        "Update SSH configs (PQ-hybrid KEX)",
        "Upgrade AES-128 to AES-256",
    ],
    2: [
        "Migrate VPN infrastructure to PQC-capable",
        "PKI preparation for PQC certificates",
        "Application-level crypto migration started",
        "Test hybrid mode in production",
    ],
    3: [
        "Full PQC certificates deployed",
        "Retire classical-only cipher suites",
        "Compliance verification complete",
        "Continuous monitoring established",
    ],
}


def generate_timeline(
    phases: list[MigrationPhase],
    start_date: datetime | None = None,
) -> Timeline:
    """Generate a timeline from migration phases.

    Args:
        phases: Migration phases with tasks.
        start_date: When migration starts (default: now).

    Returns:
        Timeline with entries.
    """
    if start_date is None:
        start_date = datetime.now()

    timeline = Timeline(
        start_date=start_date.strftime("%Y-%m-%d"),
    )

    current_date = start_date
    entries: list[TimelineEntry] = []

    for phase in phases:
        phase_num = phase.phase_number
        start_offset, default_duration = _PHASE_DURATIONS.get(
            phase_num, (phase_num * 6, 6)
        )

        # Adjust duration based on actual task count
        if phase.tasks:
            # More tasks = more time, but cap at default * 1.5
            task_factor = len(phase.tasks) / 5  # baseline: 5 tasks per phase
            adjusted = max(default_duration, int(default_duration * task_factor))
            duration = min(adjusted, int(default_duration * 1.5))
        else:
            duration = default_duration

        phase_start = start_date + timedelta(days=start_offset * 30)
        phase_end = phase_start + timedelta(days=duration * 30)

        milestones = list(_PHASE_MILESTONES.get(phase_num, []))

        entry = TimelineEntry(
            phase=phase_num,
            phase_name=phase.name,
            start_date=phase_start.strftime("%Y-%m-%d"),
            end_date=phase_end.strftime("%Y-%m-%d"),
            duration_months=duration,
            tasks_count=len(phase.tasks),
            effort_hours=phase.total_effort_hours,
            milestones=milestones,
        )
        entries.append(entry)
        current_date = phase_end

    timeline.entries = entries
    timeline.end_date = current_date.strftime("%Y-%m-%d")
    timeline.total_months = sum(e.duration_months for e in entries)

    return timeline
