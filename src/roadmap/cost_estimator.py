"""Cost estimation engine — estimate effort and cost for PQC migration."""

from __future__ import annotations

from src.roadmap.models import CostEstimate, MigrationPhase


# Effort matrix (from spec)
EFFORT_MATRIX: dict[str, dict[str, str | int]] = {
    "tls_config_update": {"person_hours": 4, "risk": "low", "downtime": "0"},
    "cipher_suite_update": {"person_hours": 8, "risk": "low", "downtime": "minutes"},
    "ssh_config_update": {"person_hours": 4, "risk": "low", "downtime": "0"},
    "vpn_migration": {"person_hours": 40, "risk": "medium", "downtime": "hours"},
    "pki_migration": {"person_hours": 160, "risk": "high", "downtime": "planned"},
    "application_code_change": {"person_hours": 80, "risk": "medium", "downtime": "varies"},
    "certificate_replacement": {"person_hours": 24, "risk": "medium", "downtime": "0 (if planned)"},
    "hardware_upgrade": {"person_hours": 200, "risk": "high", "downtime": "planned"},
    "testing_validation": {"person_hours": 120, "risk": "low", "downtime": "0"},
}

# Vietnam market hourly rates (VND)
HOURLY_RATES: dict[str, int] = {
    "junior": 300_000,      # ~$12/hr
    "mid": 500_000,         # ~$20/hr
    "senior": 800_000,      # ~$32/hr
    "expert": 1_500_000,    # ~$60/hr
}


def estimate_cost(
    phases: list[MigrationPhase],
    hourly_rate_vnd: int = 500_000,
) -> CostEstimate:
    """Estimate total cost from migration phases.

    Args:
        phases: Migration phases with tasks.
        hourly_rate_vnd: Hourly rate in VND (default: mid-level ~$20/hr).

    Returns:
        CostEstimate with breakdown.
    """
    estimate = CostEstimate(hourly_rate_vnd=hourly_rate_vnd)

    total_hours = 0
    breakdown: list[dict] = []

    for phase in phases:
        phase_hours = phase.total_effort_hours
        total_hours += phase_hours

        # Add testing overhead (20% of phase effort)
        testing_hours = int(phase_hours * 0.2)
        total_hours += testing_hours

        breakdown.append({
            "phase": phase.phase_number,
            "name": phase.name,
            "timeline": phase.timeline,
            "tasks": len(phase.tasks),
            "effort_hours": phase_hours,
            "testing_hours": testing_hours,
            "subtotal_hours": phase_hours + testing_hours,
        })

    estimate.total_person_hours = total_hours
    estimate.breakdown = breakdown

    # Timeline estimation (months)
    # Assume team of 2 working part-time (50%)
    effective_hours_per_month = 160 * 0.5 * 2  # 2 people * 50% * 160h/month
    estimate.timeline_months = max(
        3,  # minimum 3 months
        int(total_hours / effective_hours_per_month) + 1,
    )

    estimate.compute()
    return estimate


def format_vnd(amount: int) -> str:
    """Format VND amount with thousand separators."""
    if amount >= 1_000_000_000:
        return f"{amount / 1_000_000_000:.1f} tỷ VNĐ"
    elif amount >= 1_000_000:
        return f"{amount / 1_000_000:.0f} triệu VNĐ"
    else:
        return f"{amount:,} VNĐ"
