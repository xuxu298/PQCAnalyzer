"""Tests for cost estimation engine."""

import pytest

from src.roadmap.cost_estimator import estimate_cost, format_vnd
from src.roadmap.models import MigrationPhase, MigrationTask


@pytest.fixture
def sample_phases():
    return [
        MigrationPhase(
            phase_number=0, name="Assessment", timeline="0-3 months",
            tasks=[], total_effort_hours=0,
        ),
        MigrationPhase(
            phase_number=1, name="Quick Wins", timeline="3-6 months",
            tasks=[
                MigrationTask(title="Task 1", effort_hours=4),
                MigrationTask(title="Task 2", effort_hours=8),
            ],
            total_effort_hours=12,
        ),
        MigrationPhase(
            phase_number=2, name="Core Migration", timeline="6-18 months",
            tasks=[
                MigrationTask(title="Task 3", effort_hours=40),
                MigrationTask(title="Task 4", effort_hours=80),
            ],
            total_effort_hours=120,
        ),
        MigrationPhase(
            phase_number=3, name="Full PQC", timeline="18-36 months",
            tasks=[], total_effort_hours=0,
        ),
    ]


class TestCostEstimation:
    def test_total_hours(self, sample_phases):
        cost = estimate_cost(sample_phases)
        # 132 base + 20% testing overhead for each phase
        assert cost.total_person_hours > 0

    def test_includes_testing_overhead(self, sample_phases):
        cost = estimate_cost(sample_phases)
        base_hours = sum(p.total_effort_hours for p in sample_phases)
        assert cost.total_person_hours > base_hours  # testing overhead added

    def test_cost_computed(self, sample_phases):
        cost = estimate_cost(sample_phases, hourly_rate_vnd=500_000)
        assert cost.total_cost_vnd > 0
        assert cost.cost_range_low_vnd < cost.total_cost_vnd
        assert cost.cost_range_high_vnd > cost.total_cost_vnd

    def test_timeline_months(self, sample_phases):
        cost = estimate_cost(sample_phases)
        assert cost.timeline_months >= 3

    def test_breakdown(self, sample_phases):
        cost = estimate_cost(sample_phases)
        assert len(cost.breakdown) == 4  # 4 phases

    def test_to_dict(self, sample_phases):
        cost = estimate_cost(sample_phases)
        d = cost.to_dict()
        assert "total_person_hours" in d
        assert "total_cost_vnd" in d
        assert "breakdown" in d

    def test_custom_hourly_rate(self, sample_phases):
        cost_low = estimate_cost(sample_phases, hourly_rate_vnd=300_000)
        cost_high = estimate_cost(sample_phases, hourly_rate_vnd=800_000)
        assert cost_high.total_cost_vnd > cost_low.total_cost_vnd


class TestFormatVND:
    def test_format_millions(self):
        assert "triệu" in format_vnd(50_000_000)

    def test_format_billions(self):
        assert "tỷ" in format_vnd(1_500_000_000)

    def test_format_small(self):
        assert "VNĐ" in format_vnd(500_000)
