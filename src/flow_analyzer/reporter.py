"""Aggregate scored flows into a FlowAnalysisReport + rendering helpers."""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timezone

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from src.flow_analyzer.models import (
    AggregateStats,
    EndpointExposure,
    Flow,
    FlowAnalysisReport,
    HNDLScore,
    RiskBand,
)

_RISK_ORDER = [
    RiskBand.CRITICAL,
    RiskBand.HIGH,
    RiskBand.MEDIUM,
    RiskBand.LOW,
    RiskBand.SAFE,
]


def generate_report(
    flows_scored: list[tuple[Flow, HNDLScore]],
    source: str,
    duration_seconds: float,
) -> FlowAnalysisReport:
    """Build FlowAnalysisReport from per-flow scores."""
    total_flows = len(flows_scored)
    total_bytes = sum(f.bytes_total for f, _ in flows_scored)

    flows_by_risk: dict[str, int] = {b.value: 0 for b in _RISK_ORDER}
    bytes_by_risk: dict[str, int] = {b.value: 0 for b in _RISK_ORDER}
    flows_by_protocol: Counter[str] = Counter()
    exposed_bytes = 0
    pqc_flows = 0
    pqc_eligible = 0  # only flows with known crypto count toward adoption %

    for flow, score in flows_scored:
        flows_by_risk[score.risk_level.value] += 1
        bytes_by_risk[score.risk_level.value] += flow.bytes_total
        flows_by_protocol[flow.protocol.value] += 1
        if score.risk_level in (RiskBand.CRITICAL, RiskBand.HIGH, RiskBand.MEDIUM):
            exposed_bytes += flow.bytes_total
        if flow.crypto is not None and flow.crypto.kex_algorithm:
            pqc_eligible += 1
            if flow.crypto.is_hybrid_pqc or flow.crypto.is_pure_pqc:
                pqc_flows += 1

    # Extrapolate HNDL-exposed bytes to a per-day rate.
    if duration_seconds > 0:
        hndl_bps = exposed_bytes / duration_seconds
        hndl_per_day = hndl_bps * 86400.0
    else:
        hndl_per_day = 0.0

    pqc_pct = (pqc_flows / pqc_eligible * 100.0) if pqc_eligible else 0.0

    top_endpoints = _top_vulnerable_endpoints(flows_scored, limit=10)

    aggregate = AggregateStats(
        flows_by_risk=flows_by_risk,
        bytes_by_risk=bytes_by_risk,
        flows_by_protocol=dict(flows_by_protocol),
        top_vulnerable_endpoints=top_endpoints,
        hndl_exposed_bytes_per_day=hndl_per_day,
        pqc_adoption_pct=pqc_pct,
    )

    return FlowAnalysisReport(
        source=source,
        duration_seconds=duration_seconds,
        total_flows=total_flows,
        total_bytes=total_bytes,
        scored_flows=flows_scored,
        aggregate=aggregate,
        generated_at=datetime.now(tz=timezone.utc),
    )


def _top_vulnerable_endpoints(
    flows_scored: list[tuple[Flow, HNDLScore]], limit: int
) -> list[EndpointExposure]:
    """Group by (server_name or dst_ip):dst_port, rank by bytes exposed at risk."""
    groups: dict[str, list[tuple[Flow, HNDLScore]]] = defaultdict(list)
    for flow, score in flows_scored:
        label = flow.server_name or flow.dst_ip
        key = f"{label}:{flow.dst_port}"
        groups[key].append((flow, score))

    rollups: list[EndpointExposure] = []
    for endpoint, entries in groups.items():
        worst_idx = min(_RISK_ORDER.index(s.risk_level) for _, s in entries)
        worst = _RISK_ORDER[worst_idx]
        bytes_total = sum(f.bytes_total for f, _ in entries)
        sample_flow = entries[0][0]
        kex = sample_flow.crypto.kex_algorithm if sample_flow.crypto else None
        rollups.append(
            EndpointExposure(
                endpoint=endpoint,
                kex_algorithm=kex,
                sensitivity=sample_flow.sensitivity,
                flows=len(entries),
                bytes_total=bytes_total,
                worst_risk=worst,
            )
        )

    rollups.sort(
        key=lambda r: (_RISK_ORDER.index(r.worst_risk), -r.bytes_total),
    )
    return rollups[:limit]


# ---- Rendering ---------------------------------------------------------------

_RISK_STYLE: dict[RiskBand, str] = {
    RiskBand.CRITICAL: "bold red",
    RiskBand.HIGH: "bold yellow",
    RiskBand.MEDIUM: "yellow",
    RiskBand.LOW: "green",
    RiskBand.SAFE: "bold cyan",
}


def _fmt_bytes(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024.0:
            return f"{n:.1f} {unit}" if unit != "B" else f"{n} B"
        n /= 1024.0  # type: ignore[assignment]
    return f"{n:.1f} PB"


def _bar(frac: float, width: int = 20) -> str:
    filled = int(round(frac * width))
    return "█" * filled + "░" * (width - filled)


def render_cli(report: FlowAnalysisReport, console: Console | None = None) -> None:
    """Pretty-print report to terminal. Matches existing scanner CLI style."""
    c = console or Console()

    header = (
        f"Source: [bold]{report.source}[/bold]\n"
        f"Duration: {report.duration_seconds:.1f}s | "
        f"Flows: {report.total_flows} | Bytes: {_fmt_bytes(report.total_bytes)}"
    )
    c.print(Panel(header, title="[bold]PQCAnalyzer Flow Analysis[/bold]",
                  border_style="cyan"))

    # Risk distribution
    c.print()
    c.print("[bold]HNDL Exposure Summary[/bold]")
    total = max(1, report.total_flows)
    for band in _RISK_ORDER:
        count = report.aggregate.flows_by_risk.get(band.value, 0)
        size = report.aggregate.bytes_by_risk.get(band.value, 0)
        frac = count / total
        c.print(
            f"  [{_RISK_STYLE[band]}]{band.value:<9}[/{_RISK_STYLE[band]}]  "
            f"{_bar(frac)}  {count:>5} flows ({frac * 100:5.1f}%) │ {_fmt_bytes(size)}"
        )

    # PQC adoption + HNDL volume
    c.print()
    c.print(f"[bold]PQC Adoption:[/bold] {report.aggregate.pqc_adoption_pct:.1f}% (target: >95% by 2030)")
    c.print(f"[bold]HNDL-exposed per day:[/bold] {_fmt_bytes(int(report.aggregate.hndl_exposed_bytes_per_day))}")

    # Top endpoints
    if report.aggregate.top_vulnerable_endpoints:
        c.print()
        c.print("[bold]Top Vulnerable Endpoints[/bold]")
        tbl = Table(show_header=True, header_style="bold")
        tbl.add_column("Endpoint", width=36)
        tbl.add_column("KEX", width=22)
        tbl.add_column("Sensitivity", width=12)
        tbl.add_column("Flows", justify="right", width=6)
        tbl.add_column("Bytes", justify="right", width=10)
        tbl.add_column("Risk", width=9)
        for ep in report.aggregate.top_vulnerable_endpoints:
            style = _RISK_STYLE[ep.worst_risk]
            tbl.add_row(
                ep.endpoint[:36],
                ep.kex_algorithm or "—",
                ep.sensitivity.value,
                str(ep.flows),
                _fmt_bytes(ep.bytes_total),
                f"[{style}]{ep.worst_risk.value}[/{style}]",
            )
        c.print(tbl)

    c.print(
        "\n[dim]PQCAnalyzer by Vradar.io — AI SOC with post-quantum log transport · https://vradar.io[/dim]"
    )


def render_json(report: FlowAnalysisReport) -> dict:
    """JSON-serialisable dict. Matches scanner inventory schema conventions."""
    return {
        "source": report.source,
        "duration_seconds": report.duration_seconds,
        "total_flows": report.total_flows,
        "total_bytes": report.total_bytes,
        "generated_at": report.generated_at.isoformat(),
        "aggregate": report.aggregate.model_dump(),
        "flows": [
            {
                "flow": flow.model_dump(mode="json"),
                "score": score.model_dump(mode="json"),
            }
            for flow, score in report.scored_flows
        ],
    }
