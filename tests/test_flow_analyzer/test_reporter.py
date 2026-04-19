"""Reporter aggregation + JSON schema."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from src.flow_analyzer.hndl_scorer import score_hndl
from src.flow_analyzer.models import (
    CryptoPrimitive,
    DataSensitivity,
    Flow,
    Protocol,
    RetentionClass,
    RiskBand,
)
from src.flow_analyzer.reporter import generate_report, render_json


def _make_scored_flow(
    *,
    kex: str,
    hybrid: bool,
    sensitivity: DataSensitivity,
    retention: RetentionClass,
    bytes_total: int,
    dst_port: int = 443,
    server_name: str | None = None,
) -> tuple[Flow, object]:
    now = datetime.now(tz=timezone.utc)
    flow = Flow(
        src_ip="10.0.0.1", dst_ip="10.0.0.2",
        src_port=40000, dst_port=dst_port,
        transport="tcp", protocol=Protocol.TLS_1_3,
        first_seen=now, last_seen=now + timedelta(seconds=60),
        bytes_total=bytes_total,
        crypto=CryptoPrimitive(kex_algorithm=kex, is_hybrid_pqc=hybrid),
        server_name=server_name,
        sensitivity=sensitivity,
        retention=retention,
    )
    return flow, score_hndl(flow)


def test_generate_report_counts_risk_bands() -> None:
    scored = [
        _make_scored_flow(
            kex="RSA-2048", hybrid=False,
            sensitivity=DataSensitivity.SECRET, retention=RetentionClass.LIFETIME,
            bytes_total=1_000_000_000,
        ),
        _make_scored_flow(
            kex="X25519MLKEM768", hybrid=True,
            sensitivity=DataSensitivity.PUBLIC, retention=RetentionClass.EPHEMERAL,
            bytes_total=1_000,
        ),
    ]
    report = generate_report(scored, source="test.pcap", duration_seconds=60.0)
    assert report.total_flows == 2
    assert report.aggregate.flows_by_risk["CRITICAL"] >= 1
    assert report.aggregate.flows_by_risk["SAFE"] >= 1


def test_pqc_adoption_percent_only_counts_known_crypto() -> None:
    scored = [
        _make_scored_flow(
            kex="X25519MLKEM768", hybrid=True,
            sensitivity=DataSensitivity.INTERNAL, retention=RetentionClass.SHORT,
            bytes_total=10_000,
        ),
        _make_scored_flow(
            kex="x25519", hybrid=False,
            sensitivity=DataSensitivity.INTERNAL, retention=RetentionClass.SHORT,
            bytes_total=10_000,
        ),
    ]
    report = generate_report(scored, source="t.pcap", duration_seconds=1.0)
    assert report.aggregate.pqc_adoption_pct == 50.0


def test_hndl_exposed_per_day_extrapolates() -> None:
    scored = [
        _make_scored_flow(
            kex="RSA-2048", hybrid=False,
            sensitivity=DataSensitivity.SECRET, retention=RetentionClass.LIFETIME,
            bytes_total=1_000_000,
        ),
    ]
    # 60s capture with 1 MB exposed → extrapolation = 1MB/60s * 86400s = 1.44 GB/day
    report = generate_report(scored, source="t.pcap", duration_seconds=60.0)
    assert report.aggregate.hndl_exposed_bytes_per_day > 1_000_000 * 100  # sanity bound


def test_top_endpoints_sorted_by_worst_risk_then_bytes() -> None:
    scored = [
        _make_scored_flow(
            kex="RSA-2048", hybrid=False,
            sensitivity=DataSensitivity.SECRET, retention=RetentionClass.LIFETIME,
            bytes_total=500_000_000, server_name="a.bank.vn",
        ),
        _make_scored_flow(
            kex="X25519MLKEM768", hybrid=True,
            sensitivity=DataSensitivity.PUBLIC, retention=RetentionClass.EPHEMERAL,
            bytes_total=10_000_000_000, server_name="b.pqc.example",
        ),
    ]
    report = generate_report(scored, source="t.pcap", duration_seconds=60.0)
    assert report.aggregate.top_vulnerable_endpoints[0].endpoint.startswith("a.bank.vn")


def test_render_json_schema_stable() -> None:
    scored = [
        _make_scored_flow(
            kex="ECDHE", hybrid=False,
            sensitivity=DataSensitivity.CONFIDENTIAL, retention=RetentionClass.MEDIUM,
            bytes_total=1_000_000, server_name="api.example.vn",
        ),
    ]
    report = generate_report(scored, source="t.pcap", duration_seconds=10.0)
    blob = render_json(report)
    # Top-level keys
    for key in ("source", "duration_seconds", "total_flows", "total_bytes",
                "generated_at", "aggregate", "flows"):
        assert key in blob
    # Aggregate keys
    for key in ("flows_by_risk", "bytes_by_risk", "flows_by_protocol",
                "top_vulnerable_endpoints", "hndl_exposed_bytes_per_day",
                "pqc_adoption_pct"):
        assert key in blob["aggregate"]
    # Flow entries
    assert len(blob["flows"]) == 1
    entry = blob["flows"][0]
    assert "flow" in entry and "score" in entry
    assert entry["score"]["risk_level"] in (
        RiskBand.CRITICAL.value, RiskBand.HIGH.value, RiskBand.MEDIUM.value,
        RiskBand.LOW.value, RiskBand.SAFE.value,
    )
