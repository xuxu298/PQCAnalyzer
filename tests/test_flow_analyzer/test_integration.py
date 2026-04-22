"""End-to-end: synth PCAP → aggregator → scorer → reporter → JSON."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from src.flow_analyzer.data_classifier import ClassificationRules
from src.flow_analyzer.flow_aggregator import FlowAggregator
from src.flow_analyzer.hndl_scorer import score_hndl
from src.flow_analyzer.models import RiskBand
from src.flow_analyzer.pcap_reader import read_pcap
from src.flow_analyzer.reporter import generate_report, render_json

scapy = pytest.importorskip("scapy")
from scapy.layers.inet import IP, TCP  # noqa: E402
from scapy.layers.l2 import Ether  # noqa: E402
from scapy.utils import wrpcap  # noqa: E402

from tests.test_flow_analyzer.test_tls_parser import (  # noqa: E402
    _client_hello,
    _key_share_client_ext,
    _key_share_server_ext,
    _server_hello,
    _sni_ext,
    _supported_versions_ext_client,
    _supported_versions_ext_server,
)


def _pkt(src_ip: str, dst_ip: str, sport: int, dport: int, payload: bytes) -> object:
    return Ether() / IP(src=src_ip, dst=dst_ip) / TCP(sport=sport, dport=dport, flags="PA") / payload


def _hybrid_tls_bytes() -> tuple[bytes, bytes]:
    ch = _client_hello(
        cipher_suites=[0x1302],
        extensions=(
            _sni_ext("dichvucong.gov.vn")
            + _supported_versions_ext_client([0x0304])
            + _key_share_client_ext([0x11EC])
        ),
    )
    sh = _server_hello(
        cipher_suite=0x1302,
        extensions=_supported_versions_ext_server(0x0304) + _key_share_server_ext(0x11EC),
    )
    return ch, sh


def _classical_tls_bytes() -> tuple[bytes, bytes]:
    ch = _client_hello(
        cipher_suites=[0xC030],
        extensions=_sni_ext("api.unknown.example"),
    )
    sh = _server_hello(cipher_suite=0xC030)
    return ch, sh


def test_end_to_end_pcap_to_json(tmp_path: Path) -> None:
    ch_hybrid, sh_hybrid = _hybrid_tls_bytes()
    ch_cls, sh_cls = _classical_tls_bytes()
    pkts = [
        _pkt("10.0.0.1", "203.0.113.10", 40000, 443, ch_hybrid),
        _pkt("203.0.113.10", "10.0.0.1", 443, 40000, sh_hybrid),
        _pkt("10.0.0.2", "203.0.113.11", 40001, 443, ch_cls),
        _pkt("203.0.113.11", "10.0.0.2", 443, 40001, sh_cls),
    ]
    # Scapy's TCP checksum caps payload at 65535B per packet, so bulk up the
    # classical flow across many packets (~3 MB total → E ≈ 0.65, score > 5).
    filler = b"\x17\x03\x03" + (50_000).to_bytes(2, "big") + b"\x00" * 50_000
    for _ in range(60):
        pkts.append(_pkt("203.0.113.11", "10.0.0.2", 443, 40001, filler))
    pcap_path = tmp_path / "synth.pcap"
    wrpcap(str(pcap_path), pkts)

    agg = FlowAggregator()
    for p in read_pcap(pcap_path):
        agg.ingest(p)
    flows = list(agg.flush())
    assert len(flows) == 2

    rules = ClassificationRules.load()
    scored = []
    for flow in flows:
        sens, retention, _ = rules.classify(flow)
        flow.sensitivity = sens
        flow.retention = retention
        scored.append((flow, score_hndl(flow)))

    report = generate_report(scored, source=str(pcap_path), duration_seconds=60.0)
    blob = render_json(report)
    json.dumps(blob)  # must be JSON-serialisable

    # The gov.vn flow → SECRET + LIFETIME, but hybrid PQC → V=0.1 → LOW/SAFE band.
    gov_entry = next(e for e in blob["flows"] if e["flow"].get("server_name") == "dichvucong.gov.vn")
    assert gov_entry["score"]["risk_level"] in (RiskBand.SAFE.value, RiskBand.LOW.value)
    assert gov_entry["flow"]["crypto"]["is_hybrid_pqc"] is True

    # The classical + bulk flow should register as LOW/MEDIUM at minimum (non-SAFE).
    cls_entry = next(e for e in blob["flows"] if e["flow"].get("server_name") == "api.unknown.example")
    assert cls_entry["score"]["risk_level"] != RiskBand.SAFE.value
