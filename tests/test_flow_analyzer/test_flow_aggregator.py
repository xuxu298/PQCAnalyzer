"""Flow aggregator — 5-tuple grouping + TLS handshake attachment.

Uses scapy to synthesise packets carrying a TLS ClientHello and ServerHello
on port 443, then checks the aggregator reassembles them into one Flow with
parsed crypto.
"""

from __future__ import annotations

import pytest

from src.flow_analyzer.flow_aggregator import FlowAggregator, aggregate
from src.flow_analyzer.models import Protocol

scapy = pytest.importorskip("scapy")
from scapy.layers.inet import IP, TCP  # noqa: E402
from scapy.layers.l2 import Ether  # noqa: E402

# Reuse the synthetic TLS byte builders from the parser tests.
from tests.test_flow_analyzer.test_tls_parser import (  # noqa: E402
    _client_hello,
    _key_share_client_ext,
    _key_share_server_ext,
    _server_hello,
    _sni_ext,
    _supported_versions_ext_client,
    _supported_versions_ext_server,
)


def _tls13_hybrid_ch_bytes() -> bytes:
    exts = (
        _sni_ext("api.example.vn")
        + _supported_versions_ext_client([0x0304])
        + _key_share_client_ext([0x11EC])
    )
    return _client_hello(cipher_suites=[0x1302], extensions=exts)


def _tls13_hybrid_sh_bytes() -> bytes:
    return _server_hello(
        cipher_suite=0x1302,
        extensions=_supported_versions_ext_server(0x0304) + _key_share_server_ext(0x11EC),
    )


def _tcp_payload(
    src: str, dst: str, sport: int, dport: int, payload: bytes
) -> object:
    return Ether() / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="PA") / payload


def test_aggregate_single_tls_flow_extracts_hybrid_crypto() -> None:
    pkts = [
        _tcp_payload("10.0.0.1", "10.0.0.2", 40000, 443, _tls13_hybrid_ch_bytes()),
        _tcp_payload("10.0.0.2", "10.0.0.1", 443, 40000, _tls13_hybrid_sh_bytes()),
    ]
    flows = aggregate(pkts)
    assert len(flows) == 1
    flow = flows[0]
    assert flow.protocol == Protocol.TLS_1_3
    assert flow.server_name == "api.example.vn"
    assert flow.crypto is not None
    assert flow.crypto.is_hybrid_pqc is True
    assert flow.crypto.kex_algorithm == "X25519MLKEM768"


def test_aggregate_packets_in_both_directions_collapse_to_one_flow() -> None:
    """Same 5-tuple regardless of direction → one Flow."""
    pkts = [
        _tcp_payload("10.0.0.1", "10.0.0.2", 40000, 443, b"\x00" * 10),
        _tcp_payload("10.0.0.2", "10.0.0.1", 443, 40000, b"\x00" * 20),
        _tcp_payload("10.0.0.1", "10.0.0.2", 40000, 443, b"\x00" * 5),
    ]
    flows = aggregate(pkts)
    assert len(flows) == 1
    assert flows[0].packets_total == 3
    assert flows[0].bytes_total == 35


def test_aggregate_separate_flows_for_different_tuples() -> None:
    pkts = [
        _tcp_payload("10.0.0.1", "10.0.0.2", 40000, 443, b""),
        _tcp_payload("10.0.0.1", "10.0.0.3", 40001, 443, b""),
    ]
    flows = aggregate(pkts)
    assert len(flows) == 2


def test_flush_drains_state() -> None:
    agg = FlowAggregator()
    agg.ingest(_tcp_payload("10.0.0.1", "10.0.0.2", 40000, 443, b""))
    first = list(agg.flush())
    second = list(agg.flush())
    assert len(first) == 1
    assert second == []


def test_aggregate_ignores_non_ip_packets() -> None:
    pkts = [Ether() / b"\x00\x01\x02"]  # bare Ethernet, no IP
    flows = aggregate(pkts)
    assert flows == []
