"""Flow aggregator — 5-tuple grouping + TLS handshake attachment.

Feeds decoded packet records carrying a TLS ClientHello and ServerHello on
port 443, then checks the aggregator reassembles them into one Flow with
parsed crypto.
"""

from __future__ import annotations

from datetime import datetime, timezone

from src.flow_analyzer.flow_aggregator import FlowAggregator, aggregate
from src.flow_analyzer.models import Protocol
from src.flow_analyzer.pcap_reader import Packet

# Reuse the synthetic TLS byte builders from the parser tests.
from tests.test_flow_analyzer.test_tls_parser import (
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


_TS = datetime(2026, 1, 1, tzinfo=timezone.utc)


def _tcp_payload(
    src: str, dst: str, sport: int, dport: int, payload: bytes
) -> Packet:
    return Packet(_TS, src=src, dst=dst, transport="tcp", sport=sport, dport=dport, payload=payload)


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
    pkts = [Packet(_TS)]  # frame that never decoded to IP
    flows = aggregate(pkts)
    assert flows == []


def test_client_hello_after_empty_ack_is_still_parsed() -> None:
    """An empty ACK ahead of the ClientHello must not poison the c2s buffer."""
    pkts = [
        _tcp_payload("10.0.0.1", "10.0.0.2", 40000, 443, b""),
        _tcp_payload("10.0.0.1", "10.0.0.2", 40000, 443, _tls13_hybrid_ch_bytes()),
        _tcp_payload("10.0.0.2", "10.0.0.1", 443, 40000, _tls13_hybrid_sh_bytes()),
    ]
    (flow,) = aggregate(pkts)
    assert flow.crypto is not None
    assert flow.crypto.kex_algorithm == "X25519MLKEM768"


def test_flow_cap_counts_instead_of_tracking() -> None:
    agg = FlowAggregator(max_flows=2)
    for sport in (40001, 40002, 40003, 40004):
        agg.ingest(_tcp_payload("10.0.0.1", "10.0.0.2", sport, 443, b"x"))
    assert len(list(agg.flush())) == 2
    assert agg.dropped_flows == 2


def test_full_buffer_is_not_reparsed(monkeypatch) -> None:
    """A never-parsing 443 flow used to re-copy and re-parse 16 KB per packet."""
    from src.flow_analyzer import flow_aggregator as fa

    calls = {"n": 0}

    def counting_parse(data):
        calls["n"] += 1
        return None

    monkeypatch.setattr(fa, "parse_tls_client_hello", counting_parse)
    agg = FlowAggregator()
    junk = b"\x00" * 1400
    for _ in range(200):  # ~280 KB, far past the 16 KB buffer
        agg.ingest(_tcp_payload("10.0.0.1", "10.0.0.2", 40000, 443, junk))
    assert calls["n"] <= fa.MAX_PAYLOAD_BUFFER // len(junk) + 1
