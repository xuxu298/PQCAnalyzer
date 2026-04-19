"""PCAP reader — magic validation + scapy-backed round trip.

Uses scapy's PcapWriter to synthesise a tiny Ethernet+IP+TCP PCAP in a tmp
dir, reads it back, and checks that packet count + basic tuple extraction work.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from src.flow_analyzer.pcap_reader import InvalidPCAPError, read_pcap

# scapy is an optional dep; skip the whole module if missing.
scapy = pytest.importorskip("scapy")
from scapy.layers.inet import IP, TCP  # noqa: E402
from scapy.layers.l2 import Ether  # noqa: E402
from scapy.utils import wrpcap  # noqa: E402


def _make_pcap(path: Path) -> None:
    pkts = [
        Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=40000, dport=443, flags="S"),
        Ether() / IP(src="10.0.0.2", dst="10.0.0.1") / TCP(sport=443, dport=40000, flags="SA"),
    ]
    wrpcap(str(path), pkts)


def test_read_pcap_returns_packets(tmp_path: Path) -> None:
    pcap_path = tmp_path / "toy.pcap"
    _make_pcap(pcap_path)
    pkts = list(read_pcap(pcap_path))
    assert len(pkts) == 2
    assert pkts[0][TCP].dport == 443


def test_read_pcap_rejects_non_pcap_file(tmp_path: Path) -> None:
    bogus = tmp_path / "nope.pcap"
    bogus.write_bytes(b"this is not a pcap")
    with pytest.raises(InvalidPCAPError):
        list(read_pcap(bogus))


def test_read_pcap_rejects_short_file(tmp_path: Path) -> None:
    bogus = tmp_path / "short.pcap"
    bogus.write_bytes(b"ab")
    with pytest.raises(InvalidPCAPError):
        list(read_pcap(bogus))


def test_read_pcap_applies_bpf_filter(tmp_path: Path) -> None:
    pcap_path = tmp_path / "toy.pcap"
    _make_pcap(pcap_path)
    # Keep only tcp port 443 (matches both packets since both have port 443)
    pkts = list(read_pcap(pcap_path, bpf_filter="tcp port 443"))
    assert len(pkts) == 2
    # Filter to nonexistent port → empty
    none_pkts = list(read_pcap(pcap_path, bpf_filter="tcp port 8888"))
    assert none_pkts == []
