"""PCAP reader — magic validation, framing, link-layer decode, BPF matching.

Synthesises tiny captures in a tmp dir (see ``pcap_helpers``), reads them back,
and checks packet count + tuple extraction.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from src.flow_analyzer.pcap_reader import (
    InvalidFilterError,
    InvalidPCAPError,
    UnsupportedLinkTypeError,
    read_pcap,
)

# dpkt is an optional dep; skip the whole module if missing.
dpkt = pytest.importorskip("dpkt")
from tests.test_flow_analyzer.pcap_helpers import (  # noqa: E402
    ether,
    ip_tcp,
    sll,
    write_pcap,
    write_pcapng,
)

SYN = dpkt.tcp.TH_SYN
SYN_ACK = dpkt.tcp.TH_SYN | dpkt.tcp.TH_ACK


def _make_pcap(path: Path) -> None:
    write_pcap(path, [
        ether(ip_tcp("10.0.0.1", "10.0.0.2", 40000, 443, flags=SYN)),
        ether(ip_tcp("10.0.0.2", "10.0.0.1", 443, 40000, flags=SYN_ACK)),
    ])


def test_read_pcap_returns_packets(tmp_path: Path) -> None:
    pcap_path = tmp_path / "toy.pcap"
    _make_pcap(pcap_path)
    pkts = list(read_pcap(pcap_path))
    assert len(pkts) == 2
    assert pkts[0].transport == "tcp"
    assert (pkts[0].src, pkts[0].dport) == ("10.0.0.1", 443)
    assert pkts[0].timestamp is not None


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


@pytest.mark.parametrize("bad", [
    "tcp port https",          # named port: used to raise ValueError → API 500
    "port 70000",
    " or ".join(["tcp"] * 200),  # deep and/or chain: RecursionError
])
def test_malformed_bpf_filter_rejected_up_front(tmp_path: Path, bad: str) -> None:
    pcap_path = tmp_path / "toy.pcap"
    _make_pcap(pcap_path)
    with pytest.raises(InvalidFilterError):
        list(read_pcap(pcap_path, bpf_filter=bad))


def test_garbage_frames_never_raise(tmp_path: Path) -> None:
    import os
    import struct

    # Classic pcap header (Ethernet) + 200 random-byte records.
    out = bytearray(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    for _ in range(200):
        frame = os.urandom(60)
        out += struct.pack("<IIII", 0, 0, len(frame), len(frame)) + frame
    path = tmp_path / "noise.pcap"
    path.write_bytes(bytes(out))
    assert len(list(read_pcap(path))) == 200


def test_unsupported_link_type_rejected(tmp_path: Path) -> None:
    path = tmp_path / "wifi.pcap"
    write_pcap(path, [b"\x00" * 40], linktype=105)  # 802.11
    with pytest.raises(UnsupportedLinkTypeError):
        list(read_pcap(path))


@pytest.mark.parametrize(
    ("linktype", "wrap"),
    [(1, ether), (101, lambda p: p), (113, sll), (228, lambda p: p)],
)
def test_link_layers_decode_to_same_tuple(tmp_path: Path, linktype: int, wrap) -> None:
    path = tmp_path / f"lt{linktype}.pcap"
    write_pcap(path, [wrap(ip_tcp("10.0.0.1", "203.0.113.5", 40000, 443, b"hello"))], linktype=linktype)
    (pkt,) = list(read_pcap(path))
    assert (pkt.src, pkt.dst, pkt.sport, pkt.dport, pkt.payload) == (
        "10.0.0.1", "203.0.113.5", 40000, 443, b"hello",
    )


def test_ipv6_address_is_canonical(tmp_path: Path) -> None:
    path = tmp_path / "v6.pcap"
    write_pcap(path, [ether(ip_tcp("2001:db8::1", "2001:db8:0:1::10", 40000, 443, b"x"))])
    (pkt,) = list(read_pcap(path, bpf_filter="host 2001:db8::1"))
    assert (pkt.src, pkt.dst) == ("2001:db8::1", "2001:db8:0:1::10")


def test_ethernet_padding_not_counted_as_payload(tmp_path: Path) -> None:
    """NICs pad short frames to 60 bytes; padding is not TCP payload."""
    path = tmp_path / "pad.pcap"
    write_pcap(path, [ether(ip_tcp("10.0.0.1", "10.0.0.2", 40000, 443, flags=dpkt.tcp.TH_ACK), pad_to=60)])
    (pkt,) = list(read_pcap(path))
    assert pkt.payload == b""


def test_truncated_final_record_stops_cleanly(tmp_path: Path) -> None:
    path = tmp_path / "cut.pcap"
    _make_pcap(path)
    path.write_bytes(path.read_bytes()[:-10])
    pkts = list(read_pcap(path))
    assert len(pkts) == 2  # last record yields what was captured, then EOF
    assert pkts[0].dport == 443


def test_pcapng_link_type_is_per_interface(tmp_path: Path) -> None:
    """Each pcapng interface has its own link type — dpkt's reader assumes one."""
    path = tmp_path / "multi.pcapng"
    v4 = ip_tcp("10.0.0.1", "10.0.0.2", 40000, 443, b"a")
    write_pcapng(path, linktypes=[1, 101], packets=[(0, ether(v4)), (1, v4)])
    pkts = list(read_pcap(path))
    assert [p.payload for p in pkts] == [b"a", b"a"]
    assert all(p.src == "10.0.0.1" for p in pkts)


def test_pcapng_without_section_header_rejected(tmp_path: Path) -> None:
    path = tmp_path / "bad.pcapng"
    path.write_bytes(b"\x0a\x0d\x0d\x0a" + b"\x00" * 4)
    with pytest.raises(InvalidPCAPError):
        list(read_pcap(path))


def test_non_ip_frame_yields_undecoded_packet(tmp_path: Path) -> None:
    path = tmp_path / "arp.pcap"
    arp = b"\xff" * 6 + b"\x02" * 6 + b"\x08\x06" + b"\x00" * 28
    write_pcap(path, [arp])
    (pkt,) = list(read_pcap(path))
    assert pkt.src is None and pkt.transport is None
