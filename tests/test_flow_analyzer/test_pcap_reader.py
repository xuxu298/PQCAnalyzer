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
    frame = wrap(ip_tcp("10.0.0.1", "203.0.113.5", 40000, 443, b"hello"))
    write_pcap(path, [frame], linktype=linktype)
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
    ack = ip_tcp("10.0.0.1", "10.0.0.2", 40000, 443, flags=dpkt.tcp.TH_ACK)
    write_pcap(path, [ether(ack, pad_to=60)])
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


# --- regressions from the 03/10 review ---------------------------------------

import socket  # noqa: E402
import struct  # noqa: E402


def _pcapng_block(btype: int, body: bytes) -> bytes:
    body += b"\x00" * (-len(body) % 4)
    length = 12 + len(body)
    return struct.pack("<II", btype, length) + body + struct.pack("<I", length)


def _shb() -> bytes:
    return _pcapng_block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))


def _epb(frame: bytes) -> bytes:
    return _pcapng_block(6, struct.pack("<IIIII", 0, 0, 0, len(frame), len(frame)) + frame)


@pytest.mark.parametrize("code", [9, 14])
def test_idb_option_longer_than_block_does_not_crash(tmp_path: Path, code: int) -> None:
    # option claims 200 bytes but the block ends right after its header
    idb = _pcapng_block(1, struct.pack("<HHI", 1, 0, 65535) + struct.pack("<HH", code, 200))
    path = tmp_path / "bad-opt.pcapng"
    path.write_bytes(_shb() + idb + _epb(ether(ip_tcp("10.0.0.1", "10.0.0.2", 1, 443))))
    pkts = list(read_pcap(path))
    assert len(pkts) == 1 and pkts[0].transport == "tcp"


def test_large_non_packet_block_is_skipped(tmp_path: Path) -> None:
    idb = _pcapng_block(1, struct.pack("<HHI", 1, 0, 65535))
    secrets = _pcapng_block(0x0000000A, b"\x00" * (600 * 1024))  # Decryption Secrets Block
    path = tmp_path / "dsb.pcapng"
    path.write_bytes(_shb() + idb + secrets + _epb(ether(ip_tcp("10.0.0.1", "10.0.0.2", 1, 443))))
    assert len(list(read_pcap(path))) == 1


def test_pcapng_with_only_unsupported_link_types_raises(tmp_path: Path) -> None:
    path = tmp_path / "wifi.pcapng"
    write_pcapng(path, [105], [(0, b"\x00" * 40)])
    with pytest.raises(UnsupportedLinkTypeError):
        list(read_pcap(path))


@pytest.mark.parametrize("bad", [
    "port ²", "tcp port ¹²", "port ①",   # unicode digits used to 500
    "not port 22", "tcp and (port 443 or port 22)", "src host 10.0.0.1",
    "host example.com", "net 10.0.0.0/8",
])
def test_unsupported_bpf_rejected(tmp_path: Path, bad: str) -> None:
    pcap_path = tmp_path / "toy.pcap"
    _make_pcap(pcap_path)
    with pytest.raises(InvalidFilterError):
        list(read_pcap(pcap_path, bpf_filter=bad))


def test_bpf_host_matches_any_ipv6_spelling(tmp_path: Path) -> None:
    path = tmp_path / "v6.pcap"
    write_pcap(path, [ether(ip_tcp("2001:db8::1", "2001:db8::2", 40000, 443))])
    assert len(list(read_pcap(path, bpf_filter="host 2001:DB8:0::0001"))) == 1


@pytest.mark.parametrize(
    "linktype,header", [(0, struct.pack("<I", 2)), (108, struct.pack(">I", 2))],
)
def test_loopback_link_types_decode(tmp_path: Path, linktype: int, header: bytes) -> None:
    path = tmp_path / "lo.pcap"
    write_pcap(path, [header + ip_tcp("127.0.0.1", "127.0.0.1", 40000, 443)], linktype=linktype)
    pkt = list(read_pcap(path))[0]
    assert (pkt.transport, pkt.dport) == ("tcp", 443)


def _outer_ip(proto: int, payload: bytes) -> bytes:
    return bytes(dpkt.ip.IP(
        src=socket.inet_aton("192.0.2.1"), dst=socket.inet_aton("192.0.2.2"),
        p=proto, ttl=64, data=payload,
    ))


@pytest.mark.parametrize("name,frame", [
    ("ipip", lambda inner: ether(_outer_ip(4, inner))),
    ("gre-erspan2", lambda inner: ether(
        _outer_ip(47, struct.pack(">HH", 0, 0x88BE) + b"\x00" * 8 + ether(inner)))),
    ("gre-teb", lambda inner: ether(_outer_ip(47, struct.pack(">HH", 0, 0x6558) + ether(inner)))),
    ("vxlan", lambda inner: ether(bytes(dpkt.ip.IP(
        src=socket.inet_aton("192.0.2.1"), dst=socket.inet_aton("192.0.2.2"), p=17, ttl=64,
        data=dpkt.udp.UDP(
            sport=50000, dport=4789,
            data=b"\x08\x00\x00\x00\x00\x00\x01\x00" + ether(inner),
        ),
    )))),
])
def test_one_tunnel_layer_is_decapsulated(tmp_path: Path, name: str, frame) -> None:
    inner = ip_tcp("10.1.1.1", "10.1.1.2", 40000, 443)
    path = tmp_path / f"{name}.pcap"
    write_pcap(path, [frame(inner)])
    pkt = list(read_pcap(path))[0]
    assert (pkt.src, pkt.dst, pkt.transport, pkt.dport) == ("10.1.1.1", "10.1.1.2", "tcp", 443)
