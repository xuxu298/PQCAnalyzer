"""Build tiny PCAP / pcapng files from hand-made frames (dpkt for headers)."""

from __future__ import annotations

import socket
import struct
from typing import TYPE_CHECKING

import dpkt

if TYPE_CHECKING:
    from pathlib import Path


def ip_tcp(
    src: str, dst: str, sport: int, dport: int, payload: bytes = b"",
    flags: int = dpkt.tcp.TH_PUSH | dpkt.tcp.TH_ACK,
) -> bytes:
    """IPv4 or IPv6 packet carrying one TCP segment (no link layer)."""
    tcp = dpkt.tcp.TCP(sport=sport, dport=dport, flags=flags, data=payload)
    if ":" in src:
        tcp_bytes = bytes(tcp)
        ip6 = dpkt.ip6.IP6(
            src=socket.inet_pton(socket.AF_INET6, src),
            dst=socket.inet_pton(socket.AF_INET6, dst),
            nxt=dpkt.ip.IP_PROTO_TCP, hlim=64, plen=len(tcp_bytes),
        )
        return bytes(ip6) + tcp_bytes
    ip = dpkt.ip.IP(
        src=socket.inet_aton(src), dst=socket.inet_aton(dst),
        p=dpkt.ip.IP_PROTO_TCP, ttl=64, data=tcp,
    )
    return bytes(ip)


def ether(l3: bytes, pad_to: int = 0) -> bytes:
    """Wrap an IP packet in Ethernet II; optionally pad like a NIC does (to 60)."""
    ethtype = dpkt.ethernet.ETH_TYPE_IP6 if (l3[0] >> 4) == 6 else dpkt.ethernet.ETH_TYPE_IP
    dst, src = b"\x02\x00\x00\x00\x00\x02", b"\x02\x00\x00\x00\x00\x01"
    frame = dst + src + struct.pack(">H", ethtype) + l3
    return frame + b"\x00" * max(0, pad_to - len(frame))


def sll(l3: bytes) -> bytes:
    """Linux cooked v1 header (DLT 113)."""
    ethtype = 0x86DD if (l3[0] >> 4) == 6 else 0x0800
    return struct.pack(">HHH8sH", 0, 1, 6, b"\x02" * 6 + b"\x00\x00", ethtype) + l3


def write_pcap(path: Path, frames: list[bytes], linktype: int = 1, t0: int = 1_700_000_000) -> None:
    out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, linktype)
    for i, frame in enumerate(frames):
        out += struct.pack("<IIII", t0 + i, 0, len(frame), len(frame)) + frame
    path.write_bytes(out)


def write_pcapng(path: Path, linktypes: list[int], packets: list[tuple[int, bytes]]) -> None:
    """One section, one IDB per link type, one EPB per (interface_id, frame)."""

    def block(btype: int, body: bytes) -> bytes:
        body += b"\x00" * (-len(body) % 4)
        length = 12 + len(body)
        return struct.pack("<II", btype, length) + body + struct.pack("<I", length)

    out = block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
    for lt in linktypes:
        out += block(1, struct.pack("<HHI", lt, 0, 65535))
    for i, (iface, frame) in enumerate(packets):
        ts = (1_700_000_000 + i) * 1_000_000
        epb = struct.pack("<IIIII", iface, ts >> 32, ts & 0xFFFFFFFF, len(frame), len(frame))
        out += block(6, epb + frame)
    path.write_bytes(out)
