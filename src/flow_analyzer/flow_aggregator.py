"""Aggregate scapy packets into 5-tuple flows and extract handshake crypto."""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from src.flow_analyzer.handshake_parser.ssh_parser import (
    SSHKexInit,
    parse_ssh_kexinit,
    ssh_crypto_from_kexinit,
)
from src.flow_analyzer.handshake_parser.tls_parser import (
    TLSClientHello,
    TLSServerHello,
    extract_crypto,
    parse_tls_client_hello,
    parse_tls_server_hello,
)
from src.flow_analyzer.models import CryptoPrimitive, Flow, Protocol

if TYPE_CHECKING:
    from scapy.packet import Packet

# Cap per-direction buffer. ClientHello is typically < 2 KB; SSH KEXINIT < 4 KB.
# Keep the cap small so a 10 GB PCAP doesn't blow RAM on long-lived flows.
MAX_PAYLOAD_BUFFER = 16 * 1024

WELL_KNOWN_TLS_PORTS = {443, 465, 563, 636, 853, 993, 995, 8443}
WELL_KNOWN_SSH_PORTS = {22, 2222}


@dataclass
class _FlowState:
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    transport: str
    first_seen: datetime
    last_seen: datetime
    bytes_total: int = 0
    packets_total: int = 0
    # Buffers keyed by direction: "c2s" = initiator→responder, "s2c" = reverse.
    buf_c2s: bytearray = field(default_factory=bytearray)
    buf_s2c: bytearray = field(default_factory=bytearray)
    # Cached parse results — parse once per direction then stop buffering.
    tls_ch: TLSClientHello | None = None
    tls_sh: TLSServerHello | None = None
    ssh_client: SSHKexInit | None = None
    ssh_server: SSHKexInit | None = None
    protocol: Protocol = Protocol.UNKNOWN


def _canonical_key(
    src_ip: str, dst_ip: str, src_port: int, dst_port: int, transport: str
) -> tuple[str, str, int, int, str, bool]:
    """Return a direction-agnostic 5-tuple key + a flag telling if the
    canonical form flipped (True = first observed packet went s→c).

    We canonicalize by sorting (ip, port) endpoints so that packets in both
    directions map to the same flow. The flag lets us attribute direction.
    """
    a = (src_ip, src_port)
    b = (dst_ip, dst_port)
    if a < b:
        return (src_ip, dst_ip, src_port, dst_port, transport, False)
    return (dst_ip, src_ip, dst_port, src_port, transport, True)


def _is_tls_port(port: int) -> bool:
    return port in WELL_KNOWN_TLS_PORTS


def _is_ssh_port(port: int) -> bool:
    return port in WELL_KNOWN_SSH_PORTS


def _classify_protocol(src_port: int, dst_port: int) -> Protocol:
    if _is_tls_port(src_port) or _is_tls_port(dst_port):
        return Protocol.TLS_1_2  # refined later by parser (1.2 vs 1.3)
    if _is_ssh_port(src_port) or _is_ssh_port(dst_port):
        return Protocol.SSH_2
    return Protocol.UNKNOWN


def _side_is_c2s(
    flow: _FlowState, pkt_src_ip: str, pkt_src_port: int
) -> bool:
    """Determine if a packet is client→server for this flow.

    Heuristic: the side with the well-known port is the server.
    """
    client_side = (flow.src_ip, flow.src_port)
    server_side = (flow.dst_ip, flow.dst_port)
    # If dst_port is well-known, flow.(src,dst) is already client→server.
    if _is_tls_port(flow.dst_port) or _is_ssh_port(flow.dst_port):
        return (pkt_src_ip, pkt_src_port) == client_side
    if _is_tls_port(flow.src_port) or _is_ssh_port(flow.src_port):
        # server is flow.src side; flip meaning.
        return (pkt_src_ip, pkt_src_port) == server_side
    # No well-known port — default to initial canonical direction.
    return (pkt_src_ip, pkt_src_port) == client_side


class FlowAggregator:
    """Stream packets → emit Flow objects with parsed handshake crypto."""

    def __init__(self) -> None:
        self._flows: dict[tuple, _FlowState] = {}

    def ingest(self, pkt: Packet) -> None:
        info = _extract_packet_info(pkt)
        if info is None:
            return
        src_ip, dst_ip, src_port, dst_port, transport, payload, ts = info

        a, b, pa, pb, proto, _flipped = _canonical_key(
            src_ip, dst_ip, src_port, dst_port, transport
        )
        key = (a, b, pa, pb, proto)

        flow = self._flows.get(key)
        if flow is None:
            flow = _FlowState(
                src_ip=a,
                dst_ip=b,
                src_port=pa,
                dst_port=pb,
                transport=transport,
                first_seen=ts,
                last_seen=ts,
                protocol=_classify_protocol(pa, pb),
            )
            self._flows[key] = flow

        flow.last_seen = ts
        flow.bytes_total += len(payload) if payload else 0
        flow.packets_total += 1

        if not payload:
            return

        is_c2s = _side_is_c2s(flow, src_ip, src_port)
        target = flow.buf_c2s if is_c2s else flow.buf_s2c
        if len(target) < MAX_PAYLOAD_BUFFER:
            remaining = MAX_PAYLOAD_BUFFER - len(target)
            target.extend(payload[:remaining])

        # Opportunistic parse — cheap to retry until we get a message, then stop.
        if flow.protocol in (Protocol.TLS_1_2, Protocol.TLS_1_3):
            if is_c2s and flow.tls_ch is None:
                flow.tls_ch = parse_tls_client_hello(bytes(flow.buf_c2s))
            elif not is_c2s and flow.tls_sh is None:
                flow.tls_sh = parse_tls_server_hello(bytes(flow.buf_s2c))
        elif flow.protocol == Protocol.SSH_2:
            if is_c2s and flow.ssh_client is None:
                flow.ssh_client = parse_ssh_kexinit(bytes(flow.buf_c2s))
            elif not is_c2s and flow.ssh_server is None:
                flow.ssh_server = parse_ssh_kexinit(bytes(flow.buf_s2c))

    def flush(self) -> Iterator[Flow]:
        """Emit one Flow per tracked 5-tuple and drop internal state."""
        for flow in self._flows.values():
            yield self._to_flow(flow)
        self._flows.clear()

    @staticmethod
    def _to_flow(flow: _FlowState) -> Flow:
        crypto: CryptoPrimitive | None = None
        protocol = flow.protocol
        server_name: str | None = None

        if flow.protocol in (Protocol.TLS_1_2, Protocol.TLS_1_3, Protocol.UNKNOWN) and (
            flow.tls_ch or flow.tls_sh
        ):
            crypto = extract_crypto(flow.tls_ch, flow.tls_sh)
            if flow.tls_ch and flow.tls_ch.server_name:
                server_name = flow.tls_ch.server_name
            protocol = _infer_tls_version(flow.tls_ch, flow.tls_sh)

        if flow.protocol == Protocol.SSH_2 and (flow.ssh_client or flow.ssh_server):
            crypto = ssh_crypto_from_kexinit(flow.ssh_client, flow.ssh_server)

        return Flow(
            src_ip=flow.src_ip,
            dst_ip=flow.dst_ip,
            src_port=flow.src_port,
            dst_port=flow.dst_port,
            transport=flow.transport,
            protocol=protocol,
            first_seen=flow.first_seen,
            last_seen=flow.last_seen,
            bytes_total=flow.bytes_total,
            packets_total=flow.packets_total,
            crypto=crypto,
            server_name=server_name,
        )


def _infer_tls_version(
    ch: TLSClientHello | None, sh: TLSServerHello | None
) -> Protocol:
    """TLS 1.3 is signalled by supported_versions, not record-layer version."""
    if sh and sh.selected_version == 0x0304:
        return Protocol.TLS_1_3
    if ch and 0x0304 in ch.supported_versions:
        return Protocol.TLS_1_3
    return Protocol.TLS_1_2


def _extract_packet_info(
    pkt: Packet,
) -> tuple[str, str, int, int, str, bytes, datetime] | None:
    """Pull 5-tuple, payload bytes, and timestamp from a scapy packet."""
    try:
        from scapy.layers.inet import IP, TCP, UDP
        from scapy.layers.inet6 import IPv6
    except ImportError:
        return None

    if IP in pkt:
        ip = pkt[IP]
        src, dst = ip.src, ip.dst
    elif IPv6 in pkt:
        ip = pkt[IPv6]
        src, dst = ip.src, ip.dst
    else:
        return None

    if TCP in pkt:
        layer = pkt[TCP]
        transport = "tcp"
    elif UDP in pkt:
        layer = pkt[UDP]
        transport = "udp"
    else:
        return None

    payload = bytes(layer.payload) if layer.payload else b""
    ts = _pkt_timestamp(pkt)
    return (src, dst, int(layer.sport), int(layer.dport), transport, payload, ts)


def _pkt_timestamp(pkt: Packet) -> datetime:
    t = getattr(pkt, "time", None)
    if t is None:
        return datetime.now(tz=timezone.utc)
    try:
        return datetime.fromtimestamp(float(t), tz=timezone.utc)
    except (OSError, ValueError, OverflowError):
        return datetime.now(tz=timezone.utc)


def aggregate(packets: Iterable[Packet]) -> list[Flow]:
    """Convenience: one-shot aggregation of a packet iterable."""
    agg = FlowAggregator()
    for pkt in packets:
        agg.ingest(pkt)
    return list(agg.flush())
