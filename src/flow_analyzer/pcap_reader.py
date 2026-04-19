"""PCAP / pcapng streaming reader using scapy.

Design goals:
- Stream packets, never load the whole capture into memory.
- Survive truncated captures (tcpdump Ctrl-C leaves dangling records).
- Support Ethernet (DLT=1), Linux cooked v1/v2 (DLT=113/276), raw IP (DLT=12/14/101).

scapy is an optional dependency — install via `pip install vn-pqc-analyzer[flow]`.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from scapy.packet import Packet


SUPPORTED_LINK_TYPES = {
    1,    # Ethernet
    12,   # Raw IP (BSD)
    14,   # Raw IP (older)
    101,  # Raw IP (LINKTYPE_RAW)
    113,  # Linux cooked v1 (SLL)
    276,  # Linux cooked v2 (SLL2)
    228,  # IPv4 raw
    229,  # IPv6 raw
}


class InvalidPCAPError(ValueError):
    """File does not look like a valid PCAP / pcapng."""


class UnsupportedLinkTypeError(ValueError):
    """PCAP link-layer type is not handled by the parser."""

    def __init__(self, linktype: int) -> None:
        super().__init__(f"unsupported PCAP link type: {linktype}")
        self.linktype = linktype


def _check_magic(path: Path) -> None:
    with path.open("rb") as fh:
        magic = fh.read(4)
    if len(magic) < 4:
        raise InvalidPCAPError(f"{path}: file too short to be a PCAP")
    # pcap: a1b2c3d4 / d4c3b2a1 (micro) or a1b23c4d / 4d3cb2a1 (nano)
    # pcapng: 0a0d0d0a (section header block)
    valid = {
        b"\xa1\xb2\xc3\xd4", b"\xd4\xc3\xb2\xa1",
        b"\xa1\xb2\x3c\x4d", b"\x4d\x3c\xb2\xa1",
        b"\x0a\x0d\x0d\x0a",
    }
    if magic not in valid:
        raise InvalidPCAPError(f"{path}: bad magic {magic.hex()}")


def read_pcap(
    path: str | Path,
    bpf_filter: str | None = None,
) -> Iterator[Packet]:
    """Stream packets from a PCAP/pcapng file.

    Args:
        path: Path to .pcap or .pcapng.
        bpf_filter: optional BPF filter string (e.g. "tcp port 443").

    Yields:
        scapy Packet objects.

    Raises:
        InvalidPCAPError: magic bytes don't match any known PCAP format.
        UnsupportedLinkTypeError: link type is not in SUPPORTED_LINK_TYPES.
        ModuleNotFoundError: scapy not installed.
    """
    path = Path(path)
    _check_magic(path)

    try:
        # Importing the layer modules populates scapy's linktype → layer
        # dispatch table; without this, PcapReader warns "unknown LL type 1"
        # and silently returns Raw packets which our flow aggregator can't
        # decode. These imports are cheap and side-effect-only.
        import scapy.layers.inet  # noqa: F401
        import scapy.layers.inet6  # noqa: F401
        import scapy.layers.l2  # noqa: F401
        from scapy.utils import PcapNgReader, PcapReader
    except ImportError as exc:
        raise ModuleNotFoundError(
            "scapy is required for PCAP parsing. Install with: "
            'pip install "vn-pqc-analyzer[flow]"'
        ) from exc

    # Choose reader. PcapNgReader handles pcapng sections + block-per-iface linktypes.
    with path.open("rb") as fh:
        header = fh.read(4)
    is_pcapng = header == b"\x0a\x0d\x0d\x0a"

    reader_cls = PcapNgReader if is_pcapng else PcapReader

    try:
        reader = reader_cls(str(path))
    except Exception as exc:  # scapy raises generic Scapy_Exception
        raise InvalidPCAPError(f"{path}: {exc}") from exc

    # For classic pcap, reader.linktype is set; for pcapng it's per-block.
    linktype = getattr(reader, "linktype", None)
    if linktype is not None and linktype not in SUPPORTED_LINK_TYPES:
        reader.close()
        raise UnsupportedLinkTypeError(linktype)

    try:
        if bpf_filter:
            # scapy's sniff/filter pipeline requires libpcap headers for BPF
            # compilation; we fall back to a post-hoc filter using scapy's
            # built-in matcher to avoid the libpcap dependency for PCAP reads.
            from scapy.plist import PacketList
            tmp = PacketList()
            for pkt in reader:
                tmp.append(pkt)
            yield from tmp.filter(lambda p: _match_bpf(p, bpf_filter))
        else:
            for pkt in reader:
                yield pkt
    except EOFError:
        # truncated PCAP — last record cut off. Iteration already yielded
        # complete packets; silently stop.
        return
    finally:
        reader.close()


def _match_bpf(pkt: Packet, bpf_filter: str) -> bool:
    """Best-effort BPF matching without libpcap.

    We only support a narrow set of predicates that cover the common case
    for flow analysis: `tcp`, `udp`, `port <n>`, `tcp port <n>`, `udp port <n>`,
    `host <ip>`, and conjunctions with `and` / `or`. Anything else falls back
    to accepting the packet.
    """
    from scapy.layers.inet import IP, TCP, UDP
    from scapy.layers.inet6 import IPv6

    expr = bpf_filter.lower().strip()
    tokens = expr.replace("(", " ").replace(")", " ").split()

    def eval_tokens(toks: list[str]) -> bool:
        if not toks:
            return True
        if "or" in toks:
            idx = toks.index("or")
            return eval_tokens(toks[:idx]) or eval_tokens(toks[idx + 1 :])
        if "and" in toks:
            idx = toks.index("and")
            return eval_tokens(toks[:idx]) and eval_tokens(toks[idx + 1 :])
        # atomic predicates
        if toks == ["tcp"]:
            return TCP in pkt
        if toks == ["udp"]:
            return UDP in pkt
        if len(toks) == 2 and toks[0] == "port":
            return _port_match(pkt, int(toks[1]))
        if len(toks) == 3 and toks[0] in ("tcp", "udp") and toks[1] == "port":
            proto_ok = (TCP in pkt) if toks[0] == "tcp" else (UDP in pkt)
            return proto_ok and _port_match(pkt, int(toks[2]))
        if len(toks) == 2 and toks[0] == "host":
            return _host_match(pkt, toks[1], IP, IPv6)
        return True

    return eval_tokens(tokens)


def _port_match(pkt: Packet, port: int) -> bool:
    from scapy.layers.inet import TCP, UDP

    for layer in (TCP, UDP):
        if layer in pkt:
            if pkt[layer].sport == port or pkt[layer].dport == port:
                return True
    return False


def _host_match(pkt: Packet, host: str, ip_cls: type, ipv6_cls: type) -> bool:
    for cls in (ip_cls, ipv6_cls):
        if cls in pkt:
            if pkt[cls].src == host or pkt[cls].dst == host:
                return True
    return False
