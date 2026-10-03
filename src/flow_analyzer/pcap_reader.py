"""PCAP / pcapng streaming reader using dpkt.

Design goals:
- Stream packets, never load the whole capture into memory.
- Survive truncated captures (tcpdump Ctrl-C leaves dangling records).
- Support Ethernet (DLT=1), Linux cooked v1/v2 (DLT=113/276), raw IP (DLT=12/14/101/228/229).

File framing (pcap records, pcapng blocks) is read here; dpkt only decodes the
link/network/transport headers. dpkt's own pcapng reader applies the first
interface's link type to every packet, which breaks multi-interface captures.

dpkt (BSD-3-Clause) is an optional dependency — install via `pip install ".[flow]"`.
"""

from __future__ import annotations

import socket
import struct
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import BinaryIO

SUPPORTED_LINK_TYPES = {
    0,    # BSD loopback / utun (DLT_NULL, host byte order AF header)
    108,  # OpenBSD loopback (DLT_LOOP, network byte order AF header)
    1,    # Ethernet
    12,   # Raw IP (BSD)
    14,   # Raw IP (older)
    101,  # Raw IP (LINKTYPE_RAW)
    113,  # Linux cooked v1 (SLL)
    276,  # Linux cooked v2 (SLL2)
    228,  # IPv4 raw
    229,  # IPv6 raw
}

# A record or block larger than this is treated as corruption, not data.
# Max snaplen in libpcap is 262144; pcapng blocks add a few dozen bytes.
_MAX_RECORD = 512 * 1024

_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
_PCAPNG_SHB = b"\x0a\x0d\x0d\x0a"


class InvalidPCAPError(ValueError):
    """File does not look like a valid PCAP / pcapng."""


class InvalidFilterError(ValueError):
    """BPF filter string is malformed or too long for the built-in matcher."""


# The matcher recurses once per and/or, so bound the input.
_MAX_FILTER_LEN = 256
# The built-in matcher only understands this subset of BPF. Anything else
# (not, src/dst, net, parentheses, hostnames) used to be silently ignored or
# mis-grouped — 'not port 22' matched everything — so reject it up front.
_FILTER_WORDS = {"tcp", "udp", "port", "host", "and", "or"}


def validate_bpf(bpf_filter: str) -> None:
    """Reject filters the built-in matcher can't evaluate faithfully."""
    import ipaddress
    import re

    if len(bpf_filter) > _MAX_FILTER_LEN:
        raise InvalidFilterError(f"BPF filter longer than {_MAX_FILTER_LEN} characters")
    if "(" in bpf_filter or ")" in bpf_filter:
        raise InvalidFilterError("parentheses are not supported; use 'and'/'or' only")
    tokens = bpf_filter.lower().split()
    for prev, tok in zip([""] + tokens, tokens, strict=False):
        if prev == "port":
            # ASCII only: '²'.isdigit() is True but int('²') raises.
            if not re.fullmatch(r"[0-9]{1,5}", tok) or int(tok) > 65535:
                raise InvalidFilterError(f"BPF port must be a number 0-65535, got {tok!r}")
        elif prev == "host":
            try:
                ipaddress.ip_address(tok)
            except ValueError:
                raise InvalidFilterError(f"BPF host must be an IP address, got {tok!r}") from None
        elif tok not in _FILTER_WORDS:
            raise InvalidFilterError(
                f"unsupported BPF term {tok!r}; supported: tcp, udp, port N, host IP, and, or"
            )


class UnsupportedLinkTypeError(ValueError):
    """PCAP link-layer type is not handled by the parser."""

    def __init__(self, linktype: int) -> None:
        super().__init__(f"unsupported PCAP link type: {linktype}")
        self.linktype = linktype


@dataclass(frozen=True, slots=True)
class Packet:
    """One captured frame, decoded down to the transport layer where possible.

    Fields past ``timestamp`` stay ``None`` when the frame is not IP, or not
    TCP/UDP (ARP, ICMP, non-first IP fragments, undecodable bytes).
    """

    timestamp: datetime | None
    src: str | None = None
    dst: str | None = None
    transport: str | None = None  # "tcp" | "udp"
    sport: int = 0
    dport: int = 0
    payload: bytes = b""


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
        _PCAPNG_SHB,
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
        :class:`Packet` records, one per captured frame.

    Raises:
        InvalidPCAPError: magic bytes don't match any known PCAP format.
        InvalidFilterError: bpf_filter is malformed (see :func:`validate_bpf`).
        UnsupportedLinkTypeError: link type is not in SUPPORTED_LINK_TYPES.
        ModuleNotFoundError: dpkt not installed.
    """
    path = Path(path)
    if bpf_filter:
        validate_bpf(bpf_filter)
    _check_magic(path)

    try:
        import dpkt  # noqa: F401
    except ImportError as exc:
        raise ModuleNotFoundError(
            "dpkt is required for PCAP parsing. Install with: "
            'pip install ".[flow]"'
        ) from exc

    fh = path.open("rb")
    link_state = {"supported": False, "unsupported": None}
    try:
        if fh.read(4) == _PCAPNG_SHB:
            fh.seek(0)
            frames = _iter_pcapng(fh, path, link_state)
        else:
            fh.seek(0)
            frames = _iter_pcap(fh, path)

        for linktype, ts, frame in _guard_framing(frames, path):
            pkt = _decode(linktype, frame, ts)
            # Without libpcap there is no BPF compiler; apply the post-hoc
            # matcher inline so we stay streaming — buffering the whole
            # capture first turns an attacker-supplied filter into a
            # memory-exhaustion vector on large captures.
            if bpf_filter and not _match_bpf(pkt, bpf_filter):
                continue
            yield pkt
        # pcapng: classic pcap raises on an unsupported link type up front;
        # match that instead of returning a silently empty capture.
        if link_state["unsupported"] is not None and not link_state["supported"]:
            raise UnsupportedLinkTypeError(link_state["unsupported"])
    finally:
        fh.close()


def _guard_framing(frames: Iterator, path: Path) -> Iterator:
    """Turn any parsing slip in the framing code into InvalidPCAPError.

    The readers bounds-check what they know about; this catches what they
    don't, so a hostile capture is a 400 at worst, never a 500.
    """
    try:
        yield from frames
    except (struct.error, IndexError, ValueError, OverflowError) as exc:
        if isinstance(exc, (InvalidPCAPError, UnsupportedLinkTypeError)):
            raise
        raise InvalidPCAPError(f"{path}: malformed capture ({type(exc).__name__})") from exc


def _iter_pcap(fh: BinaryIO, path: Path) -> Iterator[tuple[int, datetime, bytes]]:
    header = fh.read(24)
    if len(header) < 24:
        raise InvalidPCAPError(f"{path}: truncated PCAP header")
    magic = header[:4]
    endian = "<" if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"
    nano = magic in (b"\xa1\xb2\x3c\x4d", b"\x4d\x3c\xb2\xa1")
    # Upper bits of the link-type field carry FCS metadata, not the type.
    linktype = struct.unpack(endian + "I", header[20:24])[0] & 0xFFFF
    if linktype not in SUPPORTED_LINK_TYPES:
        raise UnsupportedLinkTypeError(linktype)

    while True:
        rec = fh.read(16)
        if len(rec) < 16:
            return  # clean EOF or a record header cut off mid-way
        sec, frac, caplen, _origlen = struct.unpack(endian + "IIII", rec)
        if caplen > _MAX_RECORD:
            return  # corrupt length — nothing after this point is trustworthy
        frame = fh.read(caplen)
        usec = round(frac / 1000) if nano else frac
        yield linktype, _EPOCH + timedelta(seconds=sec, microseconds=usec), frame


@dataclass
class _Interface:
    linktype: int
    snaplen: int
    tsresol: int = 1_000_000  # ticks per second
    tsoffset: int = 0


def _iter_pcapng(
    fh: BinaryIO, path: Path, link_state: dict | None = None
) -> Iterator[tuple[int, datetime | None, bytes]]:
    link_state = link_state if link_state is not None else {}
    endian: str | None = None
    interfaces: list[_Interface] = []

    while True:
        head = fh.read(8)
        if len(head) < 8:
            if endian is None:
                raise InvalidPCAPError(f"{path}: truncated pcapng section header")
            return
        if head[:4] == _PCAPNG_SHB:
            # Section header: byte-order magic decides endianness for the section.
            first_section = endian is None
            bom = fh.read(4)
            if bom == b"\x4d\x3c\x2b\x1a":
                endian = "<"
            elif bom == b"\x1a\x2b\x3c\x4d":
                endian = ">"
            elif first_section:
                raise InvalidPCAPError(f"{path}: bad pcapng byte-order magic")
            else:
                return
            blk_len = struct.unpack(endian + "I", head[4:8])[0]
            if blk_len < 28 or blk_len % 4 or blk_len > _MAX_RECORD:
                if first_section:
                    raise InvalidPCAPError(f"{path}: bad pcapng section header")
                return
            fh.read(blk_len - 12)
            interfaces = []  # interface IDs are scoped to their section
            continue

        if endian is None:
            raise InvalidPCAPError(f"{path}: pcapng does not start with a section header")
        blk_type, blk_len = struct.unpack(endian + "II", head)
        if blk_len < 12 or blk_len % 4:
            return
        if blk_len > _MAX_RECORD:
            if blk_type in (2, 3, 6):
                return  # a packet block this large is corruption
            # Large non-packet blocks are legitimate (decryption secrets from
            # `editcap --inject-secrets`, name resolution): skip, don't read.
            fh.seek(blk_len - 8, 1)
            continue
        body = fh.read(blk_len - 8)
        if len(body) < blk_len - 8:
            return  # truncated final block
        body = body[:-4]  # trailing copy of the block length

        if blk_type == 1:  # Interface Description Block
            if len(body) < 8:
                return
            linktype, _reserved, snaplen = struct.unpack(endian + "HHI", body[:8])
            iface = _Interface(linktype=linktype, snaplen=snaplen)
            _parse_idb_options(iface, body[8:], endian)
            interfaces.append(iface)
            if linktype in SUPPORTED_LINK_TYPES:
                link_state["supported"] = True
            elif link_state.get("unsupported") is None:
                link_state["unsupported"] = linktype
        elif blk_type == 6:  # Enhanced Packet Block
            if len(body) < 20:
                return
            iface_id, ts_high, ts_low, caplen, _origlen = struct.unpack(endian + "IIIII", body[:20])
            if iface_id >= len(interfaces):
                continue
            iface = interfaces[iface_id]
            ts = _pcapng_time(iface, (ts_high << 32) | ts_low)
            yield iface.linktype, ts, body[20:20 + caplen]
        elif blk_type == 3:  # Simple Packet Block — interface 0, no timestamp
            if not interfaces or len(body) < 4:
                continue
            origlen = struct.unpack(endian + "I", body[:4])[0]
            iface = interfaces[0]
            caplen = min(origlen, iface.snaplen) if iface.snaplen else origlen
            yield iface.linktype, None, body[4:4 + caplen]
        elif blk_type == 2:  # obsolete Packet Block
            if len(body) < 20:
                return
            iface_id, _drops, ts_high, ts_low, caplen, _origlen = struct.unpack(
                endian + "HHIIII", body[:20]
            )
            if iface_id >= len(interfaces):
                continue
            iface = interfaces[iface_id]
            ts = _pcapng_time(iface, (ts_high << 32) | ts_low)
            yield iface.linktype, ts, body[20:20 + caplen]
        # every other block type (name resolution, statistics, …) is skipped


def _parse_idb_options(iface: _Interface, opts: bytes, endian: str) -> None:
    pos = 0
    while pos + 4 <= len(opts):
        code, length = struct.unpack(endian + "HH", opts[pos:pos + 4])
        if pos + 4 + length > len(opts):
            return  # option claims more bytes than the block has
        value = opts[pos + 4:pos + 4 + length]
        if code == 0:
            return
        if code == 9 and length >= 1:  # if_tsresol
            exp = value[0] & 0x7F
            iface.tsresol = (2 ** exp) if value[0] & 0x80 else (10 ** exp)
        elif code == 14 and length >= 8:  # if_tsoffset, seconds
            iface.tsoffset = struct.unpack(endian + "q", value[:8])[0]
        pos += 4 + length + (-length % 4)


def _pcapng_time(iface: _Interface, ticks: int) -> datetime | None:
    sec, frac = divmod(ticks, iface.tsresol)
    usec = round(frac * 1_000_000 / iface.tsresol)
    try:
        return _EPOCH + timedelta(seconds=sec + iface.tsoffset, microseconds=usec)
    except OverflowError:
        return None


def _raw_ip(frame: bytes):
    import dpkt

    if not frame:
        return None
    version = frame[0] >> 4
    if version == 4:
        return dpkt.ip.IP(frame)
    if version == 6:
        return dpkt.ip6.IP6(frame)
    return None


def _decapsulate(l3):
    """Strip one tunnel layer so the inner TLS/SSH flow is analysed.

    Covers IP-in-IP, 6in4, GRE (incl. transparent Ethernet and ERSPAN II/III,
    the usual feed from a remote SPAN) and VXLAN. Anything else, or a tunnel
    whose inner packet doesn't decode, is returned unchanged.
    """
    import dpkt

    inner = l3.data
    candidate = None
    if isinstance(inner, (dpkt.ip.IP, dpkt.ip6.IP6)):
        candidate = inner
    elif isinstance(inner, dpkt.gre.GRE):
        payload = inner.data
        if isinstance(payload, (dpkt.ip.IP, dpkt.ip6.IP6)):
            candidate = payload
        else:
            raw = bytes(payload)
            skip = {0x6558: 0, 0x88BE: 8, 0x22EB: 12}.get(inner.p)
            if skip is not None:
                candidate = dpkt.ethernet.Ethernet(raw[skip:]).data
    elif isinstance(inner, dpkt.udp.UDP) and inner.dport == 4789 and len(inner.data) > 8:
        candidate = dpkt.ethernet.Ethernet(bytes(inner.data)[8:]).data
    if isinstance(candidate, (dpkt.ip.IP, dpkt.ip6.IP6)):
        return candidate
    return l3


def _decode(linktype: int, frame: bytes, ts: datetime | None) -> Packet:
    """Decode a link-layer frame down to TCP/UDP. Never raises on bad bytes."""
    import dpkt

    try:
        if linktype == 1:
            l3 = dpkt.ethernet.Ethernet(frame).data
        elif linktype == 113:
            l3 = dpkt.sll.SLL(frame).data
        elif linktype == 276:
            l3 = dpkt.sll2.SLL2(frame).data
        elif linktype == 228:
            l3 = dpkt.ip.IP(frame)
        elif linktype == 229:
            l3 = dpkt.ip6.IP6(frame)
        elif linktype in (12, 14, 101):
            l3 = _raw_ip(frame)
        elif linktype in (0, 108):
            # 4-byte address-family header (byte order varies by OS); the IP
            # version nibble that follows is the reliable signal.
            l3 = _raw_ip(frame[4:])
        else:
            return Packet(ts)
        if l3 is not None:
            l3 = _decapsulate(l3)
    except Exception:  # capture bytes are untrusted; any decode failure is "not IP"
        return Packet(ts)

    if isinstance(l3, dpkt.ip.IP):
        family = socket.AF_INET
    elif isinstance(l3, dpkt.ip6.IP6):
        family = socket.AF_INET6
    else:
        return Packet(ts)
    try:
        src = socket.inet_ntop(family, l3.src)
        dst = socket.inet_ntop(family, l3.dst)
    except (ValueError, OSError):
        return Packet(ts)

    # dpkt leaves non-first fragments (and undecodable segments) as raw bytes.
    l4 = l3.data
    if isinstance(l4, dpkt.tcp.TCP):
        transport = "tcp"
    elif isinstance(l4, dpkt.udp.UDP):
        transport = "udp"
    else:
        return Packet(ts, src=src, dst=dst)

    # IP/IPv6 length already trimmed link-layer padding off the payload.
    return Packet(
        ts,
        src=src,
        dst=dst,
        transport=transport,
        sport=int(l4.sport),
        dport=int(l4.dport),
        payload=bytes(l4.data),
    )


def _match_bpf(pkt: Packet, bpf_filter: str) -> bool:
    """Best-effort BPF matching without libpcap.

    We only support a narrow set of predicates that cover the common case
    for flow analysis: `tcp`, `udp`, `port <n>`, `tcp port <n>`, `udp port <n>`,
    `host <ip>`, and conjunctions with `and` / `or`. Anything else falls back
    to accepting the packet.
    """
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
            return pkt.transport == "tcp"
        if toks == ["udp"]:
            return pkt.transport == "udp"
        if len(toks) == 2 and toks[0] == "port":
            return _port_match(pkt, int(toks[1]))
        if len(toks) == 3 and toks[0] in ("tcp", "udp") and toks[1] == "port":
            return pkt.transport == toks[0] and _port_match(pkt, int(toks[2]))
        if len(toks) == 2 and toks[0] == "host":
            return _host_match(pkt, toks[1])
        return True

    return eval_tokens(tokens)


def _port_match(pkt: Packet, port: int) -> bool:
    if pkt.transport is None:
        return False
    return pkt.sport == port or pkt.dport == port


def _host_match(pkt: Packet, host: str) -> bool:
    if pkt.src is None:
        return False
    import ipaddress

    want = ipaddress.ip_address(host)  # validated by validate_bpf
    return any(ipaddress.ip_address(a) == want for a in (pkt.src, pkt.dst) if a)
