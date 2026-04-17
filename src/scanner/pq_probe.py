"""Active probe for post-quantum TLS 1.3 key exchange groups.

Speaks TLS 1.3 ClientHello at the byte level so we can probe for
post-quantum hybrid groups regardless of the local Python/OpenSSL
build (stdlib ssl on Python <3.13 / OpenSSL <3.5 cannot offer
X25519MLKEM768 by itself).

Strategy: send one ClientHello offering both the hybrid group and a
classical control, with key_share entries for both. The server's
ServerHello (or HelloRetryRequest) reveals which group it picked.

Currently probes:
- X25519MLKEM768 (IANA 0x11EC) -- the hybrid shipping at Cloudflare,
  Google, AWS as of 2025.
"""

from __future__ import annotations

import logging
import os
import socket
import struct
from dataclasses import dataclass

logger = logging.getLogger(__name__)

GROUP_SECP256R1 = 0x0017
GROUP_X25519 = 0x001D
GROUP_SECP256R1_MLKEM768 = 0x11EB
GROUP_X25519_MLKEM768 = 0x11EC

GROUP_NAMES: dict[int, str] = {
    GROUP_SECP256R1: "secp256r1",
    GROUP_X25519: "X25519",
    GROUP_SECP256R1_MLKEM768: "SecP256r1MLKEM768",
    GROUP_X25519_MLKEM768: "X25519MLKEM768",
}

# HelloRetryRequest is a ServerHello whose random field equals
# SHA-256("HelloRetryRequest"), per RFC 8446 section 4.1.3.
HRR_RANDOM = bytes.fromhex(
    "cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c"
)

# Dummy key_share sizes (server only validates size during ClientHello parse;
# semantic key-exchange happens after ServerHello reveals the selection).
KS_LEN_X25519 = 32
KS_LEN_X25519_MLKEM768 = 1216  # ML-KEM-768 encaps key (1184) || X25519 (32)


@dataclass
class ProbeResult:
    """Outcome of a single PQ-group probe."""

    selected_group: str | None
    supported: bool
    error: str | None = None


def probe_x25519mlkem768(
    host: str, port: int = 443, timeout: float = 5.0
) -> ProbeResult:
    """Probe whether the server picks X25519MLKEM768 when offered.

    Returns supported=True iff the server's ServerHello (or HRR) selects
    group 0x11EC. A False with no error means the server preferred the
    classical control instead of the hybrid -- it does not necessarily
    prove the server cannot do MLKEM, only that it did not prefer it
    here.
    """
    # Stage 1: offer hybrid AND classical X25519 in supported_groups but
    # only send an X25519 key_share. A server that prefers the hybrid
    # responds with HelloRetryRequest naming X25519MLKEM768. We avoid
    # sending a dummy 1216-byte MLKEM key_share because AWS / Google /
    # Facebook / Fastly / Meta eagerly validate it and close the
    # connection.
    stage1 = _probe_one(
        host, port, timeout,
        target=GROUP_X25519_MLKEM768,
        groups=[GROUP_X25519_MLKEM768, GROUP_X25519],
        key_shares=[(GROUP_X25519, os.urandom(KS_LEN_X25519))],
    )
    if stage1.supported or stage1.error:
        return stage1

    # Stage 2: server picked X25519 in stage 1 -- it might still support
    # the hybrid but prefer to skip the HRR round-trip. Re-probe with
    # ONLY the hybrid in supported_groups and empty key_shares; the
    # server must either HRR with MLKEM or alert.
    stage2 = _probe_one(
        host, port, timeout,
        target=GROUP_X25519_MLKEM768,
        groups=[GROUP_X25519_MLKEM768],
        key_shares=[],
    )
    if stage2.supported:
        return stage2
    return stage1  # surface stage-1 result (selected=X25519) on negative


def _probe_one(
    host: str,
    port: int,
    timeout: float,
    target: int,
    groups: list[int],
    key_shares: list[tuple[int, bytes]],
) -> ProbeResult:
    ch = _build_client_hello(host, groups=groups, key_shares=key_shares)
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.sendall(ch)
            record = _read_record(sock)
    except (socket.timeout, OSError) as exc:
        return ProbeResult(None, False, error=str(exc))

    if not record:
        return ProbeResult(None, False, error="empty response")
    selected = _parse_server_hello_selected_group(record)
    if selected is None:
        if record and record[0] == 0x15:
            return ProbeResult(None, False, error="server alert (no common params)")
        return ProbeResult(None, False, error="failed to parse ServerHello")
    name = GROUP_NAMES.get(selected, f"unknown(0x{selected:04x})")
    return ProbeResult(name, selected == target)


def _build_client_hello(
    host: str, groups: list[int], key_shares: list[tuple[int, bytes]]
) -> bytes:
    # Order matches what mainstream browsers send. Several large CDNs
    # (Google Front End, AWS, Facebook, Fastly, Meta) reject ClientHellos
    # missing ALPN / status_request / psk_key_exchange_modes / ec_point_formats
    # and respond with a handshake_failure alert.
    extensions = (
        _ext_server_name(host)
        + _ext_ec_point_formats()
        + _ext_supported_groups(groups)
        + _ext_signature_algorithms()
        + _ext_alpn()
        + _ext_status_request()
        + _ext_supported_versions()
        + _ext_psk_key_exchange_modes()
        + _ext_key_share(key_shares)
    )
    extensions_block = struct.pack(">H", len(extensions)) + extensions

    legacy_version = b"\x03\x03"
    random_bytes = os.urandom(32)
    session_id = os.urandom(32)
    session_id_block = struct.pack(">B", len(session_id)) + session_id
    cipher_suites = b"\x13\x01\x13\x02\x13\x03"
    cipher_block = struct.pack(">H", len(cipher_suites)) + cipher_suites
    compression = b"\x01\x00"

    body = (
        legacy_version
        + random_bytes
        + session_id_block
        + cipher_block
        + compression
        + extensions_block
    )

    # Handshake header: type (1) + 24-bit length + body
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    # TLS record header: type (1) + version (2) + length (2)
    return struct.pack(">BHH", 0x16, 0x0301, len(handshake)) + handshake


def _ext_server_name(host: str) -> bytes:
    name = host.encode("ascii")
    entry = b"\x00" + struct.pack(">H", len(name)) + name
    sni_list = struct.pack(">H", len(entry)) + entry
    return struct.pack(">HH", 0x0000, len(sni_list)) + sni_list


def _ext_supported_versions() -> bytes:
    versions = b"\x03\x04"
    payload = struct.pack(">B", len(versions)) + versions
    return struct.pack(">HH", 0x002B, len(payload)) + payload


def _ext_supported_groups(groups: list[int]) -> bytes:
    g_bytes = b"".join(struct.pack(">H", g) for g in groups)
    payload = struct.pack(">H", len(g_bytes)) + g_bytes
    return struct.pack(">HH", 0x000A, len(payload)) + payload


def _ext_signature_algorithms() -> bytes:
    # rsa_pss_rsae_sha256, ecdsa_secp256r1_sha256, ed25519
    sigs = b"\x08\x04\x04\x03\x08\x07"
    payload = struct.pack(">H", len(sigs)) + sigs
    return struct.pack(">HH", 0x000D, len(payload)) + payload


def _ext_key_share(key_shares: list[tuple[int, bytes]]) -> bytes:
    entries = b""
    for group, key in key_shares:
        entries += struct.pack(">HH", group, len(key)) + key
    payload = struct.pack(">H", len(entries)) + entries
    return struct.pack(">HH", 0x0033, len(payload)) + payload


def _ext_alpn() -> bytes:
    protos = b"\x02h2" + b"\x08http/1.1"
    payload = struct.pack(">H", len(protos)) + protos
    return struct.pack(">HH", 0x0010, len(payload)) + payload


def _ext_status_request() -> bytes:
    # CertificateStatusType=ocsp(1), empty responder_id_list, empty extensions
    body = b"\x01" + b"\x00\x00" + b"\x00\x00"
    return struct.pack(">HH", 0x0005, len(body)) + body


def _ext_psk_key_exchange_modes() -> bytes:
    # PSK with (EC)DHE
    body = b"\x01\x01"
    return struct.pack(">HH", 0x002D, len(body)) + body


def _ext_ec_point_formats() -> bytes:
    # uncompressed (legacy TLS 1.2 hint; some servers still gate on it)
    body = b"\x01\x00"
    return struct.pack(">HH", 0x000B, len(body)) + body


def _read_record(sock: socket.socket) -> bytes:
    header = _recv_n(sock, 5)
    if len(header) < 5:
        return b""
    length = int.from_bytes(header[3:5], "big")
    body = _recv_n(sock, length)
    return header + body


def _recv_n(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            break
        buf += chunk
    return buf


def _parse_server_hello_selected_group(record: bytes) -> int | None:
    """Extract the selected supported_group from a ServerHello/HRR.

    Returns the group codepoint, or None if the record is not a parseable
    ServerHello (e.g. an Alert, malformed bytes, missing key_share ext).
    """
    if len(record) < 9 or record[0] != 0x16 or record[5] != 0x02:
        return None
    body_len = int.from_bytes(record[6:9], "big")
    body = record[9:9 + body_len]
    if len(body) < 2 + 32 + 1:
        return None
    is_hrr = body[2:34] == HRR_RANDOM
    sid_len = body[34]
    cursor = 35 + sid_len
    if len(body) < cursor + 2 + 1 + 2:
        return None
    cursor += 2  # cipher_suite
    cursor += 1  # compression_method
    ext_total = int.from_bytes(body[cursor:cursor + 2], "big")
    cursor += 2
    end = min(cursor + ext_total, len(body))
    while cursor + 4 <= end:
        ext_type = int.from_bytes(body[cursor:cursor + 2], "big")
        ext_len = int.from_bytes(body[cursor + 2:cursor + 4], "big")
        ext_data = body[cursor + 4:cursor + 4 + ext_len]
        cursor += 4 + ext_len
        if ext_type == 0x0033 and len(ext_data) >= 2:
            # Both ServerHello.key_share and HRR.key_share start with
            # the selected group's 2-byte codepoint.
            return int.from_bytes(ext_data[:2], "big")
    if is_hrr:
        # Older HRRs may not carry key_share if the group is signaled
        # only via supported_versions; treat as parse failure.
        return None
    return None
