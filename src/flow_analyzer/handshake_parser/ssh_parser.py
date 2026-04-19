"""SSH2 KEXINIT parser — RFC 4253 §7.1.

Wire format (after version exchange lines):

  Binary Packet Protocol (RFC 4253 §6):
    uint32  packet_length
    byte    padding_length
    byte[]  payload (packet_length - padding_length - 1 bytes)
    byte[]  random padding
    byte[]  mac (if MAC in place — pre-KEX it's not)

  KEXINIT payload (RFC 4253 §7.1):
    byte      SSH_MSG_KEXINIT (20)
    byte[16]  cookie
    name-list kex_algorithms
    name-list server_host_key_algorithms
    name-list encryption_algorithms_client_to_server
    name-list encryption_algorithms_server_to_client
    name-list mac_algorithms_client_to_server
    name-list mac_algorithms_server_to_client
    name-list compression_algorithms_client_to_server
    name-list compression_algorithms_server_to_client
    name-list languages_client_to_server
    name-list languages_server_to_client
    boolean   first_kex_packet_follows
    uint32    reserved

  name-list = uint32 length + UTF-8 comma-separated ASCII
"""

from __future__ import annotations

from dataclasses import dataclass, field

from src.flow_analyzer.models import CryptoPrimitive

SSH_MSG_KEXINIT = 20

# Known PQC KEX names — OpenSSH 9.x + drafts.
SSH_HYBRID_PQC_KEX = {
    "sntrup761x25519-sha512@openssh.com",
    "mlkem768x25519-sha256",
    "mlkem768nistp256-sha256",
    "mlkem1024nistp384-sha384",
}


@dataclass
class SSHKexInit:
    kex_algorithms: list[str] = field(default_factory=list)
    server_host_key_algorithms: list[str] = field(default_factory=list)
    encryption_algorithms_c2s: list[str] = field(default_factory=list)
    encryption_algorithms_s2c: list[str] = field(default_factory=list)
    mac_algorithms_c2s: list[str] = field(default_factory=list)
    mac_algorithms_s2c: list[str] = field(default_factory=list)


def _strip_version_banner(data: bytes) -> bytes:
    """SSH connections begin with `SSH-2.0-...\\r\\n` lines. Skip past them.

    If the payload doesn't start with a banner (e.g. we captured mid-stream),
    return it unchanged rather than swallowing it.
    """
    if not data.startswith(b"SSH-"):
        return data
    nl = data.find(b"\n")
    if nl < 0:
        return b""
    return data[nl + 1 :]


def _read_name_list(buf: bytes, pos: int) -> tuple[list[str], int]:
    if pos + 4 > len(buf):
        raise ValueError("truncated name-list length")
    n = int.from_bytes(buf[pos : pos + 4], "big")
    pos += 4
    if pos + n > len(buf):
        raise ValueError("truncated name-list body")
    raw = buf[pos : pos + n].decode("ascii", errors="replace")
    pos += n
    if not raw:
        return [], pos
    return raw.split(","), pos


def parse_ssh_kexinit(payload: bytes) -> SSHKexInit | None:
    """Parse SSH_MSG_KEXINIT from raw TCP payload of a flow direction.

    Payload may still include the version banner and one or more Binary Packet
    Protocol frames preceding KEXINIT. Returns None if no KEXINIT found.
    """
    data = _strip_version_banner(payload)
    # Walk BPP packets until we find one whose first payload byte is SSH_MSG_KEXINIT.
    pos = 0
    while pos + 5 <= len(data):
        pkt_len = int.from_bytes(data[pos : pos + 4], "big")
        if pkt_len == 0 or pkt_len > 256 * 1024:
            return None  # not BPP, or junk
        pad_len = data[pos + 4]
        payload_start = pos + 5
        payload_end = pos + 4 + pkt_len - pad_len
        if payload_end > len(data) or payload_end < payload_start:
            return None
        pkt_payload = data[payload_start:payload_end]
        if pkt_payload and pkt_payload[0] == SSH_MSG_KEXINIT:
            return _parse_kexinit_body(pkt_payload)
        pos = pos + 4 + pkt_len

    return None


def _parse_kexinit_body(payload: bytes) -> SSHKexInit | None:
    try:
        if len(payload) < 1 + 16:
            return None
        pos = 1 + 16  # skip msg_type + cookie
        result = SSHKexInit()
        result.kex_algorithms, pos = _read_name_list(payload, pos)
        result.server_host_key_algorithms, pos = _read_name_list(payload, pos)
        result.encryption_algorithms_c2s, pos = _read_name_list(payload, pos)
        result.encryption_algorithms_s2c, pos = _read_name_list(payload, pos)
        result.mac_algorithms_c2s, pos = _read_name_list(payload, pos)
        result.mac_algorithms_s2c, pos = _read_name_list(payload, pos)
        return result
    except (ValueError, IndexError):
        return None


def _pick_first_known_kex(kex_list: list[str]) -> str | None:
    """Pick first hybrid PQC if present; else first non-ext-info algo."""
    for k in kex_list:
        if k in SSH_HYBRID_PQC_KEX:
            return k
    for k in kex_list:
        if not k.startswith("ext-info-"):
            return k
    return kex_list[0] if kex_list else None


def _symmetric_from_ssh_cipher(name: str) -> str | None:
    n = name.lower()
    if "aes256-gcm" in n:
        return "AES-256-GCM"
    if "aes128-gcm" in n:
        return "AES-128-GCM"
    if "chacha20-poly1305" in n:
        return "ChaCha20-Poly1305"
    if "aes256-ctr" in n:
        return "AES-256-CTR"
    if "aes128-ctr" in n:
        return "AES-128-CTR"
    if "3des" in n:
        return "3DES"
    return None


def ssh_crypto_from_kexinit(
    client: SSHKexInit | None,
    server: SSHKexInit | None,
) -> CryptoPrimitive:
    """Estimate negotiated SSH crypto from paired KEXINITs.

    SSH negotiation picks client's first algorithm that the server also lists.
    When we only have one side, fall back to that side's first preference.
    """
    kex: str | None = None
    hostkey: str | None = None
    cipher: str | None = None

    if client and server:
        # Negotiation: first from client that appears in server
        for c in client.kex_algorithms:
            if c in server.kex_algorithms:
                kex = c
                break
        for c in client.server_host_key_algorithms:
            if c in server.server_host_key_algorithms:
                hostkey = c
                break
        for c in client.encryption_algorithms_c2s:
            if c in server.encryption_algorithms_c2s:
                cipher = c
                break
    else:
        side = client or server
        if side:
            kex = _pick_first_known_kex(side.kex_algorithms)
            hostkey = side.server_host_key_algorithms[0] if side.server_host_key_algorithms else None
            cipher = side.encryption_algorithms_c2s[0] if side.encryption_algorithms_c2s else None

    is_hybrid = kex in SSH_HYBRID_PQC_KEX if kex else False

    return CryptoPrimitive(
        kex_algorithm=kex,
        signature_algorithm=hostkey,
        symmetric_cipher=_symmetric_from_ssh_cipher(cipher) if cipher else None,
        hash_algorithm=None,
        is_hybrid_pqc=is_hybrid,
        is_pure_pqc=False,
        raw_cipher_suite=cipher,
    )
