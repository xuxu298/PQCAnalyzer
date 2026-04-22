"""TLS 1.2 / 1.3 ClientHello + ServerHello parser.

Parses raw TCP payload bytes per RFC 5246 (TLS 1.2) and RFC 8446 (TLS 1.3)
without relying on scapy's TLS layer (which is heavy and optional).

Scope:
- ClientHello: cipher_suites, SNI, supported_groups, signature_algorithms, key_share
- ServerHello: selected cipher_suite, selected key_share group
- Hybrid PQC detection via named-group codepoints

Out of scope (by design):
- Handshake decryption (TLS 1.3 post-ClientHello is encrypted anyway)
- Full X.509 validation — cert parsing is the scanner's job
"""

from __future__ import annotations

from dataclasses import dataclass, field

from src.flow_analyzer.models import CryptoPrimitive

TLS_CONTENT_HANDSHAKE = 22
HS_CLIENT_HELLO = 1
HS_SERVER_HELLO = 2

# Extension types (RFC 8446 §4.2, IANA TLS ExtensionType registry)
EXT_SERVER_NAME = 0x0000
EXT_SUPPORTED_GROUPS = 0x000A
EXT_SIGNATURE_ALGORITHMS = 0x000D
EXT_SUPPORTED_VERSIONS = 0x002B
EXT_KEY_SHARE = 0x0033

# Named groups — IANA TLS Supported Groups registry + OQS / Chrome / Cloudflare draft codepoints.
# Keep this table narrow and explicit; unknown codepoints fall through to hex format.
NAMED_GROUPS: dict[int, str] = {
    # Classical
    0x0017: "secp256r1",
    0x0018: "secp384r1",
    0x0019: "secp521r1",
    0x001D: "x25519",
    0x001E: "x448",
    0x0100: "ffdhe2048",
    0x0101: "ffdhe3072",
    0x0102: "ffdhe4096",
    # Hybrid / PQC — IANA TLS Supported Groups registry + Chrome draft codepoints.
    # References: draft-kwiatkowski-tls-ecdhe-mlkem, IANA TLS Parameters 4587/4588,
    # Cloudflare blog 2023-09 + 2024-09, Chrome platform-status.
    0x11EB: "SecP256r1MLKEM768",         # IANA 4587
    0x11EC: "X25519MLKEM768",            # IANA 4588, post-FIPS 203
    0x6399: "SecP256r1Kyber768Draft00",  # Chrome pre-standardization draft
    0x639A: "SecP384r1Kyber768Draft00",
}

HYBRID_PQC_GROUPS = {
    "X25519MLKEM768",
    "SecP256r1MLKEM768",
    "X25519Kyber768Draft00",
    "SecP256r1Kyber768Draft00",
    "SecP384r1Kyber768Draft00",
}

PURE_PQC_GROUPS = {
    "MLKEM512",
    "MLKEM768",
    "MLKEM1024",
}

# Cipher suites — minimal decode, enough to get a human name + symmetric cipher.
# Full IANA table is huge; we map the common ones. Unknown codes → hex string.
CIPHER_SUITES: dict[int, str] = {
    0x1301: "TLS_AES_128_GCM_SHA256",
    0x1302: "TLS_AES_256_GCM_SHA384",
    0x1303: "TLS_CHACHA20_POLY1305_SHA256",
    0x1304: "TLS_AES_128_CCM_SHA256",
    0x1305: "TLS_AES_128_CCM_8_SHA256",
    0xC02B: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    0xC02C: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    0xC02F: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    0xC030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    0xCCA8: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    0xCCA9: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    0x009C: "TLS_RSA_WITH_AES_128_GCM_SHA256",
    0x009D: "TLS_RSA_WITH_AES_256_GCM_SHA384",
    0x002F: "TLS_RSA_WITH_AES_128_CBC_SHA",
    0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
}


@dataclass
class TLSClientHello:
    legacy_version: int
    supported_versions: list[int] = field(default_factory=list)
    cipher_suites: list[int] = field(default_factory=list)
    supported_groups: list[int] = field(default_factory=list)
    key_share_groups: list[int] = field(default_factory=list)
    signature_algorithms: list[int] = field(default_factory=list)
    server_name: str | None = None


@dataclass
class TLSServerHello:
    legacy_version: int
    selected_version: int | None = None  # from supported_versions ext (TLS 1.3)
    cipher_suite: int = 0
    selected_group: int | None = None  # from key_share ext


class _Buf:
    """Tiny bounded reader for TLS wire format."""

    __slots__ = ("data", "pos")

    def __init__(self, data: bytes) -> None:
        self.data = data
        self.pos = 0

    def remaining(self) -> int:
        return len(self.data) - self.pos

    def need(self, n: int) -> None:
        if self.remaining() < n:
            raise _ShortBuffer(f"need {n}, have {self.remaining()}")

    def u8(self) -> int:
        self.need(1)
        v = self.data[self.pos]
        self.pos += 1
        return v

    def u16(self) -> int:
        self.need(2)
        v = int.from_bytes(self.data[self.pos : self.pos + 2], "big")
        self.pos += 2
        return v

    def u24(self) -> int:
        self.need(3)
        v = int.from_bytes(self.data[self.pos : self.pos + 3], "big")
        self.pos += 3
        return v

    def bytes_n(self, n: int) -> bytes:
        self.need(n)
        v = self.data[self.pos : self.pos + n]
        self.pos += n
        return v

    def vec8(self) -> bytes:
        n = self.u8()
        return self.bytes_n(n)

    def vec16(self) -> bytes:
        n = self.u16()
        return self.bytes_n(n)


class _ShortBuffer(ValueError):
    pass


def _extract_handshake_messages(payload: bytes) -> list[tuple[int, bytes]]:
    """Walk TLS records, concatenate handshake payloads, then parse messages.

    Returns list of (handshake_type, body_bytes).
    Handles multiple records carrying a single handshake message (fragmentation)
    by concatenating handshake-typed record bodies before parsing.
    """
    handshake_stream = bytearray()
    buf = _Buf(payload)
    while buf.remaining() >= 5:
        ct = buf.u8()
        _ver = buf.u16()
        try:
            body = buf.vec16()
        except _ShortBuffer:
            break
        if ct == TLS_CONTENT_HANDSHAKE:
            handshake_stream.extend(body)
        # Stop early once we've passed the first handshake record(s). Post-
        # handshake is encrypted in 1.3 anyway, and ChangeCipherSpec in 1.2
        # signals transition to encrypted application data.
        if ct != TLS_CONTENT_HANDSHAKE and handshake_stream:
            break

    messages: list[tuple[int, bytes]] = []
    hs = _Buf(bytes(handshake_stream))
    while hs.remaining() >= 4:
        ht = hs.u8()
        try:
            body_len = hs.u24()
            body = hs.bytes_n(body_len)
        except _ShortBuffer:
            break
        messages.append((ht, body))
    return messages


def parse_tls_client_hello(payload: bytes) -> TLSClientHello | None:
    """Parse TLS ClientHello from a TCP payload. Return None if not present."""
    for ht, body in _extract_handshake_messages(payload):
        if ht == HS_CLIENT_HELLO:
            return _parse_client_hello_body(body)
    return None


def parse_tls_server_hello(payload: bytes) -> TLSServerHello | None:
    """Parse TLS ServerHello from a TCP payload. Return None if not present."""
    for ht, body in _extract_handshake_messages(payload):
        if ht == HS_SERVER_HELLO:
            return _parse_server_hello_body(body)
    return None


def _parse_client_hello_body(body: bytes) -> TLSClientHello | None:
    try:
        b = _Buf(body)
        legacy_version = b.u16()
        b.bytes_n(32)  # random
        b.vec8()  # legacy_session_id
        cs_raw = b.vec16()
        b.vec8()  # compression_methods
        ch = TLSClientHello(legacy_version=legacy_version)
        # cipher_suites: array of uint16
        for i in range(0, len(cs_raw), 2):
            if i + 2 <= len(cs_raw):
                ch.cipher_suites.append(int.from_bytes(cs_raw[i : i + 2], "big"))

        if b.remaining() < 2:
            return ch
        ext_raw = b.vec16()
        _parse_client_extensions(ext_raw, ch)
        return ch
    except _ShortBuffer:
        return None


def _parse_server_hello_body(body: bytes) -> TLSServerHello | None:
    try:
        b = _Buf(body)
        legacy_version = b.u16()
        b.bytes_n(32)  # random
        b.vec8()  # legacy_session_id_echo
        cipher_suite = b.u16()
        _ = b.u8()  # legacy_compression_method
        sh = TLSServerHello(legacy_version=legacy_version, cipher_suite=cipher_suite)
        if b.remaining() < 2:
            return sh
        ext_raw = b.vec16()
        _parse_server_extensions(ext_raw, sh)
        return sh
    except _ShortBuffer:
        return None


def _parse_client_extensions(data: bytes, ch: TLSClientHello) -> None:
    b = _Buf(data)
    while b.remaining() >= 4:
        try:
            ext_type = b.u16()
            ext_body = b.vec16()
        except _ShortBuffer:
            break
        if ext_type == EXT_SERVER_NAME:
            ch.server_name = _parse_sni(ext_body)
        elif ext_type == EXT_SUPPORTED_GROUPS:
            ch.supported_groups = _parse_uint16_list(ext_body)
        elif ext_type == EXT_SIGNATURE_ALGORITHMS:
            ch.signature_algorithms = _parse_uint16_list(ext_body)
        elif ext_type == EXT_SUPPORTED_VERSIONS:
            # Client version: 1-byte length + list of uint16
            if ext_body:
                n = ext_body[0]
                vers = ext_body[1 : 1 + n]
                for i in range(0, len(vers), 2):
                    if i + 2 <= len(vers):
                        ch.supported_versions.append(int.from_bytes(vers[i : i + 2], "big"))
        elif ext_type == EXT_KEY_SHARE:
            ch.key_share_groups = _parse_client_key_share(ext_body)


def _parse_server_extensions(data: bytes, sh: TLSServerHello) -> None:
    b = _Buf(data)
    while b.remaining() >= 4:
        try:
            ext_type = b.u16()
            ext_body = b.vec16()
        except _ShortBuffer:
            break
        if ext_type == EXT_SUPPORTED_VERSIONS:
            if len(ext_body) >= 2:
                sh.selected_version = int.from_bytes(ext_body[:2], "big")
        elif ext_type == EXT_KEY_SHARE:
            if len(ext_body) >= 2:
                sh.selected_group = int.from_bytes(ext_body[:2], "big")


def _parse_sni(data: bytes) -> str | None:
    if len(data) < 2:
        return None
    list_len = int.from_bytes(data[:2], "big")
    if list_len + 2 > len(data):
        return None
    idx = 2
    end = 2 + list_len
    while idx + 3 <= end:
        name_type = data[idx]
        name_len = int.from_bytes(data[idx + 1 : idx + 3], "big")
        idx += 3
        if idx + name_len > end:
            return None
        if name_type == 0:  # host_name
            return data[idx : idx + name_len].decode("ascii", errors="replace")
        idx += name_len
    return None


def _parse_uint16_list(data: bytes) -> list[int]:
    if len(data) < 2:
        return []
    n = int.from_bytes(data[:2], "big")
    if n + 2 > len(data):
        return []
    out = []
    for i in range(0, n, 2):
        if 2 + i + 2 <= len(data):
            out.append(int.from_bytes(data[2 + i : 2 + i + 2], "big"))
    return out


def _parse_client_key_share(data: bytes) -> list[int]:
    """ClientHello key_share: uint16 length + list of (group u16, key_exchange vec16)."""
    if len(data) < 2:
        return []
    total = int.from_bytes(data[:2], "big")
    if total + 2 > len(data):
        return []
    out: list[int] = []
    idx = 2
    end = 2 + total
    while idx + 4 <= end:
        group = int.from_bytes(data[idx : idx + 2], "big")
        ke_len = int.from_bytes(data[idx + 2 : idx + 4], "big")
        out.append(group)
        idx += 4 + ke_len
    return out


def group_name(code: int) -> str:
    return NAMED_GROUPS.get(code, f"0x{code:04x}")


def cipher_suite_name(code: int) -> str:
    return CIPHER_SUITES.get(code, f"0x{code:04x}")


def _symmetric_from_cipher_name(name: str) -> str | None:
    n = name.upper()
    if "AES_256_GCM" in n or "AES-256-GCM" in n:
        return "AES-256-GCM"
    if "AES_128_GCM" in n or "AES-128-GCM" in n:
        return "AES-128-GCM"
    if "CHACHA20" in n:
        return "ChaCha20-Poly1305"
    if "AES_256_CBC" in n or "AES-256-CBC" in n:
        return "AES-256-CBC"
    if "AES_128_CBC" in n or "AES-128-CBC" in n:
        return "AES-128-CBC"
    if "3DES" in n or "DES_EDE" in n:
        return "3DES"
    if "RC4" in n:
        return "RC4"
    return None


def _hash_from_cipher_name(name: str) -> str | None:
    n = name.upper()
    if "SHA384" in n:
        return "SHA-384"
    if "SHA256" in n:
        return "SHA-256"
    if "SHA512" in n:
        return "SHA-512"
    if "SHA_" in n or n.endswith("SHA"):
        return "SHA-1"
    return None


def _sig_from_cipher_name(name: str) -> str | None:
    n = name.upper()
    if "ECDSA" in n:
        return "ECDSA"
    if "RSA" in n and "ECDHE_RSA" in n:
        return "RSA"
    if n.startswith("TLS_RSA"):
        return "RSA"
    # TLS 1.3 cipher suites don't encode sig alg; caller uses signature_algorithms ext.
    return None


def _kex_from_cipher_and_groups(
    cipher_name: str,
    selected_group: int | None,
    groups_fallback: list[int],
) -> str | None:
    """Pick the most specific kex label available.

    TLS 1.3: use selected_group from key_share (or first offered group).
    TLS 1.2 classical: cipher name carries the kex (ECDHE_RSA → ECDHE).
    """
    if selected_group is not None:
        return group_name(selected_group)
    if groups_fallback:
        return group_name(groups_fallback[0])
    n = cipher_name.upper()
    if "ECDHE" in n:
        return "ECDHE"
    if n.startswith("TLS_RSA"):
        return "RSA"
    if "DHE" in n:
        return "DHE"
    return None


def extract_crypto(
    client_hello: TLSClientHello | None,
    server_hello: TLSServerHello | None,
) -> CryptoPrimitive:
    """Fuse ClientHello + ServerHello into a CryptoPrimitive.

    Use server_hello when available (it's the negotiated result); fall back
    to client_hello intent if only one side was captured.
    """
    cipher_code = server_hello.cipher_suite if server_hello else 0
    if not cipher_code and client_hello and client_hello.cipher_suites:
        cipher_code = client_hello.cipher_suites[0]
    cipher_name = cipher_suite_name(cipher_code) if cipher_code else ""

    selected_group = server_hello.selected_group if server_hello else None
    groups_fallback: list[int] = []
    if client_hello:
        groups_fallback = client_hello.key_share_groups or client_hello.supported_groups

    kex = _kex_from_cipher_and_groups(cipher_name, selected_group, groups_fallback)
    is_hybrid = kex in HYBRID_PQC_GROUPS if kex else False
    is_pure_pqc = kex in PURE_PQC_GROUPS if kex else False
    sig = _sig_from_cipher_name(cipher_name) if cipher_name else None

    return CryptoPrimitive(
        kex_algorithm=kex,
        signature_algorithm=sig,
        symmetric_cipher=_symmetric_from_cipher_name(cipher_name) if cipher_name else None,
        hash_algorithm=_hash_from_cipher_name(cipher_name) if cipher_name else None,
        is_hybrid_pqc=is_hybrid,
        is_pure_pqc=is_pure_pqc,
        raw_cipher_suite=cipher_name or None,
    )
