"""TLS parser — synthetic wire bytes covering canonical handshakes.

We hand-craft minimal valid ClientHello / ServerHello records per RFC 8446
rather than depending on a PCAP fixture, so the tests run offline.
"""

from __future__ import annotations

from src.flow_analyzer.handshake_parser.tls_parser import (
    HYBRID_PQC_GROUPS,
    extract_crypto,
    parse_tls_client_hello,
    parse_tls_server_hello,
)


def _u16(n: int) -> bytes:
    return n.to_bytes(2, "big")


def _u24(n: int) -> bytes:
    return n.to_bytes(3, "big")


def _record(body: bytes) -> bytes:
    """Wrap a handshake message body in a TLS 1.2/1.3 record layer."""
    return bytes([22]) + _u16(0x0303) + _u16(len(body)) + body


def _client_hello(
    cipher_suites: list[int],
    extensions: bytes = b"",
) -> bytes:
    cs_bytes = b"".join(_u16(c) for c in cipher_suites)
    body = (
        _u16(0x0303)                   # legacy_version
        + b"\x00" * 32                  # random
        + b"\x00"                        # session_id (empty)
        + _u16(len(cs_bytes)) + cs_bytes  # cipher_suites
        + b"\x01\x00"                    # compression_methods: [null]
        + _u16(len(extensions)) + extensions
    )
    hs = bytes([1]) + _u24(len(body)) + body  # ClientHello
    return _record(hs)


def _server_hello(
    cipher_suite: int,
    extensions: bytes = b"",
    legacy_version: int = 0x0303,
) -> bytes:
    body = (
        _u16(legacy_version)
        + b"\x00" * 32                 # random
        + b"\x00"                        # session_id_echo (empty)
        + _u16(cipher_suite)             # selected
        + b"\x00"                        # legacy_compression_method
        + _u16(len(extensions)) + extensions
    )
    hs = bytes([2]) + _u24(len(body)) + body  # ServerHello
    return _record(hs)


def _ext(ext_type: int, body: bytes) -> bytes:
    return _u16(ext_type) + _u16(len(body)) + body


def _sni_ext(name: str) -> bytes:
    name_b = name.encode("ascii")
    entry = b"\x00" + _u16(len(name_b)) + name_b  # host_name type + length + name
    body = _u16(len(entry)) + entry
    return _ext(0x0000, body)


def _supported_groups_ext(groups: list[int]) -> bytes:
    lst = b"".join(_u16(g) for g in groups)
    body = _u16(len(lst)) + lst
    return _ext(0x000A, body)


def _supported_versions_ext_client(versions: list[int]) -> bytes:
    lst = b"".join(_u16(v) for v in versions)
    body = bytes([len(lst)]) + lst  # 1-byte length in client variant
    return _ext(0x002B, body)


def _supported_versions_ext_server(version: int) -> bytes:
    return _ext(0x002B, _u16(version))


def _key_share_client_ext(groups: list[int]) -> bytes:
    entries = b""
    for g in groups:
        ke = b"\x00" * 32  # fake key_exchange (length doesn't matter for parsing)
        entries += _u16(g) + _u16(len(ke)) + ke
    body = _u16(len(entries)) + entries
    return _ext(0x0033, body)


def _key_share_server_ext(group: int) -> bytes:
    ke = b"\x00" * 32
    body = _u16(group) + _u16(len(ke)) + ke
    return _ext(0x0033, body)


# --- Tests ---

def test_parse_client_hello_tls13_hybrid_mlkem() -> None:
    exts = (
        _sni_ext("example.vn")
        + _supported_versions_ext_client([0x0304])
        + _supported_groups_ext([0x11EC, 0x001D])  # X25519MLKEM768 then x25519
        + _key_share_client_ext([0x11EC])
    )
    payload = _client_hello(cipher_suites=[0x1301, 0x1302], extensions=exts)
    ch = parse_tls_client_hello(payload)
    assert ch is not None
    assert ch.server_name == "example.vn"
    assert 0x0304 in ch.supported_versions
    assert 0x11EC in ch.supported_groups
    assert 0x11EC in ch.key_share_groups
    assert ch.cipher_suites[:2] == [0x1301, 0x1302]


def test_parse_client_hello_classical_tls12() -> None:
    exts = _sni_ext("legacy.example") + _supported_groups_ext([0x0017, 0x0018])
    payload = _client_hello(cipher_suites=[0xC02F, 0xC030], extensions=exts)
    ch = parse_tls_client_hello(payload)
    assert ch is not None
    assert ch.server_name == "legacy.example"
    assert 0x0304 not in ch.supported_versions  # no TLS 1.3 signal
    assert 0x0017 in ch.supported_groups


def test_parse_server_hello_tls13_selects_mlkem() -> None:
    exts = _supported_versions_ext_server(0x0304) + _key_share_server_ext(0x11EC)
    payload = _server_hello(cipher_suite=0x1302, extensions=exts)
    sh = parse_tls_server_hello(payload)
    assert sh is not None
    assert sh.cipher_suite == 0x1302
    assert sh.selected_version == 0x0304
    assert sh.selected_group == 0x11EC


def test_extract_crypto_fuses_client_and_server() -> None:
    ch_bytes = _client_hello(
        cipher_suites=[0x1302],
        extensions=(
            _sni_ext("bank.vn")
            + _supported_versions_ext_client([0x0304])
            + _key_share_client_ext([0x11EC])
        ),
    )
    sh_bytes = _server_hello(
        cipher_suite=0x1302,
        extensions=_supported_versions_ext_server(0x0304) + _key_share_server_ext(0x11EC),
    )
    ch = parse_tls_client_hello(ch_bytes)
    sh = parse_tls_server_hello(sh_bytes)
    crypto = extract_crypto(ch, sh)
    assert crypto.raw_cipher_suite == "TLS_AES_256_GCM_SHA384"
    assert crypto.symmetric_cipher == "AES-256-GCM"
    assert crypto.hash_algorithm == "SHA-384"
    assert crypto.kex_algorithm == "X25519MLKEM768"
    assert crypto.is_hybrid_pqc is True


def test_extract_crypto_classical_ecdhe() -> None:
    ch_bytes = _client_hello(
        cipher_suites=[0xC030],
        extensions=_supported_groups_ext([0x001D]),
    )
    sh_bytes = _server_hello(cipher_suite=0xC030)
    ch = parse_tls_client_hello(ch_bytes)
    sh = parse_tls_server_hello(sh_bytes)
    crypto = extract_crypto(ch, sh)
    assert crypto.is_hybrid_pqc is False
    assert crypto.signature_algorithm == "RSA"
    # kex falls back to client's first group in absence of server key_share
    assert crypto.kex_algorithm == "x25519"


def test_parse_returns_none_on_garbage() -> None:
    assert parse_tls_client_hello(b"\x00\x01\x02") is None
    assert parse_tls_server_hello(b"\xff\xff\xff\xff\xff") is None


def test_hybrid_pqc_group_labels_stable() -> None:
    # Guardrail: if we change codepoint → label mapping, these known-good names must remain.
    assert "X25519MLKEM768" in HYBRID_PQC_GROUPS


def test_parse_handles_fragmented_records() -> None:
    """A ClientHello split across two handshake-type records must still parse."""
    exts = _sni_ext("frag.example") + _supported_versions_ext_client([0x0304])
    full = _client_hello(cipher_suites=[0x1301], extensions=exts)
    # Strip the record layer wrapper, then split body into two record fragments.
    # Record layer = 5 bytes. Handshake body starts after.
    record_body = full[5:]
    midpoint = len(record_body) // 2
    frag1 = bytes([22]) + _u16(0x0303) + _u16(midpoint) + record_body[:midpoint]
    frag2 = bytes([22]) + _u16(0x0303) + _u16(len(record_body) - midpoint) + record_body[midpoint:]
    ch = parse_tls_client_hello(frag1 + frag2)
    assert ch is not None
    assert ch.server_name == "frag.example"
