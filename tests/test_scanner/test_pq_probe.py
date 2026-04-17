"""Tests for the active PQ ClientHello probe.

Network tests are gated behind PQ_PROBE_LIVE=1 so the default `pytest`
run stays fully offline.
"""

from __future__ import annotations

import os
import struct

import pytest

from src.scanner.pq_probe import (
    GROUP_X25519,
    GROUP_X25519_MLKEM768,
    HRR_RANDOM,
    _build_client_hello,
    _parse_server_hello_selected_group,
    probe_x25519mlkem768,
)


def _make_server_hello(selected_group: int, hrr: bool = False) -> bytes:
    """Build a synthetic ServerHello/HRR carrying the given key_share group."""
    legacy_version = b"\x03\x03"
    random = HRR_RANDOM if hrr else b"\xaa" * 32
    session_id = b""
    sid_block = struct.pack(">B", len(session_id)) + session_id
    cipher = b"\x13\x01"
    compression = b"\x00"
    # key_share extension: type 0x33, payload = selected group (2B)
    if hrr:
        ks_payload = struct.pack(">H", selected_group)
    else:
        ks_payload = struct.pack(">HH", selected_group, 32) + b"\x00" * 32
    ks_ext = struct.pack(">HH", 0x0033, len(ks_payload)) + ks_payload
    sv_ext = struct.pack(">HH", 0x002B, 2) + b"\x03\x04"
    extensions = sv_ext + ks_ext
    ext_block = struct.pack(">H", len(extensions)) + extensions
    body = (
        legacy_version + random + sid_block + cipher + compression.ljust(1, b"\x00") + ext_block
    )
    handshake = b"\x02" + len(body).to_bytes(3, "big") + body
    record = struct.pack(">BHH", 0x16, 0x0303, len(handshake)) + handshake
    return record


class TestParseServerHello:
    def test_extracts_x25519mlkem768_from_server_hello(self):
        record = _make_server_hello(GROUP_X25519_MLKEM768)
        assert _parse_server_hello_selected_group(record) == GROUP_X25519_MLKEM768

    def test_extracts_classical_x25519(self):
        record = _make_server_hello(GROUP_X25519)
        assert _parse_server_hello_selected_group(record) == GROUP_X25519

    def test_extracts_from_hello_retry_request(self):
        record = _make_server_hello(GROUP_X25519_MLKEM768, hrr=True)
        assert _parse_server_hello_selected_group(record) == GROUP_X25519_MLKEM768

    def test_alert_record_returns_none(self):
        # Type 0x15 = alert
        record = b"\x15\x03\x03\x00\x02\x02\x28"
        assert _parse_server_hello_selected_group(record) is None

    def test_truncated_record_returns_none(self):
        assert _parse_server_hello_selected_group(b"\x16\x03\x03") is None
        assert _parse_server_hello_selected_group(b"") is None


class TestBuildClientHello:
    def test_offers_target_groups(self):
        ch = _build_client_hello(
            "example.com",
            groups=[GROUP_X25519_MLKEM768, GROUP_X25519],
            key_shares=[
                (GROUP_X25519_MLKEM768, b"\x00" * 1216),
                (GROUP_X25519, b"\x00" * 32),
            ],
        )
        # Record header: 0x16 0x0301 <len>
        assert ch[0] == 0x16
        # Hybrid codepoint must appear inside the supported_groups extension
        assert b"\x11\xec" in ch
        # Handshake type ClientHello
        assert ch[5] == 0x01

    def test_sni_includes_host(self):
        ch = _build_client_hello(
            "cloudflare.com",
            groups=[GROUP_X25519],
            key_shares=[(GROUP_X25519, b"\x00" * 32)],
        )
        assert b"cloudflare.com" in ch


@pytest.mark.skipif(
    os.environ.get("PQ_PROBE_LIVE") != "1",
    reason="set PQ_PROBE_LIVE=1 to run network probes",
)
class TestLiveProbe:
    def test_cloudflare_supports_x25519mlkem768(self):
        result = probe_x25519mlkem768("cloudflare.com")
        assert result.error is None, result.error
        assert result.supported is True
        assert result.selected_group == "X25519MLKEM768"
