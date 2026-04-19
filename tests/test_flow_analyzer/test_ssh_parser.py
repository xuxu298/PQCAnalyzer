"""SSH KEXINIT parser — synthetic wire bytes."""

from __future__ import annotations

from src.flow_analyzer.handshake_parser.ssh_parser import (
    parse_ssh_kexinit,
    ssh_crypto_from_kexinit,
)


def _name_list(items: list[str]) -> bytes:
    raw = ",".join(items).encode("ascii")
    return len(raw).to_bytes(4, "big") + raw


def _kexinit_payload(
    kex: list[str],
    hostkey: list[str],
    ciphers: list[str],
    macs: list[str] | None = None,
    compression: list[str] | None = None,
) -> bytes:
    macs = macs or ["hmac-sha2-256"]
    compression = compression or ["none"]
    return (
        bytes([20])                      # SSH_MSG_KEXINIT
        + b"\x00" * 16                   # cookie
        + _name_list(kex)
        + _name_list(hostkey)
        + _name_list(ciphers)            # c2s
        + _name_list(ciphers)            # s2c
        + _name_list(macs)               # c2s
        + _name_list(macs)               # s2c
        + _name_list(compression)        # c2s
        + _name_list(compression)        # s2c
        + _name_list([])                  # lang c2s
        + _name_list([])                  # lang s2c
        + b"\x00"                         # first_kex_packet_follows
        + b"\x00\x00\x00\x00"             # reserved
    )


def _bpp_frame(payload: bytes) -> bytes:
    """Wrap payload in an SSH Binary Packet Protocol frame (pre-MAC, no encryption)."""
    # packet_length covers payload + padding_length byte + padding
    pad_len = 4  # arbitrary, >= 4 per RFC
    packet_len = len(payload) + 1 + pad_len  # +1 for padding_length byte itself
    return (
        packet_len.to_bytes(4, "big")
        + bytes([pad_len])
        + payload
        + b"\x00" * pad_len
    )


def _with_banner(frame: bytes) -> bytes:
    return b"SSH-2.0-OpenSSH_9.5\r\n" + frame


def test_parse_kexinit_extracts_algorithm_lists() -> None:
    payload = _kexinit_payload(
        kex=["mlkem768x25519-sha256", "curve25519-sha256"],
        hostkey=["ssh-ed25519", "ssh-rsa"],
        ciphers=["aes256-gcm@openssh.com", "chacha20-poly1305@openssh.com"],
    )
    data = _with_banner(_bpp_frame(payload))
    result = parse_ssh_kexinit(data)
    assert result is not None
    assert "mlkem768x25519-sha256" in result.kex_algorithms
    assert "ssh-ed25519" in result.server_host_key_algorithms
    assert "aes256-gcm@openssh.com" in result.encryption_algorithms_c2s


def test_parse_kexinit_without_banner() -> None:
    payload = _kexinit_payload(
        kex=["curve25519-sha256"],
        hostkey=["ssh-ed25519"],
        ciphers=["aes128-ctr"],
    )
    result = parse_ssh_kexinit(_bpp_frame(payload))
    assert result is not None
    assert result.kex_algorithms == ["curve25519-sha256"]


def test_parse_kexinit_returns_none_on_junk() -> None:
    assert parse_ssh_kexinit(b"not SSH") is None
    assert parse_ssh_kexinit(b"") is None


def test_ssh_crypto_prefers_hybrid_pqc_when_negotiated() -> None:
    client_payload = _kexinit_payload(
        kex=["mlkem768x25519-sha256", "curve25519-sha256"],
        hostkey=["ssh-ed25519"],
        ciphers=["aes256-gcm@openssh.com"],
    )
    server_payload = _kexinit_payload(
        kex=["curve25519-sha256", "mlkem768x25519-sha256"],
        hostkey=["ssh-ed25519"],
        ciphers=["aes256-gcm@openssh.com"],
    )
    client = parse_ssh_kexinit(_bpp_frame(client_payload))
    server = parse_ssh_kexinit(_bpp_frame(server_payload))
    crypto = ssh_crypto_from_kexinit(client, server)
    assert crypto.kex_algorithm == "mlkem768x25519-sha256"
    assert crypto.is_hybrid_pqc is True
    assert crypto.symmetric_cipher == "AES-256-GCM"


def test_ssh_crypto_classical_when_no_pqc_agreed() -> None:
    client_payload = _kexinit_payload(
        kex=["curve25519-sha256"],
        hostkey=["ssh-rsa"],
        ciphers=["aes128-ctr"],
    )
    server_payload = _kexinit_payload(
        kex=["curve25519-sha256", "diffie-hellman-group14-sha256"],
        hostkey=["ssh-rsa"],
        ciphers=["aes128-ctr"],
    )
    client = parse_ssh_kexinit(_bpp_frame(client_payload))
    server = parse_ssh_kexinit(_bpp_frame(server_payload))
    crypto = ssh_crypto_from_kexinit(client, server)
    assert crypto.kex_algorithm == "curve25519-sha256"
    assert crypto.is_hybrid_pqc is False
