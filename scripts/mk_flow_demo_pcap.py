"""Generate a deterministic demo PCAP for flow_analyzer demos.

Writes a capture containing four synthetic TLS/SSH handshakes. Hostnames are
either public-scan-friendly big names or RFC 2606/5737 reserved placeholders:

 1. www.google.com:443 — hybrid X25519MLKEM768 (default bucket → SAFE)
 2. github.com:443 — classical x25519 (default bucket → LOW)
 3. github.com:22 — SSH classical curve25519 (port 22 → confidential/medium)
 4. records.medical.example:443 — classical x25519 (.medical. regex → secret/lifetime)

The handshake bytes are synthetic — no real scan was run against any listed
host. Google and GitHub are used because their public TLS/SSH crypto posture
is already catalogued by SSL Labs, Cloudflare Radar, Mozilla Observatory etc.

Output path taken as first CLI arg, defaults to docs/fixtures/flow_demo.pcap.
"""
from __future__ import annotations

import sys
from pathlib import Path

from scapy.all import Ether, IP, TCP, Raw, wrpcap


def _tls_record(msg_type: int, payload: bytes, version: bytes = b"\x03\x03") -> bytes:
    hs = bytes([msg_type]) + len(payload).to_bytes(3, "big") + payload
    return b"\x16" + version + len(hs).to_bytes(2, "big") + hs


def _sni_ext(host: str) -> bytes:
    name = host.encode()
    sn = b"\x00" + len(name).to_bytes(2, "big") + name
    sn_list = len(sn).to_bytes(2, "big") + sn
    return b"\x00\x00" + len(sn_list).to_bytes(2, "big") + sn_list


def _supported_versions_ch(versions: list[int]) -> bytes:
    body = bytes([len(versions) * 2]) + b"".join(v.to_bytes(2, "big") for v in versions)
    return b"\x00\x2b" + len(body).to_bytes(2, "big") + body


def _supported_groups(groups: list[int]) -> bytes:
    gl = b"".join(g.to_bytes(2, "big") for g in groups)
    body = len(gl).to_bytes(2, "big") + gl
    return b"\x00\x0a" + len(body).to_bytes(2, "big") + body


def _key_share_ch(entries: list[tuple[int, int]]) -> bytes:
    ks = b""
    for g, klen in entries:
        ks += g.to_bytes(2, "big") + klen.to_bytes(2, "big") + (b"\x00" * klen)
    body = len(ks).to_bytes(2, "big") + ks
    return b"\x00\x33" + len(body).to_bytes(2, "big") + body


def _key_share_sh(group: int, klen: int) -> bytes:
    body = group.to_bytes(2, "big") + klen.to_bytes(2, "big") + (b"\x00" * klen)
    return b"\x00\x33" + len(body).to_bytes(2, "big") + body


def _supported_versions_sh() -> bytes:
    return b"\x00\x2b" + (2).to_bytes(2, "big") + b"\x03\x04"


def _client_hello(sni: str, groups: list[int], ks_entries: list[tuple[int, int]]) -> bytes:
    body = b"\x03\x03"
    body += b"\x11" * 32
    body += b"\x00"
    body += (2).to_bytes(2, "big") + b"\x13\x01"
    body += b"\x01\x00"
    exts = (
        _sni_ext(sni)
        + _supported_versions_ch([0x0304])
        + _supported_groups(groups)
        + _key_share_ch(ks_entries)
    )
    body += len(exts).to_bytes(2, "big") + exts
    return _tls_record(1, body, b"\x03\x01")


def _server_hello(group: int, klen: int) -> bytes:
    body = b"\x03\x03"
    body += b"\x22" * 32
    body += b"\x00"
    body += b"\x13\x01"
    body += b"\x00"
    exts = _supported_versions_sh() + _key_share_sh(group, klen)
    body += len(exts).to_bytes(2, "big") + exts
    return _tls_record(2, body, b"\x03\x03")


def _ssh_pair() -> tuple[bytes, bytes]:
    c_banner = b"SSH-2.0-OpenSSH_9.6\r\n"
    s_banner = b"SSH-2.0-OpenSSH_9.2\r\n"

    def namelist(names: list[str]) -> bytes:
        s = ",".join(names).encode()
        return len(s).to_bytes(4, "big") + s

    def kexinit(kex_names: list[str]) -> bytes:
        payload = bytes([20]) + b"\x00" * 16
        payload += namelist(kex_names)
        payload += namelist(["ssh-ed25519"])
        payload += namelist(["aes256-gcm@openssh.com"])
        payload += namelist(["aes256-gcm@openssh.com"])
        payload += namelist(["hmac-sha2-256"])
        payload += namelist(["hmac-sha2-256"])
        payload += namelist(["none"])
        payload += namelist(["none"])
        payload += namelist([""])
        payload += namelist([""])
        payload += b"\x00"
        payload += b"\x00\x00\x00\x00"
        pad = 8 - ((len(payload) + 5) % 8)
        if pad < 4:
            pad += 8
        pkt = bytes([pad]) + payload + (b"\x00" * pad)
        return len(pkt).to_bytes(4, "big") + pkt

    client_kex = ["mlkem768x25519-sha256", "curve25519-sha256"]
    server_kex = ["curve25519-sha256", "ecdh-sha2-nistp256"]
    return c_banner + kexinit(client_kex), s_banner + kexinit(server_kex)


def _flow(src, dst, sport, dport, c_bytes, s_bytes, seq=1000, pad_to=0):
    pkts = [
        Ether() / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="PA", seq=seq) / Raw(load=c_bytes),
        Ether() / IP(src=dst, dst=src) / TCP(sport=dport, dport=sport, flags="PA", seq=seq + 5000) / Raw(load=s_bytes),
    ]
    if pad_to:
        chunk = 1200
        off_c = seq + len(c_bytes)
        off_s = seq + 5000 + len(s_bytes)
        remaining = pad_to
        while remaining > 0:
            n = min(chunk, remaining)
            pkts.append(Ether() / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="A", seq=off_c) / Raw(load=b"\x00" * n))
            off_c += n
            pkts.append(Ether() / IP(src=dst, dst=src) / TCP(sport=dport, dport=sport, flags="A", seq=off_s) / Raw(load=b"\x00" * n))
            off_s += n
            remaining -= n
    return pkts


def main() -> None:
    out = Path(sys.argv[1] if len(sys.argv) > 1 else "docs/fixtures/flow_demo.pcap")
    out.parent.mkdir(parents=True, exist_ok=True)

    pkts = []

    # 1. www.google.com — hybrid X25519MLKEM768 → expect SAFE
    ch = _client_hello("www.google.com", [0x11EB, 0x001D], [(0x11EB, 1216)])
    sh = _server_hello(0x11EB, 1120)
    pkts += _flow("10.0.0.10", "198.51.100.10", 40001, 443, ch, sh, seq=1000, pad_to=800_000)

    # 2. github.com:443 — classical x25519 → default bucket → expect LOW
    ch = _client_hello("github.com", [0x001D], [(0x001D, 32)])
    sh = _server_hello(0x001D, 32)
    pkts += _flow("10.0.0.10", "198.51.100.20", 40002, 443, ch, sh, seq=2000, pad_to=2_000_000)

    # 3. github.com:22 — SSH classical curve25519 → port 22 rule → expect MEDIUM
    ck, sk = _ssh_pair()
    pkts += _flow("10.0.0.10", "198.51.100.20", 40003, 22, ck, sk, seq=3000, pad_to=5_000_000)

    # 4. records.medical.example — matches .medical. regex → expect HIGH
    ch = _client_hello("records.medical.example", [0x001D], [(0x001D, 32)])
    sh = _server_hello(0x001D, 32)
    pkts += _flow("10.0.0.10", "198.51.100.30", 40004, 443, ch, sh, seq=4000, pad_to=2_200_000)

    wrpcap(str(out), pkts)
    print(f"Wrote {len(pkts)} packets to {out}")


if __name__ == "__main__":
    main()
