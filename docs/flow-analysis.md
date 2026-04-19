# Flow Analysis (HNDL Radar)

`pqc-analyzer scan pcap` parses captured network traffic and scores each
flow's **Harvest-Now-Decrypt-Later** (HNDL) exposure. Unlike the endpoint
scanner (which asks "*is this server PQ-ready?*"), the flow analyser answers
"*how much of what's already on the wire is a quantum liability?*".

## Install

```bash
pip install "vn-pqc-analyzer[flow]"
```

This pulls in `scapy` and `PyYAML`. No libpcap or root required for reading
PCAP files; live capture (future) will need libpcap.

## Quick start

```bash
# Scan a capture
pqc-analyzer scan pcap corp_edge.pcap

# Narrow to TLS only
pqc-analyzer scan pcap corp_edge.pcap --filter "tcp port 443"

# Custom sensitivity rules
pqc-analyzer scan pcap corp_edge.pcap --sensitivity-map ./rules.yaml

# Emit JSON for downstream pipelines
pqc-analyzer scan pcap corp_edge.pcap -o report.json

# Feed the flow report into the migration roadmap
pqc-analyzer roadmap report.json
```

## Pipeline

```
PCAP / pcapng
    │
    ▼
pcap_reader       ── scapy streaming, handles truncated captures
    │
    ▼
flow_aggregator   ── 5-tuple grouping, bidirectional merge, payload buffering
    │
    ▼
handshake_parser  ── TLS 1.2/1.3 ClientHello+ServerHello, SSH2 KEXINIT
    │
    ▼
data_classifier   ── YAML rules → DataSensitivity + RetentionClass
    │
    ▼
hndl_scorer       ── HNDL = 100 × V × S × R × E (see docs/hndl-scoring.md)
    │
    ▼
reporter          ── Rich CLI table + JSON export
```

## Supported protocols

| Protocol | Parser | Notes |
|---|---|---|
| TLS 1.2 | `handshake_parser/tls_parser.py` | ClientHello + ServerHello |
| TLS 1.3 | `handshake_parser/tls_parser.py` | `supported_versions`, `key_share` |
| SSH-2 | `handshake_parser/ssh_parser.py` | RFC 4253 §7.1 KEXINIT |
| IKEv2 | _planned_ | Phase 3 of v0.2 |
| QUIC | _planned_ | Phase 4 of v0.2, needs Initial-packet decode |

## Hybrid PQC detection

The parser recognises the following hybrid / PQC named groups on the wire:

| Codepoint | Name | Kind |
|---|---|---|
| `0x11EB` | `X25519MLKEM768` | Hybrid (IANA, post FIPS 203) |
| `0x11EC` | `X25519Kyber768Draft00` | Hybrid (Cloudflare/Chrome draft) |
| `0x6399` | `SecP256r1Kyber768Draft00` | Hybrid (Chrome draft) |
| `0x639A` | `SecP384r1Kyber768Draft00` | Hybrid |

And these SSH KEX names:

- `mlkem768x25519-sha256`
- `mlkem768nistp256-sha256`
- `mlkem1024nistp384-sha384`
- `sntrup761x25519-sha512@openssh.com`

## Sensitivity rules

Default rules live in `data/sensitivity_rules.yaml` and cover Vietnamese
banking, government, and medical SNI patterns. Override per engagement:

```yaml
rules:
  - pattern:
      sni_regex: ".*\\.internal\\.acme\\.corp$"
    sensitivity: confidential
    retention: medium
    rationale: "Acme internal HR app"

  - pattern:
      dst_port: [5432, 3306]
    sensitivity: restricted
    retention: long
    rationale: "Database traffic"

  - pattern:
      match_all: true
    sensitivity: internal
    retention: short
```

Pattern fields:

- `sni_regex` — regex matched against TLS SNI
- `dst_port` / `src_port` — int or list of ints
- `dst_ip_cidr` — list of CIDR strings
- `match_all` — wildcard fallback (put last)

First matching rule wins.

## Feeding real traffic

`docs/fixtures/flow_demo.pcap` (used by the demo GIF) is a synthetic fixture
— every handshake byte is hand-crafted in `scripts/mk_flow_demo_pcap.py`
so the demo is deterministic and offline. To analyse real traffic, pick one
of three options.

### 1. Capture your own session with tcpdump

Needs root on the capture host. Open the traffic you want to audit *while*
tcpdump is running, then stop the capture and point the scanner at it:

```bash
sudo tcpdump -i eth0 -s 0 -w /tmp/real.pcap 'tcp port 443 or tcp port 22'
# ... open browser, ssh, API client, whatever issues the handshakes ...
# Ctrl-C when done
pqc-analyzer scan pcap /tmp/real.pcap -o report.json
```

Works on any interface (`eth0`, `wlan0`, `any`, SPAN/mirror ports).

### 2. Drive handshakes from the scanner host

If you just need real handshakes against public test targets (to validate
the scanner or produce fixtures), use the helper script:

```bash
sudo ./scripts/generate_test_pcaps.sh /tmp/real_pcaps
pqc-analyzer scan pcap /tmp/real_pcaps/tls13_hybrid_mlkem.pcap
```

It runs `openssl s_client` + `ssh` against `www.google.com`,
`pq.cloudflareresearch.com`, and `github.com:22`, capturing via tcpdump.
Requires `tcpdump` + `openssl`.

### 3. Existing captures

The scanner accepts any `.pcap` / `.pcapng` it can open. Common sources:

- **Wireshark** — `File → Save As → .pcap`
- **Suricata / Zeek** rotating PCAP dumps
- **SPAN / mirror ports** on a core switch, piped into continuous tcpdump
- **Cloud network taps** — AWS VPC Traffic Mirroring, Azure vTAP, GCP Packet
  Mirroring (they all emit standard PCAP)

```bash
pqc-analyzer scan pcap /path/to/existing.pcap
```

No decryption keys needed — handshakes travel in plaintext, so passive
capture is sufficient. The scanner never reads post-handshake bytes.

### Continuous deployment

For a corporate SOC, the typical pattern is:

```bash
# Rotate hourly PCAPs on a SPAN port
tcpdump -i mirror0 -w /var/captures/net-%Y%m%d-%H.pcap -G 3600 \
  'tcp port 443 or tcp port 22 or tcp port 8443'

# Hourly cron: scan the previous hour
pqc-analyzer scan pcap /var/captures/net-$(date -d '1 hour ago' +%Y%m%d-%H).pcap \
  -o /var/reports/hndl-$(date +%Y%m%d-%H).json
```

Feed the resulting JSON into `pqc-analyzer roadmap` or your SIEM.

## What the analyser does NOT do

- Decrypt TLS payloads — post-handshake bytes stay opaque
- Active probing — this is a *passive* analyser; use `scan tls --pq-probe`
  for active hybrid-support checks
- IKEv2 / QUIC / IPsec transport decode (roadmap)
- PCAP live capture (roadmap — phase 4)

See `docs/hndl-scoring.md` for the risk formula.
