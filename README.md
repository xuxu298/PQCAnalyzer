# VN-PQC Readiness Analyzer

[![CI](https://github.com/xuxu298/PQCAnalyzer/actions/workflows/ci.yml/badge.svg)](https://github.com/xuxu298/PQCAnalyzer/actions)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://python.org)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

**Assess your system's readiness for Post-Quantum Cryptography migration.**

Open-source tool for scanning cryptographic algorithms in your infrastructure, benchmarking PQC performance, and generating actionable migration roadmaps — designed for Vietnam/ASEAN context.

[Tieng Viet](#tieng-viet) | [English](#features)

---

## Features

### Community Edition (this repo)

- **Crypto Inventory Scanner** — TLS endpoints, certificates, SSH/VPN configs, source code
- **PQC Benchmarker** — Compare classical vs PQC algorithms (ML-KEM, ML-DSA) on your hardware
- **Migration Roadmap** — Risk scoring, priority engine, 4-phase migration plan with cost estimation
- **Compliance Checker** — NIST FIPS 203/204, SP 800-131A, Vietnam Ban Co Yeu guidelines
- **CLI** — Full command-line interface with rich output
- **Bilingual** — Vietnamese/English support
- **JSON output** — Scan results and roadmaps exported as structured JSON

### Enterprise Edition

For government and enterprise clients, we offer additional modules:

- **REST API** — FastAPI backend for integration
- **Web UI** — React dashboard with interactive charts, risk heatmaps, benchmark visualizations
- **Report Generator** — HTML (dark theme), PDF (WeasyPrint), SARIF (CI/CD), Executive Summary
- **Docker Compose** — Multi-service deployment with web frontend
- **Custom branding** — Tailored report templates and UI for your organization

Contact: **support@vradar.io** for enterprise licensing.

## Quick Start

### Install

```bash
pip install -e .
```

With development tools:

```bash
pip install -e ".[dev]"
```

With PQC benchmark support (requires liboqs):

```bash
pip install -e ".[benchmark]"
```

### CLI Usage

```bash
# Scan a TLS endpoint
pqc-analyzer scan tls example.com --port 443

# Scan SSH configuration
pqc-analyzer scan ssh /etc/ssh/sshd_config

# Scan VPN configuration
pqc-analyzer scan vpn /etc/openvpn/server.conf

# Scan source code for crypto usage
pqc-analyzer scan code /path/to/project/src

# Scan config files (nginx, apache, haproxy)
pqc-analyzer scan config /etc/nginx/nginx.conf

# Generate migration roadmap
pqc-analyzer roadmap generate --findings scan_results.json

# Run PQC benchmark
pqc-analyzer benchmark kem --iterations 1000
pqc-analyzer benchmark sign --iterations 1000

# Export results as JSON
pqc-analyzer scan tls example.com -o results.json
```

### Docker

```bash
docker build -t pqc-analyzer .
docker run pqc-analyzer scan tls example.com
```

## Architecture

```
src/
  scanner/          # Crypto inventory scanner (TLS, cert, SSH, VPN, code)
  benchmarker/      # PQC performance benchmarker (KEM, signatures)
  roadmap/          # Migration roadmap (risk, recommendation, priority, cost)
  utils/            # Shared utilities (crypto DB, i18n, constants)
  cli.py            # CLI entry point (typer)

data/               # Algorithm database, NIST/Vietnam guidelines
examples/           # Demo scripts
tests/              # 163+ tests
```

## Scan Targets

| Scanner | Target | What it finds |
|---------|--------|---------------|
| TLS | `host:port` | Cipher suites, key exchange, protocol versions |
| Certificate | X.509 chain | Signature algorithms, key types, expiry |
| SSH | `sshd_config` | KEX, ciphers, MACs, host key algorithms |
| VPN | OpenVPN/WireGuard/IPSec configs | Crypto primitives, DH groups |
| Code | Source directories | Crypto API usage in Python/Java/Go/JS/C |
| Config | nginx/apache/haproxy | SSL/TLS settings |

## Output Format

### CLI Roadmap Output

```
Overall Risk: CRITICAL
Total findings: 5 | Critical: 2 | QV: 4

Phase 1 — Quick Wins (3-6 months)
  Enable hybrid KEX on TLS endpoints (8h)
  Upgrade SSH weak ciphers (4h)
  Total effort: 12 person-hours

Phase 2 — Core Migration (6-18 months)
  Migrate VPN to PQC-aware stack (40h)
  Update application crypto libraries (80h)
  Total effort: 120 person-hours

Cost Estimation:
  Total effort: 200 person-hours
  Timeline: 24 months
  Cost range: 80 trieu VND — 160 trieu VND

Compliance:
  NON_COMPLIANT NIST FIPS 203
  PARTIAL SP 800-131A Rev2
```

### JSON Export

All scan results and roadmaps export as structured JSON via CLI (`-o output.json`).

## Risk Levels

| Level | Description | Action |
|-------|-------------|--------|
| CRITICAL | Quantum-vulnerable + internet-facing | Migrate immediately |
| HIGH | Quantum-vulnerable or broken classical | Migrate in 3-6 months |
| MEDIUM | Weak but not broken | Upgrade when convenient |
| LOW | Acceptable but not optimal | Monitor |
| SAFE | Post-quantum safe or AES-256 | No action needed |

## Testing

```bash
pytest -v                          # Run all tests
pytest --cov=src --cov-report=html # With coverage
pytest -m "not integration"        # Skip network tests
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

MIT License. See [LICENSE](LICENSE).

---

## Tieng Viet

# VN-PQC Readiness Analyzer

**Cong cu danh gia muc do san sang chuyen doi mat ma hau luong tu.**

Cong cu ma nguon mo giup quet thuat toan mat ma trong ha tang, benchmark hieu nang PQC, va tao lo trinh chuyen doi — thiet ke cho boi canh Viet Nam/ASEAN.

### Phien ban

| | Community (ma nguon mo) | Enterprise (lien he) |
|---|---|---|
| Scanner (TLS, SSH, VPN, Code) | Co | Co |
| Benchmarker (KEM, Signatures) | Co | Co |
| Roadmap + Chi phi + Tuan thu | Co | Co |
| CLI | Co | Co |
| JSON output | Co | Co |
| **REST API** | - | **Co** |
| **Web UI (React dashboard)** | - | **Co** |
| **Bao cao HTML/PDF/SARIF** | - | **Co** |
| **Tom tat Dieu hanh** | - | **Co** |
| **Tuy chinh thuong hieu** | - | **Co** |

### Cai dat nhanh

```bash
pip install -e .

# Quet TLS
pqc-analyzer scan tls example.vn --port 443

# Tao lo trinh chuyen doi
pqc-analyzer roadmap generate --findings ket_qua.json

# Chay benchmark
pqc-analyzer benchmark kem --iterations 1000
```

### Doi tuong su dung

| Nguoi dung | Nhu cau | Output |
|------------|---------|--------|
| Ky su IT/vien thong | Biet he thong dung crypto gi, thay bang gi | Danh sach findings + benchmark |
| Security engineer | Danh gia risk, compliance | Risk matrix + ke hoach xu ly |
| Policy maker (Ban Co Yeu, Bo TT&TT) | Tong quan ha tang, ngan sach, timeline | JSON (Enterprise: bao cao dieu hanh + Web UI) |
| Nghien cuu sinh | Reproduce ket qua | Raw data + JSON |

Lien he **support@vradar.io** de su dung phien ban Enterprise.

---

**Developed by:** [Nguyen Dong](https://www.linkedin.com/in/dongnx/) — Founder of [vradar.io](https://vradar.io) | **License:** MIT
