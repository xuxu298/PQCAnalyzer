# VN-PQC Readiness Analyzer

[![CI](https://github.com/xuxu298/PQCAnalyzer/actions/workflows/ci.yml/badge.svg)](https://github.com/xuxu298/PQCAnalyzer/actions)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://python.org)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

**Assess your system's readiness for Post-Quantum Cryptography migration.**

Open-source tool for scanning cryptographic algorithms in your infrastructure, benchmarking PQC performance, and generating actionable migration roadmaps — designed for Vietnam/ASEAN context.

[Tieng Viet](#tieng-viet) | [English](#features)

---

## Features

- **Crypto Inventory Scanner** — TLS endpoints, certificates, SSH/VPN configs, source code
- **PQC Benchmarker** — Compare classical vs PQC algorithms (ML-KEM, ML-DSA) on your hardware
- **Migration Roadmap** — Risk scoring, priority engine, 4-phase migration plan
- **Cost Estimator** — Person-hours and VND cost estimates with Vietnam market rates
- **Compliance Checker** — NIST FIPS 203/204, SP 800-131A, Vietnam Ban Co Yeu guidelines
- **Reports** — HTML (dark theme), JSON, SARIF (CI/CD), PDF, Executive Summary
- **Bilingual** — Full Vietnamese/English support
- **Web UI** — React dashboard with interactive charts
- **REST API** — FastAPI backend for integration

## Quick Start

### Install

```bash
pip install -e ".[dev,web]"
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

# Generate HTML report
pqc-analyzer report html --findings scan_results.json -o report.html

# Run PQC benchmark
pqc-analyzer benchmark kem --iterations 1000
pqc-analyzer benchmark sign --iterations 1000
```

### API Server

```bash
# Start the API
uvicorn src.api.main:app --reload

# API docs at http://localhost:8000/docs
```

### Web UI

```bash
cd web
npm install
npm run dev
# Open http://localhost:5173
```

### Docker

```bash
# API only (default)
docker compose up

# API + Web frontend
docker compose --profile web up
```

## Architecture

```
src/
  scanner/          # Crypto inventory scanner (TLS, cert, SSH, VPN, code)
  benchmarker/      # PQC performance benchmarker (KEM, signatures)
  roadmap/          # Migration roadmap (risk, recommendation, priority, cost)
  reporter/         # Report generation (HTML, JSON, SARIF, PDF)
  api/              # FastAPI REST backend
  utils/            # Shared utilities (crypto DB, i18n, constants)

web/                # React frontend (self-contained, can be gitignored)
data/               # Algorithm database, NIST/Vietnam guidelines
examples/           # Demo scripts
tests/              # 171+ tests
```

### Modular Design

The web frontend (`web/`) and report generator (`src/reporter/`) are fully self-contained and independent. For government/enterprise deployments that require custom frontend or report templates:

```bash
# Use the government gitignore template (excludes web/ and src/reporter/)
cp .gitignore.govt .gitignore
```

The CLI and API gracefully handle missing reporter — they return a clear error message instead of crashing. See [`.gitignore.govt`](.gitignore.govt) for a ready-to-use template.

## Scan Targets

| Scanner | Target | What it finds |
|---------|--------|---------------|
| TLS | `host:port` | Cipher suites, key exchange, protocol versions |
| Certificate | X.509 chain | Signature algorithms, key types, expiry |
| SSH | `sshd_config` | KEX, ciphers, MACs, host key algorithms |
| VPN | OpenVPN/WireGuard/IPSec configs | Crypto primitives, DH groups |
| Code | Source directories | Crypto API usage in Python/Java/Go/JS/C |
| Config | nginx/apache/haproxy | SSL/TLS settings |

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

### Tinh nang chinh

- **Quet mat ma** — TLS endpoints, chung chi, SSH/VPN config, source code
- **Benchmark PQC** — So sanh classical vs PQC (ML-KEM, ML-DSA) tren phan cung thuc te
- **Lo trinh chuyen doi** — Danh gia rui ro, uu tien, ke hoach 4 giai doan
- **Uoc tinh chi phi** — Gio cong va chi phi VND theo thi truong Viet Nam
- **Kiem tra tuan thu** — NIST FIPS 203/204, Ban Co Yeu Chinh Phu
- **Bao cao** — HTML, JSON, SARIF, PDF, Tom tat Dieu hanh
- **Song ngu** — Ho tro day du Viet-Anh
- **Web UI** — React dashboard voi bieu do tuong tac
- **REST API** — FastAPI backend de tich hop

### Cai dat nhanh

```bash
pip install -e ".[dev,web]"

# Quet TLS
pqc-analyzer scan tls example.vn --port 443

# Tao lo trinh chuyen doi
pqc-analyzer roadmap generate --findings ket_qua.json

# Tao bao cao HTML
pqc-analyzer report html --findings ket_qua.json -o baocao.html
```

### Doi tuong su dung

| Nguoi dung | Nhu cau | Output |
|------------|---------|--------|
| Ky su IT/vien thong | Biet he thong dung crypto gi, thay bang gi | Danh sach findings + benchmark |
| Security engineer | Danh gia risk, compliance | Risk matrix + ke hoach xu ly |
| Policy maker (Ban Co Yeu, Bo TT&TT) | Tong quan ha tang, ngan sach, timeline | Bao cao dieu hanh |
| Nghien cuu sinh | Reproduce ket qua | Raw data + API |

---

**Author:** Nguyen Dong | **License:** MIT
