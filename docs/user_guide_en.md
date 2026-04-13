# User Guide (English)

## Installation

### Prerequisites

- Python 3.10 or later
- pip

### Basic Install

```bash
git clone https://github.com/xuxu298/PQCAnalyzer.git
cd PQCAnalyzer
pip install -e .
```

### Full Install (all features)

```bash
pip install -e ".[all]"
```

### Optional Dependencies

```bash
pip install -e ".[dev]"        # Development tools (pytest, ruff, mypy)
pip install -e ".[web]"        # FastAPI backend
pip install -e ".[report]"     # PDF reports (WeasyPrint)
pip install -e ".[benchmark]"  # PQC benchmarks (liboqs)
```

## CLI Commands

### Scanning

```bash
# TLS endpoint
pqc-analyzer scan tls example.com --port 443 --output results.json

# SSH configuration
pqc-analyzer scan ssh /etc/ssh/sshd_config

# VPN configurations
pqc-analyzer scan vpn /etc/openvpn/server.conf
pqc-analyzer scan vpn /etc/wireguard/wg0.conf

# Source code
pqc-analyzer scan code ./src --output code_findings.json

# Web server config (nginx, apache, haproxy)
pqc-analyzer scan config /etc/nginx/nginx.conf
```

### Benchmarking

```bash
# KEM algorithms (Kyber vs RSA/ECDH)
pqc-analyzer benchmark kem --iterations 1000

# Signature algorithms (Dilithium vs RSA/ECDSA)
pqc-analyzer benchmark sign --iterations 1000

# All benchmarks
pqc-analyzer benchmark all

# Hardware info
pqc-analyzer benchmark hardware
```

### Roadmap Generation

```bash
# Generate from scan results
pqc-analyzer roadmap generate --findings results.json --org "My Company"

# With Vietnamese output
pqc-analyzer roadmap generate --findings results.json --language vi
```

### Report Generation

```bash
# HTML report
pqc-analyzer report html --findings results.json -o report.html

# JSON export
pqc-analyzer report json --findings results.json -o report.json

# SARIF for CI/CD
pqc-analyzer report sarif --findings results.json -o report.sarif

# Executive summary
pqc-analyzer report summary --findings results.json
```

### Common Options

- `--verbose` / `-v` — Increase verbosity (use -vv for debug)
- `--output` / `-o` — Output file path
- `--language` / `-l` — Language: `en` or `vi`
- `--redact` — Redact hostnames/IPs in output

## API Server

```bash
# Start development server
uvicorn src.api.main:app --reload --port 8000

# API documentation
open http://localhost:8000/docs
```

## Web UI

```bash
cd web
npm install
npm run dev
# Open http://localhost:5173
```

The web UI proxies API requests to `localhost:8000`, so ensure the API server is running.

## Docker

```bash
# API only
docker compose up

# API + Web frontend
docker compose --profile web up

# Build and run
docker compose up --build
```

## Understanding Results

### Risk Levels

| Level | Meaning |
|-------|---------|
| CRITICAL | Quantum-vulnerable algorithms on internet-facing services. Immediate action needed. |
| HIGH | Quantum-vulnerable or broken classical algorithms. High priority migration. |
| MEDIUM | Weak but not broken. Upgrade during maintenance windows. |
| LOW | Acceptable but not optimal. Monitor for changes. |
| SAFE | Post-quantum safe or strong symmetric (AES-256). No action needed. |

### Migration Phases

| Phase | Timeline | Focus |
|-------|----------|-------|
| 0: Assessment | 0-3 months | Inventory and risk scoring |
| 1: Quick Wins | 3-6 months | Enable hybrid KEX, upgrade weak ciphers |
| 2: Core Migration | 6-18 months | VPN migration, code changes, certificate prep |
| 3: Full PQC | 18-36 months | Complete certificate migration to PQC |

## Troubleshooting

**"ModuleNotFoundError: No module named 'liboqs'"**
Install benchmark dependencies: `pip install -e ".[benchmark]"`

**"Connection refused" on API**
Ensure the API server is running: `uvicorn src.api.main:app --port 8000`

**"WeasyPrint not found"**
Install report dependencies: `pip install -e ".[report]"`
WeasyPrint also requires system libraries: `apt install libpango-1.0-0 libharfbuzz0b libpangoft2-1.0-0`
