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

### Optional Dependencies

```bash
pip install -e ".[dev]"        # Development tools (pytest, ruff, mypy)
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

### Common Options

- `--verbose` / `-v` — Increase verbosity (use -vv for debug)
- `--output` / `-o` — Output file path
- `--language` / `-l` — Language: `en` or `vi`
- `--redact` — Redact hostnames/IPs in output

## Docker

```bash
docker build -t pqc-analyzer .
docker run pqc-analyzer scan tls example.com
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

**"WeasyPrint not found"**
Report generation is available in the Enterprise Edition. Contact support@vradar.io.

---

**Developed by:** [Nguyen Dong](https://www.linkedin.com/in/dongnx/) — Founder of [vradar.io](https://vradar.io)
