# Architecture

## Overview

VN-PQC Readiness Analyzer follows a modular pipeline architecture:

```
Scan -> Score -> Recommend -> Prioritize -> Estimate -> Report
```

## Module Dependency Graph

```
src/
  utils/          <-- Shared: constants, crypto_db, i18n
    |
  scanner/        <-- Module 1: Crypto Inventory
    |               (tls, cert, ssh, vpn, code, config)
    |
  benchmarker/    <-- Module 2: PQC Benchmarker
    |               (kem, sign, memory, throughput, handshake)
    |
  roadmap/        <-- Module 3: Migration Roadmap
    |               (risk_scorer -> recommendation -> priority_engine
    |                -> cost_estimator -> timeline -> compliance)
    |
  reporter/       <-- Output: Reports
    |               (html, json, sarif, pdf, executive_summary)
    |
  api/            <-- FastAPI REST backend
    |               (routes: scanner, benchmarker, roadmap, reports)
    |
  cli.py          <-- CLI entry point (typer)

web/              <-- React frontend (independent, optional)
```

## Key Design Decisions

### 1. Community / Enterprise Separation

The project follows a dual-edition model:

**Community Edition** (`main` branch — open source):
- Scanner, benchmarker, roadmap, CLI, API
- JSON output for all data
- No web UI, no report generator

**Enterprise Edition** (`enterprise` branch — licensed):
- Everything in Community, plus:
- `web/` — React frontend with dashboard, charts, bilingual UI
- `src/reporter/` — HTML, PDF, SARIF, Executive Summary reports
- Docker Compose with web profile
- Custom branding support

**Technical design for separation:**
- All imports from `src/reporter/` are lazy (inside function bodies)
- CLI and API catch `ImportError` and return clear error messages
- `web/` communicates with backend only via REST API
- No Python code imports from `web/`

### 2. Risk Scoring Formula

```
total_score = vulnerability_weight x exposure_factor x data_sensitivity x harvest_now_risk
```

- `vulnerability_weight`: 0 (SAFE) to 10 (CRITICAL)
- `exposure_factor`: 1 (internal) to 3 (internet-facing)
- `data_sensitivity`: 1 (low) to 3 (high, keyword-based)
- `harvest_now_risk`: 1 (no HNDL) to 3 (key exchange, highest HNDL risk)

### 3. 4-Phase Migration Model

| Phase | Name | Timeline | What |
|-------|------|----------|------|
| 0 | Assessment | 0-3 months | Inventory, risk scoring |
| 1 | Quick Wins | 3-6 months | Hybrid KEX, cipher upgrades |
| 2 | Core Migration | 6-18 months | VPN, code, certificate prep |
| 3 | Full PQC | 18-36 months | Full certificate migration |

### 4. Algorithm Classification

`data/algorithms.json` contains 41+ algorithms with:
- Quantum vulnerability status
- NIST security level
- Recommended replacements
- Risk classification

The `crypto_db.py` fuzzy classifier matches algorithm strings from various formats
(OpenSSL names, IANA names, config file formats) to canonical entries.

### 5. Offline-First Testing

All 171+ tests run offline (no network, no liboqs required):
- Scanner tests use fixture config files
- Benchmark tests mock liboqs when unavailable
- Integration tests (network, real TLS) marked with `@pytest.mark.integration`

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Health check |
| POST | `/scan/config` | Scan config file |
| POST | `/scan/ssh` | Scan SSH config |
| POST | `/scan/vpn` | Scan VPN config |
| POST | `/scan/code` | Scan source code |
| GET | `/benchmark/hardware` | Get hardware info |
| POST | `/benchmark/kem` | Run KEM benchmark |
| POST | `/benchmark/sign` | Run signature benchmark |
| POST | `/roadmap/generate` | Generate migration roadmap |
| POST | `/report/generate` | Generate report |
| POST | `/report/html` | Generate HTML report |
| GET | `/report/formats` | List report formats |

## Data Flow

1. **Scanner** produces `Finding` objects (component, algorithm, risk, location)
2. **Risk Scorer** computes `RiskScore` for each finding
3. **Recommendation Engine** matches findings to migration templates
4. **Priority Engine** assigns phases and builds `MigrationTask` list
5. **Cost Estimator** calculates person-hours and VND costs
6. **Compliance Checker** evaluates against NIST/Vietnam standards
7. **Reporter** formats everything into HTML/JSON/SARIF/PDF output
