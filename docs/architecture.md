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
  cli.py          <-- CLI entry point (typer)
```

## Key Design Decisions

### 1. Community / Enterprise Separation

The project follows a dual-edition model:

**Community Edition** (`main` branch — open source):
- Scanner, benchmarker, roadmap, CLI
- JSON output for all data
- No API server, no web UI, no report generator

**Enterprise Edition** (`enterprise` branch — licensed):
- Everything in Community, plus:
- `src/api/` — FastAPI REST backend
- `web/` — React frontend with dashboard, charts, bilingual UI
- `src/reporter/` — HTML, PDF, SARIF, Executive Summary reports
- Docker Compose with web profile
- Custom branding support

**Technical design for separation:**
- All imports from `src/reporter/` are lazy (inside function bodies)
- CLI catches `ImportError` and returns clear error messages
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

All 163+ tests run offline (no network, no liboqs required):
- Scanner tests use fixture config files
- Benchmark tests mock liboqs when unavailable
- Integration tests (network, real TLS) marked with `@pytest.mark.integration`

## Data Flow

1. **Scanner** produces `Finding` objects (component, algorithm, risk, location)
2. **Risk Scorer** computes `RiskScore` for each finding
3. **Recommendation Engine** matches findings to migration templates
4. **Priority Engine** assigns phases and builds `MigrationTask` list
5. **Cost Estimator** calculates person-hours and VND costs
6. **Compliance Checker** evaluates against NIST/Vietnam standards
7. **CLI** outputs results as rich terminal tables or JSON files

---

**Developed by:** [Nguyen Dong](https://www.linkedin.com/in/dongnx/) — Founder of [vradar.io](https://vradar.io)
