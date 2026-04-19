# HNDL Scoring Formula

Every flow analysed by `scan pcap` is scored on a 0–100 scale representing
its **Harvest-Now-Decrypt-Later** risk. The formula:

```
HNDL_Score = 100 × V × S × R × E
```

| Symbol | Factor | Range |
|---|---|---|
| V | Vulnerability — how breakable the kex is | 0.0 – 1.0 |
| S | Sensitivity — data classification weight | 0.1 – 1.0 |
| R | Retention — how long the data stays valuable | 0.1 – 1.0 |
| E | Exposure — log-scaled volume sigmoid | 0.0 – 1.0 |

## V — Vulnerability component

Grounded in Shor (breaks RSA / ECDHE / DH) and Grover (quadratic symmetric
speedup). Hybrid PQC hedges; pure PQC is effectively safe.

| Kex | V |
|---|---|
| RSA-2048 / 3072 / 4096 | 1.00 |
| DH / DHE group 14-18 | 0.95 |
| ECDHE (P-256 / P-384 / P-521 / X25519 / X448) | 0.90 |
| Hybrid: X25519MLKEM768, Kyber-hybrid drafts | 0.10 |
| Hybrid SSH: `mlkem768x25519-sha256`, `sntrup761x25519` | 0.10 |
| Pure ML-KEM-512 | 0.05 |
| Pure ML-KEM-768 / 1024 | 0.00 |
| Unknown crypto | 0.90 (classical-assumed) |

Full table in `src/flow_analyzer/hndl_scorer.py::KEX_VULNERABILITY`.

## S — Sensitivity component

Default weighting, configurable via `data/sensitivity_rules.yaml`:

| Class | Weight | Example |
|---|---|---|
| `public` | 0.1 | CDN, static sites, marketing |
| `internal` | 0.3 | Corporate intranet, generic API |
| `confidential` | 0.6 | HR, internal admin, SSH |
| `restricted` | 0.8 | Banking, PII, financial |
| `secret` | 1.0 | Medical, government, defense |

## R — Retention component

How long the cleartext stays valuable if decrypted later:

| Class | Weight | Horizon |
|---|---|---|
| `ephemeral` | 0.1 | < 1 year |
| `short` | 0.3 | 1–5 years |
| `medium` | 0.6 | 5–15 years |
| `long` | 0.8 | 15–30 years |
| `lifetime` | 1.0 | > 30 years (medical, state secrets) |

## E — Exposure factor

```
E = min(1.0, log₁₀(bytes_total + 1) / 10)
```

Sigmoid-like; rewards larger captured volume without letting a single 100 GB
flow dominate the report.

| Volume | E |
|---|---|
| 1 KB | ~0.30 |
| 1 MB | ~0.60 |
| 1 GB | ~0.90 |
| ≥ 10 TB | 1.00 |

## Risk bands

| Overall score | Band | Action |
|---|---|---|
| ≥ 60 | **CRITICAL** | Migrate to hybrid kex before the next maintenance window |
| ≥ 40 | **HIGH** | Plan migration in current quarter |
| ≥ 20 | **MEDIUM** | Include in next PQ-readiness cycle |
| ≥ 5 | **LOW** | Monitor |
| < 5 | **SAFE** | No action |

## Worked examples

### Medical data, RSA-2048, 1 GB capture

- V = 1.00 (RSA-2048)
- S = 1.00 (`secret` — medical)
- R = 1.00 (`lifetime`)
- E ≈ 0.90 (~1 GB)

Score = 100 × 1.00 × 1.00 × 1.00 × 0.90 = **90 → CRITICAL**

### Bank SNI, X25519MLKEM768 hybrid, 500 MB

- V = 0.10 (hybrid)
- S = 0.80 (`restricted`)
- R = 0.80 (`long`)
- E ≈ 0.87

Score = 100 × 0.10 × 0.80 × 0.80 × 0.87 ≈ **5.6 → LOW**

### Public CDN, ECDHE, 10 GB

- V = 0.90
- S = 0.10 (`public`)
- R = 0.10 (`ephemeral`)
- E ≈ 0.97

Score = 100 × 0.90 × 0.10 × 0.10 × 0.97 ≈ **0.87 → SAFE**

## Academic anchor

The formula is inspired by **Kagai (2025)**
*"A Temporal HNDL Risk Model"*, MDPI Future Internet 6/4/100. We simplify
by omitting the Mosca-window time term because reports are point-in-time;
add it back if you need time-to-quantum in your model.

## Limitations

- V table is hand-curated — extending it requires editing
  `KEX_VULNERABILITY` in `hndl_scorer.py`.
- Exposure only counts bytes *observed in the capture window*; it does not
  extrapolate per-day traffic (the aggregate report does, separately).
- Rationale and recommended_action are template strings, not ML-generated.
