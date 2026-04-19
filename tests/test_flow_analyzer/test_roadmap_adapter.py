"""Roadmap input adapter — auto-detect scanner vs flow_analyzer JSON."""

from __future__ import annotations

import json
from pathlib import Path

from src.roadmap.input_adapter import load_findings
from src.utils.constants import RiskLevel


def test_load_scanner_json_unchanged(tmp_path: Path) -> None:
    payload = {
        "results": [
            {
                "findings": [
                    {
                        "component": "tls-endpoint",
                        "algorithm": "RSA-2048",
                        "risk_level": "CRITICAL",
                        "quantum_vulnerable": True,
                        "location": "example.com:443",
                        "replacement": ["ML-DSA-65"],
                        "migration_priority": 1,
                        "note": "Shor-breakable",
                    }
                ]
            }
        ]
    }
    path = tmp_path / "scanner.json"
    path.write_text(json.dumps(payload))
    findings = load_findings(path)
    assert len(findings) == 1
    assert findings[0].algorithm == "RSA-2048"
    assert findings[0].risk_level == RiskLevel.CRITICAL


def test_load_flow_report_drops_safe_flows(tmp_path: Path) -> None:
    payload = {
        "source": "x.pcap",
        "duration_seconds": 10.0,
        "total_flows": 2,
        "total_bytes": 1000,
        "generated_at": "2026-04-19T00:00:00+00:00",
        "aggregate": {"flows_by_risk": {}, "bytes_by_risk": {}, "flows_by_protocol": {},
                       "top_vulnerable_endpoints": [], "hndl_exposed_bytes_per_day": 0.0,
                       "pqc_adoption_pct": 0.0},
        "flows": [
            {
                "flow": {
                    "server_name": "api.bank.vn",
                    "dst_ip": "10.0.0.1", "dst_port": 443,
                    "protocol": "tls_1.2",
                    "crypto": {
                        "kex_algorithm": "ECDHE",
                        "is_hybrid_pqc": False,
                        "is_pure_pqc": False,
                    },
                },
                "score": {"risk_level": "HIGH", "rationale": "classical ECDHE + restricted bank"},
            },
            {
                "flow": {
                    "server_name": "www.example.com",
                    "dst_ip": "10.0.0.2", "dst_port": 443,
                    "protocol": "tls_1.3",
                    "crypto": {
                        "kex_algorithm": "X25519MLKEM768",
                        "is_hybrid_pqc": True,
                        "is_pure_pqc": False,
                    },
                },
                "score": {"risk_level": "SAFE", "rationale": "hybrid PQC"},
            },
        ],
    }
    path = tmp_path / "flow.json"
    path.write_text(json.dumps(payload))
    findings = load_findings(path)
    assert len(findings) == 1
    assert findings[0].location == "api.bank.vn:443"
    assert findings[0].risk_level == RiskLevel.HIGH
    assert findings[0].quantum_vulnerable is True
    assert findings[0].component == "tls-flow"
    assert "X25519MLKEM768" in findings[0].replacement[0]
    assert findings[0].detection_mode == "flow_passive"


def test_hybrid_pqc_flow_marked_safe_and_excluded(tmp_path: Path) -> None:
    payload = {
        "source": "x.pcap", "duration_seconds": 1.0, "total_flows": 1, "total_bytes": 0,
        "generated_at": "2026-04-19T00:00:00+00:00",
        "aggregate": {"flows_by_risk": {}, "bytes_by_risk": {}, "flows_by_protocol": {},
                       "top_vulnerable_endpoints": [], "hndl_exposed_bytes_per_day": 0.0,
                       "pqc_adoption_pct": 100.0},
        "flows": [
            {
                "flow": {"server_name": "pq.example", "dst_ip": "1.1.1.1", "dst_port": 443,
                          "protocol": "tls_1.3",
                          "crypto": {"kex_algorithm": "X25519MLKEM768", "is_hybrid_pqc": True, "is_pure_pqc": False}},
                "score": {"risk_level": "SAFE", "rationale": "hybrid"},
            }
        ],
    }
    path = tmp_path / "pure_safe.json"
    path.write_text(json.dumps(payload))
    assert load_findings(path) == []
