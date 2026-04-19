"""Load findings from scanner OR flow_analyzer JSON into a shared shape.

The roadmap module was originally built against scanner JSON (a list of
`results` → each with `findings`). With v0.2 we add PCAP flow analysis,
whose JSON shape is different. This adapter auto-detects the source and
converts flow entries into synthetic `Finding` objects so the existing
roadmap pipeline (risk_scorer → priority_engine → cost_estimator) works
without refactor.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from src.scanner.models import Finding
from src.utils.constants import RiskLevel


def load_findings(path: str | Path) -> list[Finding]:
    """Auto-detect JSON shape and return a Finding list."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if _looks_like_flow_report(data):
        return _findings_from_flow_report(data)
    return _findings_from_scanner(data)


def _looks_like_flow_report(data: Any) -> bool:
    return (
        isinstance(data, dict)
        and "flows" in data
        and "aggregate" in data
        and "source" in data
    )


def _findings_from_scanner(data: Any) -> list[Finding]:
    findings: list[Finding] = []
    scan_data = data.get("results", data.get("scan_results", []))
    for result in scan_data:
        for f in result.get("findings", []):
            findings.append(
                Finding(
                    component=f["component"],
                    algorithm=f["algorithm"],
                    risk_level=RiskLevel(f["risk_level"]),
                    quantum_vulnerable=f["quantum_vulnerable"],
                    location=f.get("location", ""),
                    replacement=f.get("replacement", []),
                    migration_priority=f.get("migration_priority", 5),
                    note=f.get("note", ""),
                    detection_mode=f.get("detection_mode", ""),
                )
            )
    return findings


# Map flow risk band → scanner RiskLevel + priority.
# Only risky flows produce findings; SAFE flows are silently dropped.
_RISK_BAND_TO_PRIORITY = {
    "CRITICAL": 1,
    "HIGH": 2,
    "MEDIUM": 3,
    "LOW": 4,
}


def _findings_from_flow_report(data: dict) -> list[Finding]:
    findings: list[Finding] = []
    for entry in data.get("flows", []):
        flow = entry["flow"]
        score = entry["score"]
        risk_label = score.get("risk_level", "SAFE")
        if risk_label == "SAFE":
            continue
        crypto = flow.get("crypto") or {}
        kex = crypto.get("kex_algorithm") or "unknown"
        server = flow.get("server_name") or flow.get("dst_ip", "")
        port = flow.get("dst_port", 0)
        is_hybrid = crypto.get("is_hybrid_pqc", False)
        is_pure = crypto.get("is_pure_pqc", False)
        qv = not (is_hybrid or is_pure)

        findings.append(
            Finding(
                component="tls-flow" if "tls" in flow.get("protocol", "") else "ssh-flow",
                algorithm=kex,
                risk_level=RiskLevel(risk_label),
                quantum_vulnerable=qv,
                location=f"{server}:{port}",
                replacement=_suggest_replacement(kex, flow.get("protocol", "")),
                migration_priority=_RISK_BAND_TO_PRIORITY.get(risk_label, 5),
                note=score.get("rationale", ""),
                detection_mode="flow_passive",
            )
        )
    return findings


def _suggest_replacement(kex: str, protocol: str) -> list[str]:
    if kex is None:
        return []
    k = kex.lower()
    if "tls" in protocol:
        if "rsa" in k:
            return ["X25519MLKEM768 + ML-DSA-65"]
        if any(t in k for t in ("ecdhe", "x25519", "secp", "ffdhe", "dhe", "dh")):
            return ["X25519MLKEM768"]
    if "ssh" in protocol:
        return ["mlkem768x25519-sha256", "sntrup761x25519-sha512@openssh.com"]
    return ["X25519MLKEM768"]
