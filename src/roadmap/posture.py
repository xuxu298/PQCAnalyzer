"""Overall posture of a set of findings, for summaries and report covers.

One place decides the headline, so the CLI, the API and every report agree:
the overall level is the worst finding; ``hndl_exposed`` says whether any
classical key exchange is in scope (the part harvest-now-decrypt-later
attacks today); ``planning_only`` marks a HIGH that comes only from leaf
certificates issued by public CAs, which nobody can replace with a
post-quantum certificate yet.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from src.scanner.models import TLSInfo
from src.utils.constants import RiskLevel

if TYPE_CHECKING:
    from collections.abc import Iterable

    from src.scanner.models import Finding

_SEVERITY = [RiskLevel.SAFE, RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL]
# Key exchange as scanners name it; PCAP flow findings ("tls-flow", "ssh-flow")
# rate the key exchange observed on the wire.
_KEX_WORDS = ("key exchange", "kex", "kem", "-flow")
_AUTHENTICATION = {TLSInfo.CERT_PUBLIC_KEY.value, TLSInfo.CERT_SIGNATURE.value}


@dataclass(frozen=True)
class Posture:
    risk: RiskLevel
    hndl_exposed: bool
    planning_only: bool


def _is_public_leaf_certificate(finding: Finding) -> bool:
    cert = getattr(finding, "certificate", None) or {}
    return (
        finding.component in _AUTHENTICATION
        and cert.get("position") == "leaf"
        and bool(cert.get("public_ca"))
    )


def overall_posture(findings: Iterable[Finding]) -> Posture:
    findings = list(findings)
    if not findings:
        return Posture(RiskLevel.SAFE, hndl_exposed=False, planning_only=False)
    risk = max((RiskLevel(f.risk_level) for f in findings), key=_SEVERITY.index)
    hndl = any(
        f.quantum_vulnerable and any(w in f.component.lower() for w in _KEX_WORDS)
        for f in findings
    )
    planning = risk == RiskLevel.HIGH and all(
        _is_public_leaf_certificate(f) for f in findings if f.risk_level == RiskLevel.HIGH
    )
    return Posture(risk, hndl_exposed=hndl, planning_only=planning)
