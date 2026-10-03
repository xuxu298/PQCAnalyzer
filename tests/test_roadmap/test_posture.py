"""Overall posture: the worst finding, and whether HNDL applies."""

from __future__ import annotations

import pytest

from src.roadmap.posture import overall_posture
from src.scanner.models import Finding, TLSInfo
from src.utils.constants import RiskLevel


def _f(component, risk, *, qv=True):
    return Finding(component=component, algorithm="x", risk_level=risk,
                   quantum_vulnerable=qv, location="h:443")


HYBRID_KEX = _f(TLSInfo.KEY_EXCHANGE, RiskLevel.SAFE, qv=False)
CLASSICAL_KEX = _f(TLSInfo.KEY_EXCHANGE, RiskLevel.CRITICAL)
LEAF = _f(TLSInfo.CERT_PUBLIC_KEY, RiskLevel.HIGH)


@pytest.mark.parametrize("findings,expected", [
    ([], RiskLevel.SAFE),
    ([HYBRID_KEX], RiskLevel.SAFE),
    ([HYBRID_KEX, _f(TLSInfo.CERT_PUBLIC_KEY, RiskLevel.LOW)], RiskLevel.LOW),
    ([_f("Bulk Encryption", RiskLevel.MEDIUM, qv=False)], RiskLevel.MEDIUM),
    ([HYBRID_KEX, LEAF], RiskLevel.HIGH),
    ([CLASSICAL_KEX, LEAF], RiskLevel.CRITICAL),
])
def test_overall_is_the_worst_finding_not_a_default(findings, expected):
    # The roadmap used to report MEDIUM for anything below HIGH, even all-SAFE.
    assert overall_posture(findings).risk == expected


def test_hndl_exposure_follows_classical_key_exchange():
    assert overall_posture([CLASSICAL_KEX, LEAF]).hndl_exposed is True
    assert overall_posture([HYBRID_KEX, LEAF]).hndl_exposed is False
    assert overall_posture([_f("tls-flow", RiskLevel.HIGH)]).hndl_exposed is True
