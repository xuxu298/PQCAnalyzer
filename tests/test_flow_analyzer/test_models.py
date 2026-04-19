"""Round-trip + weight sanity checks for flow_analyzer data models."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from src.flow_analyzer.models import (
    RETENTION_WEIGHT,
    SENSITIVITY_WEIGHT,
    CryptoPrimitive,
    DataSensitivity,
    Flow,
    Protocol,
    RetentionClass,
)


def test_sensitivity_weights_ordered() -> None:
    ordered = [
        DataSensitivity.PUBLIC,
        DataSensitivity.INTERNAL,
        DataSensitivity.CONFIDENTIAL,
        DataSensitivity.RESTRICTED,
        DataSensitivity.SECRET,
    ]
    weights = [SENSITIVITY_WEIGHT[s] for s in ordered]
    assert weights == sorted(weights)
    assert all(0 < w <= 1 for w in weights)


def test_retention_weights_ordered() -> None:
    ordered = [
        RetentionClass.EPHEMERAL,
        RetentionClass.SHORT,
        RetentionClass.MEDIUM,
        RetentionClass.LONG,
        RetentionClass.LIFETIME,
    ]
    weights = [RETENTION_WEIGHT[r] for r in ordered]
    assert weights == sorted(weights)
    assert all(0 < w <= 1 for w in weights)


def test_flow_five_tuple_stable() -> None:
    now = datetime.now(tz=timezone.utc)
    flow = Flow(
        src_ip="10.0.0.1", dst_ip="10.0.1.1",
        src_port=12345, dst_port=443,
        transport="tcp", protocol=Protocol.TLS_1_3,
        first_seen=now, last_seen=now,
    )
    assert flow.five_tuple == ("10.0.0.1", "10.0.1.1", 12345, 443, "tcp")


def test_crypto_primitive_defaults() -> None:
    cp = CryptoPrimitive()
    assert cp.kex_algorithm is None
    assert cp.is_hybrid_pqc is False
    assert cp.is_pure_pqc is False


def test_crypto_primitive_rejects_unknown_fields() -> None:
    with pytest.raises(Exception):  # pydantic ValidationError
        CryptoPrimitive(kex_algorithm="X25519", bogus="nope")  # type: ignore[call-arg]
