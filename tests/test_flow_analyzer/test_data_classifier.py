"""Sensitivity classifier — YAML loading + rule precedence."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from src.flow_analyzer.data_classifier import ClassificationRules
from src.flow_analyzer.models import DataSensitivity, Flow, Protocol, RetentionClass


def _flow(*, sni: str | None = None, dst_port: int = 443) -> Flow:
    now = datetime.now(tz=timezone.utc)
    return Flow(
        src_ip="10.0.0.1", dst_ip="10.0.0.2",
        src_port=40000, dst_port=dst_port,
        transport="tcp", protocol=Protocol.TLS_1_3,
        first_seen=now, last_seen=now,
        server_name=sni,
    )


@pytest.fixture
def rules_file(tmp_path: Path) -> Path:
    path = tmp_path / "rules.yaml"
    path.write_text(
        """
rules:
  - pattern:
      sni_regex: ".*\\\\.bank\\\\.vn$"
    sensitivity: restricted
    retention: long
    rationale: "bank test rule"
  - pattern:
      dst_port: 22
    sensitivity: confidential
    retention: medium
    rationale: "ssh admin"
  - pattern:
      match_all: true
    sensitivity: internal
    retention: short
    rationale: "default"
""".strip(),
        encoding="utf-8",
    )
    return path


def test_first_rule_wins(rules_file: Path) -> None:
    rules = ClassificationRules.load(rules_file)
    sens, retention, _ = rules.classify(_flow(sni="www.example.bank.vn"))
    assert sens == DataSensitivity.RESTRICTED
    assert retention == RetentionClass.LONG


def test_port_rule_matches(rules_file: Path) -> None:
    rules = ClassificationRules.load(rules_file)
    sens, retention, _ = rules.classify(_flow(dst_port=22))
    assert sens == DataSensitivity.CONFIDENTIAL
    assert retention == RetentionClass.MEDIUM


def test_default_fallback_matches(rules_file: Path) -> None:
    rules = ClassificationRules.load(rules_file)
    sens, retention, _ = rules.classify(_flow(dst_port=443))
    assert sens == DataSensitivity.INTERNAL
    assert retention == RetentionClass.SHORT


def test_default_rules_file_loads() -> None:
    """Repo-shipped rules must parse without errors."""
    rules = ClassificationRules.load()  # loads default path
    # Match_all fallback guarantees something always classifies.
    sens, retention, _ = rules.classify(_flow(dst_port=9999))
    assert sens == DataSensitivity.INTERNAL
    assert retention == RetentionClass.SHORT


def test_invalid_yaml_shape_raises(tmp_path: Path) -> None:
    bad = tmp_path / "bad.yaml"
    bad.write_text("not_rules: []", encoding="utf-8")
    with pytest.raises(ValueError):
        ClassificationRules.load(bad)


def test_default_rules_gov_vn_hits_secret_lifetime() -> None:
    rules = ClassificationRules.load()
    sens, retention, _ = rules.classify(_flow(sni="dichvucong.gov.vn"))
    assert sens == DataSensitivity.SECRET
    assert retention == RetentionClass.LIFETIME
