"""Classify flows into DataSensitivity + RetentionClass from YAML rules."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from src.flow_analyzer.models import DataSensitivity, Flow, RetentionClass

DEFAULT_RULES_PATH = Path(__file__).resolve().parents[2] / "data" / "sensitivity_rules.yaml"


@dataclass(frozen=True)
class _Rule:
    sni_regex: re.Pattern[str] | None
    dst_ports: frozenset[int]
    src_ports: frozenset[int]
    dst_ip_nets: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]
    match_all: bool
    sensitivity: DataSensitivity
    retention: RetentionClass
    rationale: str


class ClassificationRules:
    """Compiled ruleset. Use `load()` to read a YAML file."""

    def __init__(self, rules: list[_Rule]) -> None:
        self._rules = rules

    @classmethod
    def load(cls, path: str | Path | None = None) -> ClassificationRules:
        try:
            import yaml
        except ImportError as exc:
            raise ModuleNotFoundError(
                'PyYAML required for sensitivity rules. Install with: '
                'pip install "vn-pqc-analyzer[flow]"'
            ) from exc

        p = Path(path) if path else DEFAULT_RULES_PATH
        raw = yaml.safe_load(p.read_text(encoding="utf-8"))
        if not isinstance(raw, dict) or "rules" not in raw:
            raise ValueError(f"{p}: expected top-level 'rules' list")

        compiled: list[_Rule] = []
        for i, entry in enumerate(raw["rules"]):
            compiled.append(_compile_rule(entry, source=f"{p}#{i}"))
        return cls(compiled)

    def classify(self, flow: Flow) -> tuple[DataSensitivity, RetentionClass, str]:
        for rule in self._rules:
            if _matches(rule, flow):
                return rule.sensitivity, rule.retention, rule.rationale
        # Should be unreachable if YAML has a match_all rule; default safety net.
        return DataSensitivity.INTERNAL, RetentionClass.SHORT, "no rule matched"


def _compile_rule(entry: dict[str, Any], source: str) -> _Rule:
    pattern = entry.get("pattern", {}) or {}
    sens = DataSensitivity(entry["sensitivity"])
    retention = RetentionClass(entry["retention"])
    rationale = entry.get("rationale", "")

    sni_regex_raw = pattern.get("sni_regex")
    sni_regex = re.compile(sni_regex_raw, re.IGNORECASE) if sni_regex_raw else None

    dst_ports = _as_port_set(pattern.get("dst_port"), source, "dst_port")
    src_ports = _as_port_set(pattern.get("src_port"), source, "src_port")

    dst_ip_nets: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for cidr in pattern.get("dst_ip_cidr", []) or []:
        dst_ip_nets.append(ipaddress.ip_network(cidr, strict=False))

    match_all = bool(pattern.get("match_all", False))

    return _Rule(
        sni_regex=sni_regex,
        dst_ports=dst_ports,
        src_ports=src_ports,
        dst_ip_nets=tuple(dst_ip_nets),
        match_all=match_all,
        sensitivity=sens,
        retention=retention,
        rationale=rationale,
    )


def _as_port_set(value: Any, source: str, field: str) -> frozenset[int]:
    if value is None:
        return frozenset()
    if isinstance(value, int):
        return frozenset({value})
    if isinstance(value, list) and all(isinstance(v, int) for v in value):
        return frozenset(value)
    raise ValueError(f"{source}: {field} must be int or list[int], got {value!r}")


def _matches(rule: _Rule, flow: Flow) -> bool:
    if rule.match_all:
        return True

    any_predicate = False

    if rule.sni_regex is not None:
        any_predicate = True
        if not flow.server_name or not rule.sni_regex.match(flow.server_name):
            return False

    if rule.dst_ports:
        any_predicate = True
        if flow.dst_port not in rule.dst_ports:
            return False

    if rule.src_ports:
        any_predicate = True
        if flow.src_port not in rule.src_ports:
            return False

    if rule.dst_ip_nets:
        any_predicate = True
        try:
            ip = ipaddress.ip_address(flow.dst_ip)
        except ValueError:
            return False
        if not any(ip in net for net in rule.dst_ip_nets):
            return False

    # A rule with zero predicates and no match_all matches nothing.
    return any_predicate


def classify_flow(
    flow: Flow, rules: ClassificationRules | None = None
) -> tuple[DataSensitivity, RetentionClass, str]:
    """One-shot classifier — loads default rules if none provided."""
    if rules is None:
        rules = ClassificationRules.load()
    return rules.classify(flow)
