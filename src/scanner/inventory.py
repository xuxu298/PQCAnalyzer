"""Aggregate findings from all scanners into a unified crypto inventory."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from uuid import uuid4

from src.scanner.models import Finding, ScanResult, ScanSummary
from src.utils.constants import RiskLevel

logger = logging.getLogger(__name__)


@dataclass
class CryptoInventory:
    """Aggregated inventory of all cryptographic algorithms found across scans."""

    inventory_id: str = field(default_factory=lambda: str(uuid4()))
    timestamp: str = field(default_factory=lambda: datetime.now().astimezone().isoformat())
    scan_results: list[ScanResult] = field(default_factory=list)

    @property
    def all_findings(self) -> list[Finding]:
        """All findings from all scan results."""
        findings = []
        for result in self.scan_results:
            findings.extend(result.findings)
        return findings

    @property
    def summary(self) -> ScanSummary:
        """Aggregated summary across all scans."""
        return ScanSummary.from_findings(self.all_findings)

    @property
    def unique_algorithms(self) -> dict[str, list[Finding]]:
        """Group findings by algorithm name."""
        grouped: dict[str, list[Finding]] = {}
        for finding in self.all_findings:
            grouped.setdefault(finding.algorithm, []).append(finding)
        return grouped

    @property
    def quantum_vulnerable_findings(self) -> list[Finding]:
        """All findings that are quantum-vulnerable."""
        return [f for f in self.all_findings if f.quantum_vulnerable]

    @property
    def critical_findings(self) -> list[Finding]:
        """All CRITICAL-risk findings."""
        return [f for f in self.all_findings if f.risk_level == RiskLevel.CRITICAL]

    def add_result(self, result: ScanResult) -> None:
        """Add a scan result to the inventory."""
        self.scan_results.append(result)

    def add_results(self, results: list[ScanResult]) -> None:
        """Add multiple scan results to the inventory."""
        self.scan_results.extend(results)

    def findings_by_risk(self) -> dict[RiskLevel, list[Finding]]:
        """Group findings by risk level."""
        grouped: dict[RiskLevel, list[Finding]] = {
            RiskLevel.CRITICAL: [],
            RiskLevel.HIGH: [],
            RiskLevel.MEDIUM: [],
            RiskLevel.LOW: [],
            RiskLevel.SAFE: [],
        }
        for finding in self.all_findings:
            grouped[finding.risk_level].append(finding)
        return grouped

    def findings_by_target(self) -> dict[str, list[Finding]]:
        """Group findings by scan target."""
        grouped: dict[str, list[Finding]] = {}
        for result in self.scan_results:
            grouped[result.target] = result.findings
        return grouped

    def findings_by_priority(self) -> list[Finding]:
        """All findings sorted by migration priority (highest first)."""
        return sorted(self.all_findings, key=lambda f: f.migration_priority)

    def to_dict(self) -> dict:
        """Serialize inventory to dictionary."""
        return {
            "inventory_id": self.inventory_id,
            "timestamp": self.timestamp,
            "summary": self.summary.to_dict(),
            "scan_results": [r.to_dict() for r in self.scan_results],
        }

    def to_json(self, indent: int = 2) -> str:
        """Serialize inventory to JSON string."""
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)

    def save(self, filepath: str) -> None:
        """Save inventory to a JSON file."""
        path = Path(filepath)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.to_json(), encoding="utf-8")
        logger.info("Inventory saved to %s", filepath)

    @classmethod
    def load(cls, filepath: str) -> CryptoInventory:
        """Load inventory from a JSON file."""
        path = Path(filepath)
        data = json.loads(path.read_text(encoding="utf-8"))

        inventory = cls(
            inventory_id=data["inventory_id"],
            timestamp=data["timestamp"],
        )

        for sr_data in data.get("scan_results", []):
            findings = [
                Finding(
                    component=f["component"],
                    algorithm=f["algorithm"],
                    risk_level=RiskLevel(f["risk_level"]),
                    quantum_vulnerable=f["quantum_vulnerable"],
                    location=f["location"],
                    replacement=f.get("replacement", []),
                    migration_priority=f.get("migration_priority", 5),
                    note=f.get("note", ""),
                )
                for f in sr_data.get("findings", [])
            ]

            from src.utils.constants import ScanStatus, ScanType
            result = ScanResult(
                scan_id=sr_data.get("scan_id", str(uuid4())),
                target=sr_data["target"],
                scan_type=ScanType(sr_data["scan_type"]),
                status=ScanStatus(sr_data.get("status", "success")),
                findings=findings,
                timestamp=sr_data.get("timestamp", ""),
                duration_ms=sr_data.get("duration_ms", 0),
                error_message=sr_data.get("error_message"),
                metadata=sr_data.get("metadata", {}),
            )
            result.finalize()
            inventory.add_result(result)

        return inventory
