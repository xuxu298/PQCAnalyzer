"""Data models for scan results."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from src.utils.constants import StrEnum
from uuid import uuid4

from src.utils.constants import RiskLevel, ScanStatus, ScanType


@dataclass
class Finding:
    """A single cryptographic finding from a scan."""

    component: str
    algorithm: str
    risk_level: RiskLevel
    quantum_vulnerable: bool
    location: str
    replacement: list[str] = field(default_factory=list)
    migration_priority: int = 5
    note: str = ""
    # How the finding was arrived at. For TLS key-exchange findings:
    #   "passive"          — observed in the handshake; probe not run or errored.
    #                        Risk reflects bytes-on-the-wire (HNDL).
    #   "active_declined"  — raw-ClientHello probe offered X25519MLKEM768, server
    #                        picked classical. Risk reflects server-grade readiness.
    #   "active_supported" — probe or stdlib handshake negotiated a PQ hybrid.
    # Empty for findings where the distinction doesn't apply (cert, cipher, MAC, SSH, code).
    detection_mode: str = ""

    def to_dict(self) -> dict:
        out = {
            "component": self.component,
            "algorithm": self.algorithm,
            "risk_level": self.risk_level.value,
            "quantum_vulnerable": self.quantum_vulnerable,
            "location": self.location,
            "replacement": self.replacement,
            "migration_priority": self.migration_priority,
            "note": self.note,
        }
        if self.detection_mode:
            out["detection_mode"] = self.detection_mode
        return out


@dataclass
class ScanSummary:
    """Summary statistics for a scan."""

    total_findings: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    safe: int = 0
    overall_risk: RiskLevel = RiskLevel.SAFE

    @classmethod
    def from_findings(cls, findings: list[Finding]) -> ScanSummary:
        summary = cls(total_findings=len(findings))
        for f in findings:
            match f.risk_level:
                case RiskLevel.CRITICAL:
                    summary.critical += 1
                case RiskLevel.HIGH:
                    summary.high += 1
                case RiskLevel.MEDIUM:
                    summary.medium += 1
                case RiskLevel.LOW:
                    summary.low += 1
                case RiskLevel.SAFE:
                    summary.safe += 1

        # Overall risk = highest risk found
        if summary.critical > 0:
            summary.overall_risk = RiskLevel.CRITICAL
        elif summary.high > 0:
            summary.overall_risk = RiskLevel.HIGH
        elif summary.medium > 0:
            summary.overall_risk = RiskLevel.MEDIUM
        elif summary.low > 0:
            summary.overall_risk = RiskLevel.LOW
        else:
            summary.overall_risk = RiskLevel.SAFE
        return summary

    def to_dict(self) -> dict:
        return {
            "total_findings": self.total_findings,
            "critical": self.critical,
            "high": self.high,
            "medium": self.medium,
            "low": self.low,
            "safe": self.safe,
            "overall_risk": self.overall_risk.value,
        }


@dataclass
class ScanResult:
    """Result of scanning a single target."""

    target: str
    scan_type: ScanType
    status: ScanStatus = ScanStatus.SUCCESS
    findings: list[Finding] = field(default_factory=list)
    summary: ScanSummary | None = None
    error_message: str | None = None
    duration_ms: float = 0
    scan_id: str = field(default_factory=lambda: str(uuid4()))
    timestamp: str = field(default_factory=lambda: datetime.now().astimezone().isoformat())
    metadata: dict = field(default_factory=dict)

    def finalize(self) -> None:
        """Compute summary from findings."""
        self.summary = ScanSummary.from_findings(self.findings)

    def to_dict(self) -> dict:
        if self.summary is None:
            self.finalize()
        result: dict = {
            "scan_id": self.scan_id,
            "timestamp": self.timestamp,
            "target": self.target,
            "scan_type": self.scan_type.value,
            "status": self.status.value,
            "duration_ms": self.duration_ms,
        }
        if self.error_message:
            result["error_message"] = self.error_message
        if self.findings:
            result["findings"] = [f.to_dict() for f in self.findings]
        if self.summary:
            result["summary"] = self.summary.to_dict()
        if self.metadata:
            result["metadata"] = self.metadata
        return result


class TLSInfo(StrEnum):
    """Components of a TLS connection."""

    PROTOCOL = "TLS Protocol"
    CIPHER_SUITE = "Cipher Suite"
    KEY_EXCHANGE = "TLS Key Exchange"
    AUTHENTICATION = "TLS Authentication"
    BULK_ENCRYPTION = "Bulk Encryption"
    MAC = "MAC Algorithm"
    CERTIFICATE = "Certificate"
    CERT_SIGNATURE = "Certificate Signature"
    CERT_PUBLIC_KEY = "Certificate Public Key"


@dataclass
class TLSConnectionInfo:
    """Detailed information about a TLS connection."""

    protocol_version: str = ""
    cipher_suite: str = ""
    key_exchange: str = ""
    authentication: str = ""
    bulk_cipher: str = ""
    mac_algorithm: str = ""
    supported_protocols: list[str] = field(default_factory=list)
    supported_ciphers: list[str] = field(default_factory=list)
    certificate_chain: list[dict] = field(default_factory=list)
    # How the key_exchange value was established. See Finding.detection_mode.
    detection_mode: str = ""


@dataclass
class CertificateInfo:
    """Parsed certificate information."""

    subject: dict = field(default_factory=dict)
    issuer: dict = field(default_factory=dict)
    serial_number: str = ""
    not_before: str = ""
    not_after: str = ""
    public_key_algorithm: str = ""
    public_key_size: int = 0
    signature_algorithm: str = ""
    san: list[str] = field(default_factory=list)
    is_ca: bool = False
    key_usage: list[str] = field(default_factory=list)
    extended_key_usage: list[str] = field(default_factory=list)
    is_expired: bool = False
    is_self_signed: bool = False
    chain_position: str = ""  # "leaf", "intermediate", "root"
