"""Pydantic v2 data models for flow analysis."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from src.utils.constants import StrEnum


class Protocol(StrEnum):
    TLS_1_2 = "tls_1.2"
    TLS_1_3 = "tls_1.3"
    SSH_2 = "ssh_2"
    IKE_V2 = "ike_v2"
    QUIC = "quic"
    UNKNOWN = "unknown"


class DataSensitivity(StrEnum):
    """Data sensitivity buckets with HNDL scoring weight.

    Weight from spec §2.3.6: PUBLIC=0.1 ... SECRET=1.0.
    """

    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"
    SECRET = "secret"


SENSITIVITY_WEIGHT: dict[DataSensitivity, float] = {
    DataSensitivity.PUBLIC: 0.1,
    DataSensitivity.INTERNAL: 0.3,
    DataSensitivity.CONFIDENTIAL: 0.6,
    DataSensitivity.RESTRICTED: 0.8,
    DataSensitivity.SECRET: 1.0,
}


class RetentionClass(StrEnum):
    """Retention horizon for data carried in the flow."""

    EPHEMERAL = "ephemeral"
    SHORT = "short"
    MEDIUM = "medium"
    LONG = "long"
    LIFETIME = "lifetime"


RETENTION_WEIGHT: dict[RetentionClass, float] = {
    RetentionClass.EPHEMERAL: 0.1,
    RetentionClass.SHORT: 0.3,
    RetentionClass.MEDIUM: 0.6,
    RetentionClass.LONG: 0.8,
    RetentionClass.LIFETIME: 1.0,
}


class RiskBand(StrEnum):
    """HNDL score band. Matches repo-wide RiskLevel values."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    SAFE = "SAFE"


class CryptoPrimitive(BaseModel):
    """Normalised crypto observed in a handshake."""

    model_config = ConfigDict(frozen=False, extra="forbid")

    kex_algorithm: str | None = None
    signature_algorithm: str | None = None
    symmetric_cipher: str | None = None
    hash_algorithm: str | None = None
    is_hybrid_pqc: bool = False
    is_pure_pqc: bool = False
    raw_cipher_suite: str | None = None


class Flow(BaseModel):
    """5-tuple flow with optional parsed handshake + classification."""

    model_config = ConfigDict(extra="forbid")

    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    transport: str
    protocol: Protocol = Protocol.UNKNOWN
    first_seen: datetime
    last_seen: datetime
    bytes_total: int = 0
    packets_total: int = 0
    crypto: CryptoPrimitive | None = None
    server_name: str | None = None
    sensitivity: DataSensitivity = DataSensitivity.INTERNAL
    retention: RetentionClass = RetentionClass.SHORT

    @property
    def five_tuple(self) -> tuple[str, str, int, int, str]:
        return (self.src_ip, self.dst_ip, self.src_port, self.dst_port, self.transport)


class HNDLScore(BaseModel):
    """Per-flow HNDL scoring breakdown."""

    model_config = ConfigDict(extra="forbid")

    overall: float = Field(ge=0.0, le=100.0)
    risk_level: RiskBand
    vulnerability_component: float = Field(ge=0.0, le=1.0)
    sensitivity_component: float = Field(ge=0.0, le=1.0)
    retention_component: float = Field(ge=0.0, le=1.0)
    volume_factor: float = Field(ge=0.0, le=1.0)
    rationale: str
    recommended_action: str


class EndpointExposure(BaseModel):
    """Rollup of HNDL exposure for a single destination endpoint."""

    model_config = ConfigDict(extra="forbid")

    endpoint: str
    kex_algorithm: str | None
    sensitivity: DataSensitivity
    flows: int
    bytes_total: int
    worst_risk: RiskBand


class AggregateStats(BaseModel):
    """Campaign-level aggregation of per-flow scores."""

    model_config = ConfigDict(extra="forbid")

    flows_by_risk: dict[str, int] = Field(default_factory=dict)
    bytes_by_risk: dict[str, int] = Field(default_factory=dict)
    flows_by_protocol: dict[str, int] = Field(default_factory=dict)
    top_vulnerable_endpoints: list[EndpointExposure] = Field(default_factory=list)
    hndl_exposed_bytes_per_day: float = 0.0
    pqc_adoption_pct: float = 0.0


class FlowAnalysisReport(BaseModel):
    """Final output: scored flows + aggregate stats."""

    model_config = ConfigDict(extra="forbid")

    source: str
    duration_seconds: float
    total_flows: int
    total_bytes: int
    scored_flows: list[tuple[Flow, HNDLScore]]
    aggregate: AggregateStats
    generated_at: datetime
