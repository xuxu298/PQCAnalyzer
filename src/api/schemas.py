"""Pydantic schemas for API request/response models."""

from __future__ import annotations

from pydantic import BaseModel, Field


# --- Scanner schemas ---

class ScanConfigRequest(BaseModel):
    paths: list[str] = Field(..., description="File/directory paths to scan")
    recursive: bool = True
    language: str = "en"


class TLSScanRequest(BaseModel):
    targets: list[str] = Field(..., description="host:port targets")
    timeout_ms: int = 5000
    delay_ms: int = 100
    max_concurrent: int = 10
    language: str = "en"


class FindingResponse(BaseModel):
    component: str
    algorithm: str
    risk_level: str
    quantum_vulnerable: bool
    location: str
    replacement: list[str] = []
    migration_priority: int = 5
    note: str = ""


class ScanResultResponse(BaseModel):
    scan_id: str
    target: str
    scan_type: str
    status: str
    findings: list[FindingResponse] = []
    summary: dict | None = None
    error_message: str | None = None


# --- Benchmark schemas ---

class BenchmarkRequest(BaseModel):
    iterations: int = 1000
    warmup: int = 10
    algorithms: list[str] | None = None


class BenchmarkResultResponse(BaseModel):
    benchmark_id: str
    hardware: dict
    results: list[dict]
    comparisons: list[dict] = []


# --- Roadmap schemas ---

class RoadmapRequest(BaseModel):
    scan_results_path: str | None = None
    findings: list[FindingResponse] | None = None
    organization: str = ""
    exposure_factor: int | None = None
    data_sensitivity: int | None = None
    language: str = "en"


class RoadmapResponse(BaseModel):
    roadmap_id: str
    overall_risk: str
    total_findings: int
    critical_findings: int
    phases: list[dict]
    cost_estimate: dict
    compliance: list[dict]


# --- Report schemas ---

class ReportRequest(BaseModel):
    roadmap_id: str | None = None
    scan_results_path: str | None = None
    format: str = "html"  # html, json, sarif
    language: str = "en"
    organization: str = ""
    prepared_by: str = ""


class HealthResponse(BaseModel):
    status: str = "ok"
    version: str = "0.3.0"
