"""Configuration management for VN-PQC Analyzer."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


DEFAULT_TIMEOUT_MS = 5000
DEFAULT_DELAY_MS = 100
DEFAULT_MAX_CONCURRENT = 10
DEFAULT_ITERATIONS = 1000
DEFAULT_LANGUAGE = "en"

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_ROOT / "data"
ALGORITHM_DB_PATH = DATA_DIR / "algorithms.json"


@dataclass
class ScanConfig:
    """Configuration for scan operations."""

    timeout_ms: int = DEFAULT_TIMEOUT_MS
    delay_ms: int = DEFAULT_DELAY_MS
    max_concurrent: int = DEFAULT_MAX_CONCURRENT
    retries: int = 2
    redact: bool = False
    offline: bool = False
    language: str = DEFAULT_LANGUAGE
    verbose: int = 0


@dataclass
class BenchmarkConfig:
    """Configuration for benchmark operations."""

    iterations: int = DEFAULT_ITERATIONS
    warmup: int = 10
    language: str = DEFAULT_LANGUAGE


@dataclass
class ReportConfig:
    """Configuration for report generation."""

    language: str = DEFAULT_LANGUAGE
    org_name: str = ""
    prepared_by: str = ""
    include_raw_data: bool = False
    redact: bool = False
    output_formats: list[str] = field(default_factory=lambda: ["json"])
