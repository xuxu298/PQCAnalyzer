"""Data models for benchmark results."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from uuid import uuid4


@dataclass
class TimingStats:
    """Statistical summary of timing measurements (in milliseconds)."""

    mean: float = 0.0
    median: float = 0.0
    p95: float = 0.0
    p99: float = 0.0
    min: float = 0.0
    max: float = 0.0
    stdev: float = 0.0

    def to_dict(self) -> dict:
        return {
            "mean": round(self.mean, 4),
            "median": round(self.median, 4),
            "p95": round(self.p95, 4),
            "p99": round(self.p99, 4),
            "min": round(self.min, 4),
            "max": round(self.max, 4),
            "stdev": round(self.stdev, 4),
        }

    @classmethod
    def from_samples(cls, samples_ms: list[float]) -> TimingStats:
        """Compute stats from a list of timing samples in milliseconds."""
        import statistics

        if not samples_ms:
            return cls()

        sorted_samples = sorted(samples_ms)
        n = len(sorted_samples)

        return cls(
            mean=statistics.mean(sorted_samples),
            median=statistics.median(sorted_samples),
            p95=sorted_samples[int(n * 0.95)] if n > 1 else sorted_samples[0],
            p99=sorted_samples[int(n * 0.99)] if n > 1 else sorted_samples[0],
            min=sorted_samples[0],
            max=sorted_samples[-1],
            stdev=statistics.stdev(sorted_samples) if n > 1 else 0.0,
        )


@dataclass
class KEMBenchmarkResult:
    """Benchmark result for a KEM algorithm."""

    algorithm: str = ""
    type: str = "kem"
    iterations: int = 0
    keygen: TimingStats = field(default_factory=TimingStats)
    encaps: TimingStats = field(default_factory=TimingStats)
    decaps: TimingStats = field(default_factory=TimingStats)
    pubkey_bytes: int = 0
    seckey_bytes: int = 0
    ciphertext_bytes: int = 0
    memory_peak_kb: float = 0.0

    def to_dict(self) -> dict:
        return {
            "algorithm": self.algorithm,
            "type": self.type,
            "iterations": self.iterations,
            "keygen_ms": self.keygen.to_dict(),
            "encaps_ms": self.encaps.to_dict(),
            "decaps_ms": self.decaps.to_dict(),
            "pubkey_bytes": self.pubkey_bytes,
            "seckey_bytes": self.seckey_bytes,
            "ciphertext_bytes": self.ciphertext_bytes,
            "memory_peak_kb": round(self.memory_peak_kb, 1),
        }


@dataclass
class SignBenchmarkResult:
    """Benchmark result for a digital signature algorithm."""

    algorithm: str = ""
    type: str = "signature"
    iterations: int = 0
    keygen: TimingStats = field(default_factory=TimingStats)
    sign: TimingStats = field(default_factory=TimingStats)
    verify: TimingStats = field(default_factory=TimingStats)
    pubkey_bytes: int = 0
    seckey_bytes: int = 0
    signature_bytes: int = 0
    memory_peak_kb: float = 0.0

    def to_dict(self) -> dict:
        return {
            "algorithm": self.algorithm,
            "type": self.type,
            "iterations": self.iterations,
            "keygen_ms": self.keygen.to_dict(),
            "sign_ms": self.sign.to_dict(),
            "verify_ms": self.verify.to_dict(),
            "pubkey_bytes": self.pubkey_bytes,
            "seckey_bytes": self.seckey_bytes,
            "signature_bytes": self.signature_bytes,
            "memory_peak_kb": round(self.memory_peak_kb, 1),
        }


@dataclass
class HardwareInfo:
    """Hardware profile information."""

    cpu_model: str = ""
    cpu_cores: int = 0
    cpu_threads: int = 0
    cpu_frequency_mhz: float = 0.0
    cpu_arch: str = ""
    ram_total_gb: float = 0.0
    os_name: str = ""
    os_version: str = ""
    python_version: str = ""
    openssl_version: str = ""
    liboqs_version: str = ""
    has_aesni: bool = False
    has_avx2: bool = False
    has_avx512: bool = False
    has_sha_ext: bool = False

    def to_dict(self) -> dict:
        return {
            "cpu": self.cpu_model,
            "cores": self.cpu_cores,
            "threads": self.cpu_threads,
            "frequency_mhz": round(self.cpu_frequency_mhz, 1),
            "arch": self.cpu_arch,
            "ram_gb": round(self.ram_total_gb, 1),
            "os": f"{self.os_name} {self.os_version}",
            "python": self.python_version,
            "openssl": self.openssl_version,
            "liboqs": self.liboqs_version,
            "has_aesni": self.has_aesni,
            "has_avx2": self.has_avx2,
            "has_avx512": self.has_avx512,
            "has_sha_ext": self.has_sha_ext,
        }


@dataclass
class ComparisonResult:
    """Comparison between classical and PQC algorithms."""

    classical: str = ""
    pqc: str = ""
    metric: str = ""
    classical_value: float = 0.0
    pqc_value: float = 0.0
    ratio: float = 0.0
    summary: str = ""

    def to_dict(self) -> dict:
        return {
            "classical": self.classical,
            "pqc": self.pqc,
            "metric": self.metric,
            "classical_value": round(self.classical_value, 4),
            "pqc_value": round(self.pqc_value, 4),
            "ratio": round(self.ratio, 2),
            "summary": self.summary,
        }


@dataclass
class BenchmarkReport:
    """Full benchmark report."""

    benchmark_id: str = field(default_factory=lambda: str(uuid4()))
    timestamp: str = field(default_factory=lambda: datetime.now().astimezone().isoformat())
    hardware: HardwareInfo = field(default_factory=HardwareInfo)
    kem_results: list[KEMBenchmarkResult] = field(default_factory=list)
    sign_results: list[SignBenchmarkResult] = field(default_factory=list)
    comparisons: list[ComparisonResult] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "benchmark_id": self.benchmark_id,
            "timestamp": self.timestamp,
            "hardware": self.hardware.to_dict(),
            "results": (
                [r.to_dict() for r in self.kem_results]
                + [r.to_dict() for r in self.sign_results]
            ),
            "comparisons": [c.to_dict() for c in self.comparisons],
        }
