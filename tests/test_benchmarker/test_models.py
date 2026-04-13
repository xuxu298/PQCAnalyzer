"""Tests for benchmarker data models."""

import pytest

from src.benchmarker.models import (
    BenchmarkReport,
    ComparisonResult,
    HardwareInfo,
    KEMBenchmarkResult,
    SignBenchmarkResult,
    TimingStats,
)


class TestTimingStats:
    def test_from_samples_basic(self):
        samples = [1.0, 2.0, 3.0, 4.0, 5.0]
        stats = TimingStats.from_samples(samples)
        assert stats.mean == 3.0
        assert stats.median == 3.0
        assert stats.min == 1.0
        assert stats.max == 5.0
        assert stats.stdev > 0

    def test_from_samples_empty(self):
        stats = TimingStats.from_samples([])
        assert stats.mean == 0.0
        assert stats.median == 0.0

    def test_from_samples_single(self):
        stats = TimingStats.from_samples([5.0])
        assert stats.mean == 5.0
        assert stats.median == 5.0
        assert stats.stdev == 0.0
        assert stats.p95 == 5.0
        assert stats.p99 == 5.0

    def test_to_dict(self):
        stats = TimingStats(mean=1.1234, median=1.0, p95=2.0, p99=3.0, min=0.5, max=4.0, stdev=0.8)
        d = stats.to_dict()
        assert d["mean"] == 1.1234
        assert isinstance(d["mean"], float)
        assert "p95" in d
        assert "stdev" in d

    def test_percentiles(self):
        samples = list(range(1, 101))  # 1 to 100
        stats = TimingStats.from_samples([float(x) for x in samples])
        assert stats.p95 == 96.0
        assert stats.p99 == 100.0


class TestKEMBenchmarkResult:
    def test_to_dict(self):
        result = KEMBenchmarkResult(
            algorithm="ML-KEM-768",
            iterations=1000,
            keygen=TimingStats(mean=0.12),
            encaps=TimingStats(mean=0.14),
            decaps=TimingStats(mean=0.15),
            pubkey_bytes=1184,
            seckey_bytes=2400,
            ciphertext_bytes=1088,
        )
        d = result.to_dict()
        assert d["algorithm"] == "ML-KEM-768"
        assert d["type"] == "kem"
        assert d["iterations"] == 1000
        assert "keygen_ms" in d
        assert "encaps_ms" in d
        assert d["pubkey_bytes"] == 1184


class TestSignBenchmarkResult:
    def test_to_dict(self):
        result = SignBenchmarkResult(
            algorithm="ML-DSA-65",
            iterations=1000,
            sign=TimingStats(mean=0.5),
            verify=TimingStats(mean=0.3),
            signature_bytes=3293,
        )
        d = result.to_dict()
        assert d["algorithm"] == "ML-DSA-65"
        assert d["type"] == "signature"
        assert "sign_ms" in d
        assert "verify_ms" in d


class TestHardwareInfo:
    def test_to_dict(self):
        hw = HardwareInfo(
            cpu_model="Test CPU",
            cpu_cores=4,
            ram_total_gb=16.0,
            os_name="Linux",
            os_version="5.15",
            python_version="3.10.12",
            has_aesni=True,
            has_avx2=True,
        )
        d = hw.to_dict()
        assert d["cpu"] == "Test CPU"
        assert d["cores"] == 4
        assert d["has_aesni"] is True


class TestBenchmarkReport:
    def test_to_dict(self):
        report = BenchmarkReport(
            hardware=HardwareInfo(cpu_model="Test"),
            kem_results=[KEMBenchmarkResult(algorithm="ML-KEM-768")],
            sign_results=[SignBenchmarkResult(algorithm="ML-DSA-65")],
            comparisons=[ComparisonResult(classical="RSA-2048", pqc="ML-KEM-768", metric="keygen")],
        )
        d = report.to_dict()
        assert "benchmark_id" in d
        assert "timestamp" in d
        assert len(d["results"]) == 2
        assert len(d["comparisons"]) == 1


class TestComparisonResult:
    def test_to_dict(self):
        c = ComparisonResult(
            classical="RSA-2048",
            pqc="ML-KEM-768",
            metric="keygen_time",
            classical_value=150.0,
            pqc_value=0.12,
            ratio=1250.0,
            summary="ML-KEM-768 keygen is 1250x faster",
        )
        d = c.to_dict()
        assert d["classical"] == "RSA-2048"
        assert d["ratio"] == 1250.0
