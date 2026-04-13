"""Tests for comparison engine."""

import pytest

from src.benchmarker.comparator import (
    compare_kem_results,
    compare_sign_results,
    generate_overall_summary,
)
from src.benchmarker.models import (
    BenchmarkReport,
    ComparisonResult,
    HardwareInfo,
    KEMBenchmarkResult,
    SignBenchmarkResult,
    TimingStats,
)


@pytest.fixture
def kem_results():
    return [
        KEMBenchmarkResult(
            algorithm="RSA-2048",
            iterations=100,
            keygen=TimingStats(mean=150.0),
            encaps=TimingStats(mean=0.08),
            decaps=TimingStats(mean=1.85),
            pubkey_bytes=294,
            ciphertext_bytes=256,
        ),
        KEMBenchmarkResult(
            algorithm="Kyber768",
            iterations=100,
            keygen=TimingStats(mean=0.12),
            encaps=TimingStats(mean=0.14),
            decaps=TimingStats(mean=0.15),
            pubkey_bytes=1184,
            ciphertext_bytes=1088,
        ),
        KEMBenchmarkResult(
            algorithm="X25519",
            iterations=100,
            keygen=TimingStats(mean=0.02),
            encaps=TimingStats(mean=0.03),
            decaps=TimingStats(mean=0.03),
            pubkey_bytes=32,
            ciphertext_bytes=32,
        ),
    ]


@pytest.fixture
def sign_results():
    return [
        SignBenchmarkResult(
            algorithm="RSA-2048",
            iterations=100,
            sign=TimingStats(mean=1.5),
            verify=TimingStats(mean=0.05),
            signature_bytes=256,
        ),
        SignBenchmarkResult(
            algorithm="Dilithium3",
            iterations=100,
            sign=TimingStats(mean=0.5),
            verify=TimingStats(mean=0.3),
            signature_bytes=3293,
        ),
        SignBenchmarkResult(
            algorithm="Ed25519",
            iterations=100,
            sign=TimingStats(mean=0.02),
            verify=TimingStats(mean=0.04),
            signature_bytes=64,
        ),
    ]


class TestKEMComparison:
    def test_keygen_comparison(self, kem_results):
        comparisons = compare_kem_results(kem_results)
        keygen_comps = [c for c in comparisons if c.metric == "keygen_time"]
        assert len(keygen_comps) > 0

        # RSA-2048 vs Kyber768: Kyber should be much faster at keygen
        rsa_kyber = [c for c in keygen_comps if c.classical == "RSA-2048" and c.pqc == "Kyber768"]
        assert len(rsa_kyber) > 0
        assert rsa_kyber[0].ratio > 100  # Kyber keygen >> faster than RSA

    def test_pubkey_size_comparison(self, kem_results):
        comparisons = compare_kem_results(kem_results)
        size_comps = [c for c in comparisons if c.metric == "pubkey_size"]
        assert len(size_comps) > 0

        # Kyber768 pubkey larger than RSA-2048
        rsa_kyber = [c for c in size_comps if c.classical == "RSA-2048" and c.pqc == "Kyber768"]
        assert len(rsa_kyber) > 0
        assert rsa_kyber[0].ratio > 1  # Kyber key is larger

    def test_summary_text(self, kem_results):
        comparisons = compare_kem_results(kem_results)
        for c in comparisons:
            assert len(c.summary) > 0

    def test_no_match_returns_empty(self):
        results = [KEMBenchmarkResult(algorithm="UnknownAlgo")]
        comparisons = compare_kem_results(results)
        assert len(comparisons) == 0


class TestSignComparison:
    def test_sign_time_comparison(self, sign_results):
        comparisons = compare_sign_results(sign_results)
        sign_comps = [c for c in comparisons if c.metric == "sign_time"]
        assert len(sign_comps) > 0

    def test_signature_size_comparison(self, sign_results):
        comparisons = compare_sign_results(sign_results)
        size_comps = [c for c in comparisons if c.metric == "signature_size"]
        assert len(size_comps) > 0

        # Dilithium signature much larger than RSA
        rsa_dil = [c for c in size_comps if c.classical == "RSA-2048" and c.pqc == "Dilithium3"]
        assert len(rsa_dil) > 0
        assert rsa_dil[0].ratio > 1


class TestOverallSummary:
    def test_generates_summary(self, kem_results, sign_results):
        report = BenchmarkReport(
            hardware=HardwareInfo(cpu_model="Test"),
            kem_results=kem_results,
            sign_results=sign_results,
            comparisons=compare_kem_results(kem_results),
        )
        summary = generate_overall_summary(report)
        assert "KEM Algorithms" in summary
        assert "Signature Algorithms" in summary
        assert "RSA-2048" in summary

    def test_empty_report(self):
        report = BenchmarkReport()
        summary = generate_overall_summary(report)
        assert "Summary" in summary
