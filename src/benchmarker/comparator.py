"""Classical vs PQC comparison engine."""

from __future__ import annotations

import logging

from src.benchmarker.models import (
    BenchmarkReport,
    ComparisonResult,
    KEMBenchmarkResult,
    SignBenchmarkResult,
)

logger = logging.getLogger(__name__)

# Predefined comparison pairs: (classical, pqc)
KEM_COMPARISON_PAIRS = [
    ("RSA-2048", "Kyber512"),
    ("RSA-2048", "Kyber768"),
    ("ECDH-P256", "Kyber768"),
    ("X25519", "Kyber768"),
    ("RSA-2048", "ML-KEM-512"),
    ("RSA-2048", "ML-KEM-768"),
    ("ECDH-P256", "ML-KEM-768"),
    ("X25519", "ML-KEM-768"),
]

SIGN_COMPARISON_PAIRS = [
    ("RSA-2048", "Dilithium2"),
    ("RSA-2048", "Dilithium3"),
    ("ECDSA-P256", "Dilithium2"),
    ("Ed25519", "Dilithium2"),
    ("RSA-2048", "ML-DSA-44"),
    ("RSA-2048", "ML-DSA-65"),
    ("ECDSA-P256", "ML-DSA-44"),
    ("Ed25519", "ML-DSA-44"),
]


def compare_kem_results(
    results: list[KEMBenchmarkResult],
) -> list[ComparisonResult]:
    """Compare classical and PQC KEM benchmark results."""
    comparisons: list[ComparisonResult] = []
    by_name = {r.algorithm: r for r in results}

    for classical_name, pqc_name in KEM_COMPARISON_PAIRS:
        classical = by_name.get(classical_name)
        pqc = by_name.get(pqc_name)
        if not classical or not pqc:
            continue

        # Keygen comparison
        if classical.keygen.mean > 0 and pqc.keygen.mean > 0:
            ratio = classical.keygen.mean / pqc.keygen.mean
            comparisons.append(ComparisonResult(
                classical=classical_name,
                pqc=pqc_name,
                metric="keygen_time",
                classical_value=classical.keygen.mean,
                pqc_value=pqc.keygen.mean,
                ratio=ratio,
                summary=_keygen_summary(classical_name, pqc_name, ratio),
            ))

        # Encaps comparison
        if classical.encaps.mean > 0 and pqc.encaps.mean > 0:
            ratio = pqc.encaps.mean / classical.encaps.mean
            comparisons.append(ComparisonResult(
                classical=classical_name,
                pqc=pqc_name,
                metric="encaps_time",
                classical_value=classical.encaps.mean,
                pqc_value=pqc.encaps.mean,
                ratio=ratio,
                summary=_encaps_summary(classical_name, pqc_name, ratio),
            ))

        # Key size comparison
        if classical.pubkey_bytes > 0 and pqc.pubkey_bytes > 0:
            ratio = pqc.pubkey_bytes / classical.pubkey_bytes
            comparisons.append(ComparisonResult(
                classical=classical_name,
                pqc=pqc_name,
                metric="pubkey_size",
                classical_value=float(classical.pubkey_bytes),
                pqc_value=float(pqc.pubkey_bytes),
                ratio=ratio,
                summary=f"{pqc_name} public key is {ratio:.1f}x larger than {classical_name} "
                        f"({pqc.pubkey_bytes} vs {classical.pubkey_bytes} bytes)",
            ))

    return comparisons


def compare_sign_results(
    results: list[SignBenchmarkResult],
) -> list[ComparisonResult]:
    """Compare classical and PQC signature benchmark results."""
    comparisons: list[ComparisonResult] = []
    by_name: dict[str, SignBenchmarkResult] = {}

    for r in results:
        name = r.algorithm.replace("-Sign", "")
        by_name[name] = r

    for classical_name, pqc_name in SIGN_COMPARISON_PAIRS:
        classical = by_name.get(classical_name)
        pqc = by_name.get(pqc_name)
        if not classical or not pqc:
            continue

        # Sign time
        if classical.sign.mean > 0 and pqc.sign.mean > 0:
            ratio = pqc.sign.mean / classical.sign.mean
            comparisons.append(ComparisonResult(
                classical=classical_name,
                pqc=pqc_name,
                metric="sign_time",
                classical_value=classical.sign.mean,
                pqc_value=pqc.sign.mean,
                ratio=ratio,
                summary=_sign_summary(classical_name, pqc_name, ratio),
            ))

        # Verify time
        if classical.verify.mean > 0 and pqc.verify.mean > 0:
            ratio = pqc.verify.mean / classical.verify.mean
            comparisons.append(ComparisonResult(
                classical=classical_name,
                pqc=pqc_name,
                metric="verify_time",
                classical_value=classical.verify.mean,
                pqc_value=pqc.verify.mean,
                ratio=ratio,
                summary=_verify_summary(classical_name, pqc_name, ratio),
            ))

        # Signature size
        if classical.signature_bytes > 0 and pqc.signature_bytes > 0:
            ratio = pqc.signature_bytes / classical.signature_bytes
            comparisons.append(ComparisonResult(
                classical=classical_name,
                pqc=pqc_name,
                metric="signature_size",
                classical_value=float(classical.signature_bytes),
                pqc_value=float(pqc.signature_bytes),
                ratio=ratio,
                summary=f"{pqc_name} signature is {ratio:.1f}x larger than {classical_name} "
                        f"({pqc.signature_bytes} vs {classical.signature_bytes} bytes)",
            ))

    return comparisons


def generate_overall_summary(report: BenchmarkReport) -> str:
    """Generate a human-readable overall comparison summary."""
    lines: list[str] = []
    lines.append("=== PQC vs Classical Performance Summary ===\n")

    if report.kem_results:
        lines.append("KEM Algorithms:")
        for r in report.kem_results:
            lines.append(f"  {r.algorithm}: keygen={r.keygen.mean:.3f}ms, "
                        f"encaps={r.encaps.mean:.3f}ms, decaps={r.decaps.mean:.3f}ms, "
                        f"pubkey={r.pubkey_bytes}B")

    if report.sign_results:
        lines.append("\nSignature Algorithms:")
        for r in report.sign_results:
            lines.append(f"  {r.algorithm}: keygen={r.keygen.mean:.3f}ms, "
                        f"sign={r.sign.mean:.3f}ms, verify={r.verify.mean:.3f}ms, "
                        f"sig={r.signature_bytes}B")

    if report.comparisons:
        lines.append("\nKey Comparisons:")
        for c in report.comparisons:
            lines.append(f"  {c.summary}")

    return "\n".join(lines)


def _keygen_summary(classical: str, pqc: str, ratio: float) -> str:
    if ratio > 1:
        return f"{pqc} keygen is {ratio:.0f}x faster than {classical}"
    return f"{pqc} keygen is {1/ratio:.1f}x slower than {classical}"


def _encaps_summary(classical: str, pqc: str, ratio: float) -> str:
    if ratio > 1:
        return f"{pqc} encaps is {ratio:.1f}x slower than {classical} encrypt"
    return f"{pqc} encaps is {1/ratio:.1f}x faster than {classical} encrypt"


def _sign_summary(classical: str, pqc: str, ratio: float) -> str:
    if ratio > 1:
        return f"{pqc} signing is {ratio:.1f}x slower than {classical}"
    return f"{pqc} signing is {1/ratio:.1f}x faster than {classical}"


def _verify_summary(classical: str, pqc: str, ratio: float) -> str:
    if ratio > 1:
        return f"{pqc} verify is {ratio:.1f}x slower than {classical}"
    return f"{pqc} verify is {1/ratio:.1f}x faster than {classical}"
