"""Benchmarker API routes."""

from __future__ import annotations

from fastapi import APIRouter

from src.api.schemas import BenchmarkRequest

router = APIRouter()


@router.get("/benchmark/hardware")
def get_hardware():
    """Get detected hardware profile."""
    from src.benchmarker.hardware_profile import detect_hardware
    return detect_hardware().to_dict()


@router.post("/benchmark/kem")
def run_kem_benchmark(request: BenchmarkRequest):
    """Run KEM benchmark."""
    from src.benchmarker.comparator import compare_kem_results
    from src.benchmarker.encaps_bench import bench_kem_encaps_classical, bench_kem_encaps_pqc
    from src.benchmarker.hardware_profile import detect_hardware
    from src.benchmarker.keygen_bench import bench_kem_keygen_classical, bench_kem_keygen_pqc
    from src.benchmarker.models import BenchmarkReport

    hw = detect_hardware()
    keygen_results = bench_kem_keygen_classical(request.iterations, request.warmup)
    keygen_results.extend(bench_kem_keygen_pqc(request.iterations, request.warmup))

    encaps_results = bench_kem_encaps_classical(request.iterations, request.warmup)
    encaps_results.extend(bench_kem_encaps_pqc(request.iterations, request.warmup))

    # Merge
    all_results = keygen_results + encaps_results
    comparisons = compare_kem_results(all_results)

    report = BenchmarkReport(hardware=hw, kem_results=all_results, comparisons=comparisons)
    return report.to_dict()


@router.post("/benchmark/sign")
def run_sign_benchmark(request: BenchmarkRequest):
    """Run signature benchmark."""
    from src.benchmarker.comparator import compare_sign_results
    from src.benchmarker.hardware_profile import detect_hardware
    from src.benchmarker.models import BenchmarkReport
    from src.benchmarker.sign_bench import bench_sign_classical, bench_sign_pqc

    hw = detect_hardware()
    results = bench_sign_classical(request.iterations, request.warmup)
    results.extend(bench_sign_pqc(request.iterations, request.warmup))

    comparisons = compare_sign_results(results)
    report = BenchmarkReport(hardware=hw, sign_results=results, comparisons=comparisons)
    return report.to_dict()
