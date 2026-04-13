#!/usr/bin/env python3
"""Example: Run PQC benchmark and compare classical vs PQC performance.

Requires: pip install vn-pqc-analyzer[benchmark]
"""

from src.benchmarker.hardware_profile import detect_hardware
from src.benchmarker.comparator import generate_overall_summary

# Detect hardware
hw = detect_hardware()
print(f"CPU: {hw.cpu_model}")
print(f"Cores: {hw.cpu_cores}")
print(f"RAM: {hw.ram_total_gb:.1f} GB")
print(f"Crypto flags: {', '.join(hw.cpu_flags_crypto)}")
print()

# Run comparisons
print("Running benchmarks (this may take a few minutes)...")
summary = generate_overall_summary(iterations=100)

print(f"\nKEM Comparisons: {len(summary['kem_comparisons'])}")
for c in summary["kem_comparisons"]:
    print(f"  {c['pair']}: classical {c['classical_keygen_ms']:.2f}ms vs PQC {c['pqc_keygen_ms']:.2f}ms")

print(f"\nSignature Comparisons: {len(summary['sign_comparisons'])}")
for c in summary["sign_comparisons"]:
    print(f"  {c['pair']}: classical {c['classical_sign_ms']:.2f}ms vs PQC {c['pqc_sign_ms']:.2f}ms")
