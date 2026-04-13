#!/usr/bin/env python3
"""Example: Scan a single TLS endpoint and print findings."""

from src.scanner.tls_scanner import scan_tls_endpoint
from src.utils.crypto_db import AlgorithmDatabase

db = AlgorithmDatabase()

# Scan a TLS endpoint
result = scan_tls_endpoint("example.com", port=443)

print(f"Target: {result.target}")
print(f"Status: {result.status}")
print(f"Findings: {len(result.findings)}")
print()

for finding in result.findings:
    risk = finding.risk_level.value
    qv = "QUANTUM VULNERABLE" if finding.quantum_vulnerable else "safe"
    print(f"  [{risk}] {finding.component}: {finding.algorithm} ({qv})")
    if finding.replacement:
        print(f"    -> Replace with: {', '.join(finding.replacement)}")
    print()
