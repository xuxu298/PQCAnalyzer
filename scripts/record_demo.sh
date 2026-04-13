#!/bin/bash
# Demo script for recording with asciinema
# Usage: asciinema rec --command "bash scripts/record_demo.sh" demo.cast

set -e

# Simulated typing effect
type_cmd() {
    echo ""
    echo -n "$ "
    for ((i=0; i<${#1}; i++)); do
        echo -n "${1:$i:1}"
        sleep 0.04
    done
    echo ""
    sleep 0.3
}

clear
echo ""
echo "  VN-PQC Readiness Analyzer — Demo"
echo "  ================================="
echo ""
sleep 1

# 1. Scan multiple TLS endpoints
type_cmd "pqc-analyzer scan tls google.com cloudflare.com github.com"
pqc-analyzer scan tls google.com cloudflare.com github.com
sleep 2

# 2. Generate roadmap
type_cmd "pqc-analyzer roadmap /tmp/scan_results.json --org \"Acme Corp\""
pqc-analyzer scan tls google.com cloudflare.com github.com -o /tmp/demo_scan.json 2>/dev/null
pqc-analyzer roadmap /tmp/demo_scan.json --org "Acme Corp"
sleep 2

# 3. Benchmark
type_cmd "pqc-analyzer benchmark kem --iterations 100"
pqc-analyzer benchmark kem --iterations 100
sleep 2

# 4. Hardware info
type_cmd "pqc-analyzer benchmark hardware"
pqc-analyzer benchmark hardware
sleep 2

echo ""
echo "  ⭐ GitHub: https://github.com/xuxu298/PQCAnalyzer"
echo ""
sleep 3
