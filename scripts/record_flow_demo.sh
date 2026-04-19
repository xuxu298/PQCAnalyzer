#!/bin/bash
# Demo: PCAP → HNDL flow analysis → roadmap
# Usage: asciinema rec --overwrite --command "bash scripts/record_flow_demo.sh" docs/flow_demo.cast

set -e

type_cmd() {
    echo ""
    echo -n "$ "
    for ((i=0; i<${#1}; i++)); do
        echo -n "${1:$i:1}"
        sleep 0.035
    done
    echo ""
    sleep 0.4
}

clear
echo ""
echo "  PQCAnalyzer — Flow Analysis (HNDL Radar)"
echo "  ========================================="
echo "  4 flows: google.com, github.com:443, github.com:22, medical.example"
echo ""
sleep 1.5

# 1. Scan the PCAP
type_cmd "pqc-analyzer scan pcap docs/fixtures/flow_demo.pcap -o /tmp/flow.json"
pqc-analyzer scan pcap docs/fixtures/flow_demo.pcap -o /tmp/flow.json
sleep 7

# 2. Chain into roadmap (SAFE flows dropped automatically)
type_cmd "pqc-analyzer roadmap /tmp/flow.json"
pqc-analyzer roadmap /tmp/flow.json
sleep 6

echo ""
echo "  Repo: https://github.com/xuxu298/PQCAnalyzer"
echo ""
sleep 2
