#!/bin/bash
# Demo: active TLS 1.3 ClientHello probe for X25519MLKEM768
# Usage: asciinema rec --command "bash scripts/record_pq_probe_demo.sh" docs/pq_probe_demo.cast

set -e

type_cmd() {
    echo ""
    echo -n "$ "
    for ((i=0; i<${#1}; i++)); do
        echo -n "${1:$i:1}"
        sleep 0.04
    done
    echo ""
    sleep 0.4
}

clear
echo ""
echo "  PQC Analyzer — Active probe for X25519MLKEM768 (IANA 0x11EC)"
echo "  ============================================================"
echo ""
sleep 1.5

type_cmd "python3 examples/probe_pq_groups.py"
python3 examples/probe_pq_groups.py
sleep 6

echo ""
echo "  ⭐ GitHub: https://github.com/xuxu298/PQCAnalyzer"
echo ""
sleep 3
