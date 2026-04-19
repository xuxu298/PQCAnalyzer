#!/usr/bin/env bash
# Generate realistic PCAP fixtures for tests/fixtures/pcaps/.
#
# Why this exists: the unit tests work off hand-crafted byte strings so they
# run offline, but integration + regression needs PCAPs captured from real
# TLS handshakes. Running this requires root (tcpdump), openssl, and
# optionally a PQC-capable OpenSSL / nginx build for hybrid fixtures.
#
# Usage:
#   sudo ./scripts/generate_test_pcaps.sh [output_dir]
#
# Default output: tests/fixtures/pcaps/
#
set -euo pipefail

OUT="${1:-tests/fixtures/pcaps}"
mkdir -p "$OUT"

echo "[*] Output dir: $OUT"

if ! command -v tcpdump >/dev/null; then
  echo "tcpdump is required" >&2; exit 1
fi
if ! command -v openssl >/dev/null; then
  echo "openssl is required" >&2; exit 1
fi

# Pick a loopback-friendly interface. lo works for local captures.
IFACE="${IFACE:-lo}"

capture_and_run() {
  local name="$1"; shift
  local duration="$1"; shift
  local filter="$1"; shift
  local cmd=("$@")
  local out="$OUT/$name.pcap"
  echo "[*] Capturing: $name → $out (iface=$IFACE, filter=$filter)"
  tcpdump -i "$IFACE" -s 0 -U -w "$out" $filter &
  local td_pid=$!
  sleep 0.5
  "${cmd[@]}" || true
  sleep 0.5
  kill "$td_pid" 2>/dev/null || true
  wait "$td_pid" 2>/dev/null || true
  ls -la "$out"
}

# 1. TLS 1.3 classical handshake (x25519) against a public target.
capture_and_run \
  "tls13_classical" 5 "tcp port 443" \
  bash -c "openssl s_client -connect www.google.com:443 -servername www.google.com -tls1_3 -tlsextdebug < /dev/null 2>/dev/null | head -n 20"

# 2. TLS 1.3 hybrid X25519MLKEM768 — requires a server that supports it.
#    Cloudflare's pq.cloudflareresearch.com serves hybrid PQ handshakes.
capture_and_run \
  "tls13_hybrid_mlkem" 5 "tcp port 443" \
  bash -c "openssl s_client -connect pq.cloudflareresearch.com:443 -servername pq.cloudflareresearch.com -tls1_3 -groups X25519MLKEM768:X25519Kyber768Draft00:X25519 < /dev/null 2>/dev/null | head -n 30"

# 3. TLS 1.2 legacy (ECDHE-RSA).
capture_and_run \
  "tls12_legacy" 5 "tcp port 443" \
  bash -c "openssl s_client -connect www.google.com:443 -servername www.google.com -tls1_2 < /dev/null 2>/dev/null | head -n 20"

# 4. SSH KEXINIT to a public host (e.g. github.com).
capture_and_run \
  "ssh_kexinit" 5 "tcp port 22" \
  bash -c "ssh -o StrictHostKeyChecking=accept-new -o BatchMode=yes -o ConnectTimeout=3 github.com exit 2>/dev/null || true"

echo "[+] Done. PCAPs written to $OUT/"
echo "[+] Verify with: pqc-analyzer scan pcap $OUT/tls13_hybrid_mlkem.pcap"
