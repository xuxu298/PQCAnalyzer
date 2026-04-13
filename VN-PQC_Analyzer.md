# VN-PQC Readiness Analyzer
## Dự án đánh giá mức độ sẵn sàng chuyển đổi mật mã hậu lượng tử

**Tác giả:** Nguyễn Đồng
**Ngày tạo:** 12/04/2026
**Phiên bản:** 0.1.0 (Planning)
**License:** MIT
**Repo:** github.com/nguyendong/vn-pqc-analyzer (dự kiến)

---

## 1. Tổng quan dự án

### 1.1 Vấn đề cần giải quyết

Thuật toán Shor trên máy tính lượng tử sẽ phá vỡ RSA, ECC, và các hệ mật mã khóa công khai hiện tại. NIST đã chuẩn hóa ML-KEM (CRYSTALS-Kyber) và ML-DSA (CRYSTALS-Dilithium) làm thuật toán thay thế. Mỹ đặt deadline 2035 loại bỏ toàn bộ cryptography vulnerable.

Tại Việt Nam:
- Chưa có đánh giá hệ thống nào về mức độ phụ thuộc vào RSA/ECC trong hạ tầng quốc gia
- Kỹ sư viễn thông/ATTT chưa có công cụ để scan và đánh giá hệ thống của mình
- Policy maker (Ban Cơ yếu, Bộ TT&TT) chưa có dữ liệu để ra quyết định chuyển đổi
- Mối đe dọa "Harvest Now, Decrypt Later" đang xảy ra ngay lúc này

### 1.2 Giải pháp

**VN-PQC Readiness Analyzer** — bộ công cụ mã nguồn mở gồm 3 module:
1. **Crypto Inventory Scanner** — quét và liệt kê thuật toán mã hóa đang dùng trong hệ thống
2. **PQC Performance Benchmarker** — đo hiệu năng PQC algorithms trên phần cứng thực tế
3. **Migration Roadmap Generator** — tạo báo cáo lộ trình chuyển đổi tự động

### 1.3 Đối tượng người dùng

| Persona | Nhu cầu chính | Output mong đợi |
|---------|--------------|-----------------|
| Kỹ sư viễn thông/IT | Biết hệ thống dùng crypto gì, thay bằng gì, performance ra sao | Danh sách findings + benchmark data |
| IT Security engineer | Đánh giá risk, compliance check | Risk matrix + remediation plan |
| Policy maker (Ban Cơ yếu, Bộ TT&TT) | Overview hạ tầng quốc gia, budget estimate, timeline | Executive report PDF/HTML |
| Researcher/sinh viên | Reproduce kết quả, mở rộng nghiên cứu | Raw data + API |

### 1.4 Unique Value Proposition

- **Context Việt Nam/ASEAN** — benchmark trên phần cứng phổ thông ở khu vực (không chỉ server cao cấp Mỹ/EU)
- **End-to-end workflow** — từ scan → benchmark → report, không phải ghép nhiều tool rời rạc
- **Bilingual** — Giao diện và báo cáo song ngữ Việt-Anh
- **Actionable output** — không chỉ "bạn có vấn đề" mà "đây là cách sửa, theo thứ tự này, mất khoảng này"

---

## 2. Tech Stack

### 2.1 Core

| Thành phần | Lựa chọn | Lý do |
|-----------|---------|-------|
| Ngôn ngữ chính | Python 3.11+ | Cộng đồng quantum/crypto dùng Python, ecosystem phong phú |
| PQC Library | liboqs (Open Quantum Safe) via liboqs-python | Reference implementation chuẩn NIST, actively maintained |
| Classical Crypto | cryptography (pyca), pyOpenSSL | Mature, full-featured |
| TLS/Certificate parsing | ssl (stdlib), certifi, x509 | Phân tích cert chains |
| Network scanning | socket, ssl, scapy (optional) | Kết nối và probe TLS |
| Benchmarking | timeit, psutil, resource | Đo thời gian, CPU, memory |
| CLI | click hoặc typer | CLI framework modern, auto-generated help |
| Web UI | FastAPI (backend) + React/Vite (frontend) | API-first design, UI modern |
| Report generation | Jinja2 + WeasyPrint (PDF), Plotly (charts) | Báo cáo đẹp, có biểu đồ |
| Data storage | SQLite (local), JSON export | Lightweight, portable |
| Testing | pytest, pytest-benchmark | Standard Python testing |
| Packaging | pip (PyPI), Docker | Dễ cài đặt |

### 2.2 Thư mục dự án

```
vn-pqc-analyzer/
├── README.md
├── README.vi.md                    # README tiếng Việt
├── pyproject.toml
├── Dockerfile
├── docker-compose.yml
├── LICENSE                         # MIT
├── SECURITY.md                     # Vulnerability disclosure policy
├── CONTRIBUTING.md                 # Contribution guidelines
├── CODE_OF_CONDUCT.md              # Contributor Covenant v2.1
│
├── .github/
│   ├── ISSUE_TEMPLATE/
│   │   ├── bug_report.yml          # Bug report template
│   │   └── feature_request.yml     # Feature request template
│   ├── pull_request_template.md    # PR checklist template
│   └── workflows/
│       └── ci.yml                  # CI/CD pipeline
│
├── src/
│   ├── __init__.py
│   ├── cli.py                      # CLI entry point
│   ├── config.py                   # Configuration management
│   │
│   ├── scanner/                    # Module 1: Crypto Inventory Scanner
│   │   ├── __init__.py
│   │   ├── tls_scanner.py          # Scan TLS endpoints
│   │   ├── cert_analyzer.py        # Analyze certificate chains
│   │   ├── config_parser.py        # Parse config files (nginx, apache, haproxy...)
│   │   ├── code_scanner.py         # Scan source code for crypto usage
│   │   ├── vpn_scanner.py          # Scan VPN configurations (OpenVPN, WireGuard, IPSec)
│   │   ├── ssh_scanner.py          # Scan SSH configurations
│   │   ├── inventory.py            # Aggregate findings into inventory
│   │   └── models.py               # Data models for scan results
│   │
│   ├── benchmarker/                # Module 2: PQC Performance Benchmarker
│   │   ├── __init__.py
│   │   ├── keygen_bench.py         # Key generation benchmarks
│   │   ├── encaps_bench.py         # Encapsulation/decapsulation benchmarks (KEM)
│   │   ├── sign_bench.py           # Signing/verification benchmarks (DSA)
│   │   ├── tls_handshake_bench.py  # Full TLS handshake comparison
│   │   ├── throughput_bench.py     # Data throughput benchmarks
│   │   ├── memory_bench.py         # Memory usage profiling
│   │   ├── hardware_profile.py     # Detect and log hardware specs
│   │   ├── comparator.py           # Classical vs PQC comparison engine
│   │   └── models.py               # Data models for benchmark results
│   │
│   ├── roadmap/                    # Module 3: Migration Roadmap Generator
│   │   ├── __init__.py
│   │   ├── risk_scorer.py          # Risk assessment engine
│   │   ├── priority_engine.py      # Migration priority calculator
│   │   ├── timeline_generator.py   # Timeline estimation
│   │   ├── cost_estimator.py       # Effort/cost estimation
│   │   ├── recommendation.py       # Algorithm recommendation engine
│   │   ├── compliance_checker.py   # Check against NIST/Ban Cơ yếu guidelines
│   │   └── models.py               # Data models for roadmap
│   │
│   ├── reporter/                   # Report generation
│   │   ├── __init__.py
│   │   ├── html_report.py          # Interactive HTML report
│   │   ├── pdf_report.py           # PDF report (WeasyPrint)
│   │   ├── json_export.py          # Machine-readable export
│   │   ├── executive_summary.py    # High-level summary for policy makers
│   │   └── templates/              # Jinja2 templates
│   │       ├── report_base.html
│   │       ├── report_vi.html
│   │       ├── report_en.html
│   │       ├── executive_summary.html
│   │       └── styles.css
│   │
│   ├── api/                        # FastAPI backend
│   │   ├── __init__.py
│   │   ├── main.py                 # FastAPI app
│   │   ├── routes/
│   │   │   ├── scanner.py
│   │   │   ├── benchmarker.py
│   │   │   ├── roadmap.py
│   │   │   └── reports.py
│   │   └── schemas.py              # Pydantic schemas
│   │
│   └── utils/
│       ├── __init__.py
│       ├── crypto_db.py            # Database of algorithms + vulnerability status
│       ├── constants.py            # Algorithm classifications, NIST standards
│       └── i18n.py                 # Internationalization (vi/en)
│
├── web/                            # React frontend
│   ├── package.json
│   ├── vite.config.ts
│   ├── src/
│   │   ├── App.tsx
│   │   ├── pages/
│   │   │   ├── Dashboard.tsx       # Main dashboard
│   │   │   ├── Scanner.tsx         # Scanner interface
│   │   │   ├── Benchmark.tsx       # Benchmark interface
│   │   │   ├── Roadmap.tsx         # Roadmap viewer
│   │   │   └── Report.tsx          # Report preview/download
│   │   ├── components/
│   │   │   ├── RiskMatrix.tsx      # Risk heatmap component
│   │   │   ├── BenchmarkChart.tsx  # Performance comparison charts
│   │   │   ├── Timeline.tsx        # Migration timeline visual
│   │   │   ├── AlgorithmCard.tsx   # Algorithm info card
│   │   │   ├── ScanProgress.tsx    # Scan progress indicator
│   │   │   └── LanguageToggle.tsx  # VI/EN switch
│   │   ├── hooks/
│   │   ├── utils/
│   │   └── i18n/
│   │       ├── vi.json
│   │       └── en.json
│   └── public/
│
├── data/
│   ├── algorithms.json             # Master list of crypto algorithms + status
│   ├── nist_guidelines.json        # NIST PQC transition guidelines
│   ├── vietnam_guidelines.json     # Ban Cơ yếu / Bộ TT&TT guidelines (khi có)
│   └── sample_configs/             # Sample configs for testing
│       ├── nginx_sample.conf
│       ├── apache_sample.conf
│       ├── openvpn_sample.conf
│       └── ssh_sample_config
│
├── tests/
│   ├── test_scanner/
│   ├── test_benchmarker/
│   ├── test_roadmap/
│   └── test_reporter/
│
├── docs/
│   ├── architecture.md
│   ├── user_guide_vi.md
│   ├── user_guide_en.md
│   ├── api_reference.md
│   └── contributing.md
│
└── examples/
    ├── scan_single_host.py
    ├── scan_network_range.py
    ├── run_benchmark.py
    ├── generate_report.py
    └── demo_full_workflow.py
```

---

## 3. Module 1 — Crypto Inventory Scanner

### 3.1 Chức năng

Scanner quét và liệt kê tất cả thuật toán mã hóa đang được sử dụng trong hệ thống mục tiêu.

### 3.2 Scan Targets

#### 3.2.1 TLS Endpoint Scanner (`tls_scanner.py`)
- Input: hostname:port hoặc danh sách hosts (file txt/csv)
- Kết nối TLS, thu thập:
  - Protocol version (TLS 1.0, 1.1, 1.2, 1.3)
  - Cipher suites được chấp nhận (liệt kê tất cả, không chỉ negotiated)
  - Key exchange algorithms (RSA, ECDHE, DHE...)
  - Authentication algorithms
  - Certificate chain (phân tích riêng ở cert_analyzer)
  - Supported groups / named curves
  - Signature algorithms
- Hỗ trợ scan batch: file chứa danh sách host, scan parallel (asyncio)
- Timeout configurable, retry logic

#### 3.2.2 Certificate Analyzer (`cert_analyzer.py`)
- Input: certificate file (PEM/DER) hoặc cert chain từ TLS scan
- Phân tích:
  - Subject/Issuer
  - Public key algorithm + key size (RSA-2048, ECDSA-P256, Ed25519...)
  - Signature algorithm (sha256WithRSA, ecdsa-with-SHA384...)
  - Validity period
  - Extensions (Key Usage, Extended Key Usage, SAN...)
  - Chain of trust (root → intermediate → leaf)
- Đánh giá: mỗi algorithm → map sang mức vulnerability (Critical/High/Medium/Low/Safe)

#### 3.2.3 Configuration Parser (`config_parser.py`)
- Parse file config của:
  - **Nginx**: ssl_protocols, ssl_ciphers, ssl_certificate directives
  - **Apache**: SSLProtocol, SSLCipherSuite, SSLCertificateFile
  - **HAProxy**: bind ... ssl crt ... ciphers
  - **Caddy**: tls block
- Output: danh sách algorithms extracted từ config
- Extensible: plugin architecture để thêm parser cho config mới

#### 3.2.4 Code Scanner (`code_scanner.py`)
- Scan source code repositories tìm crypto usage patterns:
  - Python: `from cryptography...`, `from Crypto...`, `hashlib`, `ssl.PROTOCOL_*`
  - Java: `Cipher.getInstance("RSA/...")`, `KeyPairGenerator`, `Signature`
  - Go: `crypto/rsa`, `crypto/ecdsa`, `x509`
  - JavaScript/Node: `crypto.createSign`, `tls.createServer`
  - C/C++: OpenSSL API calls (`EVP_*`, `RSA_*`, `EC_*`)
- Regex + AST-based detection (nơi khả thi)
- Output: file, line number, algorithm detected, risk level

#### 3.2.5 VPN Scanner (`vpn_scanner.py`)
- Parse config:
  - **OpenVPN**: cipher, auth, tls-cipher, ca, cert, key directives
  - **WireGuard**: phân tích Curve25519 (safe vs quantum), ChaCha20-Poly1305
  - **IPSec/IKEv2**: ike=, esp=, phase1/phase2 proposals
- Đánh giá quantum vulnerability cho từng layer (key exchange, authentication, encryption)

#### 3.2.6 SSH Scanner (`ssh_scanner.py`)
- Parse sshd_config và ssh_config:
  - HostKeyAlgorithms
  - KexAlgorithms
  - Ciphers
  - MACs
  - PubkeyAcceptedAlgorithms
- Remote scan: kết nối SSH (không authenticate), thu thập server offerings

### 3.3 Vulnerability Classification

Mỗi algorithm phát hiện được → map sang classification:

```json
{
  "algorithm_db": {
    "RSA-2048": {
      "type": "asymmetric",
      "usage": ["key_exchange", "signature"],
      "quantum_vulnerable": true,
      "risk_level": "CRITICAL",
      "attack": "Shor's algorithm",
      "estimated_break": "2030-2040 (CRQC)",
      "replacement": ["ML-KEM-768", "ML-DSA-65"],
      "migration_priority": 1,
      "note_vi": "Phá vỡ hoàn toàn bởi thuật toán Shor. Cần chuyển đổi ngay.",
      "note_en": "Completely broken by Shor's algorithm. Migrate immediately."
    },
    "ECDSA-P256": {
      "type": "asymmetric",
      "usage": ["signature"],
      "quantum_vulnerable": true,
      "risk_level": "CRITICAL",
      "attack": "Shor's algorithm",
      "estimated_break": "2030-2040 (CRQC)",
      "replacement": ["ML-DSA-44", "ML-DSA-65"],
      "migration_priority": 1,
      "note_vi": "ECC bị phá bởi biến thể Shor cho logarithm rời rạc.",
      "note_en": "ECC broken by Shor's variant for discrete logarithm."
    },
    "ECDHE-P256": {
      "type": "key_exchange",
      "usage": ["key_exchange"],
      "quantum_vulnerable": true,
      "risk_level": "HIGH",
      "attack": "Shor's algorithm",
      "estimated_break": "2030-2040 (CRQC)",
      "replacement": ["ML-KEM-768", "X25519Kyber768"],
      "migration_priority": 1,
      "note_vi": "Forward secrecy bảo vệ phiên hiện tại nhưng không chống harvest-now-decrypt-later.",
      "note_en": "Forward secrecy protects current sessions but not against HNDL."
    },
    "AES-256": {
      "type": "symmetric",
      "usage": ["encryption"],
      "quantum_vulnerable": false,
      "risk_level": "LOW",
      "attack": "Grover's algorithm reduces to 128-bit security",
      "estimated_break": "Vẫn an toàn",
      "replacement": ["AES-256 (giữ nguyên)"],
      "migration_priority": 4,
      "note_vi": "AES-256 giảm xuống 128-bit security qua Grover — vẫn đủ mạnh.",
      "note_en": "AES-256 reduced to 128-bit security via Grover — still sufficient."
    },
    "AES-128": {
      "type": "symmetric",
      "usage": ["encryption"],
      "quantum_vulnerable": false,
      "risk_level": "MEDIUM",
      "attack": "Grover's algorithm reduces to 64-bit security",
      "estimated_break": "Có thể không đủ post-quantum",
      "replacement": ["AES-256"],
      "migration_priority": 3,
      "note_vi": "AES-128 giảm xuống 64-bit — nên nâng lên AES-256.",
      "note_en": "AES-128 reduced to 64-bit — should upgrade to AES-256."
    },
    "SHA-256": {
      "type": "hash",
      "usage": ["integrity", "signature"],
      "quantum_vulnerable": false,
      "risk_level": "LOW",
      "attack": "Grover reduces collision resistance, still adequate",
      "estimated_break": "Vẫn an toàn",
      "replacement": ["SHA-256 (giữ nguyên)", "SHA-384", "SHA-3"],
      "migration_priority": 5,
      "note_vi": "Hash functions ảnh hưởng nhẹ bởi Grover, SHA-256 vẫn an toàn.",
      "note_en": "Hash functions lightly affected by Grover, SHA-256 remains safe."
    },
    "ChaCha20-Poly1305": {
      "type": "symmetric",
      "usage": ["encryption", "aead"],
      "quantum_vulnerable": false,
      "risk_level": "LOW",
      "attack": "Grover (giảm key space, vẫn đủ mạnh với 256-bit key)",
      "estimated_break": "Vẫn an toàn",
      "replacement": ["ChaCha20-Poly1305 (giữ nguyên)"],
      "migration_priority": 5,
      "note_vi": "Symmetric 256-bit, an toàn post-quantum.",
      "note_en": "Symmetric 256-bit, post-quantum safe."
    },
    "ML-KEM-768": {
      "type": "kem",
      "usage": ["key_exchange"],
      "quantum_vulnerable": false,
      "risk_level": "SAFE",
      "attack": "None known",
      "estimated_break": "N/A",
      "replacement": [],
      "migration_priority": 0,
      "note_vi": "Chuẩn NIST FIPS 203. Đã sẵn sàng triển khai.",
      "note_en": "NIST FIPS 203 standard. Ready for deployment."
    },
    "ML-DSA-65": {
      "type": "signature",
      "usage": ["signature", "authentication"],
      "quantum_vulnerable": false,
      "risk_level": "SAFE",
      "attack": "None known",
      "estimated_break": "N/A",
      "replacement": [],
      "migration_priority": 0,
      "note_vi": "Chuẩn NIST FIPS 204. Đã sẵn sàng triển khai.",
      "note_en": "NIST FIPS 204 standard. Ready for deployment."
    }
  }
}
```

Thêm nhiều algorithms khác: DH, DSA, RSA-3072, RSA-4096, Ed25519, X25519, 3DES, RC4, MD5, SHA-1, SLH-DSA, FN-DSA, v.v.

### 3.4 Output Format

```json
{
  "scan_id": "uuid",
  "timestamp": "2026-04-12T10:30:00+07:00",
  "target": "example.vn:443",
  "scan_type": "tls_endpoint",
  "findings": [
    {
      "component": "TLS Key Exchange",
      "algorithm": "ECDHE-P256",
      "risk_level": "HIGH",
      "quantum_vulnerable": true,
      "location": "TLS 1.3 handshake, supported group",
      "replacement": "ML-KEM-768 or X25519Kyber768 hybrid",
      "priority": 1
    },
    {
      "component": "Certificate Signature",
      "algorithm": "ECDSA-P256 with SHA-256",
      "risk_level": "CRITICAL",
      "quantum_vulnerable": true,
      "location": "Leaf certificate, CN=example.vn",
      "replacement": "ML-DSA-65 (khi CA hỗ trợ)",
      "priority": 1
    },
    {
      "component": "Bulk Encryption",
      "algorithm": "AES-256-GCM",
      "risk_level": "LOW",
      "quantum_vulnerable": false,
      "location": "TLS 1.3 cipher suite",
      "replacement": "Giữ nguyên",
      "priority": 5
    }
  ],
  "summary": {
    "total_findings": 3,
    "critical": 1,
    "high": 1,
    "medium": 0,
    "low": 1,
    "safe": 0,
    "overall_risk": "CRITICAL"
  }
}
```

---

## 4. Module 2 — PQC Performance Benchmarker

### 4.1 Chức năng

Benchmark so sánh hiệu năng giữa classical crypto hiện tại và PQC algorithms chuẩn NIST, chạy trên phần cứng thực tế của người dùng.

### 4.2 Algorithms to Benchmark

**KEM (Key Encapsulation Mechanism):**

| Classical | PQC Replacement | NIST Standard |
|-----------|----------------|---------------|
| RSA-2048 KEM | ML-KEM-512 | FIPS 203 |
| RSA-3072 KEM | ML-KEM-768 | FIPS 203 |
| RSA-4096 KEM | ML-KEM-1024 | FIPS 203 |
| ECDH-P256 | ML-KEM-768 | FIPS 203 |
| X25519 | ML-KEM-768 | FIPS 203 |
| — | X25519Kyber768 (hybrid) | Draft |

**Digital Signatures:**

| Classical | PQC Replacement | NIST Standard |
|-----------|----------------|---------------|
| RSA-2048 Sign | ML-DSA-44 | FIPS 204 |
| RSA-3072 Sign | ML-DSA-65 | FIPS 204 |
| ECDSA-P256 | ML-DSA-44 | FIPS 204 |
| Ed25519 | ML-DSA-44 | FIPS 204 |
| RSA-4096 Sign | ML-DSA-87 | FIPS 204 |
| — | SLH-DSA-SHA2-128s | FIPS 205 |
| — | SLH-DSA-SHA2-128f | FIPS 205 |

### 4.3 Metrics to Measure

Cho mỗi algorithm, đo:

1. **Key Generation Time** (ms) — trung bình, median, p95, p99 trên N=1000 iterations
2. **Encapsulation / Encryption Time** (ms) — tương tự
3. **Decapsulation / Decryption Time** (ms)
4. **Sign Time** (ms) — cho DSA algorithms
5. **Verify Time** (ms)
6. **Key Sizes** (bytes) — public key, secret key, ciphertext/signature
7. **Memory Usage** (KB) — peak RSS during operation
8. **TLS Handshake Time** (ms) — full handshake simulation với classical vs PQC vs hybrid
9. **Throughput** (ops/sec) — operations per second under sustained load
10. **CPU Utilization** (%) — single-core và multi-core

### 4.4 Hardware Profiling

Tự động detect và log:
- CPU model, cores, frequency, architecture (x86_64/ARM)
- RAM total
- OS version
- Python version
- liboqs version
- OpenSSL version
- Có/không có hardware crypto acceleration (AES-NI, SHA extensions, AVX2, AVX-512)

Tạo hardware fingerprint để so sánh kết quả giữa các máy khác nhau.

### 4.5 Preset Hardware Profiles

Đặc biệt quan trọng cho context Việt Nam — pre-defined profiles:

```python
HARDWARE_PROFILES = {
    "vietnam_gov_server": {
        "description": "Typical Vietnamese government agency server",
        "cpu": "Intel Xeon E-2200 series or equivalent",
        "ram": "32-64 GB",
        "note": "Phổ biến trong hạ tầng chính phủ VN"
    },
    "vietnam_bank_server": {
        "description": "Vietnamese banking infrastructure server",
        "cpu": "Intel Xeon Gold 5300/6300 or equivalent",
        "ram": "64-256 GB",
        "note": "Core banking, payment gateway"
    },
    "vietnam_telco_edge": {
        "description": "Telecom edge device (base station controller, gateway)",
        "cpu": "ARM Cortex-A72 or Intel Atom",
        "ram": "4-16 GB",
        "note": "VNPT, Viettel, Mobifone edge infra"
    },
    "vietnam_iot_device": {
        "description": "IoT device common in Vietnam",
        "cpu": "ARM Cortex-M4/M7 or ESP32",
        "ram": "256 KB - 4 MB",
        "note": "Smart meter, sensor, gateway"
    },
    "vietnam_consumer_phone": {
        "description": "Mid-range smartphone popular in Vietnam",
        "cpu": "Snapdragon 6xx / MediaTek Dimensity 700",
        "ram": "4-6 GB",
        "note": "Samsung Galaxy A series, Xiaomi Redmi series"
    }
}
```

### 4.6 Output Format

```json
{
  "benchmark_id": "uuid",
  "timestamp": "2026-04-12T10:30:00+07:00",
  "hardware": {
    "cpu": "Intel Core i7-12700H",
    "cores": 14,
    "ram_gb": 32,
    "os": "Ubuntu 22.04",
    "python": "3.11.5",
    "liboqs": "0.10.0",
    "has_avx2": true,
    "has_aesni": true
  },
  "results": [
    {
      "algorithm": "ML-KEM-768",
      "type": "kem",
      "iterations": 1000,
      "keygen_ms": {"mean": 0.12, "median": 0.11, "p95": 0.15, "p99": 0.19},
      "encaps_ms": {"mean": 0.14, "median": 0.13, "p95": 0.18, "p99": 0.22},
      "decaps_ms": {"mean": 0.15, "median": 0.14, "p95": 0.19, "p99": 0.24},
      "pubkey_bytes": 1184,
      "seckey_bytes": 2400,
      "ciphertext_bytes": 1088,
      "memory_peak_kb": 245
    },
    {
      "algorithm": "RSA-2048",
      "type": "kem",
      "iterations": 1000,
      "keygen_ms": {"mean": 152.3, "median": 140.1, "p95": 280.5, "p99": 420.1},
      "encrypt_ms": {"mean": 0.08, "median": 0.07, "p95": 0.12, "p99": 0.15},
      "decrypt_ms": {"mean": 1.85, "median": 1.80, "p95": 2.10, "p99": 2.45},
      "pubkey_bytes": 294,
      "seckey_bytes": 1218,
      "ciphertext_bytes": 256,
      "memory_peak_kb": 180
    }
  ],
  "comparison": {
    "keygen_speedup": "ML-KEM-768 nhanh hơn RSA-2048 ~1200x",
    "encaps_overhead": "ML-KEM-768 chậm hơn RSA encrypt ~1.7x",
    "size_tradeoff": "ML-KEM-768 public key lớn hơn RSA-2048 ~4x",
    "overall": "ML-KEM-768 nhanh hơn đáng kể ở keygen, tương đương ở encaps/decaps, key size lớn hơn nhưng chấp nhận được"
  }
}
```

### 4.7 Visualization

Tạo biểu đồ so sánh (Plotly):
- Bar chart: thời gian keygen/encaps/decaps classical vs PQC
- Table: key sizes so sánh
- Radar chart: multi-dimensional comparison (speed, size, security level)
- Line chart: performance vs security level tradeoff

---

## 5. Module 3 — Migration Roadmap Generator

### 5.1 Chức năng

Dựa trên kết quả scan (Module 1) và benchmark (Module 2), tự động tạo lộ trình chuyển đổi PQC.

### 5.2 Risk Scoring Engine

Mỗi finding từ scanner được tính risk score:

```python
risk_score = (
    vulnerability_weight      # CRITICAL=10, HIGH=8, MEDIUM=5, LOW=2, SAFE=0
    * exposure_factor          # Internet-facing=3, Internal=2, Isolated=1
    * data_sensitivity         # Top Secret=5, Secret=4, Confidential=3, Internal=2, Public=1
    * harvest_now_risk         # Long-lived data=3, Session data=2, Ephemeral=1
)
```

### 5.3 Migration Phases

Roadmap chia thành 4 phase:

**Phase 0 — Inventory & Assessment (0-3 tháng)**
- Chạy scanner trên toàn bộ hệ thống
- Benchmark PQC trên phần cứng production
- Xác định scope

**Phase 1 — Quick Wins (3-6 tháng)**
- Enable hybrid key exchange (X25519Kyber768) trên TLS 1.3 endpoints
- Upgrade cipher suites (disable RSA key exchange, prefer ECDHE+AES-256)
- Update SSH configs (disable weak KEX algorithms)
- Nâng AES-128 → AES-256 nơi khả thi

**Phase 2 — Core Migration (6-18 tháng)**
- Migrate VPN infrastructure sang PQC-capable (IPSec with PQC proposals)
- PKI preparation: plan CA migration sang PQC certificates
- Application-level crypto migration (code changes)
- Testing hybrid mode production

**Phase 3 — Full PQC (18-36 tháng)**
- Full PQC certificates (khi CA ecosystem sẵn sàng)
- Retire classical-only cipher suites
- Compliance verification
- Continuous monitoring

### 5.4 Recommendation Engine

Cho mỗi finding, tự động recommend:

```python
def recommend_replacement(finding):
    """
    Input: finding from scanner
    Output: recommended replacement + implementation steps
    """
    recommendations = {
        "RSA-2048 key exchange": {
            "replace_with": "ML-KEM-768 (hoặc hybrid X25519Kyber768)",
            "steps": [
                "Kiểm tra server/client hỗ trợ TLS 1.3",
                "Enable X25519Kyber768 hybrid key exchange",
                "Monitor handshake performance",
                "Disable RSA key exchange sau khi verify"
            ],
            "effort": "Low-Medium",
            "risk": "Low (hybrid mode backward compatible)",
            "timeline": "Phase 1"
        },
        "ECDSA certificate": {
            "replace_with": "ML-DSA-65 (khi CA hỗ trợ), hoặc hybrid cert",
            "steps": [
                "Kiểm tra CA provider có issue PQC certs chưa",
                "Request hybrid certificate (nếu có)",
                "Test certificate chain validation",
                "Deploy song song classical + PQC cert"
            ],
            "effort": "Medium-High",
            "risk": "Medium (CA ecosystem chưa sẵn sàng hoàn toàn)",
            "timeline": "Phase 2-3"
        }
    }
    return recommendations.get(finding.algorithm_usage)
```

### 5.5 Cost Estimator

Ước tính effort cho migration:

```python
EFFORT_MATRIX = {
    "tls_config_update": {"person_hours": 4, "risk": "low", "downtime": "0"},
    "cipher_suite_update": {"person_hours": 8, "risk": "low", "downtime": "minutes"},
    "vpn_migration": {"person_hours": 40, "risk": "medium", "downtime": "hours"},
    "pki_migration": {"person_hours": 160, "risk": "high", "downtime": "planned"},
    "application_code_change": {"person_hours": 80, "risk": "medium", "downtime": "varies"},
    "certificate_replacement": {"person_hours": 24, "risk": "medium", "downtime": "0 (if planned)"},
    "hardware_upgrade": {"person_hours": 200, "risk": "high", "downtime": "planned"},
    "testing_validation": {"person_hours": 120, "risk": "low", "downtime": "0"}
}
```

### 5.6 Output: Migration Report

Bao gồm các section:

1. **Executive Summary** (1 trang) — cho policy maker: tổng quan risk, timeline, budget estimate
2. **Risk Assessment** — heatmap findings theo severity × exposure
3. **Current State Analysis** — danh sách tất cả crypto đang dùng, phân loại
4. **Benchmark Results** — performance comparison, phần cứng specific
5. **Migration Roadmap** — timeline visual, 4 phases, milestones
6. **Detailed Recommendations** — từng finding + cách sửa + effort
7. **Cost Estimation** — tổng person-hours, estimated cost range
8. **Compliance Status** — check against NIST guidelines, Ban Cơ yếu requirements (khi có)
9. **Appendix** — raw data, methodology, glossary thuật ngữ

---

## 6. UI/UX Design

### 6.1 Design Principles

- **Clarity over decoration** — data-driven, không rườm rà
- **Action-oriented** — mọi màn hình đều dẫn đến action cụ thể
- **Bilingual** — toggle VI/EN ở header, persist preference
- **Responsive** — hoạt động trên desktop và tablet
- **Dark mode default** — phù hợp context cybersecurity (light mode toggle available)

### 6.2 Color Palette

```css
/* Risk levels */
--risk-critical: #E53E3E;    /* Đỏ — Quantum vulnerable, cần sửa ngay */
--risk-high:     #ED8936;    /* Cam — Quantum vulnerable, ưu tiên cao */
--risk-medium:   #ECC94B;    /* Vàng — Cần nâng cấp */
--risk-low:      #48BB78;    /* Xanh lá — Ít ảnh hưởng */
--risk-safe:     #38B2AC;    /* Teal — Post-quantum safe */

/* UI */
--bg-primary:    #0F1729;    /* Dark navy background */
--bg-secondary:  #1A2332;    /* Card background */
--bg-tertiary:   #243044;    /* Hover/active states */
--text-primary:  #E2E8F0;    /* Main text */
--text-secondary:#A0AEC0;    /* Secondary text */
--accent:        #14A3C7;    /* Cyan accent — consistent with "Con đường Lượng tử" branding */
--accent-alt:    #0D7377;    /* Teal accent */
--border:        #2D3748;    /* Border color */
```

### 6.3 Page Layouts

#### 6.3.1 Dashboard (Landing page sau login)

```
┌─────────────────────────────────────────────────────────┐
│  VN-PQC Readiness Analyzer          [VI/EN] [⚙ Settings]│
├─────────────────────────────────────────────────────────┤
│                                                         │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌─────────┐ │
│  │ CRITICAL │  │   HIGH   │  │  MEDIUM  │  │  SAFE   │ │
│  │    12    │  │    8     │  │    23    │  │   45    │ │
│  │ findings │  │ findings │  │ findings │  │findings │ │
│  └──────────┘  └──────────┘  └──────────┘  └─────────┘ │
│                                                         │
│  Overall PQC Readiness Score                            │
│  ████████░░░░░░░░░░░░  38/100  [Needs Attention]       │
│                                                         │
│  ┌──────────────────────┐  ┌──────────────────────────┐ │
│  │  Risk Distribution   │  │  Top 5 Urgent Findings   │ │
│  │  ┌─────────────────┐ │  │                          │ │
│  │  │   [Pie Chart]   │ │  │  1. RSA-2048 on gateway  │ │
│  │  │  Critical: 14%  │ │  │  2. ECDSA cert expired   │ │
│  │  │  High: 9%       │ │  │  3. TLS 1.0 still on     │ │
│  │  │  Medium: 26%    │ │  │  4. SSH weak KEX          │ │
│  │  │  Safe: 51%      │ │  │  5. OpenVPN no PFS        │ │
│  │  └─────────────────┘ │  │                          │ │
│  └──────────────────────┘  └──────────────────────────┘ │
│                                                         │
│  Quick Actions                                          │
│  [▶ Run New Scan]  [📊 Run Benchmark]  [📄 Generate Report] │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

#### 6.3.2 Scanner Page

```
┌─────────────────────────────────────────────────────────┐
│  Scanner                                    [▶ Run Scan] │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  Scan Type:  (●) TLS Endpoints                          │
│              ( ) Config Files                            │
│              ( ) Source Code                             │
│              ( ) VPN Config                              │
│              ( ) SSH Config                              │
│              ( ) Full (all of the above)                 │
│                                                         │
│  Target:                                                │
│  ┌─────────────────────────────────────────────────┐    │
│  │ example.vn:443                                  │    │
│  │ mail.example.vn:993                             │    │
│  │ vpn.example.vn:1194                             │    │
│  │ (or upload hosts.txt / drop config files)       │    │
│  └─────────────────────────────────────────────────┘    │
│                                                         │
│  Options:                                               │
│  [✓] Scan all cipher suites    [ ] Deep cert analysis   │
│  [✓] Check HNDL exposure       [✓] Include remediation  │
│                                                         │
│  ─── Scan Results ───────────────────────────────────── │
│                                                         │
│  Progress: ████████████░░░░░░  67% (4/6 targets)       │
│                                                         │
│  ┌─────────────────────────────────────────────────┐    │
│  │ 🔴 example.vn:443                               │    │
│  │    Key Exchange: ECDHE-P256 ⚠ QUANTUM VULNERABLE│    │
│  │    Certificate:  RSA-2048   🔴 CRITICAL         │    │
│  │    Bulk Cipher:  AES-256    ✅ SAFE              │    │
│  │    [View Details] [Add to Report]                │    │
│  ├─────────────────────────────────────────────────┤    │
│  │ 🟡 mail.example.vn:993                          │    │
│  │    Key Exchange: ECDHE-P384 ⚠ QUANTUM VULNERABLE│    │
│  │    Certificate:  ECDSA-P384 ⚠ HIGH              │    │
│  │    Bulk Cipher:  AES-128    🟡 MEDIUM           │    │
│  │    [View Details] [Add to Report]                │    │
│  └─────────────────────────────────────────────────┘    │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

#### 6.3.3 Benchmark Page

```
┌─────────────────────────────────────────────────────────┐
│  Benchmark                            [▶ Run Benchmark]  │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  Hardware Detected:                                     │
│  CPU: Intel Core i7-12700H (14 cores)                   │
│  RAM: 32 GB | OS: Ubuntu 22.04 | AVX2: ✅              │
│                                                         │
│  Select Algorithms:                                     │
│  KEM:  [✓] ML-KEM-512  [✓] ML-KEM-768  [✓] ML-KEM-1024│
│        [✓] RSA-2048    [✓] ECDH-P256   [✓] X25519      │
│  DSA:  [✓] ML-DSA-44   [✓] ML-DSA-65   [ ] ML-DSA-87   │
│        [✓] RSA-2048    [✓] ECDSA-P256  [✓] Ed25519     │
│                                                         │
│  Iterations: [1000 ▼]                                   │
│                                                         │
│  ─── Results ────────────────────────────────────────── │
│                                                         │
│  Key Generation (ms)                                    │
│  ┌─────────────────────────────────────────────┐        │
│  │ ML-KEM-768  ████ 0.12                       │        │
│  │ X25519      ██ 0.04                         │        │
│  │ ECDH-P256   ███ 0.08                        │        │
│  │ RSA-2048    ████████████████████████ 152.3   │        │
│  └─────────────────────────────────────────────┘        │
│                                                         │
│  Key Sizes (bytes)                                      │
│  ┌─────────────────────────────────────────────┐        │
│  │         │ Public Key │ Secret Key │ CT/Sig  │        │
│  │ ML-KEM  │   1,184    │   2,400    │  1,088  │        │
│  │ RSA-2048│     294    │   1,218    │    256  │        │
│  │ ECDH-256│      65    │      32    │     65  │        │
│  └─────────────────────────────────────────────┘        │
│                                                         │
│  [📊 Full Comparison] [📥 Export CSV] [📄 Add to Report] │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

#### 6.3.4 Roadmap Page

```
┌─────────────────────────────────────────────────────────┐
│  Migration Roadmap                  [📄 Generate Report] │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  Based on: Scan #abc123 (12 Apr 2026) + Benchmark #xyz  │
│  Scope: 6 TLS endpoints, 2 VPN, 3 SSH servers          │
│                                                         │
│  Overall Timeline                                       │
│  ┌─────────────────────────────────────────────────┐    │
│  │ Phase 0      Phase 1      Phase 2     Phase 3   │    │
│  │ Assessment   Quick Wins   Core        Full PQC  │    │
│  │ ████         ████████     ████████████ ████████  │    │
│  │ 0-3 mo       3-6 mo       6-18 mo     18-36 mo  │    │
│  │ ✅ Done       ◀ You are here                     │    │
│  └─────────────────────────────────────────────────┘    │
│                                                         │
│  Phase 1 — Quick Wins (3-6 tháng)                       │
│  ┌─────────────────────────────────────────────────┐    │
│  │ ☐ Enable X25519Kyber768 on nginx gateway        │    │
│  │   Effort: 4h | Risk: Low | Impact: High         │    │
│  │                                                  │    │
│  │ ☐ Upgrade AES-128 → AES-256 on mail server      │    │
│  │   Effort: 8h | Risk: Low | Impact: Medium        │    │
│  │                                                  │    │
│  │ ☐ Update SSH KexAlgorithms on all servers        │    │
│  │   Effort: 2h | Risk: Low | Impact: Medium        │    │
│  └─────────────────────────────────────────────────┘    │
│                                                         │
│  Estimated Total Effort: 480 person-hours               │
│  Estimated Timeline: 24 months                          │
│  Estimated Cost Range: 200-400 triệu VNĐ               │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

#### 6.3.5 Report Page

```
┌─────────────────────────────────────────────────────────┐
│  Report Generator                                        │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  Report Type:                                           │
│  (●) Full Technical Report                              │
│  ( ) Executive Summary (Policy Maker)                   │
│  ( ) Compliance Report                                  │
│                                                         │
│  Language: (●) Tiếng Việt  ( ) English  ( ) Both        │
│                                                         │
│  Include:                                               │
│  [✓] Scan Results        [✓] Benchmark Data             │
│  [✓] Risk Assessment     [✓] Migration Roadmap          │
│  [✓] Cost Estimation     [ ] Raw Data Appendix          │
│                                                         │
│  Organization Name: [Tên tổ chức________________]       │
│  Report Date:       [12/04/2026]                        │
│  Prepared By:       [_________________________]         │
│                                                         │
│  Format: [✓] HTML (interactive)  [✓] PDF  [ ] JSON      │
│                                                         │
│  [📄 Generate Report]                                    │
│                                                         │
│  ─── Preview ────────────────────────────────────────── │
│  ┌─────────────────────────────────────────────────┐    │
│  │  VN-PQC READINESS ASSESSMENT REPORT             │    │
│  │  Tổ chức: [Tên]                                 │    │
│  │  Ngày: 12/04/2026                               │    │
│  │                                                  │    │
│  │  EXECUTIVE SUMMARY                               │    │
│  │  Hệ thống hiện có 12 điểm CRITICAL cần          │    │
│  │  chuyển đổi ngay. Ước tính 480 giờ công,        │    │
│  │  hoàn thành trong 24 tháng...                   │    │
│  └─────────────────────────────────────────────────┘    │
│                                                         │
│  [📥 Download PDF]  [🔗 Share Link]  [📧 Email Report]  │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

### 6.4 CLI Interface

Song song với Web UI, CLI đầy đủ cho automation:

```bash
# Scan single TLS endpoint
$ pqc-analyzer scan tls example.vn:443

# Scan from hosts file
$ pqc-analyzer scan tls --hosts-file targets.txt --output results.json

# Scan config files
$ pqc-analyzer scan config /etc/nginx/nginx.conf
$ pqc-analyzer scan config /etc/openvpn/server.conf

# Scan source code
$ pqc-analyzer scan code ./my-project --language python,java

# Run benchmarks
$ pqc-analyzer benchmark --algorithms all --iterations 1000
$ pqc-analyzer benchmark --algorithms ML-KEM-768,RSA-2048 --output bench.json

# Generate roadmap from scan + benchmark results
$ pqc-analyzer roadmap --scan-results scan.json --benchmark bench.json

# Generate full report
$ pqc-analyzer report \
    --scan-results scan.json \
    --benchmark bench.json \
    --format pdf,html \
    --language vi \
    --org-name "Tên tổ chức" \
    --output report/

# Full pipeline
$ pqc-analyzer full \
    --hosts-file targets.txt \
    --benchmark-iterations 1000 \
    --report-format pdf \
    --language vi \
    --output ./assessment/
```

---

## 7. Development Roadmap

### Phase 1 — MVP Scanner (Tuần 1-6)

**Mục tiêu:** Ship được scanner cơ bản, chạy từ CLI, output JSON.

Tuần 1-2:
- Setup project structure, CI/CD (GitHub Actions)
- Implement `tls_scanner.py` — scan single host, extract cipher suites + cert info
- Implement `cert_analyzer.py` — parse cert chain, extract algorithms
- Implement `algorithms.json` — master database 30+ algorithms với vulnerability classification

Tuần 3-4:
- Implement `config_parser.py` — nginx và apache parser
- Implement `ssh_scanner.py` — parse sshd_config
- Implement `inventory.py` — aggregate all findings
- CLI interface: `pqc-analyzer scan` commands

Tuần 5-6:
- Implement batch scanning (hosts file, parallel)
- JSON output format finalized
- Basic HTML report (Jinja2 template)
- Unit tests, README, documentation
- **Publish v0.1.0 trên GitHub + PyPI**
- Blog post: "Introducing VN-PQC Readiness Analyzer"

**Deliverables Phase 1:**
- `pqc-analyzer scan tls` works
- `pqc-analyzer scan config` works
- `pqc-analyzer scan ssh` works
- JSON + basic HTML output
- Published on PyPI: `pip install vn-pqc-analyzer`

### Phase 2 — Benchmarker + VPN (Tuần 7-12)

**Mục tiêu:** Thêm benchmark module, VPN scanner, nâng cấp report.

Tuần 7-8:
- Integrate liboqs-python
- Implement KEM benchmarks (ML-KEM-512/768/1024 vs RSA vs ECDH)
- Implement DSA benchmarks (ML-DSA-44/65/87 vs RSA vs ECDSA vs Ed25519)
- Hardware profiling

Tuần 9-10:
- TLS handshake benchmark simulation
- Implement `vpn_scanner.py` (OpenVPN, WireGuard, IPSec)
- Implement `code_scanner.py` (Python, Java, Go — basic regex patterns)
- Comparison engine + visualization (Plotly charts)

Tuần 11-12:
- Performance optimization
- Extended algorithm database
- Improved HTML report với charts
- **Publish v0.2.0**
- Blog post: "PQC Performance: What Vietnam's Infrastructure Should Expect"

**Deliverables Phase 2:**
- `pqc-analyzer benchmark` works
- `pqc-analyzer scan vpn` works
- `pqc-analyzer scan code` works
- Benchmark comparison charts

### Phase 3 — Roadmap Generator + Web UI (Tuần 13-20)

**Mục tiêu:** Migration roadmap engine, Web UI, PDF reports.

Tuần 13-14:
- Implement risk scoring engine
- Implement priority engine + phase assignment
- Implement recommendation engine
- Implement cost estimator

Tuần 15-16:
- Implement timeline generator
- Implement PDF report (WeasyPrint)
- Executive summary template
- Compliance checker skeleton (NIST SP 800-208 mapping)

Tuần 17-18:
- FastAPI backend — all API routes
- React frontend — Dashboard, Scanner page
- Language toggle (vi/en)

Tuần 19-20:
- React frontend — Benchmark page, Roadmap page, Report page
- Docker packaging (docker-compose up)
- End-to-end testing
- **Publish v0.3.0 — first full-featured release**
- Blog post + demo video
- Submit abstract to security conference

**Deliverables Phase 3:**
- Full Web UI (all 5 pages)
- PDF + HTML report generation
- Migration roadmap with timeline
- Docker deployment
- `docker-compose up` one-command start

### Phase 4 — Polish + Publish (Tuần 21-28)

**Mục tiêu:** Production quality, paper, community building.

Tuần 21-24:
- Run assessment trên infrastructure thật (VNPT public endpoints, gov.vn sites...)
- Collect real data cho paper
- Security audit code
- Performance optimization
- Thêm hardware profiles cho Vietnam context

Tuần 25-28:
- Viết paper: "PQC Readiness Assessment: A Case Study of Vietnam's Digital Infrastructure"
- Submit paper (IEEE CNS, ACM CCS Workshop, hoặc PQCrypto)
- Documentation hoàn chỉnh (user guide vi/en)
- Community outreach (Reddit, Hacker News, LinkedIn)
- Present at local security meetup / hội thảo ATTT Việt Nam
- **Publish v1.0.0**

---

## 8. Chiến lược PR & Community Building

### 8.1 Launch Strategy

**Pre-launch (2 tuần trước v0.1.0):**
- Teaser trên "Con đường Lượng tử" Substack — bài viết về HNDL threat
- LinkedIn post về PQC migration urgency
- Tạo GitHub repo (public), README ấn tượng, badges

**v0.1.0 Launch:**
- Blog post chi tiết trên Substack: "Hệ thống của bạn có an toàn trước máy tính lượng tử?"
- Post Reddit: r/netsec, r/QuantumComputing, r/cybersecurity
- LinkedIn article (English): "Post-Quantum Crypto Migration: A Tool for the Rest of Us"
- Hacker News: "Show HN: Open-source PQC readiness analyzer"
- Twitter/X thread

**Ongoing:**
- Weekly blog trên Substack — mỗi tuần 1 bài deep dive (kết hợp series "Con đường Lượng tử")
- Monthly release cycle
- Respond to GitHub issues promptly
- Collect testimonials từ early users

### 8.2 Target Communities

| Cộng đồng | Kênh | Nội dung |
|-----------|------|---------|
| Security VN | VNISA, SecurityBox, WhiteHat | Tool demo, hội thảo |
| Quantum VN | VNQuantum, Viện CNLT ĐHQGHN | Research collaboration |
| Policy VN | Ban Cơ yếu, Bộ TT&TT | Whitepaper, briefing |
| International OSS | GitHub, Reddit, HN | English docs, releases |
| Academic | IEEE, ACM, arXiv | Paper, preprint |
| Telecom VN | VNPT, Viettel tech teams | Pilot assessment |

### 8.3 Metrics to Track

- GitHub stars + forks + contributors
- PyPI downloads
- Number of assessments run (opt-in telemetry, anonymized)
- Paper citations
- Media mentions
- Speaking invitations

---

## 9. Rủi ro & Mitigation

| Rủi ro | Khả năng | Impact | Mitigation |
|--------|---------|--------|-----------|
| liboqs API thay đổi | Medium | High | Pin version, abstract behind wrapper |
| NIST thay đổi standards | Low | Medium | Modular algorithm DB, easy update |
| Scope creep | High | High | Strict phase gates, MVP first |
| Ít người dùng ban đầu | Medium | Medium | Focus blog content, solve real pain |
| Legal issues scanning production | Medium | High | Clear disclaimers, require user consent, scan own infra only |
| Competition (similar tool) | Low | Medium | Focus VN/ASEAN niche, bilingual, action-oriented |

---

## 10. Tiêu chí thành công

### Short-term (6 tháng)
- [ ] v0.3.0 released với full 3 modules
- [ ] 100+ GitHub stars
- [ ] 500+ PyPI downloads
- [ ] 1 blog post viral (>5000 views)
- [ ] 1 assessment chạy trên hệ thống thật

### Medium-term (12 tháng)
- [ ] v1.0.0 stable release
- [ ] 500+ GitHub stars
- [ ] 5000+ PyPI downloads
- [ ] 1 paper submitted/accepted
- [ ] 1 speaking engagement (hội thảo ATTT VN hoặc quốc tế)
- [ ] 1 tổ chức VN dùng chính thức (pilot)

### Long-term (24 tháng)
- [ ] Tool được reference trong policy document VN
- [ ] 3+ contributors ngoài tác giả
- [ ] Fork/adapt cho ≥2 quốc gia ASEAN khác
- [ ] Recognized as go-to PQC assessment tool cho khu vực

---

## 11. Ghi chú cho Claude CLI

Khi phát triển project này, tuân thủ các nguyên tắc:

1. **Python 3.11+**, type hints bắt buộc, docstrings (Google style)
2. **Test-driven**: viết test trước hoặc cùng lúc với code. Target coverage 80%+
3. **CLI first**: mọi feature phải chạy được từ CLI trước, Web UI là layer on top
4. **Modular**: mỗi module (scanner, benchmarker, roadmap) phải hoạt động independent
5. **Bilingual**: mọi user-facing string dùng i18n (vi/en), không hardcode tiếng Việt
6. **Security**: tool này scan crypto — bản thân nó phải clean. Không store credentials, không gửi data ra ngoài, clear disclaimers
7. **Documentation**: README.md (English) + README.vi.md (Vietnamese), inline code comments
8. **Conventional commits**: feat:, fix:, docs:, test:, refactor:
9. **Semantic versioning**: MAJOR.MINOR.PATCH
10. **Dependency pinning**: requirements.txt với version cụ thể

---

## 12. Security, Legal & Privacy

### 12.1 Legal Disclaimer

Tool này được thiết kế để scan và đánh giá hệ thống mà **người dùng có quyền sở hữu hoặc được ủy quyền**. Disclaimer này phải xuất hiện ở:
- README.md (mở đầu, trước hướng dẫn cài đặt)
- CLI: in ra mỗi khi chạy lệnh scan (có thể tắt bằng `--accept-disclaimer`)
- Web UI: popup xác nhận lần đầu sử dụng, lưu preference

```
⚠ DISCLAIMER / TUYÊN BỐ MIỄN TRỪ TRÁCH NHIỆM

VN-PQC Readiness Analyzer is designed to scan systems you OWN or have
EXPLICIT WRITTEN AUTHORIZATION to test. Unauthorized scanning of systems
you do not own may violate local and international laws.

The authors are not responsible for any misuse of this tool.
By using this tool, you agree that you have proper authorization.

Công cụ này được thiết kế để quét các hệ thống mà bạn SỞ HỮU hoặc có
ỦY QUYỀN BẰNG VĂN BẢN. Quét trái phép hệ thống không thuộc quyền sở hữu
của bạn có thể vi phạm pháp luật Việt Nam và quốc tế.

Tác giả không chịu trách nhiệm cho bất kỳ hành vi sử dụng sai mục đích nào.
```

### 12.2 Rate Limiting

Batch scan mà không throttle có thể gây ảnh hưởng giống DDoS. Cần:

- **Default delay**: 100ms giữa mỗi request khi scan batch
- **Configurable**: `--delay <ms>` để điều chỉnh
- **Max concurrent**: `--max-concurrent <N>` (default: 10)
- **Backoff**: exponential backoff khi gặp connection refused / timeout
- **Warning**: cảnh báo khi user set delay=0 hoặc concurrent>50

```bash
# Ví dụ
$ pqc-analyzer scan tls --hosts-file targets.txt --delay 200 --max-concurrent 5
```

### 12.3 Privacy & Data Protection

**Zero telemetry by default:**
- Tool KHÔNG gửi bất kỳ dữ liệu nào ra ngoài
- Không phân giải hostname qua DNS bên ngoài (trừ khi scan yêu cầu)
- Không check for updates tự động
- Ghi rõ trong README: "This tool makes NO outbound connections except to scan targets you specify"

**Data redaction:**
- `--redact` flag: thay hostname/IP bằng placeholder trong report output
  - `192.168.1.50` → `[REDACTED-HOST-1]`
  - `internal.company.vn` → `[REDACTED-HOST-2]`
  - Mapping lưu riêng file `redaction_map.json` (không include trong report)
- Cảnh báo khi export report chứa internal hostnames mà chưa bật `--redact`

**Scan result storage:**
- Kết quả lưu local only (SQLite / JSON files)
- Không lưu private keys, passwords, hoặc credentials phát hiện được
- Auto-expire: option `--retention-days <N>` để tự xóa kết quả cũ

### 12.4 SECURITY.md

File `SECURITY.md` ở root repo, nội dung:

```markdown
# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 1.x.x   | ✅ Security updates |
| 0.x.x   | ⚠ Best effort      |

## Reporting a Vulnerability

If you discover a security vulnerability in VN-PQC Readiness Analyzer,
please report it responsibly:

1. **DO NOT** open a public GitHub issue
2. Email: security@[project-domain] (hoặc dùng GitHub Security Advisories)
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)
4. We will acknowledge within 48 hours
5. We will provide a fix within 7 days for critical issues

## Scope

This tool scans cryptographic configurations. Security issues include:
- Command injection via user-supplied hostnames/file paths
- Path traversal in config file parsing
- Information leakage in report output
- Denial of service via malformed input
- Dependencies with known CVEs
```

---

## 13. Community & Contribution

### 13.1 CONTRIBUTING.md

```markdown
# Contributing to VN-PQC Readiness Analyzer

Cảm ơn bạn quan tâm đến dự án! / Thank you for your interest!

## Getting Started

1. Fork the repo
2. Clone your fork: `git clone https://github.com/YOUR_USERNAME/vn-pqc-analyzer`
3. Create a virtual environment: `python -m venv .venv && source .venv/bin/activate`
4. Install dev dependencies: `pip install -e ".[dev]"`
5. Run tests: `pytest`

## Development Workflow

1. Create a branch: `git checkout -b feat/my-feature`
2. Write code + tests
3. Run linting: `ruff check . && mypy src/`
4. Run tests: `pytest --cov=src --cov-report=term-missing`
5. Commit (conventional commits): `git commit -m "feat: add xyz scanner"`
6. Push and open a PR

## Branch Naming

- `feat/description` — new feature
- `fix/description` — bug fix
- `docs/description` — documentation
- `refactor/description` — code refactoring
- `test/description` — test additions/fixes

## Code Style

- Python 3.11+, type hints required
- Google-style docstrings
- Linting: ruff
- Type checking: mypy (strict mode)
- Max line length: 100 characters
- All user-facing strings via i18n (no hardcoded Vietnamese or English)

## Testing Requirements

- All new features must include tests
- Target coverage: 80%+
- Use sample fixtures in `tests/fixtures/` (never scan real hosts in tests)
- Integration tests: mark with `@pytest.mark.integration`

## Adding a New Scanner Plugin

See docs/plugin_guide.md for how to implement a custom scanner.
Subclass `BaseScanner` and implement the `scan()` method.

## i18n

When adding user-facing strings:
1. Add key to `src/utils/i18n.py`
2. Add Vietnamese translation in `web/src/i18n/vi.json`
3. Add English translation in `web/src/i18n/en.json`

## Pull Request Checklist

- [ ] Tests pass (`pytest`)
- [ ] Linting passes (`ruff check .`)
- [ ] Type checking passes (`mypy src/`)
- [ ] New strings are i18n-ready
- [ ] Documentation updated (if applicable)
- [ ] No secrets/credentials committed
- [ ] Conventional commit messages
```

### 13.2 CODE_OF_CONDUCT.md

Adopt **Contributor Covenant v2.1** (chuẩn industry). File `CODE_OF_CONDUCT.md` ở root repo.

### 13.3 Issue Templates

Tạo `.github/ISSUE_TEMPLATE/`:

**bug_report.yml:**
```yaml
name: Bug Report / Báo lỗi
description: Report a bug in VN-PQC Analyzer
labels: ["bug"]
body:
  - type: textarea
    id: description
    attributes:
      label: Bug Description
      description: What happened? What did you expect?
    validations:
      required: true
  - type: textarea
    id: reproduce
    attributes:
      label: Steps to Reproduce
      description: Commands or steps to reproduce the bug
  - type: textarea
    id: environment
    attributes:
      label: Environment
      description: "OS, Python version, liboqs version, etc."
  - type: textarea
    id: logs
    attributes:
      label: Logs / Error Output
      render: shell
```

**feature_request.yml:**
```yaml
name: Feature Request / Đề xuất tính năng
description: Suggest a new feature or improvement
labels: ["enhancement"]
body:
  - type: textarea
    id: problem
    attributes:
      label: Problem / Vấn đề
      description: What problem does this solve?
    validations:
      required: true
  - type: textarea
    id: solution
    attributes:
      label: Proposed Solution / Giải pháp đề xuất
    validations:
      required: true
  - type: textarea
    id: alternatives
    attributes:
      label: Alternatives Considered / Phương án khác đã cân nhắc
```

### 13.4 PR Template

Tạo `.github/pull_request_template.md`:

```markdown
## What / Thay đổi gì
<!-- Mô tả ngắn gọn thay đổi -->

## Why / Tại sao
<!-- Lý do thay đổi, link issue nếu có: Closes #123 -->

## How / Cách thực hiện
<!-- Mô tả kỹ thuật nếu cần -->

## Checklist
- [ ] Tests pass
- [ ] Linting + type checking pass
- [ ] i18n strings added (if user-facing)
- [ ] Documentation updated (if applicable)
- [ ] No breaking changes (or documented in description)
```

---

## 14. Logging & Error Handling

### 14.1 Logging Strategy

Sử dụng Python `logging` module với structured output:

```python
import logging
import json

class StructuredFormatter(logging.Formatter):
    """JSON structured logging for SIEM integration."""
    def format(self, record):
        log_data = {
            "timestamp": self.formatTime(record),
            "level": record.levelname,
            "module": record.module,
            "message": record.getMessage(),
        }
        if hasattr(record, "target"):
            log_data["target"] = record.target
        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)
        return json.dumps(log_data)
```

**CLI verbosity levels:**

```bash
$ pqc-analyzer scan tls example.vn:443                 # Default: WARNING+
$ pqc-analyzer scan tls example.vn:443 -v              # INFO+
$ pqc-analyzer scan tls example.vn:443 -vv             # DEBUG+
$ pqc-analyzer scan tls example.vn:443 --log-format json  # JSON structured
$ pqc-analyzer scan tls example.vn:443 --log-file scan.log
```

### 14.2 Error Handling

**Graceful failure — scan không được 1 host không làm crash cả batch:**

```python
@dataclass
class ScanResult:
    target: str
    status: Literal["success", "error", "timeout", "refused"]
    findings: list[Finding] | None = None
    error_message: str | None = None
    duration_ms: float = 0

# Batch scan tiếp tục khi 1 host fail
# Summary cuối cùng: "Scanned 95/100 hosts. 3 timeout, 2 connection refused."
```

**Lỗi cần handle gracefully:**
- Connection timeout → log warning, skip host, continue batch
- Connection refused → log warning, mark as "port closed or filtered"
- Certificate parse error → log error, report partial findings
- Invalid config file syntax → log error, report file + line number
- liboqs not installed → clear error message với hướng dẫn cài đặt
- Permission denied (reading config files) → log warning, skip file

---

## 15. Offline Mode

Nhiều hệ thống chính phủ/quân sự/banking VN không có internet hoặc network bị kiểm soát chặt.

### 15.1 Offline Capabilities

```bash
# Scan config files — không cần network
$ pqc-analyzer scan config /etc/nginx/ /etc/ssh/ --offline

# Scan source code — không cần network
$ pqc-analyzer scan code ./my-project --offline

# Benchmark — không cần network (chạy local crypto operations)
$ pqc-analyzer benchmark --algorithms all --offline

# Generate report từ kết quả đã có
$ pqc-analyzer report --scan-results scan.json --offline
```

### 15.2 Offline Requirements

- Algorithm database (`algorithms.json`) bundled cùng package
- i18n strings bundled cùng package
- Report templates bundled cùng package
- Không require network cho bất kỳ operation nào ngoài TLS/SSH scanning
- `pip install` cần network 1 lần, sau đó chạy offline hoàn toàn
- Docker image chứa mọi thứ cần thiết

---

## 16. Output Formats bổ sung

### 16.1 SARIF Output

**Static Analysis Results Interchange Format** — GitHub/GitLab hiểu format này, hiển thị findings trực tiếp trong Pull Request.

```bash
$ pqc-analyzer scan code ./my-project --output-format sarif --output results.sarif
```

Cho phép tích hợp vào CI/CD pipeline:

```yaml
# .github/workflows/pqc-check.yml
- name: PQC Readiness Check
  run: pqc-analyzer scan code . --output-format sarif --output pqc.sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: pqc.sarif
```

### 16.2 CSV Export

Cho người dùng muốn mở Excel/Google Sheets phân tích:

```bash
$ pqc-analyzer scan tls --hosts-file targets.txt --output-format csv --output findings.csv
$ pqc-analyzer benchmark --output-format csv --output benchmark.csv
```

**CSV columns (scan):**
```
target,component,algorithm,type,risk_level,quantum_vulnerable,replacement,priority,location
example.vn:443,Key Exchange,ECDHE-P256,asymmetric,HIGH,true,ML-KEM-768,1,TLS 1.3 handshake
```

### 16.3 Tổng hợp output formats

| Format | Use case | Flag |
|--------|----------|------|
| JSON | Machine-readable, API integration | `--output-format json` (default) |
| HTML | Interactive report, chia sẻ qua browser | `--output-format html` |
| PDF | Formal report, in ấn, gửi leadership | `--output-format pdf` |
| CSV | Excel analysis, data processing | `--output-format csv` |
| SARIF | GitHub/GitLab CI/CD integration | `--output-format sarif` |
| Markdown | Embed trong docs, wiki, README | `--output-format markdown` |

---

## 17. Plugin & Extension System

### 17.1 Scanner Plugin Interface

```python
from abc import ABC, abstractmethod
from dataclasses import dataclass

class BaseScanner(ABC):
    """Base class for all scanner plugins."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Scanner name, e.g., 'nginx_config'."""
        ...

    @property
    @abstractmethod
    def scan_type(self) -> str:
        """Scan type: 'tls', 'config', 'code', 'vpn', 'ssh'."""
        ...

    @abstractmethod
    def scan(self, target: str, options: dict) -> list[Finding]:
        """
        Execute scan on target.

        Args:
            target: file path, hostname:port, or directory
            options: scanner-specific options

        Returns:
            List of Finding objects
        """
        ...

    def validate_target(self, target: str) -> bool:
        """Validate target before scanning. Override if needed."""
        return True
```

### 17.2 Registering Custom Plugins

```python
# Third-party plugin example: F5 BigIP config parser
# File: pqc_analyzer_f5/scanner.py

from vn_pqc_analyzer.scanner import BaseScanner, Finding

class F5BigIPScanner(BaseScanner):
    name = "f5_bigip"
    scan_type = "config"

    def scan(self, target: str, options: dict) -> list[Finding]:
        # Parse F5 BigIP config...
        ...
```

Plugin discovery qua Python entry points:

```toml
# Third-party plugin's pyproject.toml
[project.entry-points."vn_pqc_analyzer.scanners"]
f5_bigip = "pqc_analyzer_f5.scanner:F5BigIPScanner"
```

```bash
# User installs plugin
$ pip install pqc-analyzer-f5

# Plugin auto-discovered
$ pqc-analyzer scan config /etc/f5/bigip.conf  # tự nhận dạng format
$ pqc-analyzer plugins list                      # liệt kê plugins đã cài
```

---

## 18. Testing Strategy

### 18.1 Test Fixtures & Mock Data

Thư mục `tests/fixtures/` chứa sample data để test mà không cần kết nối thật:

```
tests/
├── fixtures/
│   ├── certs/
│   │   ├── rsa2048_leaf.pem          # RSA-2048 leaf cert
│   │   ├── ecdsa_p256_leaf.pem       # ECDSA P-256 leaf cert
│   │   ├── ed25519_leaf.pem          # Ed25519 cert
│   │   ├── chain_rsa.pem            # Full RSA cert chain
│   │   ├── expired_cert.pem         # Expired cert for testing
│   │   └── self_signed.pem          # Self-signed cert
│   ├── configs/
│   │   ├── nginx_modern.conf        # TLS 1.3 only, strong ciphers
│   │   ├── nginx_legacy.conf        # TLS 1.0+, weak ciphers
│   │   ├── apache_default.conf      # Apache SSL config
│   │   ├── haproxy_ssl.cfg          # HAProxy SSL config
│   │   ├── sshd_config_strong       # Strong SSH config
│   │   ├── sshd_config_weak         # Weak SSH config
│   │   ├── openvpn_server.conf      # OpenVPN config
│   │   ├── wireguard_wg0.conf       # WireGuard config
│   │   └── ipsec.conf               # IPSec config
│   ├── code_samples/
│   │   ├── python_crypto.py         # Python code with crypto usage
│   │   ├── java_crypto.java         # Java crypto usage
│   │   ├── go_crypto.go             # Go crypto usage
│   │   └── node_crypto.js           # Node.js crypto usage
│   ├── tls_responses/
│   │   ├── tls13_response.json      # Mocked TLS 1.3 handshake data
│   │   ├── tls12_response.json      # Mocked TLS 1.2 handshake data
│   │   └── tls10_response.json      # Mocked TLS 1.0 (legacy)
│   └── expected_outputs/
│       ├── scan_result_example.json  # Expected scan output
│       └── benchmark_result.json     # Expected benchmark output
```

### 18.2 Integration Tests with Docker

```yaml
# tests/docker-compose.test.yml
services:
  nginx-modern:
    image: nginx:alpine
    volumes:
      - ./fixtures/configs/nginx_modern.conf:/etc/nginx/nginx.conf
      - ./fixtures/certs/:/etc/nginx/certs/
    ports:
      - "8443:443"

  nginx-legacy:
    image: nginx:alpine
    volumes:
      - ./fixtures/configs/nginx_legacy.conf:/etc/nginx/nginx.conf
      - ./fixtures/certs/:/etc/nginx/certs/
    ports:
      - "8444:443"

  openssh:
    image: linuxserver/openssh-server
    volumes:
      - ./fixtures/configs/sshd_config_weak:/etc/ssh/sshd_config
    ports:
      - "2222:2222"
```

```bash
# Chạy integration tests
$ docker compose -f tests/docker-compose.test.yml up -d
$ pytest tests/ -m integration
$ docker compose -f tests/docker-compose.test.yml down
```

### 18.3 CI/CD Pipeline

```yaml
# .github/workflows/ci.yml
name: CI

on: [push, pull_request]

jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"
      - run: pip install ruff mypy
      - run: ruff check .
      - run: mypy src/

  test:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        python-version: ["3.11", "3.12", "3.13"]
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: ${{ matrix.python-version }}
      - run: sudo apt-get install -y liboqs-dev
      - run: pip install -e ".[dev]"
      - run: pytest --cov=src --cov-report=xml
      - uses: codecov/codecov-action@v4

  integration:
    runs-on: ubuntu-latest
    needs: test
    steps:
      - uses: actions/checkout@v4
      - run: docker compose -f tests/docker-compose.test.yml up -d
      - run: pip install -e ".[dev]"
      - run: pytest tests/ -m integration
      - run: docker compose -f tests/docker-compose.test.yml down

  build-docker:
    runs-on: ubuntu-latest
    needs: [lint, test]
    steps:
      - uses: actions/checkout@v4
      - run: docker build -t vn-pqc-analyzer .
      - run: docker run --rm vn-pqc-analyzer --help
```

---

## 19. Docker Compose Services

```yaml
# docker-compose.yml
services:
  api:
    build: .
    command: uvicorn src.api.main:app --host 0.0.0.0 --port 8000
    ports:
      - "8000:8000"
    volumes:
      - ./data:/app/data
      - scan-results:/app/results
    environment:
      - PQC_LOG_LEVEL=INFO
      - PQC_LOG_FORMAT=json
      - PQC_DB_PATH=/app/data/pqc.db

  web:
    build: ./web
    ports:
      - "3000:3000"
    depends_on:
      - api
    environment:
      - VITE_API_URL=http://api:8000

  worker:
    build: .
    command: python -m src.worker
    volumes:
      - scan-results:/app/results
    depends_on:
      - api
    environment:
      - PQC_LOG_LEVEL=INFO

volumes:
  scan-results:
```

```bash
# One command to start everything
$ docker compose up -d

# Or just CLI mode (no web UI)
$ docker run --rm -v $(pwd)/results:/app/results vn-pqc-analyzer scan tls example.vn:443
```

---

## 20. Algorithm Database Versioning

`algorithms.json` sẽ thay đổi khi NIST update hoặc phát hiện algorithm mới. Cần version tracking:

```json
{
  "version": "1.2.0",
  "last_updated": "2026-04-12",
  "changelog": [
    {"version": "1.2.0", "date": "2026-04-12", "changes": "Added FN-DSA (FIPS 206 draft)"},
    {"version": "1.1.0", "date": "2026-03-01", "changes": "Updated ML-KEM security levels"},
    {"version": "1.0.0", "date": "2026-01-15", "changes": "Initial release with FIPS 203/204/205"}
  ],
  "algorithms": {
    "...": "..."
  }
}
```

Cho phép user cập nhật riêng algorithm DB mà không cần upgrade toàn bộ tool:

```bash
$ pqc-analyzer db update                  # Fetch latest algorithms.json từ GitHub releases
$ pqc-analyzer db version                 # Hiển thị version hiện tại
$ pqc-analyzer db import custom.json      # Import custom algorithm definitions
```

---

## 21. Accessibility (Web UI)

### 21.1 Requirements

- **WCAG 2.1 Level AA** compliance target
- Risk levels phải có **cả icon + label + color** — không dựa chỉ vào màu sắc:
  - CRITICAL: 🔴 + "CRITICAL" text + đỏ
  - HIGH: 🟠 + "HIGH" text + cam
  - MEDIUM: 🟡 + "MEDIUM" text + vàng
  - LOW: 🟢 + "LOW" text + xanh lá
  - SAFE: 🛡️ + "SAFE" text + teal
- Keyboard navigation cho tất cả interactive elements
- ARIA labels cho charts và data visualizations
- Sufficient color contrast (minimum 4.5:1 cho normal text)
- Screen reader compatible

---

## 22. README Structure

README.md (English) phải có structure sau:

```markdown
<p align="center">
  <h1>VN-PQC Readiness Analyzer</h1>
  <p>Assess your system's readiness for post-quantum cryptography migration</p>
</p>

<p align="center">
  <a href="..."><img src="https://img.shields.io/pypi/v/vn-pqc-analyzer" alt="PyPI"></a>
  <a href="..."><img src="https://img.shields.io/github/license/..." alt="License"></a>
  <a href="..."><img src="https://img.shields.io/pypi/pyversions/..." alt="Python"></a>
  <a href="..."><img src="https://img.shields.io/codecov/c/github/..." alt="Coverage"></a>
  <a href="..."><img src="https://img.shields.io/github/actions/workflow/status/..." alt="CI"></a>
</p>

> ⚠ **Disclaimer**: Only scan systems you own or have explicit authorization to test.

[Screenshot / GIF demo here]

## Features
- 🔍 **Crypto Inventory Scanner** — Scan TLS, certificates, configs, code, VPN, SSH
- ⚡ **PQC Benchmarker** — Compare classical vs post-quantum performance on your hardware
- 🗺️ **Migration Roadmap** — Auto-generated migration plan with timeline and cost estimates
- 🌐 **Bilingual** — Full Vietnamese and English support
- 📊 **Rich Reports** — Interactive HTML, PDF, CSV, SARIF output

## Quick Start

### Install
\`\`\`bash
pip install vn-pqc-analyzer
\`\`\`

### Scan a TLS endpoint
\`\`\`bash
pqc-analyzer scan tls example.com:443
\`\`\`

### Run benchmarks
\`\`\`bash
pqc-analyzer benchmark --algorithms all
\`\`\`

### Generate report
\`\`\`bash
pqc-analyzer report --scan-results scan.json --format pdf --language vi
\`\`\`

## Documentation
- [User Guide (English)](docs/user_guide_en.md)
- [Hướng dẫn sử dụng (Tiếng Việt)](docs/user_guide_vi.md)
- [API Reference](docs/api_reference.md)
- [Architecture](docs/architecture.md)
- [Contributing](CONTRIBUTING.md)

## Architecture
[Simple diagram: CLI/Web → Scanner/Benchmarker/Roadmap → Reporter → Output]

## License
MIT — see [LICENSE](LICENSE)

## Acknowledgments
- [Open Quantum Safe (liboqs)](https://openquantumsafe.org/)
- [NIST Post-Quantum Cryptography Standardization](https://csrc.nist.gov/projects/post-quantum-cryptography)
```

README.vi.md mirrors this structure in Vietnamese.

---

*Document này là living document — cập nhật theo tiến độ phát triển.*
