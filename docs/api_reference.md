# API Reference

Base URL: `http://localhost:8000`

Interactive docs: `http://localhost:8000/docs` (Swagger UI)

## Health

### GET /health

```json
{ "status": "ok", "version": "0.3.0" }
```

## Scanner

### POST /scan/config

Scan a web server config file (nginx, apache, haproxy).

**Request:**
```json
{
  "config_path": "/etc/nginx/nginx.conf"
}
```

**Response:**
```json
{
  "findings": [
    {
      "component": "SSL Cipher",
      "algorithm": "AES128-SHA",
      "risk_level": "MEDIUM",
      "quantum_vulnerable": false,
      "location": "/etc/nginx/nginx.conf",
      "replacement": ["AES-256-GCM"]
    }
  ],
  "summary": {
    "total_findings": 1,
    "critical": 0,
    "high": 0,
    "medium": 1
  }
}
```

### POST /scan/ssh

Scan SSH configuration.

**Request:**
```json
{
  "config_path": "/etc/ssh/sshd_config"
}
```

### POST /scan/vpn

Scan VPN configuration (OpenVPN, WireGuard, IPSec).

**Request:**
```json
{
  "config_path": "/etc/openvpn/server.conf"
}
```

### POST /scan/code

Scan source code for crypto usage.

**Request:**
```json
{
  "directory": "/path/to/project/src"
}
```

## Benchmark

### GET /benchmark/hardware

Returns hardware information.

**Response:**
```json
{
  "cpu_model": "Intel Core i7-10700",
  "cpu_cores": 8,
  "ram_total_gb": 16.0,
  "cpu_flags": ["aes", "avx2"],
  "cpu_flags_crypto": ["aes", "avx2"]
}
```

### POST /benchmark/kem

Run KEM benchmark (classical vs PQC).

**Request:**
```json
{
  "iterations": 100
}
```

### POST /benchmark/sign

Run signature benchmark (classical vs PQC).

**Request:**
```json
{
  "iterations": 100
}
```

## Roadmap

### POST /roadmap/generate

Generate complete migration roadmap from findings.

**Request:**
```json
{
  "organization": "My Company",
  "findings": [...],
  "language": "en"
}
```

**Response:**
```json
{
  "roadmap_id": "uuid",
  "organization": "My Company",
  "overall_risk": "CRITICAL",
  "phases": [...],
  "cost_estimate": {
    "total_person_hours": 200,
    "total_cost_vnd": 100000000,
    "timeline_months": 24
  },
  "compliance": [...]
}
```

## Reports

### POST /report/generate

Generate a report in the specified format.

**Request:**
```json
{
  "format": "json",
  "organization": "My Company",
  "findings": [...],
  "language": "en"
}
```

### POST /report/html

Generate an HTML report.

**Request:**
```json
{
  "organization": "My Company",
  "findings": [...],
  "language": "vi"
}
```

**Response:** HTML string

### GET /report/formats

List available report formats.

**Response:**
```json
{
  "formats": ["html", "json", "sarif", "pdf", "summary"]
}
```
