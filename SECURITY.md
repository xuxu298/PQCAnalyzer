# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 1.x.x   | Security updates |
| 0.x.x   | Best effort      |

## Reporting a Vulnerability

If you discover a security vulnerability in VN-PQC Readiness Analyzer, please report it responsibly:

1. **DO NOT** open a public GitHub issue
2. Email **support@vradar.io** or use [GitHub Security Advisories](https://github.com/xuxu298/PQCAnalyzer/security/advisories) to report privately
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)
4. We will acknowledge within 48 hours
5. We will provide a fix within 7 days for critical issues

## Scope

This tool scans cryptographic configurations. Security issues in scope include:

- Command injection via user-supplied hostnames or file paths
- Path traversal in config file parsing
- Information leakage in report output
- Denial of service via malformed input
- Dependencies with known CVEs
- Sensitive data exposure (credentials, private keys)

## Out of Scope

- Issues in systems being scanned (that's what this tool is for)
- Social engineering
- Physical attacks
