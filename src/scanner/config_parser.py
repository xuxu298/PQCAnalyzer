"""Configuration file parser — extract crypto settings from nginx, apache, haproxy."""

from __future__ import annotations

import logging
import re
from pathlib import Path

from src.scanner.models import Finding, ScanResult, ScanStatus
from src.utils.constants import RiskLevel, ScanType
from src.utils.crypto_db import get_algorithm_db
from src.utils.i18n import t

logger = logging.getLogger(__name__)


# The value extraction below used regexes such as `ssl_protocols?\s+([^;]+);`
# that scan to the end of the file for every occurrence without a match:
# quadratic in the file size (260 KB of `ssl_protocol ` without `;` => 16 s,
# 8 MB => hours). These helpers only ever move forward.

_NGINX_PROTOCOLS = re.compile(r"ssl_protocols?\s+")
_NGINX_CIPHERS = re.compile(r"ssl_ciphers?\s+")
_QUOTE_OR_SEMI = re.compile(r"[;'\"]")
_SEMI = re.compile(";")
_HAPROXY_BIND = re.compile(r"\bbind\s")


def _ws_before(content: str, end: int) -> int:
    """Length of the whitespace run that ends at ``end``."""
    i = end
    while i > 0 and content[i - 1] in " \t\r\n\f\v":
        i -= 1
    return end - i


def _first_nginx_value(content: str, directive: re.Pattern, quoted: bool) -> str | None:
    """Value of the first `directive … ;` statement, exactly as the old
    regexes read it (`ssl_protocols?\\s+([^;]+);` and
    `ssl_ciphers?\\s+['"]?([^;'"]+)['"]?\\s*;`), in one forward pass.

    The alternatives are tried in the regex's own order, including `\\s+`
    giving one whitespace character back to the value when the run is longer
    than one."""
    n = len(content)
    term = _QUOTE_OR_SEMI if quoted else _SEMI
    nxt = [-1]   # position of the next terminator (only moves forward)

    def next_term(start: int) -> int:
        if nxt[0] < start:
            hit = term.search(content, start)
            nxt[0] = hit.start() if hit else n
        return nxt[0]

    def closes(i: int) -> bool:   # ['"]? \s* ;
        if i < n and content[i] in "'\"":
            i += 1
        while i < n and content[i] in " \t\r\n\f\v":
            i += 1
        return i < n and content[i] == ";"

    for m in directive.finditer(content):
        pos = m.end()
        give_back = _ws_before(content, pos) >= 2
        start = pos + 1 if quoted and pos < n and content[pos] in "'\"" else pos
        end = next_term(start)
        if end >= n:
            return None   # no terminator anywhere further on: nothing can match
        if end > start and (not quoted or closes(end)):
            return content[start:end]
        # backtrack: one whitespace character becomes the value
        if give_back and (closes(pos) if quoted else content[pos] == ";"):
            return content[pos - 1]
    return None


def _has_ssl_bind(content: str) -> bool:
    """A line with `bind` and, later on it, `ssl` (one pass per line)."""
    for line in content.splitlines():
        m = re.search(r"\bbind\b", line)
        if m and re.search(r"\bssl\b", line[m.end():]):
            return True
    return False


def _haproxy_bind_ciphers(content: str):
    """`ciphers <list>` on `bind … ssl …` lines, one forward pass per line.

    `bind` is matched as a word (`\\bbind\\s`), so a leading token such as
    ``bindx`` does not hide a real ``bind`` after it. Everything is done with
    index searches (no per-match slicing) to stay linear on huge lines.
    """
    for line in content.splitlines():
        bm = _HAPROXY_BIND.search(line)
        if not bm:
            continue
        ssl_at = line.find("ssl", bm.end())
        if ssl_at < 0:
            continue
        words = line[ssl_at + 3:].split()
        if "ciphers" in words[:-1]:
            yield words[words.index("ciphers") + 1]


class ConfigParser:
    """Parse server configuration files to extract cryptographic settings."""

    def scan_file(self, filepath: str) -> ScanResult:
        """Scan a configuration file for crypto settings.

        Auto-detects config type (nginx, apache, haproxy) from content.

        Args:
            filepath: Path to config file.

        Returns:
            ScanResult with findings.
        """
        result = ScanResult(target=filepath, scan_type=ScanType.CONFIG_FILE)
        path = Path(filepath)

        if not path.exists():
            result.status = ScanStatus.ERROR
            result.error_message = f"File not found: {filepath}"
            return result

        try:
            content = path.read_text(errors="replace")
            config_type = self._detect_config_type(content, path.name)

            match config_type:
                case "nginx":
                    result.findings = self._parse_nginx(content, filepath)
                case "apache":
                    result.findings = self._parse_apache(content, filepath)
                case "haproxy":
                    result.findings = self._parse_haproxy(content, filepath)
                case _:
                    # Try all parsers
                    result.findings = self._parse_generic(content, filepath)

            result.status = ScanStatus.SUCCESS
            result.metadata = {"config_type": config_type}
            logger.info(t("config_parsed", path=filepath))
        except Exception as e:
            result.status = ScanStatus.ERROR
            result.error_message = t("config_parse_error", path=filepath, error=str(e))
            logger.error(result.error_message)

        result.finalize()
        return result

    def _detect_config_type(self, content: str, filename: str) -> str:
        """Detect the type of configuration file."""
        fname = filename.lower()

        if "nginx" in fname or re.search(r"\bserver\s*\{", content):
            if re.search(r"\bssl_protocols?\b", content) or re.search(
                r"\bssl_ciphers?\b", content
            ):
                return "nginx"

        if "apache" in fname or "httpd" in fname:
            return "apache"
        if re.search(r"\bSSLProtocol\b", content) or re.search(
            r"\bSSLCipherSuite\b", content
        ):
            return "apache"

        if "haproxy" in fname:
            return "haproxy"
        if _has_ssl_bind(content):
            return "haproxy"

        return "unknown"

    def _parse_nginx(self, content: str, filepath: str) -> list[Finding]:
        """Parse nginx SSL configuration."""
        findings: list[Finding] = []
        db = get_algorithm_db()

        # Extract ssl_protocols
        proto_value = _first_nginx_value(content, _NGINX_PROTOCOLS, quoted=False)
        if proto_value is not None:
            protocols = proto_value.strip().split()
            for proto in protocols:
                proto_clean = proto.strip()
                if proto_clean.lower() in ("tlsv1", "tlsv1.0"):
                    findings.append(Finding(
                        component="TLS Protocol",
                        algorithm="TLS 1.0",
                        risk_level=RiskLevel.HIGH,
                        quantum_vulnerable=False,
                        location=f"{filepath}, ssl_protocols directive",
                        replacement=["TLS 1.2", "TLS 1.3"],
                        migration_priority=2,
                        note=t("tls_deprecated_protocol", protocol="TLS 1.0"),
                    ))
                elif proto_clean.lower() == "tlsv1.1":
                    findings.append(Finding(
                        component="TLS Protocol",
                        algorithm="TLS 1.1",
                        risk_level=RiskLevel.HIGH,
                        quantum_vulnerable=False,
                        location=f"{filepath}, ssl_protocols directive",
                        replacement=["TLS 1.2", "TLS 1.3"],
                        migration_priority=2,
                        note=t("tls_deprecated_protocol", protocol="TLS 1.1"),
                    ))
                elif proto_clean.lower() == "sslv3":
                    findings.append(Finding(
                        component="TLS Protocol",
                        algorithm="SSLv3",
                        risk_level=RiskLevel.CRITICAL,
                        quantum_vulnerable=False,
                        location=f"{filepath}, ssl_protocols directive",
                        replacement=["TLS 1.3"],
                        migration_priority=1,
                        note=t("tls_deprecated_protocol", protocol="SSLv3"),
                    ))

        # Extract ssl_ciphers
        cipher_value = _first_nginx_value(content, _NGINX_CIPHERS, quoted=True)
        if cipher_value is not None:
            cipher_string = cipher_value.strip()
            cipher_findings = self._analyze_cipher_string(cipher_string, filepath, "nginx")
            findings.extend(cipher_findings)

        return findings

    def _parse_apache(self, content: str, filepath: str) -> list[Finding]:
        """Parse Apache SSL configuration."""
        findings: list[Finding] = []

        # SSLProtocol
        proto_match = re.search(r"SSLProtocol\s+(.+?)$", content, re.MULTILINE)
        if proto_match:
            proto_str = proto_match.group(1).strip()
            # Apache uses +/- syntax: "all -SSLv2 -SSLv3"
            if "+SSLv3" in proto_str or (
                "all" in proto_str and "-SSLv3" not in proto_str
            ):
                findings.append(Finding(
                    component="TLS Protocol",
                    algorithm="SSLv3",
                    risk_level=RiskLevel.CRITICAL,
                    quantum_vulnerable=False,
                    location=f"{filepath}, SSLProtocol directive",
                    replacement=["TLS 1.3"],
                    migration_priority=1,
                    note=t("tls_deprecated_protocol", protocol="SSLv3"),
                ))
            if "+TLSv1" in proto_str and "+TLSv1." not in proto_str:
                findings.append(Finding(
                    component="TLS Protocol",
                    algorithm="TLS 1.0",
                    risk_level=RiskLevel.HIGH,
                    quantum_vulnerable=False,
                    location=f"{filepath}, SSLProtocol directive",
                    replacement=["TLS 1.2", "TLS 1.3"],
                    migration_priority=2,
                    note=t("tls_deprecated_protocol", protocol="TLS 1.0"),
                ))

        # SSLCipherSuite
        cipher_match = re.search(
            r"SSLCipherSuite\s+(.+?)$", content, re.MULTILINE
        )
        if cipher_match:
            cipher_string = cipher_match.group(1).strip()
            cipher_findings = self._analyze_cipher_string(cipher_string, filepath, "apache")
            findings.extend(cipher_findings)

        return findings

    def _parse_haproxy(self, content: str, filepath: str) -> list[Finding]:
        """Parse HAProxy SSL configuration."""
        findings: list[Finding] = []

        # bind ... ssl ... ciphers <list>
        for cipher_string in _haproxy_bind_ciphers(content):
            cipher_findings = self._analyze_cipher_string(
                cipher_string, filepath, "haproxy"
            )
            findings.extend(cipher_findings)

        # ssl-default-bind-ciphers
        default_match = re.search(
            r"ssl-default-bind-ciphers\s+(\S+)", content
        )
        if default_match:
            cipher_string = default_match.group(1)
            cipher_findings = self._analyze_cipher_string(
                cipher_string, filepath, "haproxy"
            )
            findings.extend(cipher_findings)

        # Check for no-sslv3, no-tlsv10, etc.
        if "no-sslv3" not in content.lower() and "ssl" in content.lower():
            # SSLv3 might be enabled by default
            pass  # Only flag if positively confirmed

        return findings

    def _parse_generic(self, content: str, filepath: str) -> list[Finding]:
        """Try to extract crypto info from unknown config format."""
        findings: list[Finding] = []
        db = get_algorithm_db()

        # Look for common cipher suite patterns
        cipher_patterns = [
            r"(?:cipher[s]?\s*[=:]\s*)([^\s;]+)",
            r"(?:tls[_-]?cipher[s]?\s*[=:]\s*)([^\s;]+)",
        ]

        for pattern in cipher_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                cipher_string = match.group(1)
                cipher_findings = self._analyze_cipher_string(
                    cipher_string, filepath, "generic"
                )
                findings.extend(cipher_findings)

        return findings

    def _analyze_cipher_string(
        self, cipher_string: str, filepath: str, config_type: str
    ) -> list[Finding]:
        """Analyze an OpenSSL cipher string for weak algorithms."""
        findings: list[Finding] = []
        db = get_algorithm_db()
        seen: set[str] = set()

        # Split cipher string by : and analyze each
        ciphers = cipher_string.replace("+", ":").replace("!", ":!").split(":")
        for cipher in ciphers:
            cipher = cipher.strip().upper()
            if not cipher or cipher.startswith("!") or cipher.startswith("-"):
                continue

            # Check for known weak patterns
            weak_checks = [
                ("RC4", "RC4", RiskLevel.CRITICAL),
                ("DES-CBC3", "3DES", RiskLevel.HIGH),
                ("3DES", "3DES", RiskLevel.HIGH),
                ("NULL", "NULL cipher", RiskLevel.CRITICAL),
                ("EXPORT", "Export cipher", RiskLevel.CRITICAL),
                ("MD5", "MD5", RiskLevel.HIGH),
                ("ADH", "Anonymous DH", RiskLevel.CRITICAL),
                ("AECDH", "Anonymous ECDH", RiskLevel.CRITICAL),
            ]

            for pattern, algo_name, risk in weak_checks:
                if pattern in cipher and algo_name not in seen:
                    seen.add(algo_name)
                    algo_info = db.classify(algo_name)
                    findings.append(Finding(
                        component="Cipher Suite",
                        algorithm=algo_name,
                        risk_level=risk,
                        quantum_vulnerable=algo_info.quantum_vulnerable if algo_info else False,
                        location=f"{filepath}, {config_type} cipher config",
                        replacement=(
                            algo_info.replacement if algo_info else ["AES-256-GCM"]
                        ),
                        migration_priority=algo_info.migration_priority if algo_info else 1,
                        note=(algo_info.note_en if algo_info else f"{algo_name} is insecure"),
                    ))

            # Check for RSA key exchange (no forward secrecy)
            if cipher.startswith("RSA") and "RSA" not in seen:
                # This means RSA key exchange, not ECDHE_RSA
                if "ECDHE" not in cipher and "DHE" not in cipher:
                    seen.add("RSA-KEX")
                    findings.append(Finding(
                        component="Key Exchange",
                        algorithm="RSA key exchange",
                        risk_level=RiskLevel.CRITICAL,
                        quantum_vulnerable=True,
                        location=f"{filepath}, {config_type} cipher config",
                        replacement=["ECDHE", "X25519Kyber768"],
                        migration_priority=1,
                        note="RSA key exchange has no forward secrecy and is quantum vulnerable",
                    ))

        return findings

    def scan_directory(self, dirpath: str, recursive: bool = True) -> list[ScanResult]:
        """Scan a directory for configuration files.

        Args:
            dirpath: Directory path to scan.
            recursive: Whether to scan subdirectories.

        Returns:
            List of ScanResult objects.
        """
        results: list[ScanResult] = []
        path = Path(dirpath)

        config_patterns = [
            "*.conf", "*.cfg", "*.config",
            "nginx.conf", "httpd.conf", "apache2.conf",
            "haproxy.cfg", "ssl.conf",
        ]

        files: set[Path] = set()
        for pattern in config_patterns:
            if recursive:
                files.update(path.rglob(pattern))
            else:
                files.update(path.glob(pattern))

        for config_file in sorted(files):
            if config_file.is_file():
                result = self.scan_file(str(config_file))
                if result.findings:  # Only include files with findings
                    results.append(result)

        return results
