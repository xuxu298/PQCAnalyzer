"""TLS endpoint scanner — connect to hosts and extract crypto information."""

from __future__ import annotations

import asyncio
import logging
import socket
import ssl
import time
from dataclasses import dataclass, field

from src.config import ScanConfig
from src.scanner.models import (
    Finding,
    ScanResult,
    ScanStatus,
    TLSConnectionInfo,
    TLSInfo,
)
from src.utils.constants import RiskLevel, ScanType, TLS_VERSIONS
from src.utils.crypto_db import get_algorithm_db
from src.utils.i18n import t

logger = logging.getLogger(__name__)


@dataclass
class TLSScanner:
    """Scan TLS endpoints to extract cryptographic information."""

    config: ScanConfig = field(default_factory=ScanConfig)

    def scan_host(self, host: str, port: int = 443) -> ScanResult:
        """Scan a single TLS endpoint.

        Args:
            host: Hostname or IP address.
            port: Port number (default 443).

        Returns:
            ScanResult with findings.
        """
        target = f"{host}:{port}"
        logger.info(t("scan_starting", target=target))
        start = time.monotonic()

        result = ScanResult(target=target, scan_type=ScanType.TLS_ENDPOINT)

        try:
            tls_info = self._connect_and_extract(host, port)
            result.findings = self._analyze(tls_info, target)
            result.status = ScanStatus.SUCCESS
            result.metadata = {
                "protocol_version": tls_info.protocol_version,
                "cipher_suite": tls_info.cipher_suite,
                "supported_protocols": tls_info.supported_protocols,
            }
        except socket.timeout:
            result.status = ScanStatus.TIMEOUT
            result.error_message = t(
                "scan_timeout", target=target, timeout=self.config.timeout_ms
            )
            logger.warning(result.error_message)
        except ConnectionRefusedError:
            result.status = ScanStatus.REFUSED
            result.error_message = t("scan_refused", target=target)
            logger.warning(result.error_message)
        except Exception as e:
            result.status = ScanStatus.ERROR
            result.error_message = t("scan_error", target=target, error=str(e))
            logger.error(result.error_message)

        result.duration_ms = (time.monotonic() - start) * 1000
        result.finalize()
        return result

    def _connect_and_extract(self, host: str, port: int) -> TLSConnectionInfo:
        """Connect to a TLS endpoint and extract crypto information."""
        info = TLSConnectionInfo()
        timeout_sec = self.config.timeout_ms / 1000

        # Create SSL context that accepts all certs (we're scanning, not verifying trust)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        with socket.create_connection((host, port), timeout=timeout_sec) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                # Negotiated connection info
                info.protocol_version = ssock.version() or ""
                cipher = ssock.cipher()
                if cipher:
                    info.cipher_suite = cipher[0]
                    info.protocol_version = info.protocol_version or cipher[1]

                # Try to get negotiated KEX group (Python 3.13+: SSLSocket.group())
                negotiated_group = None
                if hasattr(ssock, "group"):
                    try:
                        negotiated_group = ssock.group()
                    except Exception:
                        negotiated_group = None

                # Parse cipher suite components
                self._parse_cipher_suite(info, negotiated_group)

                # Get certificate chain
                cert_bin = ssock.getpeercert(binary_form=True)
                cert_dict = ssock.getpeercert()
                if cert_dict:
                    info.certificate_chain.append(cert_dict)

        # Probe for supported protocols
        info.supported_protocols = self._probe_protocols(host, port, timeout_sec)

        return info

    def _parse_cipher_suite(
        self, info: TLSConnectionInfo, negotiated_group: str | None = None
    ) -> None:
        """Parse cipher suite name into components.

        For TLS 1.2 and below, the cipher suite encodes the key exchange
        (e.g. ECDHE-RSA-AES256-GCM-SHA384). For TLS 1.3, key exchange is
        negotiated out-of-band via the `supported_groups` extension and is
        NOT present in the suite name (e.g. TLS_AES_256_GCM_SHA384). TLS 1.3
        mandates (EC)DHE, so we default to ECDHE when the protocol is 1.3
        and use `negotiated_group` (when available from stdlib) to refine.
        """
        suite = info.cipher_suite.upper()
        protocol = info.protocol_version.upper().replace("V", "")

        # Key exchange
        if negotiated_group:
            info.key_exchange = negotiated_group
        elif "ECDHE" in suite:
            info.key_exchange = "ECDHE"
        elif "DHE" in suite or "EDH" in suite:
            info.key_exchange = "DHE"
        elif "RSA" in suite and "ECDHE" not in suite and "DHE" not in suite:
            info.key_exchange = "RSA"
        elif "TLS1.3" in protocol or "TLS 1.3" in protocol:
            # TLS 1.3 always uses (EC)DHE; cipher suite doesn't encode it.
            # Python <3.13 stdlib can't expose the specific group, so we
            # report generic ECDHE (quantum-vulnerable, like all classical
            # ECDH). Most servers negotiate X25519 or P-256 with Python's
            # default client.
            info.key_exchange = "ECDHE"

        # Authentication
        if "ECDSA" in suite:
            info.authentication = "ECDSA"
        elif "RSA" in suite:
            info.authentication = "RSA"

        # Bulk cipher
        if "AES_256_GCM" in suite or "AES256-GCM" in suite:
            info.bulk_cipher = "AES-256-GCM"
        elif "AES_128_GCM" in suite or "AES128-GCM" in suite:
            info.bulk_cipher = "AES-128-GCM"
        elif "AES_256" in suite or "AES256" in suite:
            info.bulk_cipher = "AES-256"
        elif "AES_128" in suite or "AES128" in suite:
            info.bulk_cipher = "AES-128"
        elif "CHACHA20" in suite:
            info.bulk_cipher = "ChaCha20-Poly1305"
        elif "3DES" in suite or "DES-CBC3" in suite:
            info.bulk_cipher = "3DES"
        elif "RC4" in suite:
            info.bulk_cipher = "RC4"

        # MAC
        if "SHA384" in suite:
            info.mac_algorithm = "SHA-384"
        elif "SHA256" in suite:
            info.mac_algorithm = "SHA-256"
        elif "SHA" in suite:
            info.mac_algorithm = "SHA-1"
        elif "MD5" in suite:
            info.mac_algorithm = "MD5"

    def _probe_protocols(
        self, host: str, port: int, timeout: float
    ) -> list[str]:
        """Probe which TLS protocol versions are supported."""
        supported = []
        protocols_to_test = [
            ("TLSv1.3", ssl.TLSVersion.TLSv1_3),
            ("TLSv1.2", ssl.TLSVersion.TLSv1_2),
            ("TLSv1.1", ssl.TLSVersion.TLSv1_1),
            ("TLSv1.0", ssl.TLSVersion.TLSv1),
        ]

        for name, version in protocols_to_test:
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                ctx.minimum_version = version
                ctx.maximum_version = version

                with socket.create_connection((host, port), timeout=timeout) as sock:
                    with ctx.wrap_socket(sock, server_hostname=host):
                        supported.append(name)
            except (ssl.SSLError, OSError):
                continue

        return supported

    def _analyze(self, info: TLSConnectionInfo, target: str) -> list[Finding]:
        """Analyze TLS connection info and produce findings."""
        findings: list[Finding] = []
        db = get_algorithm_db()

        # Check protocol version
        for proto in info.supported_protocols:
            proto_info = TLS_VERSIONS.get(proto)
            if proto_info and not proto_info["secure"]:
                findings.append(Finding(
                    component=TLSInfo.PROTOCOL,
                    algorithm=proto,
                    risk_level=RiskLevel.HIGH,
                    quantum_vulnerable=False,
                    location=f"{target}, supported protocol",
                    replacement=["TLS 1.3"],
                    migration_priority=2,
                    note=t("tls_deprecated_protocol", protocol=proto),
                ))

        # Check key exchange
        if info.key_exchange:
            algo_info = db.classify(info.key_exchange)
            if algo_info:
                findings.append(Finding(
                    component=TLSInfo.KEY_EXCHANGE,
                    algorithm=info.key_exchange,
                    risk_level=algo_info.risk_level,
                    quantum_vulnerable=algo_info.quantum_vulnerable,
                    location=f"{target}, {info.protocol_version} handshake",
                    replacement=algo_info.replacement,
                    migration_priority=algo_info.migration_priority,
                    note=algo_info.note_en,
                ))

        # Check bulk cipher
        if info.bulk_cipher:
            algo_info = db.classify(info.bulk_cipher)
            if algo_info:
                findings.append(Finding(
                    component=TLSInfo.BULK_ENCRYPTION,
                    algorithm=info.bulk_cipher,
                    risk_level=algo_info.risk_level,
                    quantum_vulnerable=algo_info.quantum_vulnerable,
                    location=f"{target}, {info.protocol_version} cipher suite",
                    replacement=algo_info.replacement,
                    migration_priority=algo_info.migration_priority,
                    note=algo_info.note_en,
                ))

        # Check MAC
        if info.mac_algorithm:
            algo_info = db.classify(info.mac_algorithm)
            if algo_info:
                findings.append(Finding(
                    component=TLSInfo.MAC,
                    algorithm=info.mac_algorithm,
                    risk_level=algo_info.risk_level,
                    quantum_vulnerable=algo_info.quantum_vulnerable,
                    location=f"{target}, MAC in cipher suite",
                    replacement=algo_info.replacement,
                    migration_priority=algo_info.migration_priority,
                    note=algo_info.note_en,
                ))

        # Check certificate from chain
        if info.certificate_chain:
            cert = info.certificate_chain[0]
            self._analyze_cert_from_dict(cert, target, findings)

        return findings

    def _analyze_cert_from_dict(
        self, cert: dict, target: str, findings: list[Finding]
    ) -> None:
        """Analyze certificate information from ssl.getpeercert() dict."""
        db = get_algorithm_db()

        # The ssl module's getpeercert() returns limited info.
        # We can get subject, issuer, notBefore, notAfter, serialNumber
        # but not the signature algorithm or public key details directly.
        # For full cert analysis, use cert_analyzer.py with the binary cert.
        # Here we add a note that deeper analysis is available.

        subject = dict(x[0] for x in cert.get("subject", ()))
        issuer = dict(x[0] for x in cert.get("issuer", ()))
        cn = subject.get("commonName", "unknown")

        # Check expiry
        not_after = cert.get("notAfter", "")
        if not_after:
            from datetime import datetime
            try:
                expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                days_left = (expiry - datetime.utcnow()).days
                if days_left < 0:
                    findings.append(Finding(
                        component=TLSInfo.CERTIFICATE,
                        algorithm="Expired",
                        risk_level=RiskLevel.CRITICAL,
                        quantum_vulnerable=False,
                        location=f"{target}, CN={cn}",
                        replacement=["Renew certificate"],
                        migration_priority=1,
                        note=t("cert_expired", date=not_after),
                    ))
                elif days_left < 30:
                    findings.append(Finding(
                        component=TLSInfo.CERTIFICATE,
                        algorithm="Expiring soon",
                        risk_level=RiskLevel.MEDIUM,
                        quantum_vulnerable=False,
                        location=f"{target}, CN={cn}",
                        replacement=["Renew certificate"],
                        migration_priority=2,
                        note=t("cert_expiring_soon", days=days_left),
                    ))
            except ValueError:
                pass

    def scan_hosts(self, targets: list[str]) -> list[ScanResult]:
        """Scan multiple hosts sequentially with delay between requests.

        Args:
            targets: List of "host:port" strings. Port defaults to 443.

        Returns:
            List of ScanResult objects.
        """
        results = []
        for i, target in enumerate(targets):
            host, port = self._parse_target(target)
            result = self.scan_host(host, port)
            results.append(result)

            # Rate limiting between requests
            if i < len(targets) - 1 and self.config.delay_ms > 0:
                time.sleep(self.config.delay_ms / 1000)

        return results

    async def scan_hosts_async(self, targets: list[str]) -> list[ScanResult]:
        """Scan multiple hosts concurrently with rate limiting.

        Args:
            targets: List of "host:port" strings.

        Returns:
            List of ScanResult objects.
        """
        semaphore = asyncio.Semaphore(self.config.max_concurrent)
        results: list[ScanResult] = []

        async def _scan_one(target: str) -> ScanResult:
            async with semaphore:
                host, port = self._parse_target(target)
                # Run blocking scan in executor
                loop = asyncio.get_event_loop()
                result = await loop.run_in_executor(None, self.scan_host, host, port)
                if self.config.delay_ms > 0:
                    await asyncio.sleep(self.config.delay_ms / 1000)
                return result

        tasks = [_scan_one(t) for t in targets]
        results = await asyncio.gather(*tasks, return_exceptions=False)
        return list(results)

    @staticmethod
    def _parse_target(target: str) -> tuple[str, int]:
        """Parse 'host:port' string. Default port is 443."""
        if ":" in target:
            parts = target.rsplit(":", 1)
            try:
                return parts[0], int(parts[1])
            except ValueError:
                return target, 443
        return target, 443

    @staticmethod
    def load_targets_file(filepath: str) -> list[str]:
        """Load targets from a text file (one host:port per line)."""
        targets = []
        with open(filepath) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    targets.append(line)
        return targets
