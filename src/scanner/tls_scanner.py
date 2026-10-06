"""TLS endpoint scanner — connect to hosts and extract crypto information."""

from __future__ import annotations

import asyncio
import logging
import socket
import ssl
import time
import warnings
from dataclasses import dataclass, field
from datetime import datetime, timezone

from src.config import ScanConfig
from src.scanner.cert_analyzer import CertAnalyzer
from src.scanner.models import (
    Finding,
    ScanResult,
    ScanStatus,
    TLSConnectionInfo,
    TLSInfo,
)
from src.scanner.pq_probe import probe_x25519mlkem768
from src.utils.constants import RiskLevel, ScanType, TLS_VERSIONS
from src.utils.crypto_db import get_algorithm_db
from src.utils.i18n import t

logger = logging.getLogger(__name__)


def inventory_context(
    min_version: ssl.TLSVersion, max_version: ssl.TLSVersion
) -> ssl.SSLContext:
    """Client context that can still talk to legacy servers.

    OpenSSL 3.x refuses TLS 1.0/1.1 (and small keys, SHA-1 handshakes) at the
    default security level before a ClientHello is even sent, so a server that
    has them enabled would look like it does not -- the HIGH "deprecated
    protocol" finding would never fire. We are inventorying what the server
    accepts, not trusting the session, so drop the security level for the probe.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        ctx.minimum_version = min_version
        ctx.maximum_version = max_version
    try:
        ctx.set_ciphers("ALL:@SECLEVEL=0")
    except ssl.SSLError:
        pass
    return ctx


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
                "certificate_chain": [
                    {
                        "position": c.chain_position,
                        "subject": c.subject.get("commonName", ""),
                        "issuer": c.issuer.get("commonName", ""),
                        "public_key_algorithm": c.public_key_algorithm,
                        "public_key_size": c.public_key_size,
                        "signature_algorithm": c.signature_algorithm,
                        "not_after": c.not_after,
                    }
                    for c in tls_info.certificate_chain
                ],
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

        # Offer post-quantum hybrid groups so servers that support them will
        # negotiate them. Requires Python 3.13+ and OpenSSL 3.5+; on older
        # stacks we silently fall back to the stdlib default groups.
        if hasattr(ctx, "set_groups"):
            try:
                ctx.set_groups([
                    "X25519MLKEM768",
                    "SecP256r1MLKEM768",
                    "x25519",
                    "secp256r1",
                    "secp384r1",
                ])
            except (ssl.SSLError, ValueError):
                pass

        try:
            self._handshake_extract(info, ctx, host, port, timeout_sec)
        except ssl.SSLError:
            # The default context refuses TLS 1.0/1.1 and weak keys, so a
            # legacy-only server (or an RSA-1024 / TLS 1.0 cert) would surface
            # as a scan error instead of the findings it deserves. Retry once
            # permissively so the endpoint still gets inventoried.
            info = TLSConnectionInfo()
            self._handshake_extract(
                info,
                inventory_context(ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1_3),
                host,
                port,
                timeout_sec,
            )

        # Probe for supported protocols
        info.supported_protocols = self._probe_protocols(host, port, timeout_sec)

        # If stdlib didn't surface a PQ hybrid group (Python <3.13 / OpenSSL
        # <3.5 cannot offer X25519MLKEM768), do an active probe so we can
        # still detect servers that support it.
        if "MLKEM" in info.key_exchange.upper():
            # stdlib handshake already negotiated PQ hybrid — the connection
            # itself is proof the server supports it.
            info.detection_mode = "active_supported"
        else:
            self._probe_pq_groups(info, host, port, timeout_sec)

        return info

    def _handshake_extract(
        self,
        info: TLSConnectionInfo,
        ctx: ssl.SSLContext,
        host: str,
        port: int,
        timeout_sec: float,
    ) -> None:
        """Run one handshake with *ctx* and fill the negotiated fields of *info*."""
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

                info.cert_chain_der = self._peer_chain_der(ssock)

    @staticmethod
    def _peer_chain_der(ssock: ssl.SSLSocket) -> list[bytes]:
        """DER certs the peer sent, leaf first.

        get_unverified_chain() is public from Python 3.13 and exists on the
        private _sslobj since 3.10; fall back to the leaf alone otherwise.
        """
        get_chain = getattr(ssock, "get_unverified_chain", None) or getattr(
            getattr(ssock, "_sslobj", None), "get_unverified_chain", None
        )
        if get_chain is not None:
            try:
                chain = get_chain() or []
                # 3.13's public API returns DER bytes; the 3.10–3.12 private
                # one returns Certificate objects.
                ders = [
                    bytes(c) if isinstance(c, (bytes, bytearray))
                    else c.public_bytes(ssl._ssl.ENCODING_DER)
                    for c in chain
                ]
                if ders:
                    return ders
            except Exception as exc:
                logger.debug("Could not read peer chain: %s", exc)
        leaf = ssock.getpeercert(binary_form=True)
        return [leaf] if leaf else []

    def _probe_pq_groups(
        self, info: TLSConnectionInfo, host: str, port: int, timeout: float
    ) -> None:
        """Active raw-ClientHello probe for PQ hybrid groups.

        Outcomes set info.detection_mode:
          active_supported — server picked X25519MLKEM768
          active_declined  — server picked classical despite being offered hybrid
          passive          — probe errored; only observed traffic tells the story
        """
        try:
            result = probe_x25519mlkem768(host, port, timeout=timeout)
        except Exception as exc:
            logger.debug("PQ probe error for %s: %s", host, exc)
            info.detection_mode = "passive"
            return
        if result.supported:
            # Promote to the actual negotiated kex; keep the classical
            # finding suppressed since the PQ hybrid is what's available.
            info.key_exchange = result.selected_group or "X25519MLKEM768"
            info.detection_mode = "active_supported"
            logger.info("Active PQ probe: %s supports %s", host, info.key_exchange)
        elif result.error:
            info.detection_mode = "passive"
        else:
            info.detection_mode = "active_declined"

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
        elif (
            protocol
            and suite
            and "TLS1.3" not in protocol
            and "TLS 1.3" not in protocol
            and not any(
                tag in suite
                for tag in (
                    "PSK", "SRP", "ADH", "AECDH", "ANON", "KRB",
                    # Non-RSA key exchanges OpenSSL also names without "RSA":
                    # don't mislabel them as RSA.
                    "GOST", "ECCPWD", "DH-DSS",
                )
            )
        ):
            # OpenSSL names static-RSA suites without saying so
            # ("AES256-SHA256", "DES-CBC3-SHA"): for TLS <=1.2 the absence of
            # an (EC)DHE marker means the session key travels encrypted under
            # the certificate's RSA key -- the worst HNDL case, no forward
            # secrecy -- so it must still raise a key-exchange finding.
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
                ctx = inventory_context(version, version)

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
                    replacement=algo_info.replacement_for("key_exchange"),
                    migration_priority=algo_info.migration_priority,
                    note=algo_info.note_en,
                    detection_mode=info.detection_mode or "passive",
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

        # Check MAC. TLS 1.3 suites are AEAD-only: the hash in the suite name
        # drives the HKDF key schedule and transcript, it is not a MAC.
        if info.mac_algorithm:
            algo_info = db.classify(info.mac_algorithm)
            if algo_info:
                tls13 = info.protocol_version == "TLSv1.3"
                where = "TLSv1.3 key schedule hash" if tls13 else "MAC in cipher suite"
                findings.append(Finding(
                    component=TLSInfo.HANDSHAKE_HASH if tls13 else TLSInfo.MAC,
                    algorithm=info.mac_algorithm,
                    risk_level=algo_info.risk_level,
                    quantum_vulnerable=algo_info.quantum_vulnerable,
                    location=f"{target}, {where}",
                    replacement=algo_info.replacement,
                    migration_priority=algo_info.migration_priority,
                    note=algo_info.note_en,
                ))

        if info.cert_chain_der:
            self._analyze_cert_chain(info, target, findings)

        return findings

    def _analyze_cert_chain(
        self, info: TLSConnectionInfo, target: str, findings: list[Finding]
    ) -> None:
        """Assess the certs the server sent: public key, signature, expiry.

        The key and signature are the authentication half of the PQ problem,
        which the cipher suite alone never shows under TLS 1.3.
        """
        certs, cert_findings = CertAnalyzer().analyze_chain_bytes(
            info.cert_chain_der, source=target
        )
        findings.extend(cert_findings)
        info.certificate_chain = certs

        # CertAnalyzer flags expired certs; endpoints also get the 30-day warning.
        if not certs or certs[0].chain_position != "leaf" or certs[0].is_expired:
            return
        leaf = certs[0]
        days_left = (
            datetime.fromisoformat(leaf.not_after) - datetime.now(timezone.utc)
        ).days
        if days_left < 30:
            cn = leaf.subject.get("commonName", "unknown")
            findings.append(Finding(
                component=TLSInfo.CERTIFICATE,
                algorithm="Expiring soon",
                risk_level=RiskLevel.MEDIUM,
                quantum_vulnerable=False,
                location=f"{target}, CN={cn}, leaf cert",
                replacement=["Renew certificate"],
                migration_priority=2,
                note=t("cert_expiring_soon", days=days_left),
            ))

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
