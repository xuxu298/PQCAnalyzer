"""Certificate chain analyzer — parse and assess certificate cryptography."""

from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.x509.oid import ExtensionOID, NameOID

from src.scanner.models import (
    CertificateInfo,
    Finding,
    ScanResult,
    ScanStatus,
    TLSInfo,
)
from src.utils.constants import RiskLevel, ScanType
from src.utils.crypto_db import get_algorithm_db
from src.utils.i18n import t

logger = logging.getLogger(__name__)

# FIPS 204 / FIPS 205 OID dotted strings — included so the analyser can flag
# PQ certs as "supported" rather than "unknown" once we encounter them. The
# `cryptography` library does not yet expose these as named curves, so we map
# directly from dotted-string OID.
_PQ_SIGNATURE_OIDS: dict[str, str] = {
    "2.16.840.1.101.3.4.3.17": "ML-DSA-44",
    "2.16.840.1.101.3.4.3.18": "ML-DSA-65",
    "2.16.840.1.101.3.4.3.19": "ML-DSA-87",
    "2.16.840.1.101.3.4.3.20": "SLH-DSA-SHA2-128s",
    "2.16.840.1.101.3.4.3.21": "SLH-DSA-SHA2-128f",
    "2.16.840.1.101.3.4.3.22": "SLH-DSA-SHA2-192s",
    "2.16.840.1.101.3.4.3.23": "SLH-DSA-SHA2-192f",
    "2.16.840.1.101.3.4.3.24": "SLH-DSA-SHA2-256s",
    "2.16.840.1.101.3.4.3.25": "SLH-DSA-SHA2-256f",
}

# Map cryptography lib signature algorithm OIDs to readable names
_SIGNATURE_ALGORITHM_NAMES: dict[str, str] = {
    "sha256WithRSAEncryption": "RSA-SHA256",
    "sha384WithRSAEncryption": "RSA-SHA384",
    "sha512WithRSAEncryption": "RSA-SHA512",
    "sha1WithRSAEncryption": "RSA-SHA1",
    "md5WithRSAEncryption": "RSA-MD5",
    "ecdsa-with-SHA256": "ECDSA-SHA256",
    "ecdsa-with-SHA384": "ECDSA-SHA384",
    "ecdsa-with-SHA512": "ECDSA-SHA512",
    "ed25519": "Ed25519",
    "ed448": "Ed448",
}


def _ca_side(finding: Finding, position: str) -> Finding:
    """Findings on CA certs the server merely relays.

    The customer can't renew or re-key a public CA's intermediate; an expired
    cross-sign in a served chain is usually harmless (clients build another
    path). Keep the quantum findings — they show which CAs to move to — but
    don't let an expired CA cert outrank the customer's own leaf.
    """
    if finding.algorithm == "Expired" and finding.risk_level == RiskLevel.CRITICAL:
        finding.risk_level = RiskLevel.MEDIUM
        suffix = f"({position} certificate sent by the server)"
        finding.note = f"{finding.note} {suffix}" if finding.note else suffix
    return finding


def _key_algorithm_oid(cert: x509.Certificate) -> str:
    try:
        return cert.public_key_algorithm_oid.dotted_string
    except Exception:  # noqa: BLE001 — best effort label for an unloadable key
        return ""


class CertAnalyzer:
    """Analyze X.509 certificates for quantum vulnerability."""

    def analyze_file(self, cert_path: str) -> ScanResult:
        """Analyze a certificate file (PEM or DER).

        Args:
            cert_path: Path to certificate file.

        Returns:
            ScanResult with findings.
        """
        result = ScanResult(target=cert_path, scan_type=ScanType.CERTIFICATE)
        path = Path(cert_path)

        try:
            cert_data = path.read_bytes()
            certs = self._load_certs(cert_data)
            if not certs:
                result.status = ScanStatus.ERROR
                result.error_message = f"No certificates found in {cert_path}"
                return result

            for i, cert in enumerate(certs):
                position = self._determine_chain_position(i, len(certs))
                cert_info = self._parse_cert(cert, position)
                findings = self._assess_cert(cert_info, cert_path)
                result.findings.extend(findings)

            result.status = ScanStatus.SUCCESS
        except Exception as e:
            result.status = ScanStatus.ERROR
            result.error_message = str(e)
            logger.error("Error analyzing %s: %s", cert_path, e)

        result.finalize()
        return result

    def analyze_cert_bytes(
        self, cert_bytes: bytes, source: str = "remote"
    ) -> tuple[CertificateInfo, list[Finding]]:
        """Analyze a certificate from raw bytes.

        Args:
            cert_bytes: DER-encoded certificate bytes.
            source: Description of where the cert came from.

        Returns:
            Tuple of (CertificateInfo, list of findings).
        """
        cert = x509.load_der_x509_certificate(cert_bytes)
        cert_info = self._parse_cert(cert, "leaf")
        findings = self._assess_cert(cert_info, source)
        return cert_info, findings

    def analyze_chain_bytes(
        self, chain_der: list[bytes], source: str = "remote"
    ) -> tuple[list[CertificateInfo], list[Finding]]:
        """Analyze a DER chain as sent by a server, leaf first.

        Certs that fail to parse are skipped so one bad intermediate does
        not hide the rest of the chain.
        """
        infos: list[CertificateInfo] = []
        findings: list[Finding] = []
        seen: set[bytes] = set()
        for i, der in enumerate(chain_der):
            # Servers sometimes send the same cert twice; assess it once.
            if der in seen:
                continue
            seen.add(der)
            try:
                cert = x509.load_der_x509_certificate(der)
                # Position comes from where the server put the cert, not from
                # how many parsed: element 0 is the leaf even if it fails.
                if i == 0:
                    position = "leaf"
                elif cert.subject == cert.issuer:
                    position = "root"
                else:
                    # Servers rarely send the root, so the last cert is usually
                    # an intermediate; only a self-signed cert counts as root.
                    position = "intermediate"
                info = self._parse_cert(cert, position)
                cert_findings = self._assess_cert(info, source)
            except Exception as exc:  # noqa: BLE001 — one odd cert must not sink the scan
                logger.warning("Skipping cert %d from %s: %s", i, source, exc)
                continue
            if position != "leaf":
                # A root's self-signature is never verified by clients; its
                # key is what matters.
                cert_findings = [
                    _ca_side(f, position) for f in cert_findings
                    if not (position == "root" and f.component == TLSInfo.CERT_SIGNATURE)
                ]
            infos.append(info)
            findings.extend(cert_findings)
        return infos, findings

    def _load_certs(self, data: bytes) -> list[x509.Certificate]:
        """Load certificates from PEM or DER data."""
        certs: list[x509.Certificate] = []

        # Try PEM first
        try:
            pem_marker = b"-----BEGIN CERTIFICATE-----"
            if pem_marker in data:
                # Split PEM bundle into individual certs
                remaining = data
                while pem_marker in remaining:
                    cert = x509.load_pem_x509_certificate(
                        remaining[remaining.index(pem_marker):]
                    )
                    certs.append(cert)
                    end_marker = b"-----END CERTIFICATE-----"
                    end_idx = remaining.index(end_marker) + len(end_marker)
                    remaining = remaining[end_idx:]
                return certs
        except Exception:
            pass

        # Try DER
        try:
            cert = x509.load_der_x509_certificate(data)
            return [cert]
        except Exception:
            pass

        return certs

    def _parse_cert(self, cert: x509.Certificate, position: str) -> CertificateInfo:
        """Parse a certificate into CertificateInfo."""
        info = CertificateInfo()
        info.chain_position = position

        # Subject and Issuer
        info.subject = self._name_to_dict(cert.subject)
        info.issuer = self._name_to_dict(cert.issuer)
        info.serial_number = format(cert.serial_number, "x")

        # Validity
        info.not_before = cert.not_valid_before_utc.isoformat()
        info.not_after = cert.not_valid_after_utc.isoformat()
        info.is_expired = datetime.now(timezone.utc) > cert.not_valid_after_utc

        # Self-signed check
        info.is_self_signed = cert.subject == cert.issuer

        # Public key. `cryptography` raises on key types it can't load (ML-DSA,
        # SLH-DSA, SM2, GOST…) — exactly the PQ/hybrid certs this tool must
        # report, so fall back to naming the key by its algorithm OID.
        try:
            pub_key = cert.public_key()
        except (ValueError, TypeError) as exc:
            oid = _key_algorithm_oid(cert)
            info.public_key_algorithm = _PQ_SIGNATURE_OIDS.get(
                oid, f"Unknown key type ({oid or exc})"
            )
            info.public_key_size = 0
            pub_key = None
        if pub_key is None:
            pass
        elif isinstance(pub_key, rsa.RSAPublicKey):
            info.public_key_algorithm = "RSA"
            info.public_key_size = pub_key.key_size
        elif isinstance(pub_key, ec.EllipticCurvePublicKey):
            curve_name = pub_key.curve.name
            info.public_key_algorithm = f"ECDSA-{curve_name}"
            info.public_key_size = pub_key.key_size
        elif isinstance(pub_key, dsa.DSAPublicKey):
            info.public_key_algorithm = "DSA"
            info.public_key_size = pub_key.key_size
        elif isinstance(pub_key, ed25519.Ed25519PublicKey):
            info.public_key_algorithm = "Ed25519"
            info.public_key_size = 256
        elif isinstance(pub_key, ed448.Ed448PublicKey):
            info.public_key_algorithm = "Ed448"
            info.public_key_size = 448
        else:
            info.public_key_algorithm = type(pub_key).__name__
            info.public_key_size = 0

        # Signature algorithm
        sig_oid = cert.signature_algorithm_oid
        sig_name = _SIGNATURE_ALGORITHM_NAMES.get(
            sig_oid._name, sig_oid._name
        )
        info.signature_algorithm = sig_name

        # Extensions
        try:
            san_ext = cert.extensions.get_extension_for_oid(
                ExtensionOID.SUBJECT_ALTERNATIVE_NAME
            )
            info.san = san_ext.value.get_values_for_type(x509.DNSName)
        except x509.ExtensionNotFound:
            pass

        try:
            bc_ext = cert.extensions.get_extension_for_oid(
                ExtensionOID.BASIC_CONSTRAINTS
            )
            info.is_ca = bc_ext.value.ca
        except x509.ExtensionNotFound:
            pass

        try:
            ku_ext = cert.extensions.get_extension_for_oid(
                ExtensionOID.KEY_USAGE
            )
            ku = ku_ext.value
            usages = []
            for attr in [
                "digital_signature", "key_encipherment", "key_agreement",
                "key_cert_sign", "crl_sign", "content_commitment",
                "data_encipherment",
            ]:
                try:
                    if getattr(ku, attr):
                        usages.append(attr)
                except ValueError:
                    pass
            info.key_usage = usages
        except x509.ExtensionNotFound:
            pass

        try:
            eku_ext = cert.extensions.get_extension_for_oid(
                ExtensionOID.EXTENDED_KEY_USAGE
            )
            info.extended_key_usage = [oid.dotted_string for oid in eku_ext.value]
        except x509.ExtensionNotFound:
            pass

        return info

    def _assess_cert(
        self, info: CertificateInfo, source: str
    ) -> list[Finding]:
        """Assess a certificate for quantum vulnerability."""
        findings: list[Finding] = []
        db = get_algorithm_db()
        cn = info.subject.get("commonName", "unknown")
        location = f"{source}, CN={cn}, {info.chain_position} cert"

        # Assess public key algorithm
        pub_key_name = self._normalize_pubkey_name(info)
        algo_info = db.classify(pub_key_name)
        key_label = (
            f"{info.public_key_algorithm}-{info.public_key_size}"
            if info.public_key_size else info.public_key_algorithm
        )
        if algo_info is None and info.public_key_algorithm.startswith("Unknown key type"):
            findings.append(Finding(
                component=TLSInfo.CERT_PUBLIC_KEY,
                algorithm=key_label,
                risk_level=RiskLevel.MEDIUM,
                quantum_vulnerable=False,
                location=location,
                replacement=[],
                migration_priority=3,
                note=(
                    "Key algorithm not recognised by this version; "
                    "review its post-quantum status manually."
                ),
            ))
        if algo_info:
            findings.append(Finding(
                component=TLSInfo.CERT_PUBLIC_KEY,
                algorithm=key_label,
                risk_level=algo_info.risk_level,
                quantum_vulnerable=algo_info.quantum_vulnerable,
                location=location,
                replacement=algo_info.replacement,
                migration_priority=algo_info.migration_priority,
                note=algo_info.note_en,
            ))

        # Assess signature algorithm
        sig_algo = db.classify(info.signature_algorithm)
        if sig_algo:
            # Signature risk considers the signing key, not hash
            findings.append(Finding(
                component=TLSInfo.CERT_SIGNATURE,
                algorithm=info.signature_algorithm,
                risk_level=sig_algo.risk_level,
                quantum_vulnerable=sig_algo.quantum_vulnerable,
                location=location,
                replacement=sig_algo.replacement,
                migration_priority=sig_algo.migration_priority,
                note=sig_algo.note_en,
            ))

        # A SHA-1/MD5 signature is forgeable today (collisions), regardless of
        # the signing key — classify() rates the signature by its key, so say
        # it separately.
        sig_upper = info.signature_algorithm.upper().replace("_", "-")
        weak_hash = None
        if "MD5" in sig_upper:
            weak_hash = "MD5"
        elif re.search(r"SHA-?1(?!\d)", sig_upper):
            weak_hash = "SHA-1"
        if weak_hash:
            findings.append(Finding(
                component=TLSInfo.CERT_SIGNATURE,
                algorithm=f"{weak_hash} signature hash",
                risk_level=RiskLevel.HIGH,
                quantum_vulnerable=False,
                location=location,
                replacement=["SHA-256", "SHA-384"],
                migration_priority=1,
                note=(
                    f"Certificate signed with {info.signature_algorithm}: "
                    f"{weak_hash} collisions make the signature forgeable."
                ),
            ))

        # Certificate expiry
        if info.is_expired:
            findings.append(Finding(
                component=TLSInfo.CERTIFICATE,
                algorithm="Expired",
                risk_level=RiskLevel.CRITICAL,
                quantum_vulnerable=False,
                location=location,
                replacement=["Renew certificate"],
                migration_priority=1,
                note=t("cert_expired", date=info.not_after),
            ))

        # Self-signed warning (not a quantum issue, but relevant for assessment)
        if info.is_self_signed and info.chain_position == "leaf":
            findings.append(Finding(
                component=TLSInfo.CERTIFICATE,
                algorithm="Self-signed",
                risk_level=RiskLevel.MEDIUM,
                quantum_vulnerable=False,
                location=location,
                replacement=["Use CA-signed certificate"],
                migration_priority=3,
                note=t("cert_self_signed"),
            ))

        return findings

    @staticmethod
    def _normalize_pubkey_name(info: CertificateInfo) -> str:
        """Normalize public key algorithm name for DB lookup."""
        algo = info.public_key_algorithm
        size = info.public_key_size

        if algo == "RSA":
            return f"RSA-{size}"
        if algo.startswith("ECDSA"):
            # "ECDSA-secp256r1" -> "ECDSA-P256"
            curve_map = {
                "secp256r1": "P256",
                "secp384r1": "P384",
                "secp521r1": "P521",
                "prime256v1": "P256",
            }
            curve = algo.split("-", 1)[1] if "-" in algo else ""
            p_name = curve_map.get(curve, f"P{size}")
            return f"ECDSA-{p_name}"
        if algo == "DSA":
            return f"DSA-{size}"
        return algo

    @staticmethod
    def _name_to_dict(name: x509.Name) -> dict[str, str]:
        """Convert x509.Name to dictionary."""
        oid_map = {
            NameOID.COMMON_NAME: "commonName",
            NameOID.ORGANIZATION_NAME: "organizationName",
            NameOID.ORGANIZATIONAL_UNIT_NAME: "organizationalUnitName",
            NameOID.COUNTRY_NAME: "countryName",
            NameOID.STATE_OR_PROVINCE_NAME: "stateOrProvinceName",
            NameOID.LOCALITY_NAME: "localityName",
        }
        result: dict[str, str] = {}
        for attr in name:
            key = oid_map.get(attr.oid, attr.oid.dotted_string)
            result[key] = str(attr.value)
        return result

    @staticmethod
    def _determine_chain_position(index: int, total: int) -> str:
        """Determine certificate position in chain."""
        if total == 1:
            return "leaf"
        if index == 0:
            return "leaf"
        if index == total - 1:
            return "root"
        return "intermediate"
