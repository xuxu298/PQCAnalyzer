"""TLS handshake benchmark simulation — compare classical vs PQC handshake overhead."""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class HandshakeResult:
    """Result of a simulated TLS handshake benchmark."""

    suite_name: str = ""
    kex_algorithm: str = ""
    auth_algorithm: str = ""
    iterations: int = 0
    kex_time_ms: float = 0.0
    auth_time_ms: float = 0.0
    total_time_ms: float = 0.0
    kex_bytes: int = 0
    auth_bytes: int = 0
    total_bytes: int = 0

    def to_dict(self) -> dict:
        return {
            "suite": self.suite_name,
            "kex_algorithm": self.kex_algorithm,
            "auth_algorithm": self.auth_algorithm,
            "iterations": self.iterations,
            "kex_time_ms": round(self.kex_time_ms, 4),
            "auth_time_ms": round(self.auth_time_ms, 4),
            "total_time_ms": round(self.total_time_ms, 4),
            "kex_bytes": self.kex_bytes,
            "auth_bytes": self.auth_bytes,
            "total_bytes": self.total_bytes,
        }


def _bench_func(func, iterations: int, warmup: int = 10) -> float:
    """Run func() and return mean time in ms."""
    for _ in range(warmup):
        func()
    total = 0.0
    for _ in range(iterations):
        start = time.perf_counter_ns()
        func()
        total += (time.perf_counter_ns() - start) / 1_000_000
    return total / iterations


def bench_tls_handshake_classical(
    iterations: int = 100, warmup: int = 5,
) -> list[HandshakeResult]:
    """Simulate classical TLS handshake key exchange + authentication."""
    results: list[HandshakeResult] = []

    try:
        from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding, ed25519
        from cryptography.hazmat.primitives.asymmetric.ec import ECDH
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        from cryptography.hazmat.primitives import hashes

        msg = b"TLS handshake test"

        # ECDHE-P256 + ECDSA-P256 (typical TLS 1.2/1.3)
        try:
            # KEX: ECDHE P-256
            priv_a = ec.generate_private_key(ec.SECP256R1())
            pub_b = ec.generate_private_key(ec.SECP256R1()).public_key()
            kex_time = _bench_func(lambda: priv_a.exchange(ECDH(), pub_b), iterations, warmup)

            # Auth: ECDSA-P256 sign + verify
            sign_key = ec.generate_private_key(ec.SECP256R1())
            verify_key = sign_key.public_key()
            sig = sign_key.sign(msg, ec.ECDSA(hashes.SHA256()))
            auth_time = _bench_func(
                lambda: verify_key.verify(sig, msg, ec.ECDSA(hashes.SHA256())),
                iterations, warmup,
            )

            results.append(HandshakeResult(
                suite_name="ECDHE-ECDSA-AES256-GCM (classical)",
                kex_algorithm="ECDHE-P256",
                auth_algorithm="ECDSA-P256",
                iterations=iterations,
                kex_time_ms=kex_time,
                auth_time_ms=auth_time,
                total_time_ms=kex_time + auth_time,
                kex_bytes=65 * 2,  # two EC public keys
                auth_bytes=len(sig),
            ))
        except Exception as e:
            logger.warning("ECDHE+ECDSA handshake bench failed: %s", e)

        # X25519 + Ed25519
        try:
            priv_a = X25519PrivateKey.generate()
            pub_b = X25519PrivateKey.generate().public_key()
            kex_time = _bench_func(lambda: priv_a.exchange(pub_b), iterations, warmup)

            sign_key = ed25519.Ed25519PrivateKey.generate()
            verify_key = sign_key.public_key()
            sig = sign_key.sign(msg)
            auth_time = _bench_func(lambda: verify_key.verify(sig, msg), iterations, warmup)

            results.append(HandshakeResult(
                suite_name="X25519-Ed25519-AES256-GCM (classical)",
                kex_algorithm="X25519",
                auth_algorithm="Ed25519",
                iterations=iterations,
                kex_time_ms=kex_time,
                auth_time_ms=auth_time,
                total_time_ms=kex_time + auth_time,
                kex_bytes=32 * 2,
                auth_bytes=len(sig),
            ))
        except Exception as e:
            logger.warning("X25519+Ed25519 handshake bench failed: %s", e)

        # RSA-2048 kex + auth (legacy TLS 1.2)
        try:
            rsa_key = rsa.generate_private_key(65537, 2048)
            rsa_pub = rsa_key.public_key()
            oaep = padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
            ct = rsa_pub.encrypt(b"\x00" * 32, oaep)
            kex_time = _bench_func(lambda: rsa_key.decrypt(ct, oaep), iterations, warmup)

            pss = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.AUTO)
            sig = rsa_key.sign(msg, pss, hashes.SHA256())
            auth_time = _bench_func(lambda: rsa_pub.verify(sig, msg, pss, hashes.SHA256()), iterations, warmup)

            results.append(HandshakeResult(
                suite_name="RSA-AES256-GCM (legacy TLS 1.2)",
                kex_algorithm="RSA-2048",
                auth_algorithm="RSA-2048",
                iterations=iterations,
                kex_time_ms=kex_time,
                auth_time_ms=auth_time,
                total_time_ms=kex_time + auth_time,
                kex_bytes=256,
                auth_bytes=len(sig),
            ))
        except Exception as e:
            logger.warning("RSA handshake bench failed: %s", e)

    except ImportError:
        logger.warning("cryptography library not available")

    return results


def bench_tls_handshake_pqc(
    iterations: int = 100, warmup: int = 5,
) -> list[HandshakeResult]:
    """Simulate PQC TLS handshake key exchange + authentication."""
    results: list[HandshakeResult] = []

    try:
        import oqs
    except ImportError:
        logger.warning("liboqs-python not installed. PQC TLS handshake benchmarks skipped.")
        return results

    available_kem = oqs.get_enabled_kem_mechanisms()
    available_sig = oqs.get_enabled_sig_mechanisms()

    msg = b"TLS handshake test"

    # ML-KEM-768 + ML-DSA-65 (future PQC TLS 1.3)
    kem_name = next((n for n in ["Kyber768", "ML-KEM-768"] if n in available_kem), None)
    sig_name = next((n for n in ["Dilithium3", "ML-DSA-65"] if n in available_sig), None)

    if kem_name and sig_name:
        try:
            # KEX: ML-KEM encaps
            kem = oqs.KeyEncapsulation(kem_name)
            pub = kem.generate_keypair()

            kex_times: list[float] = []
            for _ in range(warmup):
                oqs.KeyEncapsulation(kem_name).encap_secret(pub)
            for _ in range(iterations):
                start = time.perf_counter_ns()
                oqs.KeyEncapsulation(kem_name).encap_secret(pub)
                kex_times.append((time.perf_counter_ns() - start) / 1_000_000)
            kex_time = sum(kex_times) / len(kex_times)

            # Auth: ML-DSA sign + verify
            sig_obj = oqs.Signature(sig_name)
            sig_pub = sig_obj.generate_keypair()
            signature = sig_obj.sign(msg)

            auth_times: list[float] = []
            for _ in range(warmup):
                sig_obj.verify(msg, signature, sig_pub)
            for _ in range(iterations):
                start = time.perf_counter_ns()
                sig_obj.verify(msg, signature, sig_pub)
                auth_times.append((time.perf_counter_ns() - start) / 1_000_000)
            auth_time = sum(auth_times) / len(auth_times)

            results.append(HandshakeResult(
                suite_name=f"{kem_name}+{sig_name}-AES256-GCM (PQC TLS 1.3)",
                kex_algorithm=kem_name,
                auth_algorithm=sig_name,
                iterations=iterations,
                kex_time_ms=kex_time,
                auth_time_ms=auth_time,
                total_time_ms=kex_time + auth_time,
                kex_bytes=len(pub),
                auth_bytes=len(signature),
            ))
        except Exception as e:
            logger.warning("PQC TLS handshake bench failed: %s", e)

    # Hybrid: X25519+ML-KEM-768 + Ed25519+ML-DSA-65
    if kem_name:
        try:
            from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

            # Hybrid KEX = X25519 + ML-KEM
            kem = oqs.KeyEncapsulation(kem_name)
            pqc_pub = kem.generate_keypair()
            x_priv = X25519PrivateKey.generate()
            x_peer = X25519PrivateKey.generate().public_key()

            def hybrid_kex():
                x_priv.exchange(x_peer)
                oqs.KeyEncapsulation(kem_name).encap_secret(pqc_pub)

            kex_time = _bench_func(hybrid_kex, iterations, warmup)

            results.append(HandshakeResult(
                suite_name=f"X25519+{kem_name} hybrid (future TLS 1.3)",
                kex_algorithm=f"X25519+{kem_name}",
                auth_algorithm="(auth not included)",
                iterations=iterations,
                kex_time_ms=kex_time,
                total_time_ms=kex_time,
                kex_bytes=32 + len(pqc_pub),
            ))
        except Exception as e:
            logger.warning("Hybrid TLS handshake bench failed: %s", e)

    return results
