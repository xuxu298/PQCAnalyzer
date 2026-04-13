"""Throughput benchmarks — operations per second under sustained load."""

from __future__ import annotations

import logging
import time

logger = logging.getLogger(__name__)


def measure_ops_per_second(func, duration_seconds: float = 5.0) -> float:
    """Run func() continuously for duration_seconds and return ops/sec."""
    count = 0
    deadline = time.perf_counter() + duration_seconds
    while time.perf_counter() < deadline:
        func()
        count += 1
    elapsed = duration_seconds  # approximate
    return count / elapsed if elapsed > 0 else 0.0


def bench_kem_throughput_classical(duration: float = 5.0) -> dict[str, float]:
    """Measure KEM ops/sec for classical algorithms."""
    results: dict[str, float] = {}

    try:
        from cryptography.hazmat.primitives.asymmetric import rsa, padding, ec
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

        # RSA-2048 encrypt ops/sec
        try:
            key = rsa.generate_private_key(65537, 2048)
            pub = key.public_key()
            oaep = padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
            msg = b"\x00" * 32
            results["RSA-2048_encrypt"] = measure_ops_per_second(
                lambda: pub.encrypt(msg, oaep), duration,
            )
        except Exception as e:
            logger.warning("RSA-2048 throughput failed: %s", e)

        # X25519 key exchange ops/sec
        try:
            priv = X25519PrivateKey.generate()
            peer_pub = X25519PrivateKey.generate().public_key()
            results["X25519_exchange"] = measure_ops_per_second(
                lambda: priv.exchange(peer_pub), duration,
            )
        except Exception as e:
            logger.warning("X25519 throughput failed: %s", e)

    except ImportError:
        logger.warning("cryptography library not available")

    return results


def bench_kem_throughput_pqc(duration: float = 5.0) -> dict[str, float]:
    """Measure KEM ops/sec for PQC algorithms."""
    results: dict[str, float] = {}

    try:
        import oqs
    except ImportError:
        logger.warning("liboqs-python not installed")
        return results

    available = oqs.get_enabled_kem_mechanisms()
    for algo in ["Kyber512", "Kyber768", "Kyber1024"]:
        name_variants = [algo, algo.replace("Kyber", "ML-KEM-")]
        actual_name = None
        for name in name_variants:
            if name in available:
                actual_name = name
                break
        if not actual_name:
            continue

        try:
            kem = oqs.KeyEncapsulation(actual_name)
            pub = kem.generate_keypair()
            results[f"{actual_name}_encaps"] = measure_ops_per_second(
                lambda: oqs.KeyEncapsulation(actual_name).encap_secret(pub),
                duration,
            )
        except Exception as e:
            logger.warning("%s throughput failed: %s", algo, e)

    return results
