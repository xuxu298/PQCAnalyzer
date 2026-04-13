"""Encapsulation/decapsulation benchmarks for KEM algorithms."""

from __future__ import annotations

import logging
import time

from src.benchmarker.keygen_bench import _measure_iterations
from src.benchmarker.models import KEMBenchmarkResult, TimingStats

logger = logging.getLogger(__name__)


def bench_kem_encaps_classical(
    iterations: int = 1000, warmup: int = 10,
) -> list[KEMBenchmarkResult]:
    """Benchmark encrypt/decrypt for classical key exchange algorithms."""
    results: list[KEMBenchmarkResult] = []

    try:
        from cryptography.hazmat.primitives.asymmetric import rsa, padding, ec
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

        # RSA-2048 encrypt/decrypt (simulating KEM via OAEP)
        try:
            key = rsa.generate_private_key(65537, 2048)
            pub = key.public_key()
            message = b"0" * 32  # 256-bit shared secret

            oaep_padding = padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            )

            enc_samples = _measure_iterations(
                lambda: pub.encrypt(message, oaep_padding),
                iterations, warmup,
            )
            ciphertext = pub.encrypt(message, oaep_padding)

            dec_samples = _measure_iterations(
                lambda: key.decrypt(ciphertext, oaep_padding),
                iterations, warmup,
            )

            results.append(KEMBenchmarkResult(
                algorithm="RSA-2048",
                iterations=iterations,
                encaps=TimingStats.from_samples(enc_samples),
                decaps=TimingStats.from_samples(dec_samples),
                ciphertext_bytes=len(ciphertext),
            ))
        except Exception as e:
            logger.warning("RSA-2048 encaps benchmark failed: %s", e)

        # ECDH P-256 key exchange
        try:
            from cryptography.hazmat.primitives.asymmetric.ec import ECDH

            priv_a = ec.generate_private_key(ec.SECP256R1())
            pub_b = ec.generate_private_key(ec.SECP256R1()).public_key()

            enc_samples = _measure_iterations(
                lambda: priv_a.exchange(ECDH(), pub_b),
                iterations, warmup,
            )

            priv_b = ec.generate_private_key(ec.SECP256R1())
            pub_a = priv_a.public_key()

            dec_samples = _measure_iterations(
                lambda: priv_b.exchange(ECDH(), pub_a),
                iterations, warmup,
            )

            shared = priv_a.exchange(ECDH(), pub_b)
            results.append(KEMBenchmarkResult(
                algorithm="ECDH-P256",
                iterations=iterations,
                encaps=TimingStats.from_samples(enc_samples),
                decaps=TimingStats.from_samples(dec_samples),
                ciphertext_bytes=len(shared),
            ))
        except Exception as e:
            logger.warning("ECDH-P256 encaps benchmark failed: %s", e)

        # X25519 key exchange
        try:
            priv_a = X25519PrivateKey.generate()
            pub_b = X25519PrivateKey.generate().public_key()

            enc_samples = _measure_iterations(
                lambda: priv_a.exchange(pub_b),
                iterations, warmup,
            )

            priv_b = X25519PrivateKey.generate()
            pub_a = priv_a.public_key()

            dec_samples = _measure_iterations(
                lambda: priv_b.exchange(pub_a),
                iterations, warmup,
            )

            shared = priv_a.exchange(pub_b)
            results.append(KEMBenchmarkResult(
                algorithm="X25519",
                iterations=iterations,
                encaps=TimingStats.from_samples(enc_samples),
                decaps=TimingStats.from_samples(dec_samples),
                ciphertext_bytes=len(shared),
            ))
        except Exception as e:
            logger.warning("X25519 encaps benchmark failed: %s", e)

    except ImportError:
        logger.warning("cryptography library not available for classical encaps benchmarks")

    return results


def bench_kem_encaps_pqc(
    iterations: int = 1000, warmup: int = 10,
) -> list[KEMBenchmarkResult]:
    """Benchmark encapsulation/decapsulation for PQC KEM algorithms."""
    results: list[KEMBenchmarkResult] = []

    try:
        import oqs
    except ImportError:
        logger.warning("liboqs-python not installed. PQC KEM encaps benchmarks skipped.")
        return results

    kem_algos = ["Kyber512", "Kyber768", "Kyber1024"]
    available = oqs.get_enabled_kem_mechanisms()

    for algo in kem_algos:
        name_variants = [algo, algo.replace("Kyber", "ML-KEM-")]
        actual_name = None
        for name in name_variants:
            if name in available:
                actual_name = name
                break
        if not actual_name:
            continue

        try:
            # Generate keypair
            kem = oqs.KeyEncapsulation(actual_name)
            public_key = kem.generate_keypair()

            # Encapsulation benchmark
            enc_samples: list[float] = []
            for _ in range(warmup):
                kem_enc = oqs.KeyEncapsulation(actual_name)
                kem_enc.encap_secret(public_key)

            ciphertext = None
            for _ in range(iterations):
                kem_enc = oqs.KeyEncapsulation(actual_name)
                start = time.perf_counter_ns()
                ct, ss = kem_enc.encap_secret(public_key)
                elapsed_ms = (time.perf_counter_ns() - start) / 1_000_000
                enc_samples.append(elapsed_ms)
                if ciphertext is None:
                    ciphertext = ct

            # Decapsulation benchmark
            dec_samples: list[float] = []
            for _ in range(warmup):
                kem.decap_secret(ciphertext)

            for _ in range(iterations):
                start = time.perf_counter_ns()
                kem.decap_secret(ciphertext)
                elapsed_ms = (time.perf_counter_ns() - start) / 1_000_000
                dec_samples.append(elapsed_ms)

            results.append(KEMBenchmarkResult(
                algorithm=actual_name,
                iterations=iterations,
                encaps=TimingStats.from_samples(enc_samples),
                decaps=TimingStats.from_samples(dec_samples),
                ciphertext_bytes=len(ciphertext) if ciphertext else 0,
            ))
            logger.info(
                "%s encaps: %.3f ms, decaps: %.3f ms",
                actual_name, results[-1].encaps.mean, results[-1].decaps.mean,
            )
        except Exception as e:
            logger.warning("%s encaps benchmark failed: %s", algo, e)

    return results
