"""Key generation benchmarks — classical vs PQC algorithms."""

from __future__ import annotations

import logging
import time

from src.benchmarker.models import KEMBenchmarkResult, SignBenchmarkResult, TimingStats

logger = logging.getLogger(__name__)


def _measure_iterations(func, iterations: int, warmup: int = 10) -> list[float]:
    """Run func() for warmup + iterations, return timing samples in ms."""
    # Warmup
    for _ in range(warmup):
        func()

    samples: list[float] = []
    for _ in range(iterations):
        start = time.perf_counter_ns()
        func()
        elapsed_ms = (time.perf_counter_ns() - start) / 1_000_000
        samples.append(elapsed_ms)

    return samples


def bench_kem_keygen_classical(
    iterations: int = 1000, warmup: int = 10,
) -> list[KEMBenchmarkResult]:
    """Benchmark key generation for classical KEM/key-exchange algorithms."""
    results: list[KEMBenchmarkResult] = []

    try:
        from cryptography.hazmat.primitives.asymmetric import rsa, ec, dh

        # RSA-2048
        try:
            samples = _measure_iterations(
                lambda: rsa.generate_private_key(65537, 2048),
                iterations, warmup,
            )
            key = rsa.generate_private_key(65537, 2048)
            pub = key.public_key()
            from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption
            results.append(KEMBenchmarkResult(
                algorithm="RSA-2048",
                iterations=iterations,
                keygen=TimingStats.from_samples(samples),
                pubkey_bytes=len(pub.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)),
                seckey_bytes=len(key.private_bytes(Encoding.DER, PrivateFormat.PKCS8, NoEncryption())),
            ))
            logger.info("RSA-2048 keygen: %.3f ms mean", results[-1].keygen.mean)
        except Exception as e:
            logger.warning("RSA-2048 keygen benchmark failed: %s", e)

        # RSA-3072
        try:
            samples = _measure_iterations(
                lambda: rsa.generate_private_key(65537, 3072),
                min(iterations, 100), warmup,  # RSA-3072 is slow, reduce iterations
            )
            results.append(KEMBenchmarkResult(
                algorithm="RSA-3072",
                iterations=min(iterations, 100),
                keygen=TimingStats.from_samples(samples),
            ))
        except Exception as e:
            logger.warning("RSA-3072 keygen benchmark failed: %s", e)

        # ECDH P-256
        try:
            samples = _measure_iterations(
                lambda: ec.generate_private_key(ec.SECP256R1()),
                iterations, warmup,
            )
            key = ec.generate_private_key(ec.SECP256R1())
            pub = key.public_key()
            from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption
            results.append(KEMBenchmarkResult(
                algorithm="ECDH-P256",
                iterations=iterations,
                keygen=TimingStats.from_samples(samples),
                pubkey_bytes=len(pub.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)),
                seckey_bytes=len(key.private_bytes(Encoding.DER, PrivateFormat.PKCS8, NoEncryption())),
            ))
        except Exception as e:
            logger.warning("ECDH-P256 keygen benchmark failed: %s", e)

        # X25519
        try:
            from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
            samples = _measure_iterations(
                X25519PrivateKey.generate,
                iterations, warmup,
            )
            key = X25519PrivateKey.generate()
            pub = key.public_key()
            from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption
            results.append(KEMBenchmarkResult(
                algorithm="X25519",
                iterations=iterations,
                keygen=TimingStats.from_samples(samples),
                pubkey_bytes=len(pub.public_bytes(Encoding.Raw, PublicFormat.Raw)),
                seckey_bytes=len(key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())),
            ))
        except Exception as e:
            logger.warning("X25519 keygen benchmark failed: %s", e)

    except ImportError:
        logger.warning("cryptography library not available for classical benchmarks")

    return results


def bench_kem_keygen_pqc(
    iterations: int = 1000, warmup: int = 10,
) -> list[KEMBenchmarkResult]:
    """Benchmark key generation for PQC KEM algorithms (requires liboqs)."""
    results: list[KEMBenchmarkResult] = []

    try:
        import oqs
    except ImportError:
        logger.warning("liboqs-python not installed. PQC KEM benchmarks skipped.")
        return results

    kem_algos = ["Kyber512", "Kyber768", "Kyber1024"]
    # liboqs may use different names depending on version
    available = oqs.get_enabled_kem_mechanisms()

    for algo in kem_algos:
        # Try standard names and ML-KEM names
        name_variants = [algo, algo.replace("Kyber", "ML-KEM-")]
        actual_name = None
        for name in name_variants:
            if name in available:
                actual_name = name
                break
        if not actual_name:
            logger.info("KEM %s not available in liboqs", algo)
            continue

        try:
            kem = oqs.KeyEncapsulation(actual_name)
            samples = _measure_iterations(
                lambda: oqs.KeyEncapsulation(actual_name).generate_keypair(),
                iterations, warmup,
            )
            pub = kem.generate_keypair()
            result = KEMBenchmarkResult(
                algorithm=actual_name,
                iterations=iterations,
                keygen=TimingStats.from_samples(samples),
                pubkey_bytes=len(pub),
                seckey_bytes=len(kem.export_secret_key()),
            )
            results.append(result)
            logger.info("%s keygen: %.3f ms mean", actual_name, result.keygen.mean)
        except Exception as e:
            logger.warning("%s keygen benchmark failed: %s", algo, e)

    return results


def bench_sign_keygen_classical(
    iterations: int = 1000, warmup: int = 10,
) -> list[SignBenchmarkResult]:
    """Benchmark key generation for classical signature algorithms."""
    results: list[SignBenchmarkResult] = []

    try:
        from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519

        # RSA-2048 Sign
        try:
            samples = _measure_iterations(
                lambda: rsa.generate_private_key(65537, 2048),
                iterations, warmup,
            )
            results.append(SignBenchmarkResult(
                algorithm="RSA-2048-Sign",
                iterations=iterations,
                keygen=TimingStats.from_samples(samples),
            ))
        except Exception as e:
            logger.warning("RSA-2048-Sign keygen benchmark failed: %s", e)

        # ECDSA P-256
        try:
            samples = _measure_iterations(
                lambda: ec.generate_private_key(ec.SECP256R1()),
                iterations, warmup,
            )
            results.append(SignBenchmarkResult(
                algorithm="ECDSA-P256",
                iterations=iterations,
                keygen=TimingStats.from_samples(samples),
            ))
        except Exception as e:
            logger.warning("ECDSA-P256 keygen benchmark failed: %s", e)

        # Ed25519
        try:
            samples = _measure_iterations(
                ed25519.Ed25519PrivateKey.generate,
                iterations, warmup,
            )
            results.append(SignBenchmarkResult(
                algorithm="Ed25519",
                iterations=iterations,
                keygen=TimingStats.from_samples(samples),
            ))
        except Exception as e:
            logger.warning("Ed25519 keygen benchmark failed: %s", e)

    except ImportError:
        logger.warning("cryptography library not available for classical sign benchmarks")

    return results


def bench_sign_keygen_pqc(
    iterations: int = 1000, warmup: int = 10,
) -> list[SignBenchmarkResult]:
    """Benchmark key generation for PQC signature algorithms (requires liboqs)."""
    results: list[SignBenchmarkResult] = []

    try:
        import oqs
    except ImportError:
        logger.warning("liboqs-python not installed. PQC sign benchmarks skipped.")
        return results

    sig_algos = ["Dilithium2", "Dilithium3", "Dilithium5"]
    available = oqs.get_enabled_sig_mechanisms()

    for algo in sig_algos:
        name_variants = [algo, algo.replace("Dilithium", "ML-DSA-")]
        actual_name = None
        for name in name_variants:
            if name in available:
                actual_name = name
                break
        if not actual_name:
            logger.info("Sig %s not available in liboqs", algo)
            continue

        try:
            sig = oqs.Signature(actual_name)
            samples = _measure_iterations(
                lambda: oqs.Signature(actual_name).generate_keypair(),
                iterations, warmup,
            )
            pub = sig.generate_keypair()
            result = SignBenchmarkResult(
                algorithm=actual_name,
                iterations=iterations,
                keygen=TimingStats.from_samples(samples),
                pubkey_bytes=len(pub),
                seckey_bytes=len(sig.export_secret_key()),
            )
            results.append(result)
            logger.info("%s keygen: %.3f ms mean", actual_name, result.keygen.mean)
        except Exception as e:
            logger.warning("%s keygen benchmark failed: %s", algo, e)

    return results
