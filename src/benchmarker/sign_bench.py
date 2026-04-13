"""Signing/verification benchmarks for digital signature algorithms."""

from __future__ import annotations

import logging
import time

from src.benchmarker.keygen_bench import _measure_iterations
from src.benchmarker.models import SignBenchmarkResult, TimingStats

logger = logging.getLogger(__name__)

# Standard test message for signing benchmarks
_TEST_MESSAGE = b"PQC Readiness Assessment - Benchmark Test Message - 256 bytes padding" + b"\x00" * 186


def bench_sign_classical(
    iterations: int = 1000, warmup: int = 10,
) -> list[SignBenchmarkResult]:
    """Benchmark sign/verify for classical signature algorithms."""
    results: list[SignBenchmarkResult] = []

    try:
        from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, padding, utils
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption

        # RSA-2048 Sign/Verify
        try:
            key = rsa.generate_private_key(65537, 2048)
            pub = key.public_key()
            rsa_padding = padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.AUTO,
            )

            sign_samples = _measure_iterations(
                lambda: key.sign(_TEST_MESSAGE, rsa_padding, hashes.SHA256()),
                iterations, warmup,
            )
            sig = key.sign(_TEST_MESSAGE, rsa_padding, hashes.SHA256())

            verify_samples = _measure_iterations(
                lambda: pub.verify(sig, _TEST_MESSAGE, rsa_padding, hashes.SHA256()),
                iterations, warmup,
            )

            results.append(SignBenchmarkResult(
                algorithm="RSA-2048",
                iterations=iterations,
                sign=TimingStats.from_samples(sign_samples),
                verify=TimingStats.from_samples(verify_samples),
                pubkey_bytes=len(pub.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)),
                seckey_bytes=len(key.private_bytes(Encoding.DER, PrivateFormat.PKCS8, NoEncryption())),
                signature_bytes=len(sig),
            ))
        except Exception as e:
            logger.warning("RSA-2048 sign benchmark failed: %s", e)

        # ECDSA P-256 Sign/Verify
        try:
            key = ec.generate_private_key(ec.SECP256R1())
            pub = key.public_key()

            sign_samples = _measure_iterations(
                lambda: key.sign(_TEST_MESSAGE, ec.ECDSA(hashes.SHA256())),
                iterations, warmup,
            )
            sig = key.sign(_TEST_MESSAGE, ec.ECDSA(hashes.SHA256()))

            verify_samples = _measure_iterations(
                lambda: pub.verify(sig, _TEST_MESSAGE, ec.ECDSA(hashes.SHA256())),
                iterations, warmup,
            )

            results.append(SignBenchmarkResult(
                algorithm="ECDSA-P256",
                iterations=iterations,
                sign=TimingStats.from_samples(sign_samples),
                verify=TimingStats.from_samples(verify_samples),
                pubkey_bytes=len(pub.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)),
                seckey_bytes=len(key.private_bytes(Encoding.DER, PrivateFormat.PKCS8, NoEncryption())),
                signature_bytes=len(sig),
            ))
        except Exception as e:
            logger.warning("ECDSA-P256 sign benchmark failed: %s", e)

        # Ed25519 Sign/Verify
        try:
            key = ed25519.Ed25519PrivateKey.generate()
            pub = key.public_key()

            sign_samples = _measure_iterations(
                lambda: key.sign(_TEST_MESSAGE),
                iterations, warmup,
            )
            sig = key.sign(_TEST_MESSAGE)

            verify_samples = _measure_iterations(
                lambda: pub.verify(sig, _TEST_MESSAGE),
                iterations, warmup,
            )

            results.append(SignBenchmarkResult(
                algorithm="Ed25519",
                iterations=iterations,
                sign=TimingStats.from_samples(sign_samples),
                verify=TimingStats.from_samples(verify_samples),
                pubkey_bytes=len(pub.public_bytes(Encoding.Raw, PublicFormat.Raw)),
                seckey_bytes=len(key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())),
                signature_bytes=len(sig),
            ))
        except Exception as e:
            logger.warning("Ed25519 sign benchmark failed: %s", e)

    except ImportError:
        logger.warning("cryptography library not available for classical sign benchmarks")

    return results


def bench_sign_pqc(
    iterations: int = 1000, warmup: int = 10,
) -> list[SignBenchmarkResult]:
    """Benchmark sign/verify for PQC signature algorithms (requires liboqs)."""
    results: list[SignBenchmarkResult] = []

    try:
        import oqs
    except ImportError:
        logger.warning("liboqs-python not installed. PQC sign benchmarks skipped.")
        return results

    sig_algos = ["Dilithium2", "Dilithium3", "Dilithium5"]
    available = oqs.get_enabled_sig_mechanisms()

    # Also try SLH-DSA / SPHINCS+ variants
    slh_algos = ["SPHINCS+-SHA2-128f-simple", "SPHINCS+-SHA2-128s-simple"]
    sig_algos.extend(slh_algos)

    for algo in sig_algos:
        name_variants = [algo]
        if "Dilithium" in algo:
            name_variants.append(algo.replace("Dilithium", "ML-DSA-"))
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
            public_key = sig.generate_keypair()

            # Sign benchmark
            sign_samples: list[float] = []
            for _ in range(warmup):
                sig.sign(_TEST_MESSAGE)

            signature = None
            for _ in range(iterations):
                start = time.perf_counter_ns()
                s = sig.sign(_TEST_MESSAGE)
                elapsed_ms = (time.perf_counter_ns() - start) / 1_000_000
                sign_samples.append(elapsed_ms)
                if signature is None:
                    signature = s

            # Verify benchmark
            verify_samples: list[float] = []
            for _ in range(warmup):
                sig.verify(_TEST_MESSAGE, signature, public_key)

            for _ in range(iterations):
                start = time.perf_counter_ns()
                sig.verify(_TEST_MESSAGE, signature, public_key)
                elapsed_ms = (time.perf_counter_ns() - start) / 1_000_000
                verify_samples.append(elapsed_ms)

            results.append(SignBenchmarkResult(
                algorithm=actual_name,
                iterations=iterations,
                sign=TimingStats.from_samples(sign_samples),
                verify=TimingStats.from_samples(verify_samples),
                pubkey_bytes=len(public_key),
                seckey_bytes=len(sig.export_secret_key()),
                signature_bytes=len(signature) if signature else 0,
            ))
            logger.info(
                "%s sign: %.3f ms, verify: %.3f ms",
                actual_name, results[-1].sign.mean, results[-1].verify.mean,
            )
        except Exception as e:
            logger.warning("%s sign benchmark failed: %s", algo, e)

    return results
