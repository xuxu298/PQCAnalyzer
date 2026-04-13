"""Memory usage profiling for crypto operations."""

from __future__ import annotations

import logging
import os
import platform

logger = logging.getLogger(__name__)


def get_peak_rss_kb() -> float:
    """Get current peak RSS (Resident Set Size) in KB."""
    if platform.system() == "Linux":
        try:
            with open(f"/proc/{os.getpid()}/status") as f:
                for line in f:
                    if line.startswith("VmHWM:"):
                        return float(line.split()[1])  # already in KB
        except Exception:
            pass

    # Fallback: resource module
    try:
        import resource
        usage = resource.getrusage(resource.RUSAGE_SELF)
        # On Linux ru_maxrss is in KB, on macOS it's in bytes
        if platform.system() == "Darwin":
            return usage.ru_maxrss / 1024
        return float(usage.ru_maxrss)
    except Exception:
        pass

    return 0.0


def measure_memory_delta(func, iterations: int = 100) -> float:
    """Measure approximate memory increase from running func() repeatedly.

    Returns estimated memory per operation in KB.
    """
    import gc
    gc.collect()
    before = get_peak_rss_kb()

    for _ in range(iterations):
        func()

    gc.collect()
    after = get_peak_rss_kb()

    delta = max(0, after - before)
    return delta / iterations if iterations > 0 else 0.0
