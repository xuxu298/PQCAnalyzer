"""Hardware profiling — detect CPU, RAM, crypto extensions."""

from __future__ import annotations

import os
import platform
import re
import sys
from pathlib import Path

from src.benchmarker.models import HardwareInfo


def detect_hardware() -> HardwareInfo:
    """Detect hardware and software environment."""
    info = HardwareInfo()

    # CPU info
    info.cpu_arch = platform.machine()
    info.cpu_model = _get_cpu_model()
    info.cpu_cores = os.cpu_count() or 0
    info.cpu_threads = info.cpu_cores  # updated below if /proc available

    # Parse /proc/cpuinfo for details (Linux)
    cpuinfo = _read_proc_cpuinfo()
    if cpuinfo:
        if not info.cpu_model:
            info.cpu_model = cpuinfo.get("model_name", "Unknown")
        freq = cpuinfo.get("cpu_mhz", "0")
        try:
            info.cpu_frequency_mhz = float(freq)
        except ValueError:
            pass

        # CPU extensions
        flags = cpuinfo.get("flags", "")
        info.has_aesni = "aes" in flags.split()
        info.has_avx2 = "avx2" in flags.split()
        info.has_avx512 = any(f.startswith("avx512") for f in flags.split())
        info.has_sha_ext = "sha_ni" in flags.split()

        siblings = cpuinfo.get("siblings", "")
        if siblings:
            try:
                info.cpu_threads = int(siblings)
            except ValueError:
                pass

    # RAM
    info.ram_total_gb = _get_ram_gb()

    # OS
    info.os_name = platform.system()
    info.os_version = platform.release()

    # Python
    info.python_version = platform.python_version()

    # OpenSSL
    info.openssl_version = _get_openssl_version()

    # liboqs
    info.liboqs_version = _get_liboqs_version()

    return info


def _get_cpu_model() -> str:
    """Get CPU model string."""
    if platform.system() == "Linux":
        cpuinfo = _read_proc_cpuinfo()
        return cpuinfo.get("model_name", "Unknown")
    elif platform.system() == "Darwin":
        try:
            import subprocess
            result = subprocess.run(
                ["sysctl", "-n", "machdep.cpu.brand_string"],
                capture_output=True, text=True, timeout=5,
            )
            if result.returncode == 0:
                return result.stdout.strip()
        except Exception:
            pass
    return platform.processor() or "Unknown"


def _read_proc_cpuinfo() -> dict[str, str]:
    """Read /proc/cpuinfo and return first processor's info."""
    cpuinfo_path = Path("/proc/cpuinfo")
    if not cpuinfo_path.exists():
        return {}

    try:
        content = cpuinfo_path.read_text()
        result: dict[str, str] = {}
        for line in content.splitlines():
            if ":" in line:
                key, _, value = line.partition(":")
                key = key.strip().lower().replace(" ", "_")
                value = value.strip()
                if key not in result:  # first processor only
                    result[key] = value
        return result
    except Exception:
        return {}


def _get_ram_gb() -> float:
    """Get total RAM in GB."""
    if platform.system() == "Linux":
        meminfo = Path("/proc/meminfo")
        if meminfo.exists():
            try:
                content = meminfo.read_text()
                match = re.search(r"MemTotal:\s+(\d+)\s+kB", content)
                if match:
                    return int(match.group(1)) / (1024 * 1024)
            except Exception:
                pass

    # Fallback: psutil if available
    try:
        import psutil
        return psutil.virtual_memory().total / (1024 ** 3)
    except ImportError:
        pass

    return 0.0


def _get_openssl_version() -> str:
    """Get OpenSSL version string."""
    try:
        import ssl
        return ssl.OPENSSL_VERSION
    except Exception:
        return "Unknown"


def _get_liboqs_version() -> str:
    """Get liboqs-python version if installed."""
    try:
        import oqs
        return getattr(oqs, "__version__", "installed (version unknown)")
    except ImportError:
        return "not installed"


# Vietnam-specific hardware profiles for estimation
HARDWARE_PROFILES = {
    "vietnam_gov_server": {
        "description": "Typical Vietnamese government agency server",
        "cpu": "Intel Xeon E-2200 series or equivalent",
        "ram": "32-64 GB",
        "note": "Phổ biến trong hạ tầng chính phủ VN",
    },
    "vietnam_bank_server": {
        "description": "Vietnamese banking infrastructure server",
        "cpu": "Intel Xeon Gold 5300/6300 or equivalent",
        "ram": "64-256 GB",
        "note": "Core banking, payment gateway",
    },
    "vietnam_telco_edge": {
        "description": "Telecom edge device (base station controller, gateway)",
        "cpu": "ARM Cortex-A72 or Intel Atom",
        "ram": "4-16 GB",
        "note": "VNPT, Viettel, Mobifone edge infra",
    },
    "vietnam_iot_device": {
        "description": "IoT device common in Vietnam",
        "cpu": "ARM Cortex-M4/M7 or ESP32",
        "ram": "256 KB - 4 MB",
        "note": "Smart meter, sensor, gateway",
    },
    "vietnam_consumer_phone": {
        "description": "Mid-range smartphone popular in Vietnam",
        "cpu": "Snapdragon 6xx / MediaTek Dimensity 700",
        "ram": "4-6 GB",
        "note": "Samsung Galaxy A series, Xiaomi Redmi series",
    },
}
