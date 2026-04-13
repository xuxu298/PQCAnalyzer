"""Tests for hardware profiling."""

import pytest

from src.benchmarker.hardware_profile import detect_hardware, HARDWARE_PROFILES


class TestHardwareDetection:
    def test_detect_returns_hardware_info(self):
        hw = detect_hardware()
        assert hw.cpu_arch != ""
        assert hw.cpu_cores > 0
        assert hw.python_version != ""
        assert hw.os_name != ""

    def test_detect_cpu_model(self):
        hw = detect_hardware()
        # Should detect something
        assert hw.cpu_model != ""

    def test_detect_ram(self):
        hw = detect_hardware()
        # Should detect some RAM (at least 0.1 GB for any modern system)
        assert hw.ram_total_gb > 0.1

    def test_detect_openssl(self):
        hw = detect_hardware()
        assert hw.openssl_version != ""
        assert hw.openssl_version != "Unknown"

    def test_to_dict(self):
        hw = detect_hardware()
        d = hw.to_dict()
        assert "cpu" in d
        assert "cores" in d
        assert "ram_gb" in d
        assert "python" in d
        assert "has_aesni" in d


class TestHardwareProfiles:
    def test_vietnam_profiles_exist(self):
        assert "vietnam_gov_server" in HARDWARE_PROFILES
        assert "vietnam_bank_server" in HARDWARE_PROFILES
        assert "vietnam_telco_edge" in HARDWARE_PROFILES
        assert "vietnam_iot_device" in HARDWARE_PROFILES
        assert "vietnam_consumer_phone" in HARDWARE_PROFILES

    def test_profiles_have_required_fields(self):
        for name, profile in HARDWARE_PROFILES.items():
            assert "description" in profile, f"{name} missing description"
            assert "cpu" in profile, f"{name} missing cpu"
            assert "ram" in profile, f"{name} missing ram"
