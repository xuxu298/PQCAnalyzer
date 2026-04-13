"""Internationalization support for Vietnamese and English."""

from __future__ import annotations

from typing import Literal

Language = Literal["vi", "en"]

_current_language: Language = "en"

# All user-facing strings, keyed by English identifier
_STRINGS: dict[str, dict[Language, str]] = {
    # General
    "app_name": {
        "en": "VN-PQC Readiness Analyzer",
        "vi": "Công cụ đánh giá sẵn sàng PQC Việt Nam",
    },
    "app_description": {
        "en": "Assess your system's readiness for post-quantum cryptography migration",
        "vi": "Đánh giá mức độ sẵn sàng chuyển đổi mật mã hậu lượng tử của hệ thống",
    },
    # Disclaimer
    "disclaimer": {
        "en": (
            "WARNING: Only scan systems you own or have explicit written authorization to test. "
            "Unauthorized scanning may violate local and international laws. "
            "The authors are not responsible for any misuse of this tool."
        ),
        "vi": (
            "CẢNH BÁO: Chỉ quét các hệ thống mà bạn sở hữu hoặc có ủy quyền bằng văn bản. "
            "Quét trái phép có thể vi phạm pháp luật Việt Nam và quốc tế. "
            "Tác giả không chịu trách nhiệm cho bất kỳ hành vi sử dụng sai mục đích nào."
        ),
    },
    # Scan commands
    "scan_starting": {
        "en": "Starting scan on {target}...",
        "vi": "Bắt đầu quét {target}...",
    },
    "scan_complete": {
        "en": "Scan complete. {count} finding(s) detected.",
        "vi": "Quét hoàn tất. Phát hiện {count} vấn đề.",
    },
    "scan_error": {
        "en": "Error scanning {target}: {error}",
        "vi": "Lỗi khi quét {target}: {error}",
    },
    "scan_timeout": {
        "en": "Connection to {target} timed out after {timeout}ms",
        "vi": "Kết nối đến {target} hết thời gian chờ sau {timeout}ms",
    },
    "scan_refused": {
        "en": "Connection to {target} refused",
        "vi": "Kết nối đến {target} bị từ chối",
    },
    "scan_batch_summary": {
        "en": "Scanned {success}/{total} hosts. {timeout} timeout, {refused} refused.",
        "vi": "Đã quét {success}/{total} host. {timeout} hết giờ, {refused} bị từ chối.",
    },
    # Risk levels
    "risk_critical": {
        "en": "CRITICAL — Quantum vulnerable, migrate immediately",
        "vi": "NGHIÊM TRỌNG — Dễ bị tấn công lượng tử, cần chuyển đổi ngay",
    },
    "risk_high": {
        "en": "HIGH — Quantum vulnerable, high priority",
        "vi": "CAO — Dễ bị tấn công lượng tử, ưu tiên cao",
    },
    "risk_medium": {
        "en": "MEDIUM — Needs upgrade",
        "vi": "TRUNG BÌNH — Cần nâng cấp",
    },
    "risk_low": {
        "en": "LOW — Minor improvement recommended",
        "vi": "THẤP — Khuyến nghị cải thiện nhỏ",
    },
    "risk_safe": {
        "en": "SAFE — Post-quantum safe",
        "vi": "AN TOÀN — An toàn hậu lượng tử",
    },
    # TLS Scanner
    "tls_protocol_version": {
        "en": "Protocol Version",
        "vi": "Phiên bản giao thức",
    },
    "tls_cipher_suite": {
        "en": "Cipher Suite",
        "vi": "Bộ mã hóa",
    },
    "tls_key_exchange": {
        "en": "Key Exchange",
        "vi": "Trao đổi khóa",
    },
    "tls_deprecated_protocol": {
        "en": "{protocol} is deprecated and insecure",
        "vi": "{protocol} đã lỗi thời và không an toàn",
    },
    # Certificate
    "cert_expired": {
        "en": "Certificate expired on {date}",
        "vi": "Chứng chỉ đã hết hạn vào {date}",
    },
    "cert_expiring_soon": {
        "en": "Certificate expires in {days} days",
        "vi": "Chứng chỉ hết hạn sau {days} ngày",
    },
    "cert_self_signed": {
        "en": "Self-signed certificate detected",
        "vi": "Phát hiện chứng chỉ tự ký",
    },
    # Config parser
    "config_parsed": {
        "en": "Parsed config file: {path}",
        "vi": "Đã phân tích file cấu hình: {path}",
    },
    "config_parse_error": {
        "en": "Error parsing config file {path}: {error}",
        "vi": "Lỗi phân tích file cấu hình {path}: {error}",
    },
    # SSH
    "ssh_weak_kex": {
        "en": "Weak key exchange algorithm: {algorithm}",
        "vi": "Thuật toán trao đổi khóa yếu: {algorithm}",
    },
    "ssh_weak_cipher": {
        "en": "Weak cipher: {algorithm}",
        "vi": "Thuật toán mã hóa yếu: {algorithm}",
    },
    # Report
    "report_generated": {
        "en": "Report generated: {path}",
        "vi": "Báo cáo đã tạo: {path}",
    },
    "report_title": {
        "en": "PQC Readiness Assessment Report",
        "vi": "Báo cáo đánh giá sẵn sàng PQC",
    },
    "report_executive_summary": {
        "en": "Executive Summary",
        "vi": "Tóm tắt tổng quan",
    },
    # Output
    "results_saved": {
        "en": "Results saved to {path}",
        "vi": "Kết quả đã lưu vào {path}",
    },
    "no_findings": {
        "en": "No findings detected. System appears post-quantum safe.",
        "vi": "Không phát hiện vấn đề. Hệ thống có vẻ an toàn hậu lượng tử.",
    },
    # Redaction
    "redaction_warning": {
        "en": "WARNING: Report contains internal hostnames. Use --redact to anonymize.",
        "vi": "CẢNH BÁO: Báo cáo chứa hostname nội bộ. Dùng --redact để ẩn danh.",
    },
    # Rate limiting
    "rate_limit_warning": {
        "en": "WARNING: Delay set to 0ms with {concurrent} concurrent connections. This may resemble a DoS attack.",
        "vi": "CẢNH BÁO: Delay đặt 0ms với {concurrent} kết nối đồng thời. Hành vi này có thể giống tấn công DoS.",
    },
}


def set_language(lang: Language) -> None:
    """Set the current language."""
    global _current_language
    _current_language = lang


def get_language() -> Language:
    """Get the current language."""
    return _current_language


def t(key: str, **kwargs: object) -> str:
    """Translate a string key to the current language.

    Args:
        key: The string key to translate.
        **kwargs: Format arguments for the string.

    Returns:
        The translated and formatted string.
    """
    strings = _STRINGS.get(key)
    if strings is None:
        return key
    text = strings.get(_current_language, strings.get("en", key))
    if kwargs:
        text = text.format(**kwargs)
    return text


def t_lang(key: str, lang: Language, **kwargs: object) -> str:
    """Translate a string key to a specific language."""
    strings = _STRINGS.get(key)
    if strings is None:
        return key
    text = strings.get(lang, strings.get("en", key))
    if kwargs:
        text = text.format(**kwargs)
    return text
