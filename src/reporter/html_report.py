"""HTML report generator — interactive HTML report with dark theme."""

from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from src.roadmap.cost_estimator import format_vnd
from src.roadmap.models import MigrationRoadmap

_TEMPLATES_DIR = Path(__file__).parent / "templates"

# Localization strings
_STRINGS = {
    "en": {
        "title": "PQC Readiness Assessment Report",
        "subtitle": "Post-Quantum Cryptography Migration Assessment",
        "org_label": "Organization",
        "date_label": "Date",
        "prepared_label": "Prepared by",
        "risk_label": "Risk",
        "summary_title": "Summary",
        "findings_title": "Findings",
        "roadmap_title": "Migration Roadmap",
        "cost_title": "Cost Estimation",
        "compliance_title": "Compliance Status",
        "col_risk": "Risk",
        "col_component": "Component",
        "col_algorithm": "Algorithm",
        "col_qv": "Quantum Vuln.",
        "col_location": "Location",
        "col_replacement": "Replacement",
        "effort_label": "Effort",
        "total_hours_label": "Total effort",
        "hours_unit": "person-hours",
        "timeline_label": "Estimated timeline",
        "months_unit": "months",
        "cost_range_label": "Cost range",
        "compliant_text": "PASS",
        "non_compliant_text": "FAIL",
        "partial_text": "PARTIAL",
    },
    "vi": {
        "title": "Báo cáo Đánh giá Sẵn sàng PQC",
        "subtitle": "Đánh giá Chuyển đổi Mã hóa Hậu Lượng tử",
        "org_label": "Tổ chức",
        "date_label": "Ngày",
        "prepared_label": "Người lập",
        "risk_label": "Rủi ro",
        "summary_title": "Tổng quan",
        "findings_title": "Phát hiện",
        "roadmap_title": "Lộ trình Chuyển đổi",
        "cost_title": "Ước tính Chi phí",
        "compliance_title": "Trạng thái Tuân thủ",
        "col_risk": "Rủi ro",
        "col_component": "Thành phần",
        "col_algorithm": "Thuật toán",
        "col_qv": "Lỗ hổng QC",
        "col_location": "Vị trí",
        "col_replacement": "Thay thế",
        "effort_label": "Công sức",
        "total_hours_label": "Tổng công sức",
        "hours_unit": "giờ công",
        "timeline_label": "Thời gian ước tính",
        "months_unit": "tháng",
        "cost_range_label": "Phạm vi chi phí",
        "compliant_text": "ĐẠT",
        "non_compliant_text": "KHÔNG ĐẠT",
        "partial_text": "MỘT PHẦN",
    },
}


def generate_html_report(
    roadmap: MigrationRoadmap,
    findings: list | None = None,
    language: str = "en",
    organization: str = "",
    prepared_by: str = "",
) -> str:
    """Generate an interactive HTML report.

    Args:
        roadmap: Complete migration roadmap.
        findings: Scanner findings (optional, extracted from roadmap if not provided).
        language: 'en' or 'vi'.
        organization: Organization name.
        prepared_by: Report author.

    Returns:
        HTML string.
    """
    env = Environment(
        loader=FileSystemLoader(str(_TEMPLATES_DIR)),
        autoescape=True,
    )
    template = env.get_template("report_base.html")

    strings = _STRINGS.get(language, _STRINGS["en"])

    # Load CSS
    css_path = _TEMPLATES_DIR / "styles.css"
    css = css_path.read_text() if css_path.exists() else ""

    # Prepare findings data
    findings_data = []
    if findings:
        for f in findings:
            risk = f.risk_level.value if hasattr(f.risk_level, "value") else str(f.risk_level)
            findings_data.append({
                "risk_level": risk,
                "component": f.component,
                "algorithm": f.algorithm,
                "quantum_vulnerable": f.quantum_vulnerable,
                "location": f.location,
                "replacement": ", ".join(f.replacement[:2]) if f.replacement else "—",
            })
    findings_data.sort(key=lambda x: ["CRITICAL", "HIGH", "MEDIUM", "LOW", "SAFE"].index(x["risk_level"])
                       if x["risk_level"] in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "SAFE"] else 5)

    # Count stats
    stats = {"critical": 0, "high": 0, "medium": 0, "low": 0, "safe": 0}
    for f in findings_data:
        key = f["risk_level"].lower()
        if key in stats:
            stats[key] += 1

    # Prepare phases data
    phases_data = [p.to_dict() for p in roadmap.phases]

    # Cost formatting
    cost = roadmap.cost_estimate

    html = template.render(
        lang=language,
        css=css,
        organization=organization or roadmap.organization,
        date=roadmap.timestamp[:10],
        prepared_by=prepared_by,
        overall_risk=roadmap.overall_risk.value,
        stats=stats,
        findings=findings_data,
        phases=phases_data,
        cost=cost.to_dict(),
        cost_range_low=format_vnd(cost.cost_range_low_vnd),
        cost_range_high=format_vnd(cost.cost_range_high_vnd),
        compliance=[c.to_dict() for c in roadmap.compliance],
        **strings,
    )

    return html


def save_html_report(
    html: str,
    output_path: str,
) -> str:
    """Save HTML report to file.

    Args:
        html: HTML content.
        output_path: Path to write HTML file.

    Returns:
        Path to written file.
    """
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(html, encoding="utf-8")
    return str(path)
