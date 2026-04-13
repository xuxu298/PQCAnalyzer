"""Executive summary generator — high-level summary for policy makers."""

from __future__ import annotations

from src.roadmap.cost_estimator import format_vnd
from src.roadmap.models import MigrationRoadmap
from src.utils.constants import RiskLevel


def generate_executive_summary(
    roadmap: MigrationRoadmap,
    language: str = "en",
) -> str:
    """Generate executive summary text.

    Args:
        roadmap: Complete migration roadmap.
        language: 'en' or 'vi'.

    Returns:
        Formatted executive summary text.
    """
    if language == "vi":
        return _generate_vi(roadmap)
    return _generate_en(roadmap)


def _generate_en(roadmap: MigrationRoadmap) -> str:
    """Generate English executive summary."""
    cost = roadmap.cost_estimate
    lines = [
        "EXECUTIVE SUMMARY",
        "=" * 60,
        "",
        f"Organization: {roadmap.organization or 'Not specified'}",
        f"Assessment Date: {roadmap.timestamp[:10]}",
        f"Overall Risk Level: {roadmap.overall_risk.value}",
        "",
        "--- KEY FINDINGS ---",
        "",
        f"Total findings: {roadmap.total_findings}",
        f"Critical findings requiring immediate action: {roadmap.critical_findings}",
        f"Quantum-vulnerable components: {roadmap.quantum_vulnerable_count}",
        "",
    ]

    # Risk assessment
    if roadmap.overall_risk in (RiskLevel.CRITICAL, RiskLevel.HIGH):
        lines.append(
            "WARNING: Your infrastructure has significant quantum vulnerability exposure. "
            "Immediate action is recommended to begin PQC migration, especially for "
            "internet-facing services that handle sensitive data."
        )
    elif roadmap.overall_risk == RiskLevel.MEDIUM:
        lines.append(
            "Your infrastructure has moderate quantum vulnerability. "
            "A structured migration plan should be developed within the next 6-12 months."
        )
    else:
        lines.append(
            "Your infrastructure has limited quantum vulnerability. "
            "Continue monitoring PQC developments and plan gradual migration."
        )

    lines.extend([
        "",
        "--- MIGRATION OVERVIEW ---",
        "",
    ])

    for phase in roadmap.phases:
        if phase.tasks:
            lines.append(
                f"Phase {phase.phase_number} — {phase.name} ({phase.timeline}): "
                f"{len(phase.tasks)} task(s), {phase.total_effort_hours} person-hours"
            )

    lines.extend([
        "",
        "--- COST ESTIMATION ---",
        "",
        f"Total effort: {cost.total_person_hours} person-hours",
        f"Estimated timeline: {cost.timeline_months} months",
        f"Cost range: {format_vnd(cost.cost_range_low_vnd)} — {format_vnd(cost.cost_range_high_vnd)}",
        "",
        "--- COMPLIANCE ---",
        "",
    ])

    for c in roadmap.compliance:
        status_icon = {"compliant": "[OK]", "non_compliant": "[FAIL]",
                       "partial": "[PARTIAL]"}.get(c.status, "[?]")
        lines.append(f"  {status_icon} {c.standard}: {c.requirement}")

    lines.extend([
        "",
        "--- RECOMMENDED IMMEDIATE ACTIONS ---",
        "",
    ])

    # Top 5 highest priority tasks
    all_tasks = []
    for phase in roadmap.phases:
        all_tasks.extend(phase.tasks)
    all_tasks.sort(key=lambda t: (t.phase, t.priority))

    for i, task in enumerate(all_tasks[:5], 1):
        lines.append(f"  {i}. {task.title}")
        lines.append(f"     Phase: {task.phase_name} | Effort: {task.effort_hours}h | Risk: {task.risk_level}")

    return "\n".join(lines)


def _generate_vi(roadmap: MigrationRoadmap) -> str:
    """Generate Vietnamese executive summary."""
    cost = roadmap.cost_estimate
    lines = [
        "TÓM TẮT ĐIỀU HÀNH",
        "=" * 60,
        "",
        f"Tổ chức: {roadmap.organization or 'Chưa xác định'}",
        f"Ngày đánh giá: {roadmap.timestamp[:10]}",
        f"Mức độ rủi ro tổng thể: {roadmap.overall_risk.value}",
        "",
        "--- PHÁT HIỆN CHÍNH ---",
        "",
        f"Tổng số phát hiện: {roadmap.total_findings}",
        f"Phát hiện nghiêm trọng cần xử lý ngay: {roadmap.critical_findings}",
        f"Thành phần dễ bị tấn công lượng tử: {roadmap.quantum_vulnerable_count}",
        "",
    ]

    if roadmap.overall_risk in (RiskLevel.CRITICAL, RiskLevel.HIGH):
        lines.append(
            "CẢNH BÁO: Hạ tầng của bạn có mức độ lộ lỗ hổng lượng tử đáng kể. "
            "Cần hành động ngay để bắt đầu chuyển đổi PQC, đặc biệt với các "
            "dịch vụ kết nối internet xử lý dữ liệu nhạy cảm."
        )
    elif roadmap.overall_risk == RiskLevel.MEDIUM:
        lines.append(
            "Hạ tầng có mức độ lỗ hổng lượng tử trung bình. "
            "Nên xây dựng kế hoạch chuyển đổi có cấu trúc trong 6-12 tháng tới."
        )
    else:
        lines.append(
            "Hạ tầng có mức độ lỗ hổng lượng tử thấp. "
            "Tiếp tục theo dõi phát triển PQC và lên kế hoạch chuyển đổi dần."
        )

    lines.extend([
        "",
        "--- TỔNG QUAN CHUYỂN ĐỔI ---",
        "",
    ])

    phase_names_vi = {
        0: "Kiểm kê & Đánh giá",
        1: "Thắng lợi nhanh",
        2: "Chuyển đổi cốt lõi",
        3: "PQC toàn diện",
    }

    for phase in roadmap.phases:
        if phase.tasks:
            name_vi = phase_names_vi.get(phase.phase_number, phase.name)
            lines.append(
                f"Giai đoạn {phase.phase_number} — {name_vi} ({phase.timeline}): "
                f"{len(phase.tasks)} nhiệm vụ, {phase.total_effort_hours} giờ công"
            )

    lines.extend([
        "",
        "--- ƯỚC TÍNH CHI PHÍ ---",
        "",
        f"Tổng công sức: {cost.total_person_hours} giờ công",
        f"Thời gian ước tính: {cost.timeline_months} tháng",
        f"Phạm vi chi phí: {format_vnd(cost.cost_range_low_vnd)} — {format_vnd(cost.cost_range_high_vnd)}",
        "",
        "--- TUÂN THỦ ---",
        "",
    ])

    for c in roadmap.compliance:
        status_icon = {"compliant": "[ĐẠT]", "non_compliant": "[KHÔNG ĐẠT]",
                       "partial": "[MỘT PHẦN]"}.get(c.status, "[?]")
        lines.append(f"  {status_icon} {c.standard}: {c.requirement}")

    lines.extend([
        "",
        "--- HÀNH ĐỘNG KHUYẾN NGHỊ NGAY ---",
        "",
    ])

    all_tasks = []
    for phase in roadmap.phases:
        all_tasks.extend(phase.tasks)
    all_tasks.sort(key=lambda t: (t.phase, t.priority))

    for i, task in enumerate(all_tasks[:5], 1):
        lines.append(f"  {i}. {task.title}")
        lines.append(f"     Giai đoạn: {task.phase_name} | Công sức: {task.effort_hours}h | Rủi ro: {task.risk_level}")

    return "\n".join(lines)
