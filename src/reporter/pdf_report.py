"""PDF report generator — uses WeasyPrint to convert HTML report to PDF."""

from __future__ import annotations

from pathlib import Path

from src.roadmap.models import MigrationRoadmap
from src.scanner.models import Finding


def generate_pdf_report(
    roadmap: MigrationRoadmap,
    findings: list[Finding] | None = None,
    language: str = "en",
    organization: str = "",
    prepared_by: str = "",
    output_path: str = "report.pdf",
) -> str:
    """Generate a PDF report from the HTML template.

    Requires weasyprint to be installed (pip install vn-pqc-analyzer[report]).

    Args:
        roadmap: Complete migration roadmap.
        findings: Scanner findings.
        language: 'en' or 'vi'.
        organization: Organization name.
        prepared_by: Report author.
        output_path: Path to write PDF file.

    Returns:
        Path to written PDF file.

    Raises:
        ImportError: If weasyprint is not installed.
    """
    try:
        from weasyprint import HTML
    except ImportError:
        raise ImportError(
            "WeasyPrint is required for PDF generation. "
            "Install it with: pip install vn-pqc-analyzer[report]"
        )

    from src.reporter.html_report import generate_html_report

    html_content = generate_html_report(
        roadmap=roadmap,
        findings=findings,
        language=language,
        organization=organization,
        prepared_by=prepared_by,
    )

    # Inject print-optimized CSS overrides
    print_css = """
    <style>
        @page {
            size: A4;
            margin: 15mm 12mm;
        }
        body {
            background: #ffffff !important;
            color: #1a1a1a !important;
            font-size: 10pt;
        }
        .container { max-width: 100%; padding: 0; }
        .header { background: #1a2332 !important; -webkit-print-color-adjust: exact; print-color-adjust: exact; }
        .stat-card { border: 1px solid #ccc; background: #f9f9f9 !important; }
        .stat-card .stat-value { color: #1a1a1a !important; }
        table { page-break-inside: auto; }
        tr { page-break-inside: avoid; }
        .phase-card { page-break-inside: avoid; border: 1px solid #ccc; background: #f9f9f9 !important; }
        .risk-critical { color: #dc2626 !important; }
        .risk-high { color: #ea580c !important; }
        .risk-medium { color: #ca8a04 !important; }
        .risk-low { color: #16a34a !important; }
        .risk-safe { color: #0d9488 !important; }
    </style>
    """
    html_content = html_content.replace("</head>", f"{print_css}</head>")

    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    html_doc = HTML(string=html_content)
    html_doc.write_pdf(str(path))

    return str(path)
