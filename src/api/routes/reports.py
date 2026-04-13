"""Report generation API routes."""

from __future__ import annotations

from fastapi import APIRouter
from fastapi.responses import HTMLResponse

from src.api.schemas import ReportRequest

router = APIRouter()


@router.post("/report/generate")
def generate_report(request: ReportRequest):
    """Generate a report in the specified format."""
    # For now, generate a roadmap first then create report
    # In a full implementation, this would use stored roadmap data

    return {
        "status": "ok",
        "message": f"Report generation in {request.format} format. "
                   "Use /roadmap/generate first, then /report/html or /report/json.",
        "available_formats": ["html", "json", "sarif"],
    }


@router.post("/report/html", response_class=HTMLResponse)
def generate_html(request: ReportRequest):
    """Generate HTML report from scan results."""
    try:
        from src.reporter.html_report import generate_html_report
    except ImportError:
        from fastapi import HTTPException
        raise HTTPException(
            status_code=501,
            detail="Reporter module not installed. This deployment does not include report generation.",
        )
    from src.roadmap.models import MigrationRoadmap

    # Create minimal roadmap for report
    roadmap = MigrationRoadmap(
        organization=request.organization,
    )

    html = generate_html_report(
        roadmap=roadmap,
        language=request.language,
        organization=request.organization,
        prepared_by=request.prepared_by,
    )

    return HTMLResponse(content=html)


@router.get("/report/formats")
def list_formats():
    """List available report formats."""
    return {
        "formats": [
            {"id": "html", "name": "Interactive HTML Report", "description": "Dark-themed HTML with tables and charts"},
            {"id": "json", "name": "JSON Export", "description": "Machine-readable JSON format"},
            {"id": "sarif", "name": "SARIF", "description": "Static Analysis Results Interchange Format for CI/CD"},
        ]
    }
