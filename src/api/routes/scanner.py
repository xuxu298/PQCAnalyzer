"""Scanner API routes."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException

from src.api.schemas import ScanConfigRequest, ScanResultResponse

router = APIRouter()


@router.post("/scan/config", response_model=list[ScanResultResponse])
def scan_config(request: ScanConfigRequest):
    """Scan configuration files for crypto algorithms."""
    from src.scanner.config_parser import ConfigParser

    parser = ConfigParser()
    results = []

    for path in request.paths:
        from pathlib import Path
        p = Path(path)
        if p.is_dir():
            results.extend(parser.scan_directory(str(p), recursive=request.recursive))
        elif p.is_file():
            results.append(parser.scan_file(str(p)))
        else:
            raise HTTPException(status_code=404, detail=f"Path not found: {path}")

    return [_scan_result_to_response(r) for r in results]


@router.post("/scan/ssh", response_model=list[ScanResultResponse])
def scan_ssh(request: ScanConfigRequest):
    """Scan SSH configuration files."""
    from src.scanner.ssh_scanner import SSHScanner

    scanner = SSHScanner()
    results = []

    for path in request.paths:
        results.append(scanner.scan_file(path))

    return [_scan_result_to_response(r) for r in results]


@router.post("/scan/vpn", response_model=list[ScanResultResponse])
def scan_vpn(request: ScanConfigRequest):
    """Scan VPN configuration files."""
    from src.scanner.vpn_scanner import VPNScanner

    scanner = VPNScanner()
    results = []

    for path in request.paths:
        results.append(scanner.scan_file(path))

    return [_scan_result_to_response(r) for r in results]


@router.post("/scan/code", response_model=list[ScanResultResponse])
def scan_code(request: ScanConfigRequest):
    """Scan source code for crypto usage patterns."""
    from src.scanner.code_scanner import CodeScanner

    scanner = CodeScanner()
    results = []

    for path in request.paths:
        from pathlib import Path
        p = Path(path)
        if p.is_dir():
            results.extend(scanner.scan_directory(str(p), recursive=request.recursive))
        elif p.is_file():
            result = scanner.scan_file(str(p))
            if result.findings:
                results.append(result)
        else:
            raise HTTPException(status_code=404, detail=f"Path not found: {path}")

    return [_scan_result_to_response(r) for r in results]


def _scan_result_to_response(result) -> dict:
    """Convert ScanResult to API response."""
    if result.summary is None:
        result.finalize()
    return {
        "scan_id": result.scan_id,
        "target": result.target,
        "scan_type": result.scan_type.value,
        "status": result.status.value,
        "findings": [
            {
                "component": f.component,
                "algorithm": f.algorithm,
                "risk_level": f.risk_level.value if hasattr(f.risk_level, "value") else f.risk_level,
                "quantum_vulnerable": f.quantum_vulnerable,
                "location": f.location,
                "replacement": f.replacement,
                "migration_priority": f.migration_priority,
                "note": f.note,
            }
            for f in result.findings
        ],
        "summary": result.summary.to_dict() if result.summary else None,
        "error_message": result.error_message,
    }
