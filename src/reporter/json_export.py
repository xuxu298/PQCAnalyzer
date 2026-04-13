"""JSON export — machine-readable report output."""

from __future__ import annotations

import json
from pathlib import Path

from src.roadmap.models import MigrationRoadmap


def export_json(
    roadmap: MigrationRoadmap,
    output_path: str,
    indent: int = 2,
) -> str:
    """Export roadmap as JSON file.

    Args:
        roadmap: Migration roadmap to export.
        output_path: Path to write JSON file.
        indent: JSON indentation level.

    Returns:
        Path to written file.
    """
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    data = roadmap.to_dict()
    path.write_text(
        json.dumps(data, indent=indent, ensure_ascii=False),
        encoding="utf-8",
    )
    return str(path)


def export_sarif(
    roadmap: MigrationRoadmap,
    output_path: str,
) -> str:
    """Export findings in SARIF format (Static Analysis Results Interchange Format).

    SARIF is useful for integration with CI/CD tools and GitHub Code Scanning.
    """
    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "VN-PQC Readiness Analyzer",
                    "version": "0.3.0",
                    "informationUri": "https://github.com/xuxu298/PQCAnalyzer",
                    "rules": [],
                }
            },
            "results": [],
        }],
    }

    rules_seen: set[str] = set()
    run = sarif["runs"][0]

    for score in roadmap.risk_scores:
        rule_id = f"PQC-{score.finding_component.replace(' ', '-')}"

        if rule_id not in rules_seen:
            rules_seen.add(rule_id)
            run["tool"]["driver"]["rules"].append({
                "id": rule_id,
                "name": score.finding_component,
                "shortDescription": {"text": f"Quantum vulnerability in {score.finding_component}"},
                "defaultConfiguration": {
                    "level": "error" if score.total_score >= 100 else "warning",
                },
            })

        run["results"].append({
            "ruleId": rule_id,
            "level": "error" if score.total_score >= 100 else "warning",
            "message": {
                "text": f"{score.finding_algorithm} in {score.finding_component} "
                        f"(risk score: {score.total_score})",
            },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": score.finding_location},
                },
            }] if score.finding_location else [],
        })

    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(sarif, indent=2, ensure_ascii=False), encoding="utf-8")
    return str(path)
