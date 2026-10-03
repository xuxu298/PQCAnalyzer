"""The free CLI points at the commercial edition once, after the summary."""

from typer.testing import CliRunner

from src.cli import UPGRADE_HINT, app


def test_hint_names_the_product_site():
    assert "https://vpqaudit.atkvn.com" in UPGRADE_HINT


def test_scan_summary_ends_with_the_hint():
    result = CliRunner().invoke(app, ["scan", "config", "tests/fixtures/configs"])
    assert result.exit_code == 0, result.output
    flat = " ".join(result.output.split())
    assert flat.count("vpqaudit.atkvn.com") == 1
