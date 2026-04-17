"""Render docs/scan_screenshot.png from a live TLS scan.

Runs `scan tls` on cloudflare.com google.com github.com, captures the rich
output into an SVG, and shells out to rsvg-convert for PNG.

Usage:
    python3 scripts/render_scan_screenshot.py
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from rich.console import Console

from src import cli as cli_module
from src.config import ScanConfig
from src.scanner.inventory import CryptoInventory
from src.scanner.tls_scanner import TLSScanner

TARGETS = ["cloudflare.com", "google.com", "github.com"]
OUT_SVG = Path("docs/scan_screenshot.svg")
OUT_PNG = Path("docs/scan_screenshot.png")
TITLE = "pqc-analyzer scan tls cloudflare.com google.com github.com"


def main() -> int:
    console = Console(record=True, width=110)
    cli_module.console = console

    console.print(f"[bold]Scanning {len(TARGETS)} target(s)...[/bold]\n")

    scanner = TLSScanner(config=ScanConfig())
    inventory = CryptoInventory()
    for target in TARGETS:
        host, port = scanner._parse_target(target)
        result = scanner.scan_host(host, port)
        inventory.add_result(result)
        if result.status.value == "success":
            console.print(
                f"[green]OK {target}[/green] -- {len(result.findings)} finding(s)"
            )
        else:
            console.print(f"[red]FAIL {target}: {result.error_message}[/red]")

    if inventory.all_findings:
        console.print()
        cli_module._print_findings_table(inventory.all_findings)

    cli_module._print_summary(inventory.summary)

    OUT_SVG.parent.mkdir(parents=True, exist_ok=True)
    console.save_svg(str(OUT_SVG), title=TITLE)

    try:
        subprocess.run(
            ["rsvg-convert", "-o", str(OUT_PNG), str(OUT_SVG)], check=True
        )
    except FileNotFoundError:
        print("rsvg-convert not found; SVG saved but PNG not rendered", file=sys.stderr)
        return 1

    OUT_SVG.unlink(missing_ok=True)
    print(f"Wrote {OUT_PNG}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
