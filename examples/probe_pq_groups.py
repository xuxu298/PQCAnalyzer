"""Active probe for X25519MLKEM768 across a list of public hosts.

Usage:
    python3 examples/probe_pq_groups.py
    python3 examples/probe_pq_groups.py extra.host1.com extra.host2.com
"""

from __future__ import annotations

import sys
import time

from rich.console import Console
from rich.table import Table

from src.scanner.pq_probe import probe_x25519mlkem768

DEFAULT_HOSTS = [
    "cloudflare.com",
    "www.google.com",
    "youtube.com",
    "aws.amazon.com",
    "www.facebook.com",
    "meta.com",
    "www.fastly.com",
    "www.akamai.com",
    "tls13.akamai.io",
    "example.com",
    "github.com",
    "www.microsoft.com",
    "azure.microsoft.com",
    "www.apple.com",
    "tls13.1d.pw",
]


def main() -> int:
    console = Console()
    hosts = sys.argv[1:] or DEFAULT_HOSTS

    table = Table(
        title="X25519MLKEM768 active probe (TLS 1.3, IANA codepoint 0x11EC)",
        title_style="bold cyan",
        header_style="bold",
    )
    table.add_column("Host", style="white", no_wrap=True)
    table.add_column("Status", justify="center", no_wrap=True)
    table.add_column("Negotiated group", style="dim")
    table.add_column("ms", justify="right", style="dim")

    pq = cls = err = 0
    for host in hosts:
        t0 = time.perf_counter()
        try:
            r = probe_x25519mlkem768(host, timeout=8.0)
        except Exception as exc:  # pragma: no cover - defensive
            r = None
            err += 1
            elapsed = (time.perf_counter() - t0) * 1000
            table.add_row(host, "[red]ERROR[/red]", str(exc), f"{elapsed:.0f}")
            continue
        elapsed = (time.perf_counter() - t0) * 1000
        if r.supported:
            pq += 1
            table.add_row(host, "[bold green]PQ-SAFE[/bold green]", r.selected_group or "", f"{elapsed:.0f}")
        elif r.error:
            err += 1
            table.add_row(host, "[yellow]?[/yellow]", r.error, f"{elapsed:.0f}")
        else:
            cls += 1
            table.add_row(host, "[red]classical[/red]", r.selected_group or "", f"{elapsed:.0f}")

    console.print()
    console.print(table)
    console.print()
    console.print(
        f"  [bold green]PQ-safe: {pq}[/bold green]   "
        f"[red]classical: {cls}[/red]   "
        f"[yellow]error: {err}[/yellow]   "
        f"[dim]of {len(hosts)} hosts[/dim]"
    )
    console.print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
