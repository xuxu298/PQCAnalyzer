"""Aggregate Global PQ Readiness Index results by sector, region, and KEM group.

Reads a results CSV produced by global_pq_index.py and prints summary tables.
Designed as a quick-look CLI; the report-writing pipeline can pull the same
aggregates programmatically by importing summarize().

Usage:
    python3 scripts/analyze_pq_index.py ReadinessIndex/results_20260423_120000.csv
    python3 scripts/analyze_pq_index.py ReadinessIndex/results_*.csv  # glob picks newest
"""

from __future__ import annotations

import argparse
import csv
import glob
from collections import defaultdict
from pathlib import Path

from rich.console import Console
from rich.table import Table


def load_results(path: Path) -> list[dict]:
    with path.open(newline="") as f:
        return list(csv.DictReader(f))


def _bucket_table(
    title: str, key: str, rows: list[dict]
) -> Table:
    grouped: dict[str, dict[str, int]] = defaultdict(
        lambda: {"PQ-SAFE": 0, "CLASSICAL": 0, "ERROR": 0, "TOTAL": 0}
    )
    for r in rows:
        g = grouped[r.get(key, "(unknown)")]
        g["TOTAL"] += 1
        g[r.get("status", "ERROR")] = g.get(r.get("status", "ERROR"), 0) + 1

    table = Table(title=title, header_style="bold", title_style="bold cyan")
    table.add_column(key.title(), no_wrap=True)
    table.add_column("Total", justify="right")
    table.add_column("PQ-safe", justify="right", style="green")
    table.add_column("Classical", justify="right", style="red")
    table.add_column("Error", justify="right", style="yellow")
    table.add_column("PQ %", justify="right")
    for name in sorted(grouped):
        d = grouped[name]
        pct = d["PQ-SAFE"] / d["TOTAL"] * 100 if d["TOTAL"] else 0
        table.add_row(
            name,
            str(d["TOTAL"]),
            str(d["PQ-SAFE"]),
            str(d["CLASSICAL"]),
            str(d["ERROR"]),
            f"{pct:.1f}%",
        )
    return table


def _kem_table(rows: list[dict]) -> Table:
    counter: dict[str, int] = defaultdict(int)
    for r in rows:
        if r.get("status") == "PQ-SAFE":
            counter[r.get("negotiated_group") or "(empty)"] += 1
    table = Table(
        title="Negotiated PQ key-agreement group",
        header_style="bold",
        title_style="bold cyan",
    )
    table.add_column("Group", no_wrap=True)
    table.add_column("Count", justify="right", style="green")
    for k in sorted(counter, key=lambda x: -counter[x]):
        table.add_row(k, str(counter[k]))
    return table


def summarize(rows: list[dict]) -> dict:
    total = len(rows)
    pq = sum(1 for r in rows if r.get("status") == "PQ-SAFE")
    classical = sum(1 for r in rows if r.get("status") == "CLASSICAL")
    error = sum(1 for r in rows if r.get("status") == "ERROR")
    return {
        "total": total,
        "pq_safe": pq,
        "classical": classical,
        "error": error,
        "pq_pct": (pq / total * 100) if total else 0,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "results",
        help="Results CSV path (glob accepted; newest match wins).",
    )
    args = parser.parse_args()

    matches = sorted(glob.glob(args.results))
    if not matches:
        print(f"No file matches: {args.results}")
        return 2
    path = Path(matches[-1])
    rows = load_results(path)

    s = summarize(rows)
    console = Console()
    console.print(
        f"\n[bold]Source:[/bold] {path}\n"
        f"[bold]Headline:[/bold] {s['pq_safe']}/{s['total']} hosts PQ-safe "
        f"([green]{s['pq_pct']:.1f}%[/green])  "
        f"classical={s['classical']}  error={s['error']}\n"
    )
    console.print(_bucket_table("By sector", "sector", rows))
    console.print()
    console.print(_bucket_table("By region", "region", rows))
    console.print()
    console.print(_kem_table(rows))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
