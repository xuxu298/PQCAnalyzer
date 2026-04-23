"""Run X25519MLKEM768 active probe across the Global PQ Readiness Index target list.

Reads targets from ReadinessIndex/targets.csv, probes each host in parallel using
the same 2-stage raw ClientHello probe shipped in src/scanner/pq_probe.py, and
writes timestamped results to ReadinessIndex/results_<ts>.csv.

Usage:
    python3 scripts/global_pq_index.py
    python3 scripts/global_pq_index.py --workers 30 --timeout 10
    python3 scripts/global_pq_index.py --targets ReadinessIndex/targets.csv --output ReadinessIndex/results_test.csv
"""

from __future__ import annotations

import argparse
import csv
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

from rich.console import Console
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    TextColumn,
    TimeRemainingColumn,
)

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from src.scanner.pq_probe import probe_x25519mlkem768  # noqa: E402

OUT_DIR = ROOT / "ReadinessIndex"
DEFAULT_TARGETS = OUT_DIR / "targets.csv"

FIELDNAMES = [
    "host",
    "sector",
    "region",
    "status",
    "negotiated_group",
    "ms",
    "error",
    "ts",
]


def load_targets(path: Path) -> list[dict]:
    with path.open(newline="") as f:
        return list(csv.DictReader(f))


def probe_one(target: dict, timeout: float) -> dict:
    host = target["host"].strip()
    t0 = time.perf_counter()
    base = {
        "host": host,
        "sector": target.get("sector", ""),
        "region": target.get("region", ""),
        "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    try:
        r = probe_x25519mlkem768(host, timeout=timeout)
        elapsed = (time.perf_counter() - t0) * 1000
        if r.supported:
            status = "PQ-SAFE"
        elif r.error:
            status = "ERROR"
        else:
            status = "CLASSICAL"
        base.update(
            status=status,
            negotiated_group=r.selected_group or "",
            ms=f"{elapsed:.0f}",
            error=r.error or "",
        )
    except Exception as exc:  # pragma: no cover - defensive
        elapsed = (time.perf_counter() - t0) * 1000
        base.update(
            status="ERROR",
            negotiated_group="",
            ms=f"{elapsed:.0f}",
            error=f"{type(exc).__name__}: {exc}",
        )
    return base


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--targets", default=str(DEFAULT_TARGETS))
    parser.add_argument("--workers", type=int, default=40)
    parser.add_argument("--timeout", type=float, default=8.0)
    parser.add_argument("--output", default=None)
    args = parser.parse_args()

    targets_path = Path(args.targets)
    if not targets_path.exists():
        print(f"Targets file not found: {targets_path}", file=sys.stderr)
        return 2

    targets = load_targets(targets_path)
    if not targets:
        print("No targets loaded.", file=sys.stderr)
        return 2

    if args.output:
        out_path = Path(args.output)
    else:
        ts_tag = datetime.now().strftime("%Y%m%d_%H%M%S")
        out_path = OUT_DIR / f"results_{ts_tag}.csv"
    out_path.parent.mkdir(parents=True, exist_ok=True)

    console = Console()
    console.print(
        f"[bold]Global PQ Readiness Index probe[/bold]\n"
        f"  targets : {len(targets)} hosts ({targets_path})\n"
        f"  workers : {args.workers}\n"
        f"  timeout : {args.timeout}s\n"
        f"  output  : {out_path}\n"
    )

    counts: dict[str, int] = {"PQ-SAFE": 0, "CLASSICAL": 0, "ERROR": 0}
    with out_path.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDNAMES)
        writer.writeheader()
        with Progress(
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            MofNCompleteColumn(),
            TextColumn("•"),
            TimeRemainingColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("Probing", total=len(targets))
            with ThreadPoolExecutor(max_workers=args.workers) as ex:
                futures = {
                    ex.submit(probe_one, t, args.timeout): t for t in targets
                }
                for fut in as_completed(futures):
                    result = fut.result()
                    writer.writerow(result)
                    f.flush()
                    counts[result["status"]] = counts.get(result["status"], 0) + 1
                    progress.update(task, advance=1)

    total = sum(counts.values())
    pq_pct = counts["PQ-SAFE"] / total * 100 if total else 0
    console.print()
    console.print(
        f"  [bold green]PQ-safe : {counts['PQ-SAFE']:>4} ({pq_pct:.1f}%)[/bold green]"
    )
    console.print(f"  [red]classical: {counts['CLASSICAL']:>4}[/red]")
    console.print(f"  [yellow]error    : {counts['ERROR']:>4}[/yellow]")
    console.print(f"  [dim]results -> {out_path}[/dim]")
    return 0


if __name__ == "__main__":
    sys.exit(main())
