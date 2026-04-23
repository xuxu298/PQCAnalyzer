"""Render PNG charts for the Global PQ Readiness Index report.

Reads results CSV, writes:
  ReadinessIndex/chart_by_sector.png
  ReadinessIndex/chart_by_region.png
"""

from __future__ import annotations

import csv
import sys
from collections import defaultdict
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

ROOT = Path(__file__).resolve().parent.parent
OUT_DIR = ROOT / "ReadinessIndex"


def load(path: Path) -> list[dict]:
    with path.open(newline="") as f:
        return list(csv.DictReader(f))


def aggregate(rows: list[dict], key: str) -> dict[str, dict[str, int]]:
    g: dict[str, dict[str, int]] = defaultdict(
        lambda: {"PQ-SAFE": 0, "CLASSICAL": 0, "ERROR": 0, "TOTAL": 0}
    )
    for r in rows:
        bucket = g[r.get(key, "(unknown)")]
        bucket["TOTAL"] += 1
        bucket[r.get("status", "ERROR")] = bucket.get(r.get("status", "ERROR"), 0) + 1
    return g


def stacked_bar(agg: dict[str, dict[str, int]], title: str, out: Path, top_n: int | None = None) -> None:
    items = sorted(agg.items(), key=lambda kv: -kv[1]["PQ-SAFE"] / kv[1]["TOTAL"] if kv[1]["TOTAL"] else 0)
    if top_n:
        items = [it for it in items if it[1]["TOTAL"] >= 3][:top_n]
    labels = [k for k, _ in items]
    pq = [v["PQ-SAFE"] for _, v in items]
    cl = [v["CLASSICAL"] for _, v in items]
    er = [v["ERROR"] for _, v in items]

    fig, ax = plt.subplots(figsize=(10, max(4, len(labels) * 0.45)))
    y = range(len(labels))
    ax.barh(y, pq, color="#10b981", label="PQ-safe (X25519MLKEM768)")
    ax.barh(y, cl, left=pq, color="#ef4444", label="Classical only")
    ax.barh(y, er, left=[p + c for p, c in zip(pq, cl)], color="#f59e0b", label="Probe error / WAF reject")
    ax.set_yticks(list(y))
    ax.set_yticklabels(labels)
    ax.invert_yaxis()
    ax.set_xlabel("Hosts probed")
    ax.set_title(title, fontsize=13, weight="bold")
    ax.legend(loc="lower right", framealpha=0.95)
    ax.grid(axis="x", linestyle=":", alpha=0.4)

    for i, (p, c, e) in enumerate(zip(pq, cl, er)):
        total = p + c + e
        if total:
            pct = p / total * 100
            ax.text(total + 0.5, i, f"{pct:.0f}%", va="center", fontsize=9)

    fig.tight_layout()
    fig.savefig(out, dpi=140, bbox_inches="tight")
    plt.close(fig)


def main() -> int:
    if len(sys.argv) < 2:
        print("Usage: render_pq_index_charts.py <results.csv>")
        return 2
    rows = load(Path(sys.argv[1]))

    by_sector = aggregate(rows, "sector")
    stacked_bar(
        by_sector,
        "PQ-readiness by sector — April 2026 (350 hosts)",
        OUT_DIR / "chart_by_sector.png",
    )
    print(f"wrote {OUT_DIR / 'chart_by_sector.png'}")

    by_region = aggregate(rows, "region")
    stacked_bar(
        by_region,
        "PQ-readiness by region — top regions (≥3 hosts)",
        OUT_DIR / "chart_by_region.png",
        top_n=20,
    )
    print(f"wrote {OUT_DIR / 'chart_by_region.png'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
