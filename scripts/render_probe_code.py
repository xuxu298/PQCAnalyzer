"""Render a syntax-highlighted image of the X25519MLKEM768 probe core logic.

Captures the 2-stage probe function from src/scanner/pq_probe.py as an SVG
and converts to PNG for use in technical blog posts / forum writeups.

Usage:
    python3 scripts/render_probe_code.py
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from rich.console import Console
from rich.syntax import Syntax

OUT_SVG = Path("docs/probe_code.svg")
OUT_PNG = Path("docs/probe_code.png")
TITLE = "src/scanner/pq_probe.py — X25519MLKEM768 active probe (2-stage)"

CODE = '''def probe_x25519mlkem768(
    host: str, port: int = 443, timeout: float = 5.0
) -> ProbeResult:
    # Stage 1: offer hybrid AND classical X25519 in supported_groups but
    # only send an X25519 key_share. A server that prefers the hybrid
    # responds with HelloRetryRequest naming X25519MLKEM768. We avoid
    # sending a dummy 1216-byte MLKEM key_share because several CDN front
    # ends eagerly validate it and close the connection.
    stage1 = _probe_one(
        host, port, timeout,
        target=GROUP_X25519_MLKEM768,
        groups=[GROUP_X25519_MLKEM768, GROUP_X25519],
        key_shares=[(GROUP_X25519, os.urandom(KS_LEN_X25519))],
    )
    if stage1.supported or stage1.error:
        return stage1

    # Stage 2: server picked X25519 in stage 1 -- it might still support
    # the hybrid but prefer to skip the HRR round-trip. Re-probe with
    # ONLY the hybrid in supported_groups and empty key_shares; the
    # server must either HRR with MLKEM or alert.
    stage2 = _probe_one(
        host, port, timeout,
        target=GROUP_X25519_MLKEM768,
        groups=[GROUP_X25519_MLKEM768],
        key_shares=[],
    )
    if stage2.supported:
        return stage2
    return stage1  # surface stage-1 result (selected=X25519) on negative
'''


def main() -> int:
    console = Console(record=True, width=100)
    syntax = Syntax(
        CODE,
        "python",
        theme="monokai",
        line_numbers=True,
        word_wrap=False,
    )
    console.print(syntax)

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
