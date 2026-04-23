"""Render the PQ Readiness Index markdown report as a print-ready PDF.

Uses python-markdown for the conversion + WeasyPrint for layout. Resolves
relative image paths against the markdown file's directory so chart_*.png
embed correctly. CSS targets A4 print, JetBrains Mono for inline code,
and a sober deep-space header for the cover.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import markdown
from weasyprint import CSS, HTML

CSS_TEXT = """
@page {
    size: A4;
    margin: 18mm 16mm 22mm 16mm;
    @bottom-left {
        content: "Global PQ Readiness Index — April 2026";
        font-family: "Inter", "Segoe UI", sans-serif;
        font-size: 8pt;
        color: #6b7280;
    }
    @bottom-right {
        content: counter(page) " / " counter(pages);
        font-family: "Inter", "Segoe UI", sans-serif;
        font-size: 8pt;
        color: #6b7280;
    }
}
@page :first {
    @bottom-left { content: ""; }
    @bottom-right { content: ""; }
}

html, body {
    font-family: "Inter", "Segoe UI", "Noto Sans", Arial, sans-serif;
    font-size: 10pt;
    line-height: 1.5;
    color: #111827;
    margin: 0;
    padding: 0;
}

h1 {
    font-size: 22pt;
    font-weight: 700;
    color: #0a0e1a;
    margin: 0 0 4mm 0;
    padding-bottom: 3mm;
    border-bottom: 2pt solid #7c3aed;
}
h2 {
    font-size: 14pt;
    font-weight: 700;
    color: #0a0e1a;
    margin-top: 8mm;
    margin-bottom: 2mm;
    page-break-after: avoid;
}
h3 {
    font-size: 11pt;
    font-weight: 700;
    color: #0a0e1a;
    margin-top: 5mm;
    margin-bottom: 1mm;
    page-break-after: avoid;
}
p { margin: 0 0 2.5mm 0; }
ul, ol { margin: 0 0 3mm 0; padding-left: 6mm; }
li { margin-bottom: 1.2mm; }
strong { font-weight: 700; color: #0a0e1a; }
em { font-style: italic; }

code {
    font-family: "JetBrains Mono", "Consolas", monospace;
    font-size: 9pt;
    background: #f3f4f6;
    color: #1f2937;
    padding: 0.4mm 1mm;
    border-radius: 1mm;
}
pre {
    font-family: "JetBrains Mono", "Consolas", monospace;
    font-size: 8.5pt;
    background: #0f172a;
    color: #e5e7eb;
    padding: 3mm;
    border-radius: 1.5mm;
    line-height: 1.4;
    page-break-inside: avoid;
    overflow-wrap: anywhere;
    white-space: pre-wrap;
}
pre code { background: transparent; color: inherit; padding: 0; }

a { color: #2563eb; text-decoration: none; }
a:hover { text-decoration: underline; }

table {
    width: 100%;
    border-collapse: collapse;
    margin: 2mm 0 4mm 0;
    font-size: 9pt;
    page-break-inside: avoid;
}
th {
    background: #1f2937;
    color: #f9fafb;
    padding: 1.5mm 2mm;
    text-align: left;
    font-weight: 600;
}
td {
    padding: 1.2mm 2mm;
    border-bottom: 0.4pt solid #e5e7eb;
    vertical-align: top;
}
tr:nth-child(even) td { background: #f9fafb; }

img {
    max-width: 100%;
    height: auto;
    display: block;
    margin: 3mm auto;
    page-break-inside: avoid;
}

hr {
    border: none;
    border-top: 0.6pt solid #d1d5db;
    margin: 5mm 0;
}

blockquote {
    margin: 2mm 0 2mm 4mm;
    padding-left: 3mm;
    border-left: 2pt solid #7c3aed;
    color: #374151;
    font-style: italic;
}

.cover-meta {
    font-size: 9pt;
    color: #4b5563;
    margin: 0 0 1mm 0;
}
"""


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "input",
        nargs="?",
        default="ReadinessIndex/report_2026-04-23.md",
        help="Path to report markdown",
    )
    parser.add_argument(
        "--output",
        default="ReadinessIndex/report_2026-04-23.pdf",
        help="Path for the output PDF",
    )
    args = parser.parse_args()

    src = Path(args.input).resolve()
    if not src.exists():
        print(f"Input not found: {src}", file=sys.stderr)
        return 2

    md_text = src.read_text(encoding="utf-8")

    html_body = markdown.markdown(
        md_text,
        extensions=["tables", "fenced_code", "sane_lists", "toc", "attr_list"],
        output_format="html5",
    )
    html_doc = f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>Global PQ Readiness Index — April 2026</title></head>
<body>{html_body}</body>
</html>
"""

    out = Path(args.output).resolve()
    out.parent.mkdir(parents=True, exist_ok=True)

    HTML(string=html_doc, base_url=str(src.parent)).write_pdf(
        target=str(out),
        stylesheets=[CSS(string=CSS_TEXT)],
    )
    print(f"wrote {out} ({out.stat().st_size // 1024} KB)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
