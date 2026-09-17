"""
report_export.py
----------------
Turns the Markdown security report into a self-contained, print-ready HTML
document. Opening the HTML and choosing "Print -> Save as PDF" produces the PDF
deliverable without pulling a heavyweight PDF engine into requirements.txt.

If `reportlab` happens to be installed, `markdown_to_pdf_bytes()` will also
produce a real PDF directly.
"""

from __future__ import annotations

import html
import re
from typing import List

_CSS = """
:root { --ink:#16181d; --muted:#5b6472; --line:#e3e6ea; --accent:#1f6feb; --bg:#ffffff; --code:#f6f8fa; }
* { box-sizing: border-box; }
body { background: var(--bg); color: var(--ink); font-family: -apple-system, BlinkMacSystemFont,
       "Segoe UI", Inter, Roboto, Helvetica, Arial, sans-serif; line-height: 1.6;
       max-width: 900px; margin: 0 auto; padding: 48px 32px 96px; }
h1 { font-size: 30px; margin: 0 0 8px; letter-spacing: -0.02em; }
h2 { font-size: 21px; margin: 40px 0 12px; padding-bottom: 8px; border-bottom: 1px solid var(--line); }
h3 { font-size: 17px; margin: 28px 0 10px; }
p, li { font-size: 14.5px; }
table { width: 100%; border-collapse: collapse; margin: 14px 0; font-size: 13.5px; }
th, td { border: 1px solid var(--line); padding: 8px 10px; text-align: left; vertical-align: top; }
th { background: var(--code); font-weight: 600; }
pre { background: var(--code); border: 1px solid var(--line); border-radius: 8px; padding: 14px;
      overflow-x: auto; font-size: 12.5px; line-height: 1.5; }
code { font-family: "SF Mono", ui-monospace, Menlo, Consolas, monospace; font-size: 12.5px; }
p code, li code, td code { background: var(--code); padding: 1px 5px; border-radius: 4px; }
blockquote { border-left: 3px solid var(--accent); margin: 16px 0; padding: 4px 16px; color: var(--muted); }
hr { border: none; border-top: 1px solid var(--line); margin: 32px 0; }
@media print { body { padding: 0 12px; max-width: none; } h2 { page-break-after: avoid; } pre { page-break-inside: avoid; } }
"""


def markdown_to_html(md: str, title: str = "ASCR Security Report") -> str:
    body = _render(md)
    return (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width, initial-scale=1'>"
        f"<title>{html.escape(title)}</title><style>{_CSS}</style></head>"
        f"<body>{body}</body></html>"
    )


def _render(md: str) -> str:
    out: List[str] = []
    lines = md.splitlines()
    i = 0
    in_table = False

    while i < len(lines):
        line = lines[i]

        # fenced code
        if line.strip().startswith("```"):
            lang = line.strip().strip("`").strip()
            i += 1
            buf: List[str] = []
            while i < len(lines) and not lines[i].strip().startswith("```"):
                buf.append(lines[i])
                i += 1
            i += 1
            out.append(
                f"<pre><code class='language-{html.escape(lang)}'>"
                + html.escape("\n".join(buf))
                + "</code></pre>"
            )
            continue

        # tables
        if line.strip().startswith("|") and line.strip().endswith("|"):
            rows = []
            while i < len(lines) and lines[i].strip().startswith("|"):
                rows.append(lines[i].strip())
                i += 1
            out.append(_table(rows))
            in_table = False
            continue

        stripped = line.strip()
        if not stripped:
            out.append("")
        elif stripped.startswith("#"):
            level = len(stripped) - len(stripped.lstrip("#"))
            out.append(f"<h{level}>{_inline(stripped[level:].strip())}</h{level}>")
        elif stripped.startswith(">"):
            out.append(f"<blockquote>{_inline(stripped[1:].strip())}</blockquote>")
        elif re.match(r"^[-*]\s+", stripped):
            items = []
            while i < len(lines) and re.match(r"^[-*]\s+", lines[i].strip()):
                items.append(f"<li>{_inline(re.sub(r'^[-*]\\s+', '', lines[i].strip()))}</li>")
                i += 1
            out.append("<ul>" + "".join(items) + "</ul>")
            continue
        elif re.match(r"^\d+\.\s+", stripped):
            items = []
            while i < len(lines) and re.match(r"^\d+\.\s+", lines[i].strip()):
                items.append(f"<li>{_inline(re.sub(r'^\\d+\\.\\s+', '', lines[i].strip()))}</li>")
                i += 1
            out.append("<ol>" + "".join(items) + "</ol>")
            continue
        else:
            out.append(f"<p>{_inline(stripped)}</p>")
        i += 1

    _ = in_table
    return "\n".join(out)


def _table(rows: List[str]) -> str:
    def cells(row: str) -> List[str]:
        return [c.strip() for c in row.strip().strip("|").split("|")]

    if len(rows) >= 2 and set(rows[1].replace("|", "").replace(" ", "")) <= set("-:"):
        header, body = cells(rows[0]), rows[2:]
    else:
        header, body = [], rows

    html_out = "<table>"
    if header:
        html_out += "<thead><tr>" + "".join(f"<th>{_inline(c)}</th>" for c in header) + "</tr></thead>"
    html_out += "<tbody>"
    for row in body:
        html_out += "<tr>" + "".join(f"<td>{_inline(c)}</td>" for c in cells(row)) + "</tr>"
    return html_out + "</tbody></table>"


def _inline(text: str) -> str:
    text = html.escape(text)
    text = re.sub(r"`([^`]+)`", r"<code>\1</code>", text)
    text = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", text)
    text = re.sub(r"(?<!\*)\*([^*]+)\*(?!\*)", r"<em>\1</em>", text)
    text = re.sub(r"_([^_]+)_", r"<em>\1</em>", text)
    text = re.sub(r"\[([^\]]+)\]\(([^)]+)\)", r"<a href='\2'>\1</a>", text)
    return text


def markdown_to_pdf_bytes(md: str, title: str = "ASCR Security Report") -> bytes | None:
    """Best-effort direct PDF. Returns None when reportlab is not installed."""
    try:
        from io import BytesIO

        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import mm
        from reportlab.platypus import Paragraph, Preformatted, SimpleDocTemplate, Spacer
    except Exception:
        return None

    buf = BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, title=title,
                            leftMargin=18 * mm, rightMargin=18 * mm,
                            topMargin=18 * mm, bottomMargin=18 * mm)
    styles = getSampleStyleSheet()
    mono = ParagraphStyle("mono", parent=styles["Code"], fontSize=7.5, leading=9.5)
    flow = []
    in_code, buffer = False, []

    for line in md.splitlines():
        if line.strip().startswith("```"):
            if in_code:
                flow.append(Preformatted("\n".join(buffer), mono))
                flow.append(Spacer(1, 6))
                buffer = []
            in_code = not in_code
            continue
        if in_code:
            buffer.append(line)
            continue
        stripped = line.strip()
        if not stripped:
            flow.append(Spacer(1, 5))
        elif stripped.startswith("#"):
            level = min(len(stripped) - len(stripped.lstrip("#")), 3)
            flow.append(Paragraph(_pdf_inline(stripped.lstrip("# ").strip()), styles[f"Heading{level}"]))
        else:
            flow.append(Paragraph(_pdf_inline(stripped), styles["BodyText"]))

    doc.build(flow)
    return buf.getvalue()


def _pdf_inline(text: str) -> str:
    text = html.escape(text)
    text = re.sub(r"\*\*([^*]+)\*\*", r"<b>\1</b>", text)
    text = re.sub(r"`([^`]+)`", r"<font face='Courier'>\1</font>", text)
    return text
