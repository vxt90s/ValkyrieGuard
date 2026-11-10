"""Combined HTML report builder (every dynamic value is HTML-escaped)."""

import html
from datetime import datetime
from typing import List

from .config import LEVELS, PORT_NOTES, SEV_ORDER
from .models import ScanResult, severity_summary


def build_html(host: str, ip: str, findings: List[dict], results: List[ScanResult], ext: List[str]) -> str:
    e = html.escape
    lvl_col = {"ALERT": "#f43f5e", "WARNING": "#f97316", "INFO": "#3b82f6", "OK": "#10b981",
               "CRITICAL": "#f43f5e", "HIGH": "#f97316", "MEDIUM": "#eab308", "LOW": "#3b82f6", "-": "#10b981"}
    a = {k: sum(1 for f in findings if f.get("Level") == k) for k in LEVELS}
    n = severity_summary(results)

    def badge(t):
        return f'<span class="b" style="background:{lvl_col.get(t, "#64748b")}">{e(t)}</span>'

    cards = "".join(f'<div class="c"><div class="l">Audit {k}</div><div class="v" style="color:{lvl_col[k]}">{a[k]}</div></div>' for k in LEVELS)
    cards += "".join(f'<div class="c"><div class="l">CVE {k}</div><div class="v" style="color:{lvl_col[k]}">{n[k]}</div></div>' for k in SEV_ORDER)

    rows = ""
    for f in sorted(findings, key=lambda x: LEVELS.index(x.get("Level", "INFO")) if x.get("Level") in LEVELS else 9):
        rows += (f'<tr><td>{badge(f.get("Level", ""))}</td><td>{e(str(f.get("Area", "")))}</td>'
                 f'<td><b>{e(str(f.get("Title", "")))}</b><br><small>{e(str(f.get("Detail", "")))}</small>'
                 f'<br><small class="fix">{e(str(f.get("Fix", "")))}</small></td></tr>')
    audit_tbl = f"<table><tr><th>Level</th><th>Area</th><th>Finding</th></tr>{rows}</table>" if rows else "<p>No system audit was run.</p>"

    prow = ""
    for r in results:
        v = "".join(f'<div class="vb">{badge(x.severity)} <b>{e(x.cve)}</b><br><small>{e(x.description)}</small></div>' for x in r.vulnerabilities) or badge("-").replace(">-<", ">No known pattern<")
        note = PORT_NOTES.get(r.port, "")
        prow += (f'<tr><td class="p">{r.port}</td><td>{e(r.detected_service.upper())}</td>'
                 f'<td><code>{e(r.version)}</code><br><small>Raw: {e(r.banner)}</small>'
                 f'{"<br><small class=fix>" + e(note) + "</small>" if note else ""}</td><td>{v}</td></tr>')
    scan_tbl = (f"<table><tr><th>Port</th><th>Service</th><th>Version / banner</th><th>Matches</th></tr>{prow}</table>"
                if prow else "<p>No open ports found (or no scan was run).</p>")
    ext_html = ("<h2>Shodan cross-reference</h2><p>" + " ".join(f'<span class="b" style="background:#334155">{e(x)}</span>' for x in ext) + "</p>") if ext else ""

    return f"""<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><title>ValkyrieGuard Report</title><style>
body{{font-family:'Segoe UI',system-ui,sans-serif;background:#0b0f19;color:#f1f5f9;margin:0;padding:28px}}
.w{{max-width:1150px;margin:0 auto}} h1{{color:#38bdf8;margin:0}} h2{{margin-top:34px;color:#e2e8f0}}
.g{{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:12px;margin-top:20px}}
.c{{background:#111b2e;border:1px solid #1e293b;border-radius:8px;padding:12px}} .l{{font-size:11px;color:#94a3b8;text-transform:uppercase}} .v{{font-size:26px;font-weight:700}}
table{{width:100%;border-collapse:collapse;background:#111b2e;border:1px solid #1e293b;margin-top:12px}}
th,td{{padding:11px 14px;text-align:left;vertical-align:top;border-bottom:1px solid #1e293b}} th{{color:#38bdf8;font-size:12px;text-transform:uppercase}}
.b{{display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:700;color:#fff}}
small{{color:#94a3b8}} .fix{{color:#7dd3fc}} .p{{font-family:monospace;color:#38bdf8;font-weight:700}}
.vb{{border-left:4px solid #f43f5e;background:#1c131d;padding:8px;margin:6px 0;border-radius:4px}}
footer{{margin-top:40px;text-align:center;color:#64748b;font-size:12px}}</style></head><body><div class="w">
<h1>ValkyrieGuard Report</h1><div style="color:#94a3b8">Target: {e(host)} ({e(ip)}) &middot; {e(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))}</div>
<div class="g">{cards}</div><h2>1. System audit</h2>{audit_tbl}<h2>2. Network scan</h2>{scan_tbl}{ext_html}
<footer>ValkyrieGuard &middot; automated checks can miss problems and can raise false alarms.</footer></div></body></html>"""
