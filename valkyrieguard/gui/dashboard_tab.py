"""Dashboard tab: overall verdict, severity cards, full-scan button and report export."""

import json
import os
import tkinter as tk
from dataclasses import asdict
from datetime import datetime
from tkinter import filedialog, messagebox, ttk
from typing import Dict

from ..config import IS_WIN, LEVELS, SEV_ORDER
from ..models import severity_summary
from ..report import build_html
from .base import AppBase
from .theme import BG, COL, LINE, MUT, PANEL, TXT


class DashboardTab(AppBase):
    def _tab_dashboard(self):
        t = ttk.Frame(self.nb)
        self.nb.add(t, text="  Dashboard  ")
        self.verdict = tk.Label(t, text="", bg=BG, fg=TXT, font=("Segoe UI", 17, "bold"), anchor="w")
        self.verdict.pack(fill="x", padx=14, pady=(16, 2))
        self.sub = tk.Label(t, text="", bg=BG, fg=MUT, anchor="w", font=("Segoe UI", 10))
        self.sub.pack(fill="x", padx=14)

        self.cards: Dict[str, tk.Label] = {}
        for row, (title, keys, pre) in enumerate([("SYSTEM AUDIT (this PC)", LEVELS, "a"), ("NETWORK SCAN (CVE pattern matches)", SEV_ORDER, "n")]):
            tk.Label(t, text=title, bg=BG, fg=MUT, font=("Segoe UI", 9, "bold"), anchor="w").pack(fill="x", padx=16, pady=(16, 0))
            g = tk.Frame(t, bg=BG)
            g.pack(fill="x", padx=8)
            for i, k in enumerate(keys):
                g.columnconfigure(i, weight=1, uniform=pre)
                f = tk.Frame(g, bg=PANEL, highlightbackground=LINE, highlightthickness=1)
                f.grid(row=0, column=i, padx=6, pady=6, sticky="nsew")
                tk.Label(f, text=k, bg=PANEL, fg=MUT, font=("Segoe UI", 9)).pack(anchor="w", padx=12, pady=(10, 0))
                v = tk.Label(f, text="-", bg=PANEL, fg=COL[k], font=("Segoe UI", 26, "bold"))
                v.pack(anchor="w", padx=12, pady=(0, 10))
                self.cards[pre + k] = v

        bar = tk.Frame(t, bg=BG)
        bar.pack(fill="x", padx=14, pady=(20, 4))
        self.btn_full = ttk.Button(bar, text="Run Full Scan (audit + this PC's ports)", style="Accent.TButton", command=self.run_full)
        self.btn_full.pack(side="left")
        ttk.Button(bar, text="Export HTML report", command=self.export_html).pack(side="left", padx=8)
        ttk.Button(bar, text="Export JSON", command=self.export_json).pack(side="left")
        self.prog = ttk.Progressbar(t, mode="determinate", maximum=100)
        self.prog.pack(fill="x", padx=14, pady=(10, 2))
        self.status = tk.Label(t, text="Idle", bg=BG, fg=MUT, anchor="w")
        self.status.pack(fill="x", padx=14)
        tk.Label(t, bg=BG, fg=MUT, anchor="w", justify="left", wraplength=1050,
                 text="How it works: the System Audit checks Windows protections, accounts, auto-start items and risky programs (read-only). "
                      "The Network Scan connects to ports on a target, reads service banners and matches versions against known CVE patterns. "
                      "Only scan systems you own or have permission to test.").pack(fill="x", padx=14, pady=(14, 0))

    def refresh_dashboard(self) -> None:
        a = {k: 0 for k in LEVELS}
        for f in self.audit_findings:
            if f.get("Level") in a:
                a[f["Level"]] += 1
        n = severity_summary(self.results)
        have_audit, have_scan = bool(self.audit_findings), bool(self.results) or self.ip != "-"
        for k in LEVELS:
            self.cards["a" + k].configure(text=str(a[k]) if have_audit else "-")
        for k in SEV_ORDER:
            self.cards["n" + k].configure(text=str(n[k]) if have_scan else "-")
        if not (have_audit or have_scan):
            text, col = "No scan yet - press Run Full Scan", MUT
        elif a["ALERT"] or n["CRITICAL"]:
            text, col = "ATTENTION NEEDED - serious problems found", COL["ALERT"]
        elif a["WARNING"] or n["HIGH"]:
            text, col = "MOSTLY OK - some things need a look", COL["WARNING"]
        else:
            text, col = "LOOKS GOOD - no problems found", COL["OK"]
        self.verdict.configure(text=text, fg=col)
        self.sub.configure(text=f"Scan target: {self.host} ({self.ip})   |   Open ports found: {len(self.results)}   |   Audit findings: {len(self.audit_findings)}")

    def run_full(self) -> None:
        self.chain = True
        self.nb.select(0)
        if IS_WIN:
            self.start_audit()
        else:
            self.log("Not Windows: skipping the system audit.")
            self.target_var.set("127.0.0.1")
            self.start_scan()

    def _payload(self) -> dict:
        return {"generated": datetime.now().isoformat(), "target": self.host, "resolved_ip": self.ip,
                "system_audit": self.audit_findings, "cve_summary": severity_summary(self.results),
                "open_ports": [asdict(r) for r in self.results], "shodan_cves": self.ext_cves}

    def export_html(self) -> None:
        if not (self.audit_findings or self.results):
            messagebox.showinfo("Nothing to export", "Run a scan first.")
            return
        p = filedialog.asksaveasfilename(defaultextension=".html", initialfile=f"ValkyrieGuard_Report_{datetime.now():%Y-%m-%d_%H-%M}.html")
        if p:
            with open(p, "w", encoding="utf-8") as f:
                f.write(build_html(self.host, self.ip, self.audit_findings, self.results, self.ext_cves))
            self.log(f"HTML report saved: {p}")
            if IS_WIN:
                os.startfile(p)  # type: ignore[attr-defined]

    def export_json(self) -> None:
        if not (self.audit_findings or self.results):
            messagebox.showinfo("Nothing to export", "Run a scan first.")
            return
        p = filedialog.asksaveasfilename(defaultextension=".json", initialfile=f"ValkyrieGuard_{datetime.now():%Y-%m-%d_%H-%M}.json")
        if p:
            with open(p, "w", encoding="utf-8") as f:
                json.dump(self._payload(), f, indent=2)
            self.log(f"JSON saved: {p}")
