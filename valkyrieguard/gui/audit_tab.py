"""System Audit tab: runs the PowerShell audit and shows findings with plain-English advice."""

import threading
from datetime import datetime
from tkinter import filedialog, messagebox, ttk
import tkinter as tk

from ..config import IS_WIN, LEVELS
from .base import AppBase
from .theme import BG, MUT, make_text, make_tree, set_text


class AuditTab(AppBase):
    def _tab_audit(self):
        t = ttk.Frame(self.nb)
        self.nb.add(t, text="  System Audit  ")
        bar = tk.Frame(t, bg=BG)
        bar.pack(fill="x", padx=12, pady=10)
        self.btn_audit = ttk.Button(bar, text="Run System Audit", style="Accent.TButton", command=self.start_audit)
        self.btn_audit.pack(side="left")
        self.btn_audit_stop = ttk.Button(bar, text="Cancel", command=self.cancel_audit, state="disabled")
        self.btn_audit_stop.pack(side="left", padx=8)
        ttk.Label(bar, text="Show:", style="Muted.TLabel").pack(side="left", padx=(18, 4))
        self.filter_var = tk.StringVar(value="All")
        cb = ttk.Combobox(bar, textvariable=self.filter_var, values=["All"] + LEVELS, width=10, state="readonly")
        cb.pack(side="left")
        cb.bind("<<ComboboxSelected>>", lambda e: self.refresh_audit_tree())
        ttk.Button(bar, text="Save full text report", command=self.save_audit_text).pack(side="right")
        self.audit_prog = ttk.Progressbar(t, mode="determinate", maximum=7)
        self.audit_prog.pack(fill="x", padx=12)
        self.audit_status = tk.Label(t, text="Not run yet", bg=BG, fg=MUT, anchor="w")
        self.audit_status.pack(fill="x", padx=12, pady=(2, 6))
        pw = ttk.PanedWindow(t, orient="vertical")
        pw.pack(fill="both", expand=True, padx=12, pady=(0, 10))
        fr, self.audit_tree = make_tree(t, [("lvl", "Level"), ("area", "Area"), ("title", "Finding")], [100, 130, 700])
        pw.add(fr, weight=3)
        fr2, self.audit_detail = make_text(t, 7)
        pw.add(fr2, weight=2)
        self.audit_tree.bind("<<TreeviewSelect>>", self._audit_select)
        if not IS_WIN:
            self.audit_status.configure(text="The System Audit needs Windows (it uses PowerShell). The Network Scan works everywhere.")

    def start_audit(self) -> None:
        if not IS_WIN:
            messagebox.showinfo("Windows only", "The System Audit uses PowerShell and only works on Windows.")
            return
        if self.audit_running:
            return
        self.audit_running = True
        self.audit_findings, self.audit_report = [], ""
        self.refresh_audit_tree()
        self.btn_audit.configure(state="disabled")
        self.btn_audit_stop.configure(state="normal")
        self.audit_prog["value"] = 0
        self.audit_status.configure(text="Starting audit...")
        self._busy()
        self.log("System audit started.")
        threading.Thread(target=self.audit_runner.run, daemon=True).start()

    def cancel_audit(self) -> None:
        self.chain = False
        self.audit_runner.cancel()

    def refresh_audit_tree(self) -> None:
        self.audit_tree.delete(*self.audit_tree.get_children())
        flt = self.filter_var.get()
        items = sorted(self.audit_findings, key=lambda f: LEVELS.index(f["Level"]) if f.get("Level") in LEVELS else 9)
        for i, f in enumerate(items):
            if flt == "All" or f.get("Level") == flt:
                self.audit_tree.insert("", "end", iid=str(i), values=(f.get("Level", ""), f.get("Area", ""), f.get("Title", "")), tags=(f.get("Level", ""),))
        self._sorted_findings = items
        set_text(self.audit_detail, "")

    def _audit_select(self, _e=None) -> None:
        sel = self.audit_tree.selection()
        if not sel:
            return
        f = self._sorted_findings[int(sel[0])]
        txt = f"[{f.get('Level')}] {f.get('Title')}\n\n"
        if f.get("Detail"):
            txt += f"What we saw:\n  {f['Detail']}\n\n"
        if f.get("Fix"):
            txt += f"What to do:\n  {f['Fix']}\n"
        set_text(self.audit_detail, txt)

    def save_audit_text(self) -> None:
        if not self.audit_report:
            messagebox.showinfo("No report", "Run the System Audit first.")
            return
        p = filedialog.asksaveasfilename(defaultextension=".txt", initialfile=f"Security_Audit_{datetime.now():%Y-%m-%d_%H-%M}.txt")
        if p:
            with open(p, "w", encoding="utf-8") as f:
                f.write(self.audit_report)
            self.log(f"Text report saved: {p}")
