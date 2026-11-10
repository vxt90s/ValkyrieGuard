"""Main window: wires the tabs together and pumps worker-thread messages into the UI."""

import queue
import threading
import tkinter as tk
from tkinter import messagebox, ttk
from typing import List

from ..audit import AuditRunner
from ..config import IS_WIN
from ..models import ScanResult
from ..system import is_admin, relaunch_as_admin
from ..vuln_db import VulnerabilityDatabase
from .audit_tab import AuditTab
from .dashboard_tab import DashboardTab
from .log_tab import LogTab
from .scan_tab import ScanTab
from .theme import ACC, BG, COL, MUT, apply_style


class App(DashboardTab, AuditTab, ScanTab, LogTab):
    def __init__(self):
        super().__init__()
        self.title("ValkyrieGuard - System Audit + Network Scanner")
        self.geometry("1180x780")
        self.minsize(980, 660)
        self.configure(bg=BG)

        self.q: "queue.Queue" = queue.Queue()
        self.stop_event = threading.Event()
        self.db = VulnerabilityDatabase()
        self.audit_runner = AuditRunner(self.q.put)
        self.audit_findings: List[dict] = []
        self.audit_report = ""
        self.results: List[ScanResult] = []
        self.ext_cves: List[str] = []
        self.host, self.ip = "-", "-"
        self.chain = False
        self.audit_running = False
        self.scan_running = False
        self._sorted_findings: List[dict] = []

        apply_style(self)
        self._header()
        self.nb = ttk.Notebook(self)
        self.nb.pack(fill="both", expand=True, padx=14, pady=(4, 12))
        self._tab_dashboard()
        self._tab_audit()
        self._tab_scan()
        self._tab_log()
        self.refresh_dashboard()
        self.log("Ready. " + ("Running as Administrator." if is_admin() else "Not running as Administrator - some audit checks will be limited."))
        self.protocol("WM_DELETE_WINDOW", self._close)
        self._poll_job = self.after(100, self._poll)

    def _header(self):
        h = tk.Frame(self, bg=BG)
        h.pack(fill="x", padx=18, pady=(14, 6))
        tk.Label(h, text="ValkyrieGuard", bg=BG, fg=ACC, font=("Segoe UI", 20, "bold")).pack(side="left")
        tk.Label(h, text="  System Audit + Network Scanner", bg=BG, fg=MUT, font=("Segoe UI", 11)).pack(side="left", pady=(8, 0))
        admin = is_admin()
        right = tk.Frame(h, bg=BG)
        right.pack(side="right")
        tk.Label(right, text="Administrator: YES" if admin else "Administrator: NO", bg=BG,
                 fg=COL["OK"] if admin else COL["WARNING"], font=("Segoe UI", 10, "bold")).pack(side="left", padx=10)
        if not admin and IS_WIN:
            ttk.Button(right, text="Restart as Administrator", command=self._elevate).pack(side="left")

    def _elevate(self):
        if messagebox.askyesno("Administrator", "Windows will show a permission (UAC) pop-up.\nRestart this program as Administrator?"):
            if relaunch_as_admin():
                self.destroy()
            else:
                messagebox.showinfo("Cancelled", "Administrator permission was not granted.")

    def _busy(self) -> None:
        self.btn_full.configure(state="disabled" if (self.audit_running or self.scan_running) else "normal")

    def _poll(self) -> None:
        try:
            while True:
                self._handle(self.q.get_nowait())
        except queue.Empty:
            pass
        self._poll_job = self.after(100, self._poll)

    def _handle(self, m: tuple) -> None:
        k = m[0]
        if k == "log":
            self.log(m[1])
        elif k == "audit_step":
            self.audit_prog["value"] = m[1]
            self.audit_status.configure(text=f"Step {m[1]} of 7: {m[2]}")
            self.status.configure(text=f"System audit - step {m[1]} of 7")
            self.prog["value"] = m[1] / 7 * 50
        elif k == "audit_done":
            _, findings, report, err = m
            self.audit_running = False
            self.btn_audit.configure(state="normal")
            self.btn_audit_stop.configure(state="disabled")
            if findings is not None:
                self.audit_findings, self.audit_report = findings, report
                self.audit_prog["value"] = 7
                self.audit_status.configure(text=f"Done - {len(findings)} findings")
                self.log(f"System audit finished: {len(findings)} findings.")
            else:
                self.audit_status.configure(text=err or "Audit failed")
                self.log(err or "Audit failed")
                if err:
                    messagebox.showwarning("System audit", err)
            self.refresh_audit_tree()
            self.refresh_dashboard()
            self._busy()
            if self.chain and findings is not None:
                self.target_var.set("127.0.0.1")
                self.start_scan()
            else:
                self.chain = False
        elif k == "scan_start":
            self.host, self.ip = m[1], m[2]
            self.scan_status.configure(text=f"Scanning {m[1]} ({m[2]})...")
            self.refresh_dashboard()
        elif k == "scan_progress":
            pct = m[1] / max(1, m[2]) * 100
            self.scan_prog["value"] = pct
            self.scan_status.configure(text=f"Scanned {m[1]} of {m[2]} ports")
            self.status.configure(text=f"Network scan - {m[1]} of {m[2]} ports")
            self.prog["value"] = (50 if IS_WIN else 0) + pct * (0.5 if IS_WIN else 1)
        elif k == "scan_result":
            self.results.append(m[1])
            self._add_scan_row(m[1])
        elif k == "scan_done":
            _, host, ip, ext, err = m
            self.scan_running = False
            self.btn_scan.configure(state="normal")
            self.btn_scan_stop.configure(state="disabled")
            if err:
                self.scan_status.configure(text=err)
                self.log(err)
                messagebox.showwarning("Network scan", err)
            else:
                self.host, self.ip, self.ext_cves = host, ip, ext
                stopped = self.stop_event.is_set()
                self.results.sort(key=lambda r: r.port)
                self.scan_tree.delete(*self.scan_tree.get_children())
                for r in self.results:
                    self._add_scan_row(r)
                self.scan_status.configure(text=("Stopped - " if stopped else "Done - ") + f"{len(self.results)} open port(s)")
                self.log(f"Network scan {'stopped' if stopped else 'finished'}: {len(self.results)} open port(s).")
                if not stopped:
                    self.scan_prog["value"] = 100
                    self.prog["value"] = 100
                    self.status.configure(text="Finished")
            self.chain = False
            self.refresh_dashboard()
            self._busy()

    def _close(self) -> None:
        try:
            self.after_cancel(self._poll_job)
        except Exception:
            pass
        self.stop_event.set()
        self.cancel_audit()
        self.destroy()
