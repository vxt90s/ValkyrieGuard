"""Shared declarations so type checkers (Pylance/Pyright) understand the tab mixins.

Every tab class derives from AppBase. The attributes below are created in App.__init__ or in a
tab's _tab_* builder; the methods are placeholders that the real implementations (in the tab
mixins or in App) override, because those classes come earlier in the method-resolution order.
"""

import queue
import threading
import tkinter as tk
from tkinter import ttk
from typing import Dict, List

from ..audit import AuditRunner
from ..models import ScanResult
from ..vuln_db import VulnerabilityDatabase


class AppBase(tk.Tk):
    # ---- shared state (set in App.__init__)
    q: "queue.Queue[tuple]"
    stop_event: threading.Event
    db: VulnerabilityDatabase
    audit_runner: AuditRunner
    audit_findings: List[dict]
    audit_report: str
    results: List[ScanResult]
    ext_cves: List[str]
    host: str
    ip: str
    chain: bool
    audit_running: bool
    scan_running: bool
    _sorted_findings: List[dict]
    _poll_job: str

    # ---- widgets (created by the _tab_* builders)
    nb: ttk.Notebook
    verdict: tk.Label
    sub: tk.Label
    cards: Dict[str, tk.Label]
    btn_full: ttk.Button
    prog: ttk.Progressbar
    status: tk.Label
    btn_audit: ttk.Button
    btn_audit_stop: ttk.Button
    filter_var: tk.StringVar
    audit_prog: ttk.Progressbar
    audit_status: tk.Label
    audit_tree: ttk.Treeview
    audit_detail: tk.Text
    target_var: tk.StringVar
    ports_var: tk.StringVar
    threads_var: tk.IntVar
    timeout_var: tk.DoubleVar
    auth_var: tk.BooleanVar
    shodan_var: tk.BooleanVar
    btn_scan: ttk.Button
    btn_scan_stop: ttk.Button
    scan_prog: ttk.Progressbar
    scan_status: tk.Label
    scan_tree: ttk.Treeview
    scan_detail: tk.Text
    log_text: tk.Text

    # ---- cross-tab methods (overridden by the real implementations)
    def log(self, msg: str) -> None:
        raise NotImplementedError

    def refresh_dashboard(self) -> None:
        raise NotImplementedError

    def refresh_audit_tree(self) -> None:
        raise NotImplementedError

    def start_audit(self) -> None:
        raise NotImplementedError

    def start_scan(self) -> None:
        raise NotImplementedError

    def _busy(self) -> None:
        raise NotImplementedError
