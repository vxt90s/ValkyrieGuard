"""Network Scan tab: target form, live results table and per-port details."""

import socket
import threading
import tkinter as tk
from tkinter import messagebox, ttk

from ..config import DEFAULT_PORTS, PORT_NOTES
from ..intel import query_shodan
from ..models import ScanResult, top_severity
from ..scanner import PortScanner, is_local_ip, parse_ports
from .base import AppBase
from .theme import BG, MUT, make_text, make_tree, set_text


class ScanTab(AppBase):
    def _tab_scan(self):
        t = ttk.Frame(self.nb)
        self.nb.add(t, text="  Network Scan  ")
        form = tk.Frame(t, bg=BG)
        form.pack(fill="x", padx=12, pady=(12, 4))
        self.target_var = tk.StringVar(value="127.0.0.1")
        self.ports_var = tk.StringVar(value=DEFAULT_PORTS)
        self.threads_var = tk.IntVar(value=40)
        self.timeout_var = tk.DoubleVar(value=1.8)
        self.auth_var = tk.BooleanVar(value=False)
        self.shodan_var = tk.BooleanVar(value=False)
        for c, (lbl, w) in enumerate([("Target (IP or name)", 26), ("Ports (e.g. 22,80,1-1024)", 50)]):
            tk.Label(form, text=lbl, bg=BG, fg=MUT, font=("Segoe UI", 9)).grid(row=0, column=c * 2, sticky="w", padx=(0 if c == 0 else 14, 4))
        ttk.Entry(form, textvariable=self.target_var, width=26).grid(row=1, column=0, columnspan=2, sticky="w")
        ttk.Entry(form, textvariable=self.ports_var, width=52).grid(row=1, column=2, columnspan=2, sticky="w", padx=(14, 0))
        tk.Label(form, text="Threads", bg=BG, fg=MUT, font=("Segoe UI", 9)).grid(row=0, column=4, sticky="w", padx=(14, 4))
        tk.Label(form, text="Timeout (s)", bg=BG, fg=MUT, font=("Segoe UI", 9)).grid(row=0, column=5, sticky="w", padx=(8, 4))
        ttk.Spinbox(form, from_=1, to=200, textvariable=self.threads_var, width=6).grid(row=1, column=4, padx=(14, 4))
        ttk.Spinbox(form, from_=0.3, to=10, increment=0.3, textvariable=self.timeout_var, width=6).grid(row=1, column=5, padx=(8, 4))

        opts = tk.Frame(t, bg=BG)
        opts.pack(fill="x", padx=12, pady=6)
        ttk.Checkbutton(opts, text="I own this system or have written permission to scan it (required for non-local targets)", variable=self.auth_var).pack(anchor="w")
        ttk.Checkbutton(opts, text="Also ask Shodan InternetDB about this public IP (sends the IP to shodan.io)", variable=self.shodan_var).pack(anchor="w")

        bar = tk.Frame(t, bg=BG)
        bar.pack(fill="x", padx=12, pady=6)
        self.btn_scan = ttk.Button(bar, text="Start Scan", style="Accent.TButton", command=self.start_scan)
        self.btn_scan.pack(side="left")
        self.btn_scan_stop = ttk.Button(bar, text="Stop", command=self.stop_scan, state="disabled")
        self.btn_scan_stop.pack(side="left", padx=8)
        ttk.Button(bar, text="Scan this PC", command=self.scan_this_pc).pack(side="left")
        self.scan_prog = ttk.Progressbar(t, mode="determinate", maximum=100)
        self.scan_prog.pack(fill="x", padx=12)
        self.scan_status = tk.Label(t, text="Not run yet", bg=BG, fg=MUT, anchor="w")
        self.scan_status.pack(fill="x", padx=12, pady=(2, 6))
        pw = ttk.PanedWindow(t, orient="vertical")
        pw.pack(fill="both", expand=True, padx=12, pady=(0, 10))
        fr, self.scan_tree = make_tree(t, [("port", "Port"), ("svc", "Service"), ("ver", "Version / banner"), ("risk", "Top risk"), ("cves", "CVE matches")], [80, 110, 420, 100, 260])
        pw.add(fr, weight=3)
        fr2, self.scan_detail = make_text(t, 7)
        pw.add(fr2, weight=2)
        self.scan_tree.bind("<<TreeviewSelect>>", self._scan_select)

    def scan_this_pc(self) -> None:
        self.target_var.set("127.0.0.1")
        self.start_scan()

    def start_scan(self) -> None:
        if self.scan_running:
            return
        try:
            ports = parse_ports(self.ports_var.get())
            threads = max(1, min(200, int(self.threads_var.get())))
            timeout = max(0.2, float(self.timeout_var.get()))
        except (ValueError, tk.TclError) as e:
            messagebox.showerror("Invalid input", f"Please check the ports, threads and timeout.\n\n{e}")
            self.chain = False
            return
        target = self.target_var.get().strip()
        if not target:
            messagebox.showerror("Missing target", "Enter an IP address or host name.")
            return
        self.scan_running = True
        self.stop_event.clear()
        self.results, self.ext_cves = [], []
        self.scan_tree.delete(*self.scan_tree.get_children())
        set_text(self.scan_detail, "")
        self.btn_scan.configure(state="disabled")
        self.btn_scan_stop.configure(state="normal")
        self.scan_prog["value"] = 0
        self.scan_status.configure(text=f"Resolving {target}...")
        self._busy()
        self.log(f"Network scan started: {target} ({len(ports)} ports, {threads} threads)")
        threading.Thread(target=self._scan_worker, args=(target, ports, threads, timeout, self.auth_var.get(), self.shodan_var.get()), daemon=True).start()

    def _scan_worker(self, target, ports, threads, timeout, authorized, use_shodan) -> None:
        try:
            ip = socket.gethostbyname(target)
        except socket.gaierror as e:
            self.q.put(("scan_done", target, "-", [], f"Cannot resolve '{target}': {e}"))
            return
        if not is_local_ip(ip) and not authorized:
            self.q.put(("scan_done", target, ip, [], "This target is not a local/private address. Tick the permission box to confirm you are allowed to scan it."))
            return
        self.q.put(("scan_start", target, ip))
        sc = PortScanner(ip, target, ports, threads, timeout, self.db, self.stop_event,
                         lambda d, t: self.q.put(("scan_progress", d, t)), lambda r: self.q.put(("scan_result", r)))
        sc.run()
        ext = query_shodan(ip) if (use_shodan and not self.stop_event.is_set() and not is_local_ip(ip)) else []
        self.q.put(("scan_done", target, ip, ext, None))

    def stop_scan(self) -> None:
        self.chain = False
        self.stop_event.set()
        self.scan_status.configure(text="Stopping...")

    def _add_scan_row(self, r: ScanResult) -> None:
        top = top_severity(r)
        self.scan_tree.insert("", "end", iid=str(r.port), tags=(top,),
                              values=(r.port, r.detected_service.upper(), r.version if r.version != "Unknown" else (r.banner[:60] if r.banner != "N/A" else "Unknown"),
                                      top if top != "-" else "none", ", ".join(v.cve for v in r.vulnerabilities) or "-"))

    def _scan_select(self, _e=None) -> None:
        sel = self.scan_tree.selection()
        if not sel:
            return
        r = next((x for x in self.results if str(x.port) == sel[0]), None)
        if not r:
            return
        txt = f"Port {r.port}  ({r.default_service})\nDetected service: {r.detected_service.upper()}\nVersion: {r.version}\nRaw banner: {r.banner}\n"
        if r.port in PORT_NOTES:
            txt += f"\nNote: {PORT_NOTES[r.port]}\n"
        if r.vulnerabilities:
            txt += "\nPossible vulnerabilities (matched from the version text, so confirm before acting):\n"
            for v in r.vulnerabilities:
                txt += f"\n  [{v.severity}] {v.cve}\n  {v.description}\n"
        else:
            txt += "\nNo known pattern matched this version."
        set_text(self.scan_detail, txt)
