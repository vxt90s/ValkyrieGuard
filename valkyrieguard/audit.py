"""Runs the PowerShell system audit and reads back its structured results.

The audit script (resources/security_audit.ps1) prints "[n/7]" progress lines and, when
-JsonOut / -ReportOut are given, writes machine-readable findings plus a plain-English report.
"""

import json
import os
import re
import shutil
import subprocess
import tempfile
from typing import Callable, List, Optional

from .config import AUDIT_SCRIPT, IS_WIN

STEP_RE = re.compile(r"\s*\[(\d)/7\]\s*(.*)")
FIELDS = ("Level", "Area", "Title", "Detail", "Fix")


class AuditRunner:
    """Blocking runner; call run() from a worker thread. Every message goes through emit(tuple)."""

    def __init__(self, emit: Callable[[tuple], None], shell: Optional[str] = None, script: str = AUDIT_SCRIPT):
        self.emit = emit
        self.shell = shell or "powershell.exe"
        self.script = script
        self.proc: Optional[subprocess.Popen] = None
        self.cancelled = False

    def cancel(self) -> None:
        self.cancelled = True
        if self.proc:
            try:
                self.proc.terminate()
            except Exception:
                pass

    @staticmethod
    def _normalise(data) -> List[dict]:
        items = data if isinstance(data, list) else [data]
        return [{k: str(i.get(k, "") or "") for k in FIELDS} for i in items if isinstance(i, dict)]

    def run(self) -> None:
        findings: Optional[List[dict]] = None
        report, err = "", None
        tail: List[str] = []
        tmp = tempfile.mkdtemp(prefix="vg_")
        self.cancelled = False
        try:
            if not os.path.isfile(self.script):
                raise RuntimeError(f"Audit script not found: {self.script}")
            js, rp = os.path.join(tmp, "findings.json"), os.path.join(tmp, "report.txt")
            cmd = [self.shell, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", self.script,
                   "-JsonOut", js, "-ReportOut", rp, "-NoOpen"]
            no_window = 0x08000000 if IS_WIN else 0  # CREATE_NO_WINDOW: no black console flashes up
            self.proc = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                         stderr=subprocess.STDOUT, text=True, errors="replace",
                                         creationflags=no_window)
            assert self.proc.stdout is not None
            for line in self.proc.stdout:
                line = line.rstrip()
                if not line.strip():
                    continue
                tail.append(line.strip())
                m = STEP_RE.match(line)
                if m:
                    self.emit(("audit_step", int(m.group(1)), m.group(2)))
                self.emit(("log", "audit: " + line.strip()))
            rc = self.proc.wait()
            if os.path.isfile(js):
                with open(js, "r", encoding="utf-8-sig") as f:
                    findings = self._normalise(json.load(f))
                if os.path.isfile(rp):
                    with open(rp, "r", encoding="utf-8-sig") as f:
                        report = f.read()
            elif self.cancelled:
                err = "The audit was cancelled."
            else:
                err = (f"The audit script finished (exit code {rc}) but wrote no results.\n\n"
                       "Last output:\n" + "\n".join(tail[-8:]))
        except FileNotFoundError:
            err = f"PowerShell was not found ({self.shell}). The System Audit needs Windows PowerShell."
        except Exception as ex:
            err = f"Audit failed: {ex}"
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
            self.proc = None
        self.emit(("audit_done", findings, report, err))
