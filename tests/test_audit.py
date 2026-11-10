"""Runs the real PowerShell audit through AuditRunner (skipped when PowerShell is not installed)."""

import os
import shutil
import unittest

from valkyrieguard.audit import AuditRunner
from valkyrieguard.config import IS_WIN

SHELL = "powershell.exe" if IS_WIN else (shutil.which("pwsh") or shutil.which("powershell"))


@unittest.skipUnless(SHELL, "PowerShell not installed")
class AuditRunnerTests(unittest.TestCase):
    def test_produces_findings_report_and_progress(self):
        msgs: list = []
        AuditRunner(msgs.append, shell=SHELL).run()
        done = [m for m in msgs if m[0] == "audit_done"]
        self.assertEqual(len(done), 1)
        _, findings, report, err = done[0]
        self.assertIsNone(err, err)
        self.assertTrue(findings, "no findings were returned")
        for f in findings:
            self.assertIn(f["Level"], ("ALERT", "WARNING", "INFO", "OK"))
            self.assertTrue(f["Title"])
        self.assertIn("EASY SECURITY AUDIT REPORT", report)
        steps = sorted({m[1] for m in msgs if m[0] == "audit_step"})
        self.assertEqual(steps, [1, 2, 3, 4, 5, 6, 7])

    def test_missing_script_gives_clear_error(self):
        msgs: list = []
        AuditRunner(msgs.append, shell=SHELL, script=os.path.join("no", "such.ps1")).run()
        _, findings, _, err = [m for m in msgs if m[0] == "audit_done"][0]
        self.assertIsNone(findings)
        self.assertIn("not found", err)


if __name__ == "__main__":
    unittest.main()
