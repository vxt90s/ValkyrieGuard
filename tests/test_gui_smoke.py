"""Starts the real window (needs a display; skipped otherwise) and drives scan + audit end to end."""

import shutil
import socket
import threading
import time
import unittest
from unittest import mock

SHELL = shutil.which("pwsh") or shutil.which("powershell")

try:
    import tkinter as tk
    _probe = tk.Tk()
    _probe.destroy()
    HAVE_DISPLAY = True
except Exception:  # no Tk, or no display
    HAVE_DISPLAY = False


def pump(app, until, timeout=30.0):
    end = time.time() + timeout
    while time.time() < end:
        app.update()
        if until():
            return True
        time.sleep(0.03)
    return False


@unittest.skipUnless(HAVE_DISPLAY, "no display available for Tk")
class GuiSmokeTests(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch.multiple("tkinter.messagebox", showwarning=mock.DEFAULT, showinfo=mock.DEFAULT, showerror=mock.DEFAULT)
        patcher.start()
        self.addCleanup(patcher.stop)
        from valkyrieguard.gui.main_window import App
        self.app = App()
        self.addCleanup(self.app._close)

    def test_scan_updates_table_and_dashboard(self):
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(5)
        port = srv.getsockname()[1]

        def serve():
            try:
                c, _ = srv.accept()
                c.sendall(b"SSH-2.0-OpenSSH_9.2p1 Debian\r\n")
                c.close()
            except OSError:
                pass

        threading.Thread(target=serve, daemon=True).start()
        self.app.ports_var.set(str(port))
        self.app.start_scan()
        self.assertTrue(pump(self.app, lambda: not self.app.scan_running and self.app.results))
        srv.close()
        self.assertEqual(self.app.cards["nCRITICAL"].cget("text"), "1")
        self.assertIn("ATTENTION", self.app.verdict.cget("text"))
        self.assertEqual(len(self.app.scan_tree.get_children()), 1)

    def test_bad_port_input_does_not_start_scan(self):
        self.app.ports_var.set("not-a-port")
        self.app.start_scan()
        self.assertFalse(self.app.scan_running)

    @unittest.skipUnless(SHELL, "PowerShell not installed")
    def test_audit_results_reach_the_ui(self):
        assert SHELL
        self.app.audit_runner.shell = SHELL
        self.app.audit_running = True
        threading.Thread(target=self.app.audit_runner.run, daemon=True).start()
        self.assertTrue(pump(self.app, lambda: not self.app.audit_running, 90))
        self.assertTrue(self.app.audit_findings)
        self.assertEqual(len(self.app.audit_tree.get_children()), len(self.app.audit_findings))
        self.assertIn("EASY SECURITY AUDIT REPORT", self.app.audit_report)


if __name__ == "__main__":
    unittest.main()
