"""Unit tests for the non-GUI modules (no Tk needed)."""

import socket
import threading
import unittest
from typing import List

from valkyrieguard.config import AUDIT_SCRIPT, DEFAULT_PORTS
from valkyrieguard.models import ScanResult, severity_summary
from valkyrieguard.report import build_html
from valkyrieguard.scanner import PortScanner, is_local_ip, parse_ports, parse_service_details
from valkyrieguard.vuln_db import VulnerabilityDatabase


class VulnDbTests(unittest.TestCase):
    def setUp(self):
        self.db = VulnerabilityDatabase("__does_not_exist__.json")

    def test_openssh_regresshion(self):
        self.assertTrue(any(v.cve == "CVE-2024-6387" for v in self.db.find("ssh", "OpenSSH_9.2p1")))

    def test_apache_only_vulnerable_versions(self):
        self.assertFalse(self.db.find("http", "Apache/2.4.41 (Ubuntu)"))
        self.assertTrue(self.db.find("http", "Apache/2.4.49 (Unix)"))

    def test_vsftpd_backdoor_only_2_3_4(self):
        self.assertTrue(self.db.find("ftp", "vsFTPd 2.3.4"))
        self.assertFalse(self.db.find("ftp", "vsFTPd 3.0.5"))


class ParsingTests(unittest.TestCase):
    def test_ssh_banner(self):
        self.assertEqual(parse_service_details(22, "SSH-2.0-OpenSSH_8.2p1 Ubuntu"), ("ssh", "OpenSSH_8.2p1"))

    def test_http_server_header(self):
        self.assertEqual(parse_service_details(80, "HTTP/1.1 200 OK\r\nServer: nginx/1.14.0\r\n\r\n"), ("http", "nginx/1.14.0"))

    def test_smb_alias(self):
        self.assertEqual(parse_service_details(445, "")[0], "smb")

    def test_port_lists(self):
        self.assertEqual(parse_ports("22, 80,1-3"), [1, 2, 3, 22, 80])
        self.assertEqual(len(parse_ports(DEFAULT_PORTS)), 13)
        for bad in ("0", "70000", "abc", ""):
            with self.assertRaises(ValueError):
                parse_ports(bad)

    def test_local_addresses(self):
        self.assertTrue(is_local_ip("127.0.0.1") and is_local_ip("192.168.1.5"))
        self.assertFalse(is_local_ip("8.8.8.8"))


class LiveScanTests(unittest.TestCase):
    def test_finds_fake_ssh_server_and_matches_cve(self):
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
        found: List[ScanResult] = []
        PortScanner("127.0.0.1", "localhost", [port], 2, 2.0, VulnerabilityDatabase("__none__.json"),
                    threading.Event(), lambda d, t: None, found.append).run()
        srv.close()
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].detected_service, "ssh")
        self.assertEqual(severity_summary(found)["CRITICAL"], 1)

    def test_stop_event_prevents_scanning(self):
        stop = threading.Event()
        stop.set()
        found: List[ScanResult] = []
        PortScanner("127.0.0.1", "localhost", [1, 2, 3], 2, 0.5, VulnerabilityDatabase("__none__.json"),
                    stop, lambda d, t: None, found.append).run()
        self.assertEqual(found, [])


class ReportTests(unittest.TestCase):
    def test_html_is_escaped(self):
        r = ScanResult(80, "HTTP", "http", "<script>x</script>", "<b>", [])
        out = build_html("h", "1.1.1.1", [{"Level": "ALERT", "Area": "a", "Title": "<img>", "Detail": "", "Fix": ""}], [r], [])
        self.assertNotIn("<script>x", out)
        self.assertNotIn("<img>", out)


class ResourceTests(unittest.TestCase):
    def test_audit_script_contract(self):
        with open(AUDIT_SCRIPT, "r", encoding="utf-8-sig") as f:
            ps = f.read()
        for needle in ("param(", "$JsonOut", "$ReportOut", "$NoOpen", "ConvertTo-Json", "[7/7]"):
            self.assertIn(needle, ps)
        self.assertNotIn("@($Findings)", ps)  # the construct that broke JSON export
        self.assertTrue(all(ord(c) < 128 for c in ps), "script must stay ASCII for PowerShell 5.1")


if __name__ == "__main__":
    unittest.main()
