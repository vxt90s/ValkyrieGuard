"""Shared constants, paths and the built-in vulnerability signatures."""

import os
from typing import Dict, List

IS_WIN = os.name == "nt"
PACKAGE_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(PACKAGE_DIR)
DATA_DIR = os.path.join(ROOT_DIR, "data")
RESOURCE_DIR = os.path.join(PACKAGE_DIR, "resources")
AUDIT_SCRIPT = os.path.join(RESOURCE_DIR, "security_audit.ps1")
VULN_FILE = os.path.join(DATA_DIR, "vulns.json")  # optional override (see data/vulns.example.json)

COMMON_PORTS: Dict[int, str] = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
    110: "POP3", 139: "NetBIOS", 443: "HTTPS", 445: "SMB", 3306: "MySQL",
    3389: "RDP", 8080: "HTTP-Proxy",
}
DEFAULT_PORTS = "21,22,23,25,53,80,110,139,443,445,3306,3389,8080"

PORT_NOTES: Dict[int, str] = {
    21: "FTP sends passwords in plain text. Prefer SFTP.",
    23: "Telnet is old and unencrypted. Use SSH instead.",
    139: "NetBIOS file sharing. Block it from untrusted networks.",
    445: "Windows file sharing (SMB). A common ransomware target; keep it off the internet.",
    3306: "MySQL database. Should not be open to the whole network.",
    3389: "Remote Desktop. A very common attack target; use a VPN and strong passwords.",
}

DEFAULT_VULN_DB: Dict[str, List[Dict[str, str]]] = {
    "ssh": [
        {"version_pattern": r"OpenSSH_([0-7]\.[0-9]|8\.[0-4])", "cve": "CVE-2020-15778", "severity": "HIGH",
         "description": "Command injection in scp in OpenSSH allows remote attackers to run commands via crafted filenames."},
        {"version_pattern": r"OpenSSH_8\.5p1|OpenSSH_9\.[0-7]p1", "cve": "CVE-2024-6387", "severity": "CRITICAL",
         "description": "regreSSHion: remote code execution in sshd due to a signal handler race condition."},
    ],
    "ftp": [
        {"version_pattern": r"vsFTPd 2\.3\.4", "cve": "CVE-2011-2523", "severity": "CRITICAL",
         "description": "vsftpd 2.3.4 contains a backdoor triggered by a smiley face ':)' in the username."},
    ],
    "http": [
        {"version_pattern": r"Apache/2\.4\.(49|50)\b", "cve": "CVE-2021-41773", "severity": "HIGH",
         "description": "Path traversal and file disclosure in Apache HTTP Server 2.4.49 and 2.4.50."},
        {"version_pattern": r"nginx/1\.1[0-9]\.", "cve": "CVE-2017-7529", "severity": "MEDIUM",
         "description": "Integer overflow in the nginx range filter module allows information disclosure."},
    ],
    "smb": [
        {"version_pattern": r"Windows", "cve": "CVE-2017-0144", "severity": "CRITICAL",
         "description": "EternalBlue: remote code execution in Microsoft SMBv1."},
    ],
}

SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
LEVELS = ["ALERT", "WARNING", "INFO", "OK"]
