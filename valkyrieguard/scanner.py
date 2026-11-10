"""Multi-threaded TCP port scanner with banner grabbing and service parsing."""

import ipaddress
import re
import socket
import ssl
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Callable, List, Tuple

from .config import COMMON_PORTS
from .models import ScanResult
from .vuln_db import VulnerabilityDatabase


def parse_ports(text: str) -> List[int]:
    """'22,80,1000-1010' -> sorted unique list. Raises ValueError on bad input."""
    ports = set()
    for part in text.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, b = (int(x) for x in part.split("-", 1))
            if a > b:
                a, b = b, a
            ports.update(range(a, b + 1))
        else:
            ports.add(int(part))
    if not ports or min(ports) < 1 or max(ports) > 65535:
        raise ValueError("Ports must be numbers from 1 to 65535.")
    return sorted(ports)


def is_local_ip(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
        return a.is_loopback or a.is_private or a.is_link_local
    except ValueError:
        return False


def parse_service_details(port: int, banner: str) -> Tuple[str, str]:
    service = "smb" if port in (139, 445) else COMMON_PORTS.get(port, "unknown").lower()
    version = "Unknown"
    if not banner:
        return service, version
    if "HTTP/" in banner or "Server:" in banner:
        service = "http"
        m = re.search(r"Server:\s*([^\r\n]+)", banner, re.IGNORECASE)
        if m:
            version = m.group(1)
        else:
            t = re.search(r"<title>(.*?)</title>", banner, re.IGNORECASE)
            version = f"Web Service (Title: {t.group(1).strip()})" if t else "Generic HTTP Daemon"
    elif "SSH-" in banner:
        service = "ssh"
        m = re.search(r"OpenSSH_[^\s]+", banner)
        version = m.group(0) if m else banner.split("\n")[0].strip()
    elif "220" in banner and "ftp" in banner.lower():
        service = "ftp"
        m = re.search(r"vsFTPd\s*[0-9.]+", banner, re.IGNORECASE)
        version = m.group(0) if m else "Active FTP Server"
    return service, version


class PortScanner:
    def __init__(self, ip: str, host: str, ports: List[int], threads: int, timeout: float,
                 db: VulnerabilityDatabase, stop: threading.Event,
                 on_progress: Callable[[int, int], None], on_result: Callable[[ScanResult], None]):
        self.ip, self.host, self.ports = ip, host, ports
        self.threads, self.timeout, self.db, self.stop = threads, timeout, db, stop
        self.on_progress, self.on_result = on_progress, on_result
        self.done = 0
        self.lock = threading.Lock()

    def grab_banner(self, s: socket.socket, port: int) -> str:
        buf: List[str] = []
        try:
            host_b = self.host.encode("idna")
        except UnicodeError:
            host_b = b"localhost"
        head = b"HEAD / HTTP/1.1\r\nHost: " + host_b + b"\r\nConnection: close\r\n\r\n"
        try:
            if port == 443:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                with ctx.wrap_socket(s, server_hostname=self.host) as sec:
                    sec.sendall(head)
                    while True:
                        chunk = sec.recv(2048)
                        if not chunk:
                            break
                        buf.append(chunk.decode("utf-8", errors="ignore"))
            else:
                s.sendall(head if port in (80, 8080) else b"\r\n")
                while True:
                    chunk = s.recv(2048)
                    if not chunk:
                        break
                    buf.append(chunk.decode("utf-8", errors="ignore"))
                    if len(buf) >= 4 or "\r\n\r\n" in "".join(buf):
                        break
        except Exception:
            pass  # keep whatever was already received (many daemons send a banner, then reset)
        return "".join(buf).strip()

    def scan_port(self, port: int) -> None:
        try:
            if self.stop.is_set():
                return
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                if s.connect_ex((self.ip, port)) == 0:
                    banner = self.grab_banner(s, port)
                    service, version = parse_service_details(port, banner)
                    self.on_result(ScanResult(
                        port=port, default_service=COMMON_PORTS.get(port, "Unknown"),
                        detected_service=service, version=version,
                        banner=banner[:300].replace("\r", " ").replace("\n", " ") if banner else "N/A",
                        vulnerabilities=self.db.find(service, version)))
        except Exception:
            pass
        finally:
            with self.lock:
                self.done += 1
                total = len(self.ports)
                if self.done == total or self.done % max(1, total // 200) == 0:
                    self.on_progress(self.done, total)

    def run(self) -> None:
        with ThreadPoolExecutor(max_workers=self.threads) as ex:
            list(ex.map(self.scan_port, self.ports))
