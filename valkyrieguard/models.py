"""Data classes shared by the scanner, the report builder and the GUI."""

from dataclasses import dataclass, field
from typing import Dict, List

from .config import SEV_ORDER


@dataclass
class Vulnerability:
    cve: str
    severity: str
    description: str


@dataclass
class ScanResult:
    port: int
    default_service: str
    detected_service: str
    version: str
    banner: str
    vulnerabilities: List[Vulnerability] = field(default_factory=list)


def severity_summary(results: List[ScanResult]) -> Dict[str, int]:
    s = {k: 0 for k in SEV_ORDER}
    for r in results:
        for v in r.vulnerabilities:
            s[v.severity if v.severity in s else "MEDIUM"] += 1
    return s


def top_severity(r: ScanResult) -> str:
    for sev in SEV_ORDER:
        if any(v.severity == sev for v in r.vulnerabilities):
            return sev
    return "-"
