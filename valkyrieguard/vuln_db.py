"""Version-signature database (regex -> CVE). An optional data/vulns.json overrides the defaults."""

import json
import os
import re
from typing import Dict, List, Optional, Tuple

from .config import DEFAULT_VULN_DB, VULN_FILE
from .models import Vulnerability


class VulnerabilityDatabase:
    """Compiled regex signatures. Optional 'vulns.json' next to the script overrides the defaults."""

    def __init__(self, filepath: Optional[str] = None):
        self.compiled: Dict[str, List[Tuple["re.Pattern", Vulnerability]]] = {}
        raw = DEFAULT_VULN_DB
        path = filepath or VULN_FILE
        if os.path.isfile(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    raw = json.load(f)
            except (OSError, json.JSONDecodeError):
                raw = DEFAULT_VULN_DB
        for service, items in raw.items():
            self.compiled[service.lower()] = []
            for it in items:
                try:
                    self.compiled[service.lower()].append((
                        re.compile(it["version_pattern"], re.IGNORECASE),
                        Vulnerability(it["cve"], it["severity"].upper(), it["description"])))
                except (re.error, KeyError):
                    continue

    def find(self, service: str, version: str) -> List[Vulnerability]:
        return [v for p, v in self.compiled.get(service.lower(), []) if p.search(version)]
