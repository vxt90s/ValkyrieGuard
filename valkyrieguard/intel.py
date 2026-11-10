"""Optional threat-intel lookup (Shodan InternetDB). Only used when the user ticks the box."""

import json
import urllib.request
from typing import List


def query_shodan(ip: str) -> List[str]:
    try:
        req = urllib.request.Request(f"https://internetdb.shodan.io/{ip}", headers={"User-Agent": "ValkyrieGuard/1.0"})
        with urllib.request.urlopen(req, timeout=4) as r:
            return json.loads(r.read().decode()).get("vulns", [])
    except Exception:
        return []
