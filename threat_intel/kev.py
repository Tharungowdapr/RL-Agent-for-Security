import httpx
import json
import os
from typing import Set

_CACHE_DIR = os.path.join(os.path.dirname(__file__), "cache")
KEV_CACHE_PATH = os.path.join(_CACHE_DIR, "kev_cves.json")
CISA_KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)

def get_kev_list(timeout: float = 30) -> Set[str]:
    os.makedirs(_CACHE_DIR, exist_ok=True)
    if os.path.exists(KEV_CACHE_PATH):
        try:
            with open(KEV_CACHE_PATH, "r") as f:
                cached = json.load(f)
            return set(cached)
        except Exception:
            pass

    kev_set: Set[str] = set()
    try:
        resp = httpx.get(CISA_KEV_URL, timeout=timeout)
        resp.raise_for_status()
        data = resp.json()
        for vuln in data.get("vulnerabilities", []):
            cve_id = vuln.get("cveID", "")
            if cve_id:
                kev_set.add(cve_id)
        
        with open(KEV_CACHE_PATH, "w") as f:
            json.dump(list(kev_set), f)
    except Exception as e:
        print(f"❌ KEV fetch failed: {e}")

    return kev_set
