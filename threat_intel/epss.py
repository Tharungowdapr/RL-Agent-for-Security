import httpx
import json
import os
from typing import Dict, List

_CACHE_DIR = os.path.join(os.path.dirname(__file__), "cache")
EPSS_CACHE_PATH = os.path.join(_CACHE_DIR, "epss_scores.json")
EPSS_API_URL = "https://api.first.org/data/v1/epss"

def get_epss_scores(limit: int = 500) -> Dict[str, float]:
    """Fetch EPSS scores. Since the environment needs a batch easily, we'll try cache first,
    or we can fetch for known CVEs. For simplicity, we just return the cache if it exists,
    or we return an empty dict and fetch on demand if needed."""
    
    if os.path.exists(EPSS_CACHE_PATH):
        try:
            with open(EPSS_CACHE_PATH, "r") as f:
                return json.load(f)
        except Exception:
            pass
    return {}

def fetch_epss_batch(cve_ids: List[str], timeout: float = 30) -> Dict[str, float]:
    os.makedirs(_CACHE_DIR, exist_ok=True)
    scores: Dict[str, float] = {}
    try:
        cve_param = ",".join(cve_ids)
        resp = httpx.get(
            EPSS_API_URL,
            params={"cve": cve_param},
            timeout=timeout
        )
        resp.raise_for_status()
        data = resp.json()
        for entry in data.get("data", []):
            cid = entry.get("cve", "")
            epss = float(entry.get("epss", 0.0))
            scores[cid] = epss
    except Exception as e:
        print(f"❌ EPSS batch fetch failed: {e}")
    
    for cve_id in cve_ids:
        if cve_id not in scores:
            scores[cve_id] = 0.0

    try:
        existing = {}
        if os.path.exists(EPSS_CACHE_PATH):
            with open(EPSS_CACHE_PATH, "r") as f:
                existing = json.load(f)
        existing.update(scores)
        with open(EPSS_CACHE_PATH, "w") as f:
            json.dump(existing, f, indent=2)
    except Exception:
        pass

    return scores
