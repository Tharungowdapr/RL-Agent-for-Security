"""
Threat Intelligence Module
Fetches live data from:
  - EPSS API  (Exploit Prediction Scoring System)
  - CISA KEV  (Known Exploited Vulnerabilities catalog)
"""

import httpx
import json
import os
from typing import Dict, Set, List

# ───────────────────── Cache Paths ───────────────────── #
_CACHE_DIR = os.path.join(os.path.dirname(__file__), "cache")
EPSS_CACHE_PATH = os.path.join(_CACHE_DIR, "epss_scores.json")
KEV_CACHE_PATH = os.path.join(_CACHE_DIR, "kev_cves.json")

EPSS_API_URL = "https://api.first.org/data/v1/epss"
CISA_KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)


# ═══════════════════════════════════════════════════════ #
#                    EPSS  FETCHER                        #
# ═══════════════════════════════════════════════════════ #

def fetch_epss_score(cve_id: str, timeout: float = 10) -> float:
    """Fetch EPSS score for a single CVE from the FIRST API.
    Returns a float in [0.0, 1.0]. Falls back to 0.0 on failure."""
    try:
        resp = httpx.get(
            EPSS_API_URL,
            params={"cve": cve_id},
            timeout=timeout
        )
        resp.raise_for_status()
        data = resp.json()
        entries = data.get("data", [])
        if entries:
            return float(entries[0].get("epss", 0.0))
    except Exception as e:
        print(f"⚠️  EPSS fetch failed for {cve_id}: {e}")
    return 0.0


def fetch_epss_batch(cve_ids: List[str], timeout: float = 30) -> Dict[str, float]:
    """Fetch EPSS scores for a batch of CVEs in a single API call.
    Returns {cve_id: epss_score}."""
    os.makedirs(_CACHE_DIR, exist_ok=True)

    # Try cache first
    if os.path.exists(EPSS_CACHE_PATH):
        try:
            with open(EPSS_CACHE_PATH, "r") as f:
                cached = json.load(f)
            # Check if all requested CVEs are cached
            if all(cve_id in cached for cve_id in cve_ids):
                print(f"📂 EPSS: Loaded {len(cve_ids)} scores from cache")
                return {cid: cached[cid] for cid in cve_ids}
        except Exception:
            pass

    scores: Dict[str, float] = {}

    try:
        # EPSS API accepts comma-separated CVEs
        cve_param = ",".join(cve_ids)
        print(f"🌐 Fetching EPSS scores for {len(cve_ids)} CVEs...")
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

        print(f"✅ EPSS: Got scores for {len(scores)}/{len(cve_ids)} CVEs")

    except Exception as e:
        print(f"❌ EPSS batch fetch failed: {e}")

    # Fill missing with 0.0
    for cve_id in cve_ids:
        if cve_id not in scores:
            scores[cve_id] = 0.0

    # Save to cache (merge with existing)
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


# ═══════════════════════════════════════════════════════ #
#                  CISA  KEV  FETCHER                     #
# ═══════════════════════════════════════════════════════ #

def fetch_kev_set(timeout: float = 30) -> Set[str]:
    """Fetch CISA Known Exploited Vulnerabilities catalog.
    Returns a set of CVE IDs for O(1) membership lookups."""
    os.makedirs(_CACHE_DIR, exist_ok=True)

    # Try cache first
    if os.path.exists(KEV_CACHE_PATH):
        try:
            with open(KEV_CACHE_PATH, "r") as f:
                cached = json.load(f)
            kev_set = set(cached)
            print(f"📂 KEV: Loaded {len(kev_set)} known-exploited CVEs from cache")
            return kev_set
        except Exception:
            pass

    kev_set: Set[str] = set()

    try:
        print("🌐 Fetching CISA KEV catalog...")
        resp = httpx.get(CISA_KEV_URL, timeout=timeout)
        resp.raise_for_status()
        data = resp.json()

        vulnerabilities = data.get("vulnerabilities", [])
        for vuln in vulnerabilities:
            cve_id = vuln.get("cveID", "")
            if cve_id:
                kev_set.add(cve_id)

        print(f"✅ KEV: Loaded {len(kev_set)} known-exploited CVEs")

        # Cache it
        with open(KEV_CACHE_PATH, "w") as f:
            json.dump(list(kev_set), f)

    except Exception as e:
        print(f"❌ KEV fetch failed: {e}")

    return kev_set


# ═══════════════════════════════════════════════════════ #
#                COMBINED  ENRICHMENT                     #
# ═══════════════════════════════════════════════════════ #

def enrich_cves_with_threat_intel(cves) -> None:
    """Mutate CVERecord list in-place: add epss_score and in_kev."""
    cve_ids = [c.cve_id for c in cves]

    # Batch-fetch EPSS
    epss_scores = fetch_epss_batch(cve_ids)

    # Fetch KEV set
    kev_set = fetch_kev_set()

    for cve in cves:
        cve.epss_score = epss_scores.get(cve.cve_id, 0.0)
        cve.in_kev = cve.cve_id in kev_set

    kev_count = sum(1 for c in cves if c.in_kev)
    print(f"🔒 Enriched {len(cves)} CVEs — {kev_count} in KEV, "
          f"avg EPSS={sum(c.epss_score for c in cves)/max(len(cves),1):.4f}")
