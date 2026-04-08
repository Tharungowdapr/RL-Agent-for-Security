import httpx
import json
import os
from typing import List, Dict, Any
from threat_intel.epss import fetch_epss_batch

CACHE_PATH = os.path.join(os.path.dirname(__file__), "cache", "cves_dict.json")
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def _get_fallback_cves() -> List[Dict[str, Any]]:
    return [
        {
            "id": "CVE-2024-0001",
            "description": "Remote code execution in Apache HTTP Server",
            "cvss": 9.8, "severity_label": "CRITICAL",
            "affected_software": ["apache httpd"], "published_date": "2024-01-15"
        },
        {
            "id": "CVE-2024-0002",
            "description": "SQL injection vulnerability in MySQL",
            "cvss": 8.5, "severity_label": "HIGH",
            "affected_software": ["mysql"], "published_date": "2024-01-20"
        },
        {
            "id": "CVE-2024-0003",
            "description": "Privilege escalation in Linux kernel",
            "cvss": 7.8, "severity_label": "HIGH",
            "affected_software": ["linux kernel"], "published_date": "2024-02-01"
        },
        {
            "id": "CVE-2024-0004",
            "description": "XSS vulnerability in nginx",
            "cvss": 6.1, "severity_label": "MEDIUM",
            "affected_software": ["nginx"], "published_date": "2024-02-10"
        },
        {
            "id": "CVE-2024-0005",
            "description": "Information disclosure in OpenSSL",
            "cvss": 9.1, "severity_label": "CRITICAL",
            "affected_software": ["openssl"], "published_date": "2024-02-15"
        },
    ]

def parse_nvd_record(item: dict):
    try:
        cve = item.get("cve", {})
        cve_id = cve.get("id", "CVE-UNKNOWN")
        descriptions = cve.get("descriptions", [])
        description = next(
            (d.get("value", "") for d in descriptions if d.get("lang") == "en"),
            "No description available"
        )[:300]

        metrics = cve.get("metrics", {})
        cvss_data = {}
        for m_key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            if m_key in metrics:
                cvss_data = metrics[m_key][0].get("cvssData", {})
                break

        cvss_score = float(cvss_data.get("baseScore", 5.0))
        severity = cvss_data.get("baseSeverity", "MEDIUM").upper()

        affected = ["unknown software"]
        configs = cve.get("configurations", [])
        for config in configs[:2]:
            for node in config.get("nodes", [])[:2]:
                for match in node.get("cpeMatch", [])[:1]:
                    criteria = match.get("criteria", "")
                    parts = criteria.split(":")
                    if len(parts) > 4:
                        affected = [f"{parts[3]} {parts[4]}"]
                        break
        
        return {
            "id": cve_id,
            "cvss": cvss_score,
            "description": description,
            "severity_label": severity,
            "published_date": cve.get("published", "2024-01-01")[:10],
            "affected_software": affected
        }
    except Exception:
        return None

def fetch_cves_from_api(limit: int = 50) -> List[Dict[str, Any]]:
    # 1. Check cache
    os.makedirs(os.path.dirname(CACHE_PATH), exist_ok=True)
    if os.path.exists(CACHE_PATH):
        try:
            with open(CACHE_PATH, "r") as f:
                cves = json.load(f)
            if cves: return cves
        except Exception:
            pass

    # 2. Fetch API
    try:
        resp = httpx.get(NVD_API_URL, params={"resultsPerPage": limit, "startIndex": 0, "cvssV3Severity": "HIGH"}, timeout=15)
        resp.raise_for_status()
        vulns = resp.json().get("vulnerabilities", [])
        cves = []
        for item in vulns:
            parsed = parse_nvd_record(item)
            if parsed: cves.append(parsed)
        
        if cves:
            with open(CACHE_PATH, "w") as f:
                json.dump(cves, f, indent=2)
            return cves
    except Exception:
        pass

    return _get_fallback_cves()

def load_cves():
    """Load CVEs and return as a list of dicts for the new security_env."""
    cves = None
    if os.path.exists(CACHE_PATH):
        try:
            with open(CACHE_PATH, "r") as f:
                cves = json.load(f)
        except Exception:
            pass

    if not cves:
        cves = fetch_cves_from_api()

    # Pre-fetch EPSS for the loaded CVEs
    if cves:
        cve_ids = [c["id"] for c in cves]
        fetch_epss_batch(cve_ids)
        
    return cves
