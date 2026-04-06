import httpx
import json
import os
import time
from typing import List
from env.models import CVERecord

CACHE_PATH = os.path.join(os.path.dirname(__file__), "cache", "cves.json")
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def fetch_cves_from_api(limit: int = 50) -> List[dict]:
    params = {
        "resultsPerPage": limit,
        "startIndex": 0,
        "cvssV3Severity": "HIGH"
    }
    try:
        response = httpx.get(NVD_API_URL, params=params, timeout=30)
        response.raise_for_status()
        data = response.json()
        return data.get("vulnerabilities", [])
    except Exception as e:
        print(f"[WARN] NVD API fetch failed: {e}. Using cache.")
        return []


def parse_nvd_record(item: dict) -> CVERecord:
    cve = item.get("cve", {})
    cve_id = cve.get("id", "CVE-UNKNOWN")
    
    descriptions = cve.get("descriptions", [])
    description = next(
        (d["value"] for d in descriptions if d["lang"] == "en"),
        "No description available"
    )[:300]

    metrics = cve.get("metrics", {})
    cvss_data = {}
    
    if "cvssMetricV31" in metrics:
        cvss_data = metrics["cvssMetricV31"][0].get("cvssData", {})
    elif "cvssMetricV30" in metrics:
        cvss_data = metrics["cvssMetricV30"][0].get("cvssData", {})
    elif "cvssMetricV2" in metrics:
        cvss_data = metrics["cvssMetricV2"][0].get("cvssData", {})

    cvss_score = float(cvss_data.get("baseScore", 5.0))
    severity = cvss_data.get("baseSeverity", "MEDIUM").upper()
    
    exploit_score = 0.0
    if "cvssMetricV31" in metrics:
        exploit_score = float(
            metrics["cvssMetricV31"][0].get("exploitabilityScore", 0.0)
        )

    configs = cve.get("configurations", [])
    affected = []
    for config in configs[:2]:
        for node in config.get("nodes", [])[:2]:
            for match in node.get("cpeMatch", [])[:1]:
                criteria = match.get("criteria", "")
                parts = criteria.split(":")
                if len(parts) > 4:
                    affected.append(f"{parts[3]} {parts[4]}")

    if not affected:
        affected = ["unknown software"]

    patch_available = bool(cve.get("references", []))
    published = cve.get("published", "2024-01-01")[:10]

    return CVERecord(
        cve_id=cve_id,
        description=description,
        cvss_score=cvss_score,
        severity=severity,
        exploitability_score=exploit_score,
        patch_available=patch_available,
        affected_software=affected,
        published_date=published
    )


def load_or_fetch_cves(limit: int = 50) -> List[CVERecord]:
    os.makedirs(os.path.dirname(CACHE_PATH), exist_ok=True)
    
    if os.path.exists(CACHE_PATH):
        with open(CACHE_PATH, "r") as f:
            raw = json.load(f)
        return [CVERecord(**item) for item in raw]

    raw_items = fetch_cves_from_api(limit)
    
    if not raw_items:
        return _get_fallback_cves()

    cves = []
    for item in raw_items:
        try:
            cves.append(parse_nvd_record(item))
        except Exception:
            continue

    if cves:
        with open(CACHE_PATH, "w") as f:
            json.dump([c.model_dump() for c in cves], f, indent=2)

    return cves if cves else _get_fallback_cves()


def _get_fallback_cves() -> List[CVERecord]:
    \"\"\"Hardcoded fallback CVEs so environment always works offline.\"\"\"
    return [
        CVERecord(
            cve_id="CVE-2024-0001",
            description="Remote code execution in Apache HTTP Server via crafted request headers",
            cvss_score=9.8, severity="CRITICAL",
            exploitability_score=9.5, patch_available=True,
            affected_software=["apache httpd"], published_date="2024-01-15"
        ),
        CVERecord(
            cve_id="CVE-2024-0002",
            description="SQL injection vulnerability in MySQL allowing data exfiltration",
            cvss_score=8.5, severity="HIGH",
            exploitability_score=7.8, patch_available=True,
            affected_software=["mysql"], published_date="2024-01-20"
        ),
        CVERecord(
            cve_id="CVE-2024-0003",
            description="Privilege escalation in Linux kernel via use-after-free bug",
            cvss_score=7.8, severity="HIGH",
            exploitability_score=6.5, patch_available=False,
            affected_software=["linux kernel"], published_date="2024-02-01"
        ),
        CVERecord(
            cve_id="CVE-2024-0004",
            description="XSS vulnerability in nginx allowing session hijacking",
            cvss_score=6.1, severity="MEDIUM",
            exploitability_score=5.0, patch_available=True,
            affected_software=["nginx"], published_date="2024-02-10"
        ),
        CVERecord(
            cve_id="CVE-2024-0005",
            description="Information disclosure in OpenSSL exposing private keys",
            cvss_score=9.1, severity="CRITICAL",
            exploitability_score=8.9, patch_available=True,
            affected_software=["openssl"], published_date="2024-02-15"
        ),
        CVERecord(
            cve_id="CVE-2024-0006",
            description="Buffer overflow in libpng causing denial of service",
            cvss_score=5.5, severity="MEDIUM",
            exploitability_score=4.2, patch_available=True,
            affected_software=["libpng"], published_date="2024-02-20"
        ),
        CVERecord(
            cve_id="CVE-2024-0007",
            description="Authentication bypass in SSH daemon via malformed packets",
            cvss_score=9.0, severity="CRITICAL",
            exploitability_score=9.2, patch_available=False,
            affected_software=["openssh"], published_date="2024-03-01"
        ),
        CVERecord(
            cve_id="CVE-2024-0008",
            description="Path traversal in Python Flask allowing file read",
            cvss_score=6.8, severity="MEDIUM",
            exploitability_score=5.5, patch_available=True,
            affected_software=["python flask"], published_date="2024-03-05"
        ),
        CVERecord(
            cve_id="CVE-2024-0009",
            description="SSRF vulnerability in Redis allowing internal network scanning",
            cvss_score=7.5, severity="HIGH",
            exploitability_score=6.8, patch_available=True,
            affected_software=["redis"], published_date="2024-03-10"
        ),
        CVERecord(
            cve_id="CVE-2024-0010",
            description="Denial of service in curl via infinite loop on malformed URL",
            cvss_score=3.5, severity="LOW",
            exploitability_score=2.8, patch_available=True,
            affected_software=["curl"], published_date="2024-03-15"
        ),
        CVERecord(
            cve_id="CVE-2024-0011",
            description="Memory corruption in PostgreSQL query planner",
            cvss_score=8.1, severity="HIGH",
            exploitability_score=7.2, patch_available=True,
            affected_software=["postgresql"], published_date="2024-03-20"
        ),
        CVERecord(
            cve_id="CVE-2024-0012",
            description="CSRF in Django admin panel allowing admin account takeover",
            cvss_score=8.8, severity="HIGH",
            exploitability_score=7.9, patch_available=True,
            affected_software=["python django"], published_date="2024-03-25"
        ),
        CVERecord(
            cve_id="CVE-2024-0013",
            description="Insecure deserialization in Java Spring Boot RCE",
            cvss_score=9.8, severity="CRITICAL",
            exploitability_score=9.7, patch_available=False,
            affected_software=["spring boot"], published_date="2024-04-01"
        ),
        CVERecord(
            cve_id="CVE-2024-0014",
            description="Log injection in Node.js Express allowing log forgery",
            cvss_score=4.3, severity="MEDIUM",
            exploitability_score=3.5, patch_available=True,
            affected_software=["nodejs express"], published_date="2024-04-05"
        ),
        CVERecord(
            cve_id="CVE-2024-0015",
            description="Heap overflow in Kubernetes API server denial of service",
            cvss_score=7.5, severity="HIGH",
            exploitability_score=6.0, patch_available=True,
            affected_software=["kubernetes"], published_date="2024-04-10"
        ),
    ]
