import httpx
import json
import os
from typing import List
from env.models import CVERecord

CACHE_PATH = os.path.join(os.path.dirname(__file__), "cache", "cves.json")
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


# ---------------- FETCH ---------------- #
def fetch_cves_from_api(limit: int = 5000) -> List[dict]:
    params = {
        "resultsPerPage": limit,
        "startIndex": 0,
        "cvssV3Severity": "HIGH"
    }

    try:
        print("🌐 Fetching CVEs from NVD API...")
        response = httpx.get(NVD_API_URL, params=params, timeout=30)
        response.raise_for_status()
        data = response.json()

        vulns = data.get("vulnerabilities", [])
        print(f"✅ Fetched {len(vulns)} raw CVEs")

        return vulns

    except Exception as e:
        print(f"❌ API fetch failed: {e}")
        return []


# ---------------- PARSE ---------------- #
def parse_nvd_record(item: dict) -> CVERecord:
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

        # Affected software
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

    except Exception as e:
        print(f"⚠️ Parse error: {e}")
        return None


# ---------------- MAIN LOADER ---------------- #
def load_or_fetch_cves(limit: int = 500) -> List[CVERecord]:
    os.makedirs(os.path.dirname(CACHE_PATH), exist_ok=True)

    # 1️⃣ Try loading cache
    if os.path.exists(CACHE_PATH):
        try:
            print("📂 Loading CVEs from cache...")
            with open(CACHE_PATH, "r") as f:
                raw = json.load(f)

            cves = [CVERecord(**item) for item in raw]
            print(f"✅ Loaded {len(cves)} CVEs from cache")

            if cves:
                return cves

        except Exception as e:
            print(f"⚠️ Cache corrupted: {e}")

    # 2️⃣ Fetch from API
    raw_items = fetch_cves_from_api(limit)

    if not raw_items:
        print("⚠️ No data from API → Using fallback CVEs")
        return _get_fallback_cves()

    # 3️⃣ Parse
    cves = []
    for item in raw_items:
        parsed = parse_nvd_record(item)
        if parsed:
            cves.append(parsed)

    print(f"✅ Parsed {len(cves)} CVEs")

    # 4️⃣ Save cache
    if cves:
        with open(CACHE_PATH, "w") as f:
            json.dump([c.model_dump() for c in cves], f, indent=2)
        return cves

    # 5️⃣ Final fallback
    print("⚠️ Parsing failed → Using fallback CVEs")
    return _get_fallback_cves()


# ---------------- FALLBACK ---------------- #
def _get_fallback_cves() -> List[CVERecord]:
    print("📦 Loading fallback CVEs...")

    return [
        CVERecord(
            cve_id="CVE-2024-0001",
            description="Remote code execution in Apache HTTP Server",
            cvss_score=9.8, severity="CRITICAL",
            exploitability_score=9.5, patch_available=True,
            affected_software=["apache httpd"], published_date="2024-01-15"
        ),
        CVERecord(
            cve_id="CVE-2024-0002",
            description="SQL injection vulnerability in MySQL",
            cvss_score=8.5, severity="HIGH",
            exploitability_score=7.8, patch_available=True,
            affected_software=["mysql"], published_date="2024-01-20"
        ),
        CVERecord(
            cve_id="CVE-2024-0003",
            description="Privilege escalation in Linux kernel",
            cvss_score=7.8, severity="HIGH",
            exploitability_score=6.5, patch_available=False,
            affected_software=["linux kernel"], published_date="2024-02-01"
        ),
        CVERecord(
            cve_id="CVE-2024-0004",
            description="XSS vulnerability in nginx",
            cvss_score=6.1, severity="MEDIUM",
            exploitability_score=5.0, patch_available=True,
            affected_software=["nginx"], published_date="2024-02-10"
        ),
        CVERecord(
            cve_id="CVE-2024-0005",
            description="Information disclosure in OpenSSL",
            cvss_score=9.1, severity="CRITICAL",
            exploitability_score=8.9, patch_available=True,
            affected_software=["openssl"], published_date="2024-02-15"
        ),
    ]