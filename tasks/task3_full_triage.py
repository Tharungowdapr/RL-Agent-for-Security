"""
Task 3 — Full Triage Under Noise (Enhanced)

Advanced priority scoring:
  Priority = (Severity × 0.4) + (EPSS × 0.3) + (Asset Criticality × 0.2)
           + (KEV Bonus × 0.2) - (Duplicate Penalty × 0.1) - (Outdated Penalty)
"""

from typing import List, Tuple, Dict, Set
from env.models import CVERecord, CompanyAsset, Action, Observation
from data.asset_generator import generate_assets, get_affected_assets
import random


# ─────────────────────── Noise CVEs ─────────────────────── #
NOISE_CVES = [
    CVERecord(
        cve_id="CVE-2019-OUTDATED",
        description="[DISPUTED] Vendor states this is not a vulnerability. No exploit confirmed.",
        cvss_score=8.5, severity="HIGH",
        exploitability_score=1.0, patch_available=False,
        affected_software=["old software v1"], published_date="2019-01-01",
        epss_score=0.01, in_kev=False
    ),
    CVERecord(
        cve_id="CVE-2020-DUPLICATE",
        description="Duplicate entry — see CVE-2024-0001 for the canonical record.",
        cvss_score=9.8, severity="CRITICAL",
        exploitability_score=0.5, patch_available=False,
        affected_software=["apache httpd"], published_date="2020-06-01",
        epss_score=0.02, in_kev=False
    ),
    CVERecord(
        cve_id="CVE-2024-NOASSET",
        description="Critical RCE in IBM Mainframe COBOL runtime.",
        cvss_score=9.9, severity="CRITICAL",
        exploitability_score=9.8, patch_available=False,
        affected_software=["ibm mainframe cobol"], published_date="2024-01-01",
        epss_score=0.90, in_kev=False
    ),
]

NOISE_IDS: Set[str] = {c.cve_id for c in NOISE_CVES}


# ─────────────────── Advanced Priority Scoring ─────────── #
def compute_advanced_priority(
    cve: CVERecord,
    assets: List[CompanyAsset],
    all_cve_ids: List[str],
) -> float:
    """
    Priority = (Severity × 0.4) + (EPSS × 0.3) + (Asset Crit × 0.2)
             + (KEV Bonus × 0.2) - (Dup Penalty × 0.1) - (Outdated Penalty)
    """

    # ── Severity component (normalize CVSS 0-10 → 0-1) ──
    severity_norm = cve.cvss_score / 10.0

    # ── EPSS component (already 0-1) ──
    epss = cve.epss_score

    # ── Asset Criticality component ──
    affected_ids = get_affected_assets(cve.affected_software, assets)
    if affected_ids:
        affected = [a for a in assets if a.asset_id in affected_ids]
        # Normalize 0-10 → 0-1
        asset_crit = max(a.criticality_score for a in affected) / 10.0 if affected else 0.1
    else:
        asset_crit = 0.0  # No matching asset → penalized

    # ── KEV Bonus ──
    kev_bonus = 1.0 if cve.in_kev else 0.0

    # ── Duplicate Penalty ──
    # Count how many times this CVE ID appears
    occurrences = all_cve_ids.count(cve.cve_id)
    dup_penalty = 1.0 if occurrences > 1 else 0.0

    # ── Outdated CVE Penalty (before 2015) ──
    try:
        year = int(cve.published_date[:4])
    except (ValueError, IndexError):
        year = 2024

    if year < 2015:
        outdated_penalty = 0.3  # Significant penalty
    elif year < 2020:
        outdated_penalty = 0.1  # Slight penalty
    else:
        outdated_penalty = 0.0

    # ── Final formula ──
    priority = (
        (severity_norm * 0.4)
        + (epss * 0.3)
        + (asset_crit * 0.2)
        + (kev_bonus * 0.2)
        - (dup_penalty * 0.1)
        - outdated_penalty
    )

    return max(priority, 0.0)


# ─────────────────── Scenario Builder ─────────────────── #
def build_scenario(cves: List[CVERecord]) -> Tuple[List[CVERecord], List[CompanyAsset]]:
    real_cves = cves[:15]
    noisy_cves = NOISE_CVES.copy()
    all_cves = real_cves + noisy_cves
    random.shuffle(all_cves)
    assets = generate_assets(10)
    return all_cves, assets


# ─────────────────── Observation Builder ─────────────────── #
def build_observation(cves: List[CVERecord], assets: List[CompanyAsset], step: int) -> Observation:
    return Observation(
        task_id="task3_full_triage",
        step=step,
        cves=cves,
        assets=assets,
        patches_available_count=5,
        message=(
            "Task 3 — Full Triage Under Noise (Enhanced).\n"
            "You have 18 CVEs but can only patch 5 this sprint. "
            "Warning: some entries are disputed, duplicates, or affect software "
            "your company does not run. Filter noise, then prioritize the top 5 "
            "real CVEs that pose the greatest business risk.\n\n"
            "Use these factors for ranking:\n"
            "  • Severity (CVSS score)\n"
            "  • Exploit likelihood (EPSS score — higher = more likely to be exploited)\n"
            "  • Asset criticality (which company systems are impacted)\n"
            "  • Known Exploited Vulnerabilities (CISA KEV — actively exploited in the wild)\n"
            "  • Remove duplicates and deprioritize outdated CVEs (before 2015)\n\n"
            "Return exactly 5 CVE IDs in priority order."
        )
    )


# ─────────────────── Grader ─────────────────── #
def grade(action: Action, cves: List[CVERecord], assets: List[CompanyAsset]) -> float:
    """Grade with the advanced priority formula."""

    # Deduplicate input CVEs
    seen_ids: Set[str] = set()
    unique_cves: List[CVERecord] = []
    for c in cves:
        if c.cve_id not in seen_ids:
            seen_ids.add(c.cve_id)
            unique_cves.append(c)

    real_cves = [c for c in unique_cves if c.cve_id not in NOISE_IDS]

    # Compute advanced priority for all real CVEs
    all_ids = [c.cve_id for c in cves]  # includes dups for penalty calc
    scores: Dict[str, float] = {}
    for cve in real_cves:
        scores[cve.cve_id] = compute_advanced_priority(cve, assets, all_ids)

    ground_truth_top5 = sorted(
        scores.keys(), key=lambda x: scores[x], reverse=True
    )[:5]

    predicted = action.priority_order[:5] if action.priority_order else []
    if not predicted:
        return 0.0

    # ── Noise filtering score ──
    noise_included = sum(1 for p in predicted if p in NOISE_IDS)
    noise_penalty = noise_included / 5.0
    noise_score = 1.0 - noise_penalty

    # ── Top-5 selection accuracy ──
    gt_set = set(ground_truth_top5)
    pred_set = set(predicted) - NOISE_IDS
    selection_score = len(gt_set & pred_set) / 5.0

    # ── Ordering score ──
    valid_preds = [p for p in predicted if p not in NOISE_IDS and p in scores]
    order_score = 0.0
    if valid_preds:
        for rank, cve_id in enumerate(valid_preds):
            if cve_id in ground_truth_top5:
                gt_rank = ground_truth_top5.index(cve_id)
                order_score += max(0.0, 1.0 - abs(rank - gt_rank) / 5.0)
        order_score /= 5.0

    # ── Duplicate penalty in submission ──
    dup_count = len(predicted) - len(set(predicted))
    dup_penalty = min(dup_count * 0.1, 0.3)

    # ── Outdated CVE penalty (if agent includes pre-2015 CVEs) ──
    outdated_count = 0
    cve_map = {c.cve_id: c for c in cves}
    for p in predicted:
        if p in cve_map:
            try:
                yr = int(cve_map[p].published_date[:4])
                if yr < 2015:
                    outdated_count += 1
            except (ValueError, IndexError):
                pass
    outdated_penalty = min(outdated_count * 0.1, 0.3)

    final = (
        (noise_score * 0.25)
        + (selection_score * 0.35)
        + (order_score * 0.25)
        - dup_penalty
        - outdated_penalty
    )

    # Add KEV awareness bonus (if agent correctly puts KEV CVEs at top)
    kev_bonus = 0.0
    for i, p in enumerate(predicted[:3]):
        if p in cve_map and cve_map[p].in_kev:
            kev_bonus += 0.05  # up to 0.15 bonus
    final += kev_bonus

    return round(min(max(final, 0.0), 1.0), 4)
