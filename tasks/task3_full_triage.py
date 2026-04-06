from typing import List, Tuple, Dict
from env.models import CVERecord, CompanyAsset, Action, Observation
from data.asset_generator import generate_assets, get_affected_assets
from tasks.task2_asset_prioritization import compute_priority_score
import random


NOISE_CVES = [
    CVERecord(
        cve_id="CVE-2019-OUTDATED",
        description="[DISPUTED] Vendor states this is not a vulnerability. No exploit confirmed.",
        cvss_score=8.5, severity="HIGH",
        exploitability_score=1.0, patch_available=False,
        affected_software=["old software v1"], published_date="2019-01-01"
    ),
    CVERecord(
        cve_id="CVE-2020-DUPLICATE",
        description="Duplicate entry — see CVE-2024-0001 for the canonical record.",
        cvss_score=9.8, severity="CRITICAL",
        exploitability_score=0.5, patch_available=False,
        affected_software=["apache httpd"], published_date="2020-06-01"
    ),
    CVERecord(
        cve_id="CVE-2024-NOASSET",
        description="Critical RCE in IBM Mainframe COBOL runtime.",
        cvss_score=9.9, severity="CRITICAL",
        exploitability_score=9.8, patch_available=False,
        affected_software=["ibm mainframe cobol"], published_date="2024-01-01"
    ),
]


def build_scenario(cves: List[CVERecord]) -> Tuple[List[CVERecord], List[CompanyAsset]]:
    real_cves = cves[:15]
    noisy_cves = NOISE_CVES.copy()
    all_cves = real_cves + noisy_cves
    random.shuffle(all_cves)
    assets = generate_assets(10)
    return all_cves, assets


def build_observation(cves: List[CVERecord], assets: List[CompanyAsset], step: int) -> Observation:
    return Observation(
        task_id="task3_full_triage",
        step=step,
        cves=cves,
        assets=assets,
        patches_available_count=5,
        message=(
            "Task 3 — Full Triage Under Noise.\n"
            "You have 18 CVEs but can only patch 5 this sprint. "
            "Warning: some entries are disputed, duplicates, or affect software "
            "your company does not run. Filter noise, then prioritize the top 5 "
            "real CVEs that pose the greatest business risk. "
            "Return exactly 5 CVE IDs in priority order."
        )
    )


def grade(action: Action, cves: List[CVERecord], assets: List[CompanyAsset]) -> float:
    noise_ids = {c.cve_id for c in NOISE_CVES}
    real_cves = [c for c in cves if c.cve_id not in noise_ids]
    
    # Score real CVEs by combined priority
    asset_ids = {a.asset_id for a in assets}
    scores = {}
    for cve in real_cves:
        affected = get_affected_assets(cve.affected_software, assets)
        has_asset = len(affected) > 0
        priority = compute_priority_score(cve, assets) if has_asset else cve.cvss_score * 0.3
        scores[cve.cve_id] = priority

    ground_truth_top5 = sorted(scores.keys(), key=lambda x: scores[x], reverse=True)[:5]

    predicted = action.priority_order[:5] if action.priority_order else []

    if not predicted:
        return 0.0

    # Noise filtering score (did agent avoid noise CVEs?)
    noise_included = sum(1 for p in predicted if p in noise_ids)
    noise_penalty = noise_included / 5.0
    noise_score = 1.0 - noise_penalty

    # Top-5 selection accuracy
    gt_set = set(ground_truth_top5)
    pred_set = set(predicted) - noise_ids
    selection_score = len(gt_set & pred_set) / 5.0

    # Ordering score (within the valid predictions)
    valid_preds = [p for p in predicted if p not in noise_ids and p in scores]
    order_score = 0.0
    if valid_preds:
        for rank, cve_id in enumerate(valid_preds):
            if cve_id in ground_truth_top5:
                gt_rank = ground_truth_top5.index(cve_id)
                order_score += max(0.0, 1.0 - abs(rank - gt_rank) / 5.0)
        order_score /= 5.0

    final = (noise_score * 0.3) + (selection_score * 0.4) + (order_score * 0.3)
    return round(min(max(final, 0.0), 1.0), 4)
