"""
Task 2 — Asset-Aware Prioritization (Enhanced)

Priority combines CVSS severity, asset criticality, EPSS score, and KEV status.
"""

from typing import List, Tuple, Dict
from env.models import CVERecord, CompanyAsset, Action, Observation
from data.asset_generator import generate_assets, get_affected_assets
import random


def compute_priority_score(cve: CVERecord, assets: List[CompanyAsset]) -> float:
    """Enhanced priority: CVSS + asset criticality + EPSS + KEV."""
    affected_ids = get_affected_assets(cve.affected_software, assets)
    if not affected_ids:
        asset_score = 1.0
    else:
        affected = [a for a in assets if a.asset_id in affected_ids]
        asset_score = max(a.criticality_score for a in affected) if affected else 1.0

    # Base: severity + asset (original formula, preserved for backward compat)
    base = (cve.cvss_score * 0.4) + (asset_score * 0.3)

    # EPSS boost (0-1 scaled to 0-10 for same magnitude)
    epss_component = cve.epss_score * 10.0 * 0.2

    # KEV bonus
    kev_bonus = 2.0 if cve.in_kev else 0.0

    combined = base + epss_component + (kev_bonus * 0.1)
    return combined


def build_scenario(cves: List[CVERecord]) -> Tuple[List[CVERecord], List[CompanyAsset]]:
    selected = cves[:12]
    random.shuffle(selected)
    assets = generate_assets(10)
    return selected, assets


def build_observation(cves: List[CVERecord], assets: List[CompanyAsset], step: int) -> Observation:
    return Observation(
        task_id="task2_asset_prioritization",
        step=step,
        cves=cves,
        assets=assets,
        patches_available_count=5,
        message=(
            "Task 2 — Asset-Aware Prioritization (Enhanced).\n"
            "Consider ALL of these factors when ranking:\n"
            "  • CVE severity (CVSS score)\n"
            "  • Which company assets are affected and their criticality\n"
            "  • Exploit likelihood (EPSS score)\n"
            "  • Whether the CVE is in CISA KEV (actively exploited)\n\n"
            "A critical CVE on a low-value dev server may be lower priority than "
            "a medium CVE on the payment processing server. "
            "Return CVE IDs ordered by true business risk."
        )
    )


def grade(action: Action, cves: List[CVERecord], assets: List[CompanyAsset]) -> float:
    scores = {cve.cve_id: compute_priority_score(cve, assets) for cve in cves}
    ground_truth = sorted(scores.keys(), key=lambda x: scores[x], reverse=True)
    predicted = action.priority_order

    if not predicted:
        return 0.0

    valid_ids = set(c.cve_id for c in cves)
    predicted = [p for p in predicted if p in valid_ids]
    if not predicted:
        return 0.0

    n = len(ground_truth)

    # Rank correlation scoring
    rank_truth = {cve_id: i for i, cve_id in enumerate(ground_truth)}
    rank_pred = {cve_id: i for i, cve_id in enumerate(predicted)}

    rank_score = 0.0
    for cve_id in ground_truth:
        if cve_id in rank_pred:
            error = abs(rank_truth[cve_id] - rank_pred[cve_id])
            rank_score += max(0.0, 1.0 - error / n)

    rank_score /= n

    # Top-5 patch slot accuracy
    top5_truth = set(ground_truth[:5])
    top5_pred = set(predicted[:5]) if len(predicted) >= 5 else set(predicted)
    patch_accuracy = len(top5_truth & top5_pred) / 5.0

    final = (rank_score * 0.5) + (patch_accuracy * 0.5)
    return round(min(max(final, 0.0), 1.0), 4)
