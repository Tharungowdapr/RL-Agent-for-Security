from typing import List, Tuple
from env.models import CVERecord, CompanyAsset, Action, Observation
from data.asset_generator import generate_assets
import random


def build_scenario(cves: List[CVERecord]) -> Tuple[List[CVERecord], List[CompanyAsset]]:
    selected = sorted(cves, key=lambda x: x.cvss_score, reverse=True)[:10]
    random.shuffle(selected)
    assets = generate_assets(5)
    return selected, assets


def build_observation(cves: List[CVERecord], assets: List[CompanyAsset], step: int) -> Observation:
    return Observation(
        task_id="task1_severity_ranking",
        step=step,
        cves=cves,
        assets=assets,
        patches_available_count=10,
        message=(
            "Task 1 — Basic Severity Ranking.\n"
            "Rank all CVEs from most critical to least critical "
            "based on their CVSS score. Return the CVE IDs in order."
        )
    )


def grade(action: Action, cves: List[CVERecord]) -> float:
    ground_truth = [
        c.cve_id for c in sorted(cves, key=lambda x: x.cvss_score, reverse=True)
    ]
    predicted = action.priority_order

    if not predicted:
        return 0.0

    predicted = [p for p in predicted if p in [c.cve_id for c in cves]]
    if not predicted:
        return 0.0

    n = len(ground_truth)
    score = 0.0

    # Score based on position accuracy
    for i, cve_id in enumerate(ground_truth):
        if cve_id in predicted:
            predicted_pos = predicted.index(cve_id)
            position_error = abs(i - predicted_pos)
            position_score = max(0.0, 1.0 - (position_error / n))
            score += position_score

    # Top-3 bonus: getting the top 3 exactly right earns extra credit
    top3_truth = set(ground_truth[:3])
    top3_pred = set(predicted[:3]) if len(predicted) >= 3 else set(predicted)
    top3_overlap = len(top3_truth & top3_pred) / 3.0
    
    base_score = score / n
    final_score = (base_score * 0.7) + (top3_overlap * 0.3)
    return round(min(max(final_score, 0.0), 1.0), 4)
