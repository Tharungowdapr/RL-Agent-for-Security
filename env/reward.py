"""
Reward Engine (Enhanced)

Computes rewards with detailed breakdowns including:
- EPSS awareness scoring
- KEV bonus tracking
- Duplicate & outdated penalties
"""

from env.models import Action, CVERecord, CompanyAsset, Reward
from typing import List, Dict


def compute_reward(
    task_id: str,
    action: Action,
    cves: List[CVERecord],
    assets: List[CompanyAsset]
) -> Reward:
    from tasks.task1_severity_ranking import grade as grade_t1
    from tasks.task2_asset_prioritization import grade as grade_t2
    from tasks.task3_full_triage import grade as grade_t3

    breakdown: Dict[str, float] = {}

    if task_id == "task1_severity_ranking":
        score = grade_t1(action, cves)
        breakdown = {"ranking_accuracy": score}
        feedback = f"Ranking score: {score:.2f}. Top-3 accuracy included."

    elif task_id == "task2_asset_prioritization":
        score = grade_t2(action, cves, assets)
        breakdown = {"combined_priority_score": score}
        feedback = f"Asset-aware priority score: {score:.2f}."

    elif task_id == "task3_full_triage":
        score = grade_t3(action, cves, assets)

        # Build detailed breakdown for Task 3
        from tasks.task3_full_triage import (
            NOISE_IDS, compute_advanced_priority
        )

        predicted = action.priority_order[:5] if action.priority_order else []
        cve_map = {c.cve_id: c for c in cves}

        noise_in = sum(1 for p in predicted if p in NOISE_IDS)
        kev_in = sum(1 for p in predicted
                     if p in cve_map and cve_map[p].in_kev)
        avg_epss = 0.0
        if predicted:
            epss_vals = [cve_map[p].epss_score for p in predicted
                         if p in cve_map]
            avg_epss = sum(epss_vals) / max(len(epss_vals), 1)

        dup_count = len(predicted) - len(set(predicted))

        breakdown = {
            "full_triage_score": score,
            "noise_cves_included": float(noise_in),
            "kev_cves_selected": float(kev_in),
            "avg_epss_of_selection": round(avg_epss, 4),
            "duplicate_submissions": float(dup_count),
        }
        feedback = (
            f"Full triage score: {score:.2f}. "
            f"Noise filtered: {5 - noise_in}/5 clean. "
            f"KEV CVEs selected: {kev_in}. "
            f"Avg EPSS: {avg_epss:.3f}."
        )

    else:
        score = 0.0
        breakdown = {"error": 0.0}
        feedback = "Unknown task ID."

    # ── Global penalties ──
    if not action.priority_order:
        score = 0.0
        feedback = "No priority order provided — zero score."
    elif len(set(action.priority_order)) != len(action.priority_order):
        score *= 0.8
        feedback += " Duplicate CVE IDs detected — 20% penalty applied."

    return Reward(
        score=round(min(max(score, 0.0), 1.0), 4),
        breakdown=breakdown,
        feedback=feedback
    )
