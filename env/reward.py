from env.models import Action, CVERecord, CompanyAsset, Reward
from typing import List


def compute_reward(
    task_id: str,
    action: Action,
    cves: List[CVERecord],
    assets: List[CompanyAsset]
) -> Reward:
    from tasks.task1_severity_ranking import grade as grade_t1
    from tasks.task2_asset_prioritization import grade as grade_t2
    from tasks.task3_full_triage import grade as grade_t3

    breakdown = {}

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
        breakdown = {"full_triage_score": score}
        feedback = f"Full triage score: {score:.2f}. Noise filtering + selection + ordering."

    else:
        score = 0.0
        breakdown = {"error": 0.0}
        feedback = "Unknown task ID."

    # Global penalties
    if not action.priority_order:
        score = 0.0
        feedback = "No priority order provided — zero score."
    elif len(set(action.priority_order)) != len(action.priority_order):
        score *= 0.8
        feedback += " Duplicate CVE IDs detected — penalty applied."

    return Reward(
        score=round(min(max(score, 0.0), 1.0), 4),
        breakdown=breakdown,
        feedback=feedback
    )
