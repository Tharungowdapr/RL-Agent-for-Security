from core.scoring import compute_priority

def rank_and_reward(action_id, vulns, key_func, apply_kev=False):
    """
    Ranks the vulnerabilities by the key function and returns the correct reward + reason.
    Returns: (reward: float, reason: str)
    """
    sorted_vulns = sorted(vulns, key=key_func, reverse=True)
    
    # Check if selected ID is valid
    if not any(v["id"] == action_id for v in vulns):
        return -0.5, "Invalid CVE ID selected.", -1

    # Identify the rank of the selected vulnerability
    rank = next((idx for idx, v in enumerate(sorted_vulns) if v["id"] == action_id), -1)
    selected_vuln = next((v for v in vulns if v["id"] == action_id), None)

    reward = 0.0
    reason = ""

    if rank == 0:
        reward = 1.0
        reason = "Optimal choice. Selected the most critical vulnerability."
    elif rank < 3:
        reward = 0.7
        reason = f"Good choice. Selected a top 3 vulnerability (Rank {rank + 1})."
    elif rank < 5:
        reward = 0.4
        reason = f"Relevant but suboptimal. Vulnerability ranked {rank + 1}."
    else:
        reward = -0.2
        reason = f"Poor pick. Vulnerability ranked {rank + 1} is a low priority."

    # Apply KEV bonus if flag is on
    if apply_kev and selected_vuln and selected_vuln.get("kev"):
        reward += 0.2
        reason += " [Bonus +0.2: Identified active CISA KEV exploit]"

    return round(reward, 2), reason, rank


def grade_easy(action, vulns):
    # Easy task: strictly CVSS score
    return rank_and_reward(action.target_id, vulns, key_func=lambda v: v["severity"], apply_kev=False)


def grade_medium(action, vulns):
    # Medium task: severity + EPSS weighting
    return rank_and_reward(action.target_id, vulns, key_func=lambda v: v["severity"] * 0.6 + v["epss"] * 0.4, apply_kev=True)


def grade_hard(action, vulns):
    # Hard task: full comprehensive compute formula
    return rank_and_reward(action.target_id, vulns, key_func=compute_priority, apply_kev=True)
