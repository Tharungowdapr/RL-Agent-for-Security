"""
Inference Agent (Enhanced)

AI-driven vulnerability triage using:
  - EPSS (Exploit Prediction Scoring System)
  - CISA KEV (Known Exploited Vulnerabilities)
  - Asset criticality awareness
  - Structured explainable JSON output
"""

import os
import json
import asyncio
from typing import List, Dict
from dotenv import load_dotenv
from openai import OpenAI
import httpx

load_dotenv()  # Load variables from .env into environment

API_BASE_URL = os.getenv("API_BASE_URL", "https://api.openai.com/v1")
API_KEY = os.getenv("HF_TOKEN")
MODEL_NAME = os.getenv("MODEL_NAME", "gpt-4o-mini")
ENV_URL = os.getenv("ENV_URL", "http://localhost:7860")

MAX_STEPS = 3
MAX_TOTAL_REWARD = 3.0
SUCCESS_THRESHOLD = 0.6

TASKS = [
    "task1_severity_ranking",
    "task2_asset_prioritization",
    "task3_full_triage"
]


# ═══════════════════════════════════════════════════════ #
#                     LOGGING                             #
# ═══════════════════════════════════════════════════════ #

def log_start(task: str, env: str, model: str):
    print(json.dumps({
        "event": "START",
        "task": task,
        "env": env,
        "model": model
    }), flush=True)


def log_step(step: int, action: str, reward: float, done: bool, error=None):
    print(json.dumps({
        "event": "STEP",
        "step": step,
        "action": action,
        "reward": reward,
        "done": done,
        "error": error
    }), flush=True)


def log_end(success: bool, steps: int, score: float, rewards: List[float]):
    print(json.dumps({
        "event": "END",
        "success": success,
        "steps": steps,
        "score": score,
        "rewards": rewards
    }), flush=True)


# ═══════════════════════════════════════════════════════ #
#              ENHANCED PROMPT BUILDER                    #
# ═══════════════════════════════════════════════════════ #

def build_prompt(obs: dict, step: int, last_reward: float, history: List[str]) -> str:
    cves = obs.get("cves", [])
    assets = obs.get("assets", [])
    task_id = obs.get("task_id", "")
    message = obs.get("message", "")

    # ── Build rich CVE table with EPSS + KEV ──
    cve_lines = []
    for c in cves:
        epss = c.get("epss_score", 0.0)
        in_kev = c.get("in_kev", False)
        kev_tag = " 🔴 [CISA KEV — ACTIVELY EXPLOITED]" if in_kev else ""
        epss_bar = "█" * int(epss * 10) + "░" * (10 - int(epss * 10))

        cve_lines.append(
            f"  - {c['cve_id']}: CVSS={c['cvss_score']:.1f} ({c['severity']}) | "
            f"EPSS={epss:.3f} [{epss_bar}] | "
            f"Exploit={c['exploitability_score']:.1f} | "
            f"Patch={'Yes' if c['patch_available'] else 'No'} | "
            f"Published={c.get('published_date', 'unknown')} | "
            f"Affects: {', '.join(c['affected_software'][:3])}"
            f"{kev_tag}"
        )
    cve_text = "\n".join(cve_lines)

    # ── Build asset table ──
    asset_lines = []
    for a in assets:
        asset_lines.append(
            f"  - {a['asset_id']} ({a['name']}): "
            f"criticality={a['criticality']} score={a['criticality_score']:.1f} | "
            f"runs: {', '.join(a['software'][:4])}"
        )
    asset_text = "\n".join(asset_lines)

    history_text = "\n".join(history[-3:]) if history else "None"

    # ── Structured prompt ──
    return f"""You are a senior cybersecurity analyst performing vulnerability triage.
You have access to real-time threat intelligence data.

═══════════════════════════════════════════
TASK: {task_id}
INSTRUCTIONS: {message}
STEP: {step} | LAST REWARD: {last_reward:.2f}
═══════════════════════════════════════════

📋 CVEs TO TRIAGE:
{cve_text}

🏢 COMPANY ASSETS:
{asset_text}

📜 RECENT HISTORY:
{history_text}

═══════════════════════════════════════════
RANKING CRITERIA (use ALL of these):
═══════════════════════════════════════════
1. SEVERITY: Higher CVSS score = higher priority
2. EXPLOIT LIKELIHOOD (EPSS): Higher EPSS = more likely to be exploited in the wild
3. ASSET CRITICALITY: CVEs affecting critical assets (payment, auth, DB) rank higher
4. CISA KEV: CVEs in the Known Exploited Vulnerabilities list get priority boost
5. RECENCY: Deprioritize outdated CVEs (before 2015)
6. NOISE FILTERING: Skip disputed, duplicate, or irrelevant entries
7. ASSET MATCH: CVEs that don't affect any of YOUR company's software are lower priority

═══════════════════════════════════════════
RESPONSE FORMAT (return ONLY this JSON):
═══════════════════════════════════════════
{{
  "priority_order": ["CVE-ID-1", "CVE-ID-2", ...],
  "justifications": {{
    "CVE-ID-1": "brief reason referencing CVSS, EPSS, KEV, asset impact",
    "CVE-ID-2": "brief reason"
  }}
}}

CRITICAL RULES:
- Only include CVE IDs that appear in the list above
- Remove duplicates
- For Task 3: return EXACTLY 5 CVE IDs
- Order from HIGHEST to LOWEST business risk
"""


# ═══════════════════════════════════════════════════════ #
#              ENHANCED FALLBACK LOGIC                    #
# ═══════════════════════════════════════════════════════ #

def compute_fallback_priority(cve: dict) -> float:
    """When LLM fails, use the advanced formula locally."""
    severity = cve.get("cvss_score", 0.0) / 10.0
    epss = cve.get("epss_score", 0.0)
    in_kev = cve.get("in_kev", False)

    # Check if outdated
    pub_date = cve.get("published_date", "2024")
    try:
        year = int(pub_date[:4])
    except (ValueError, IndexError):
        year = 2024
    outdated = 0.3 if year < 2015 else (0.1 if year < 2020 else 0.0)

    # Check if description suggests noise
    desc = cve.get("description", "").lower()
    is_noise = any(kw in desc for kw in ["disputed", "duplicate", "see cve-"])

    priority = (
        (severity * 0.4)
        + (epss * 0.3)
        + (1.0 if in_kev else 0.0) * 0.2
        - outdated
        - (0.5 if is_noise else 0.0)
    )
    return max(priority, 0.0)


# ═══════════════════════════════════════════════════════ #
#                 MODEL ACTION                            #
# ═══════════════════════════════════════════════════════ #

def get_model_action(client: OpenAI, obs: dict, step: int, last_reward: float, history: List[str]) -> dict:
    prompt = build_prompt(obs, step, last_reward, history)
    try:
        completion = client.chat.completions.create(
            model=MODEL_NAME,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=1500,
            temperature=0.1
        )
        text = (completion.choices[0].message.content or "").strip()

        # Clean JSON from markdown if present
        if "```json" in text:
            text = text.split("```json")[1].split("```")[0].strip()
        elif "```" in text:
            text = text.split("```")[1].split("```")[0].strip()

        parsed = json.loads(text)

        # Deduplicate the priority_order
        if "priority_order" in parsed:
            seen = set()
            deduped = []
            for cve_id in parsed["priority_order"]:
                if cve_id not in seen:
                    seen.add(cve_id)
                    deduped.append(cve_id)
            parsed["priority_order"] = deduped

        return parsed

    except Exception as e:
        print(f"[DEBUG] Model error: {e}", flush=True)
        print("[DEBUG] Using enhanced fallback (EPSS+KEV-aware sort)...", flush=True)

        cves = obs.get("cves", [])
        ranked = sorted(cves, key=lambda x: compute_fallback_priority(x), reverse=True)

        # Deduplicate
        seen = set()
        fallback_order = []
        for c in ranked:
            cid = c["cve_id"]
            if cid not in seen:
                seen.add(cid)
                fallback_order.append(cid)

        return {"priority_order": fallback_order}


# ═══════════════════════════════════════════════════════ #
#                  TASK RUNNER                             #
# ═══════════════════════════════════════════════════════ #

def run_task(task_id: str, client: OpenAI) -> float:
    log_start(task=task_id, env="security-vulnerability-triage", model=MODEL_NAME)

    rewards = []
    history = []
    steps_taken = 0
    score = 0.0
    success = False

    try:
        # Reset
        reset_resp = httpx.post(
            f"{ENV_URL}/reset",
            params={"task_id": task_id},
            timeout=30
        )
        reset_resp.raise_for_status()
        reset_data = reset_resp.json()
        obs = reset_data["observation"]
        done = obs.get("done", False)
        last_reward = 0.0

        for step in range(1, MAX_STEPS + 1):
            if done:
                break

            action_dict = get_model_action(client, obs, step, last_reward, history)

            step_resp = httpx.post(
                f"{ENV_URL}/step",
                json=action_dict,
                timeout=30
            )
            step_resp.raise_for_status()
            step_data = step_resp.json()

            reward = step_data.get("reward", 0.0)
            done = step_data.get("done", False)
            obs = step_data.get("observation", obs)
            info = step_data.get("info", {})

            rewards.append(reward)
            steps_taken = step
            last_reward = reward

            action_str = json.dumps(action_dict.get("priority_order", [])[:5])
            log_step(step=step, action=action_str, reward=reward, done=done, error=None)

            # Enhanced history with feedback
            feedback = info.get("feedback", "")
            history.append(
                f"Step {step}: priority={action_str} reward={reward:.2f}"
                f"{' | ' + feedback if feedback else ''}"
            )

            if done:
                break

        score = sum(rewards) / MAX_TOTAL_REWARD if MAX_TOTAL_REWARD > 0 else 0.0
        score = min(max(score, 0.0), 1.0)
        success = score >= SUCCESS_THRESHOLD

    except Exception as e:
        print(f"[DEBUG] Task {task_id} error: {e}", flush=True)
        log_step(step=steps_taken, action="error", reward=0.0, done=True, error=str(e))

    finally:
        log_end(success=success, steps=steps_taken, score=score, rewards=rewards)

    return score


# ═══════════════════════════════════════════════════════ #
#                      MAIN                               #
# ═══════════════════════════════════════════════════════ #

def main():
    # Validate API key
    if not API_KEY:
        print("🚨 [ERROR] HF_TOKEN / API key not set!", flush=True)
        print("   Set it in .env file or via: $env:HF_TOKEN='sk-...'", flush=True)
        print("   Falling back to local scoring (no LLM)...", flush=True)

    client = OpenAI(base_url=API_BASE_URL, api_key=API_KEY or "no-key")

    print(f"[DEBUG] Running inference on {ENV_URL} with model {MODEL_NAME}", flush=True)
    print(f"[DEBUG] API key set: {'YES' if API_KEY else 'NO (fallback mode)'}", flush=True)

    all_scores = {}
    all_results = []

    for task_id in TASKS:
        print(f"\n[DEBUG] === Starting {task_id} ===", flush=True)
        score = run_task(task_id, client)
        all_scores[task_id] = score
        all_results.append({
            "task": task_id,
            "score": round(score, 4),
            "success": score >= SUCCESS_THRESHOLD
        })
        print(f"[DEBUG] {task_id} final score: {score:.4f}", flush=True)

    print("\n[DEBUG] === FINAL RESULTS ===", flush=True)
    for task_id, score in all_scores.items():
        status = "✅ PASS" if score >= SUCCESS_THRESHOLD else "❌ FAIL"
        print(f"[DEBUG] {task_id}: {score:.4f} {status}", flush=True)

    avg = sum(all_scores.values()) / len(all_scores)
    print(f"[DEBUG] Average score: {avg:.4f}", flush=True)

    # Save structured results
    results_output = {
        "model": MODEL_NAME,
        "env_url": ENV_URL,
        "average_score": round(avg, 4),
        "tasks": all_results,
        "enhanced_features": [
            "EPSS integration",
            "CISA KEV integration",
            "Advanced priority scoring",
            "Duplicate deduplication",
            "Outdated CVE penalties",
            "Explainable justifications"
        ]
    }
    print(f"\n{json.dumps(results_output, indent=2)}", flush=True)


if __name__ == "__main__":
    main()
