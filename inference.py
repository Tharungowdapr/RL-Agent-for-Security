import os
import json
import asyncio
from typing import List
from openai import OpenAI
import httpx

API_BASE_URL = os.environ.get("API_BASE_URL", "https://api.openai.com/v1")
API_KEY = os.environ.get("HF_TOKEN", os.environ.get("OPENAI_API_KEY", ""))
MODEL_NAME = os.environ.get("MODEL_NAME", "gpt-4o-mini")
ENV_URL = os.environ.get("ENV_URL", "http://localhost:7860")

MAX_STEPS = 3
MAX_TOTAL_REWARD = 3.0
SUCCESS_THRESHOLD = 0.6

TASKS = [
    "task1_severity_ranking",
    "task2_asset_prioritization",
    "task3_full_triage"
]


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


def build_prompt(obs: dict, step: int, last_reward: float, history: List[str]) -> str:
    cves = obs.get("cves", [])
    assets = obs.get("assets", [])
    task_id = obs.get("task_id", "")
    message = obs.get("message", "")

    cve_text = "\n".join([
        f"- {c['cve_id']}: CVSS={c['cvss_score']} ({c['severity']}) | "
        f"Exploit={c['exploitability_score']} | "
        f"Patch={'Yes' if c['patch_available'] else 'No'} | "
        f"Affects: {', '.join(c['affected_software'][:2])}"
        for c in cves
    ])

    asset_text = "\n".join([
        f"- {a['asset_id']} ({a['name']}): criticality={a['criticality']} "
        f"score={a['criticality_score']} | runs: {', '.join(a['software'][:3])}"
        for a in assets
    ])

    history_text = "\n".join(history[-3:]) if history else "None"

    return f"""You are a cybersecurity analyst performing vulnerability triage.

Task: {task_id}
Instructions: {message}
Step: {step} | Last reward: {last_reward:.2f}

CVEs to triage:
{cve_text}

Company assets:
{asset_text}

Recent history:
{history_text}

Respond with ONLY a valid JSON object in this exact format:
{{
  "priority_order": ["CVE-ID-1", "CVE-ID-2", "CVE-ID-3"],
  "justifications": {{
    "CVE-ID-1": "reason",
    "CVE-ID-2": "reason"
  }}
}}

Order CVEs from highest to lowest business risk priority.
Only include CVE IDs that actually appear in the list above.
"""


def get_model_action(client: OpenAI, obs: dict, step: int, last_reward: float, history: List[str]) -> dict:
    prompt = build_prompt(obs, step, last_reward, history)
    try:
        completion = client.chat.completions.create(
            model=MODEL_NAME,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=1000,
            temperature=0.1
        )
        text = (completion.choices[0].message.content or "").strip()
        
        # Clean JSON from markdown if present
        if "```json" in text:
            text = text.split("```json")[1].split("```")[0].strip()
        elif "```" in text:
            text = text.split("```")[1].split("```")[0].strip()
        
        return json.loads(text)
    except Exception as e:
        print(f"[DEBUG] Model error: {e}", flush=True)
        cves = obs.get("cves", [])
        fallback_order = [c["cve_id"] for c in sorted(
            cves, key=lambda x: x["cvss_score"], reverse=True
        )]
        return {"priority_order": fallback_order}


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

            rewards.append(reward)
            steps_taken = step
            last_reward = reward

            action_str = json.dumps(action_dict.get("priority_order", [])[:3])
            log_step(step=step, action=action_str, reward=reward, done=done, error=None)
            history.append(f"Step {step}: priority={action_str} reward={reward:.2f}")

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


def main():
    client = OpenAI(base_url=API_BASE_URL, api_key=API_KEY)
    
    print(f"[DEBUG] Running inference on {ENV_URL} with model {MODEL_NAME}", flush=True)
    
    all_scores = {}
    for task_id in TASKS:
        print(f"\n[DEBUG] === Starting {task_id} ===", flush=True)
        score = run_task(task_id, client)
        all_scores[task_id] = score
        print(f"[DEBUG] {task_id} final score: {score:.4f}", flush=True)

    print("\n[DEBUG] === FINAL RESULTS ===", flush=True)
    for task_id, score in all_scores.items():
        print(f"[DEBUG] {task_id}: {score:.4f}", flush=True)
    
    avg = sum(all_scores.values()) / len(all_scores)
    print(f"[DEBUG] Average score: {avg:.4f}", flush=True)


if __name__ == "__main__":
    main()
