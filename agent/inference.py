import os
import sys
from openai import OpenAI
import requests

API_BASE_URL = os.getenv("API_BASE_URL", "https://api.openai.com/v1")
MODEL_NAME = os.getenv("MODEL_NAME", "gpt-4.1-mini")
HF_TOKEN = os.getenv("HF_TOKEN", "mock_key")
ENV_API_URL = os.getenv("ENV_API_URL", "http://localhost:7860")

client = OpenAI(base_url=API_BASE_URL, api_key=HF_TOKEN)

def get_action(obs, selected_set):
    prompt = f"""
You are a cybersecurity analyst.

Select the most critical vulnerability ID from:
{obs["vulnerabilities"]}

Return ONLY the CVE ID.
"""

    try:
        response = client.chat.completions.create(
            model=MODEL_NAME,
            messages=[{"role": "user", "content": prompt}]
        )
        cve_id = response.choices[0].message.content.strip()
    except Exception:
        # Strict fallback without logging to maintain stdout integrity
        available = [v["id"] for v in obs["vulnerabilities"] if v["id"] not in selected_set]
        if available:
            cve_id = available[0]
        else:
            cve_id = obs["vulnerabilities"][0]["id"] if obs["vulnerabilities"] else "CVE-UNKNOWN"

    return cve_id


def run_task(task):
    # RESET ENV VIA API
    res = requests.post(f"{ENV_API_URL}/reset", params={"task_id": task})

    if res.status_code != 200:
        raise Exception("Reset API failed")

    data = res.json()
    
    obs = data["observation"]

    print(f"[START] task={task} env=security model={MODEL_NAME}")

    rewards = []
    step = 0
    selected = set()

    try:
        while True:
            step += 1

            # GET ACTION FROM LLM
            cve_id = get_action(obs, selected)

            # CALL STEP API
            step_res = requests.post(
                f"{ENV_API_URL}/step",
                json={"action_type": "prioritize", "target_id": cve_id}
            )

            step_data = step_res.json()

            obs = step_data["observation"]
            reward = step_data["reward"]
            done = step_data["done"]
            info = step_data["info"]

            selected.add(cve_id)

            last_error = info.get("error", None)
            rewards.append(f"{reward:.2f}")

            print(f"[STEP] step={step} action={cve_id} reward={reward:.2f} done={str(done).lower()} error={last_error if last_error else 'null'}")

            if done:
                break

        print(f"[END] success=true steps={step} rewards={','.join(rewards)}")

    except Exception:
        print(f"[END] success=false steps={step} rewards={','.join(rewards)}")


if __name__ == "__main__":
    # Remove traceback and unhandled prints silently during inference scripts
    sys.stderr = open(os.devnull, 'w')
    for t in ["easy", "medium", "hard"]:
        run_task(t)
