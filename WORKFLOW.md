# 🔐 RL Agent for Security — Workflow & Training Guide

> **⚠️ Important:** This project currently uses a **pre-trained LLM (GPT-4o-mini)** as the decision-making agent (zero-shot inference). This document explains the existing inference workflow AND what it would take to **train a proper RL model** if you want to go beyond zero-shot API calls.

---

## 📌 What This Project Is

This is a **Reinforcement Learning environment** for **cybersecurity vulnerability triage**. An AI agent is given a list of real-world CVEs (Common Vulnerabilities and Exposures) and must rank them by business risk — taking into account CVSS scores, asset criticality, exploitability, and patch availability.

The environment is built on the **OpenEnv** standard and exposes a FastAPI interface that any RL agent (LLM or trained model) can interact with.

---

## 🧠 Do We Need to Train a Model?

### ✅ Current Approach: Zero-Shot LLM (Inference Only)

Right now, `inference.py` uses **GPT-4o-mini** through the OpenAI API. The LLM reads the CVE context and generates a prioritized JSON response — **no training is involved**.

```
LLM (gpt-4o-mini) —— prompt ——> JSON priority_order ——> environment /step ——> reward
```

This works for basic evaluation, but:
- ❌ No learning happens across episodes
- ❌ The model doesn't improve from rewards
- ❌ Not true Reinforcement Learning

### 🚀 Better Approach: Train an RL Model

To make this a **real RL agent**, you need a training loop where the model improves its policy based on rewards. See the Training section below.

---

## 🔄 RL Agent Workflow (End-to-End)

```
┌─────────────────────────────────────────────────────────┐
│                   EPISODE LIFECYCLE                     │
│                                                         │
│  POST /reset ──► Observation (CVEs + Assets)            │
│                          │                              │
│                          ▼                              │
│            Agent reads observation                      │
│           (LLM prompt or NN forward pass)               │
│                          │                              │
│                          ▼                              │
│        Action: { "priority_order": ["CVE-A", ...] }     │
│                          │                              │
│                          ▼                              │
│           POST /step ──► Reward (0.0 – 1.0)             │
│                          │                              │
│                    done? ┤                              │
│                    YES ──► log_end(), next episode      │
│                    NO  ──► next step (max 3 steps)      │
└─────────────────────────────────────────────────────────┘
```

---

## 🏗️ System Architecture

```
RL-Agent-for-Security/
│
├── inference.py          ← Agent brain (currently LLM-based)
│
├── api/
│   └── server.py         ← FastAPI server exposing /reset, /step, /state
│
├── env/
│   ├── environment.py    ← Core RL environment (reset/step logic)
│   ├── reward.py         ← Reward computation engine
│   ├── models.py         ← Pydantic models: CVERecord, Action, Observation
│   └── state_manager.py  ← Tracks episode state (step count, history)
│
├── tasks/
│   ├── task1_severity_ranking.py      ← Sort CVEs by CVSS score
│   ├── task2_asset_prioritization.py  ← Rank CVEs by affected asset criticality
│   └── task3_full_triage.py           ← Full triage with noise filtering
│
└── data/
    ├── nvd_fetcher.py    ← Fetches real CVEs from NVD API
    └── cache/cves.json   ← Local cache of CVE data
```

---

## 🎯 The 3 Tasks Explained

| Task | What the Agent Must Do | Reward Signal |
|------|------------------------|---------------|
| `task1_severity_ranking` | Rank CVEs from **highest to lowest** CVSS score | How accurately the agent orders by severity |
| `task2_asset_prioritization` | Rank CVEs based on **which company assets they affect** (criticality-wise) | Combined CVE + asset criticality score |
| `task3_full_triage` | Full ranking with **noise filtering** (irrelevant CVEs must be excluded) | Full triage accuracy: ordering + filtering |

Each task runs for **max 3 steps**. Score is normalized to `[0.0, 1.0]`. A score ≥ `0.6` counts as **success**.

---

## 🏋️ How to Train a Real RL Model

> Skip this if you're only doing LLM inference for the hackathon demo.

### Step 1 — Define a Policy Network

Replace the LLM call in `inference.py` with a trainable model:

```python
import torch
import torch.nn as nn

class TriagePolicy(nn.Module):
    def __init__(self, input_dim, output_dim):
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(input_dim, 128),
            nn.ReLU(),
            nn.Linear(128, output_dim),
            nn.Softmax(dim=-1)
        )

    def forward(self, x):
        return self.net(x)
```

### Step 2 — Encode Observations as Feature Vectors

Convert the CVE observation dict into a numeric tensor:

```python
def encode_observation(obs: dict) -> torch.Tensor:
    cves = obs.get("cves", [])
    features = []
    for cve in cves:
        features.extend([
            cve["cvss_score"] / 10.0,
            cve["exploitability_score"] / 10.0,
            1.0 if cve["patch_available"] else 0.0
        ])
    return torch.tensor(features, dtype=torch.float32)
```

### Step 3 — Write the Training Loop (REINFORCE / PPO)

```python
optimizer = torch.optim.Adam(policy.parameters(), lr=1e-3)

for episode in range(1000):
    obs = requests.post(f"{ENV_URL}/reset", params={"task_id": task_id}).json()["observation"]

    log_probs = []
    rewards = []

    for step in range(MAX_STEPS):
        state = encode_observation(obs)
        probs = policy(state)
        action_idx = torch.multinomial(probs, num_samples=NUM_CVES, replacement=False)

        priority_order = [cve_ids[i] for i in action_idx]
        action = {"priority_order": priority_order}

        result = requests.post(f"{ENV_URL}/step", json=action).json()
        reward = result["reward"]

        log_probs.append(torch.log(probs[action_idx]).sum())
        rewards.append(reward)

        obs = result["observation"]
        if result["done"]:
            break

    # REINFORCE update
    returns = compute_returns(rewards, gamma=0.99)
    loss = -sum(lp * R for lp, R in zip(log_probs, returns))

    optimizer.zero_grad()
    loss.backward()
    optimizer.step()
```

### Step 4 — Save the Trained Model

```python
torch.save(policy.state_dict(), "trained_policy.pt")
```

### Step 5 — Load and Run (Inference)

```python
policy.load_state_dict(torch.load("trained_policy.pt"))
policy.eval()
```

---

## 🔐 Environment Variables (`.env`)

All config is managed via environment variables. Set them in your `.env` file:

```env
API_BASE_URL=https://api.openai.com/v1     # LLM API base URL
HF_TOKEN=your_openai_api_key_here          # OpenAI / HuggingFace API key
MODEL_NAME=gpt-4o-mini                     # LLM model to use
ENV_URL=http://localhost:7860              # URL of the running RL environment server
```

In PowerShell, load them before running:

```powershell
$env:HF_TOKEN="your-real-api-key"
python inference.py
```

---

## 🚦 Running the Full Pipeline

```bash
# Terminal 1: Start the environment server
uvicorn api.server:app --host 0.0.0.0 --port 7860

# Terminal 2: Run the agent
python inference.py
```

---

## 📊 Scoring Criteria

| Metric | Description |
|--------|-------------|
| `reward` per step | Score from `0.0` to `1.0` for that action |
| `score` (episode) | `sum(rewards) / MAX_TOTAL_REWARD`, capped at `1.0` |
| `success` | `score >= 0.6` |
| `average_score` | Mean across all 3 tasks |

---

## 💡 Key Takeaways

| Aspect | Current (LLM) | Future (Trained RL) |
|--------|--------------|---------------------|
| Training needed? | ❌ No | ✅ Yes |
| Learns from rewards? | ❌ No | ✅ Yes |
| Improves over episodes? | ❌ No | ✅ Yes |
| API cost | 💸 Per call | 🆓 After training |
| Setup complexity | Low | High |

---

> 📝 **For Hackathon purposes**, the zero-shot LLM approach is perfectly valid and demonstrates the RL loop clearly. Training a full RL policy would be the next step for production deployment.
