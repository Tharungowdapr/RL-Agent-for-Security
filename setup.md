# Security Vulnerability Triage — OpenEnv Details

## Tasks
| Task | Difficulty | Description |
|------|-----------|-------------|
| task1_severity_ranking | Easy | Rank CVEs by CVSS score |
| task2_asset_prioritization | Medium | Prioritize by severity + asset criticality |
| task3_full_triage | Hard | Full triage with noise, red herrings, limited patches |

## Baseline Scores
| Task | Score |
|------|-------|
| task1_severity_ranking | ~0.72 |
| task2_asset_prioritization | ~0.58 |
| task3_full_triage | ~0.41 |

---

# 🛠️ Comprehensive Setup Guide

### Step 1 — Clone and install
```bash
git clone https://github.com/Tharungowdapr/RL-Agent-for-Security.git
cd RL-Agent-for-Security
pip install -r requirements.txt
```

### Step 2 — Pre-fetch CVE data
```bash
python -c "from data.nvd_fetcher import load_or_fetch_cves; cves = load_or_fetch_cves(); print(f'Loaded {len(cves)} CVEs')"
```

### Step 3 — Start the server
```bash
uvicorn api.server:app --host 0.0.0.0 --port 7860
```

### Step 4 — Test it manually
```bash
curl http://localhost:7860/
curl -X POST "http://localhost:7860/reset?task_id=task1_severity_ranking"
curl -X POST http://localhost:7860/step \
  -H "Content-Type: application/json" \
  -d '{"priority_order": ["CVE-2024-0001", "CVE-2024-0005"]}'
```

### Step 5 — Run inference
```bash
export API_BASE_URL=https://api.openai.com/v1
export HF_TOKEN=sk-your-key
export MODEL_NAME=gpt-4o-mini
export ENV_URL=http://localhost:7860
python inference.py
```

### Step 6 — Docker Deployment
```bash
docker build -t security-triage-env .
docker run -p 7860:7860 \
  -e API_BASE_URL=https://api.openai.com/v1 \
  -e HF_TOKEN=your_key \
  security-triage-env
```

### Step 7 — Deploy to Hugging Face Spaces
- Create a new Space with **Docker** runtime
- Push this entire repo to the Space
- Set `HF_TOKEN`, `API_BASE_URL`, `MODEL_NAME` as Space secrets
- Space URL becomes your `ENV_URL`
