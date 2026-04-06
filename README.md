# Security Vulnerability Triage — OpenEnv

An OpenEnv environment where an AI agent triages real-world CVEs.

## Tasks
| Task | Difficulty | Description |
|------|-----------|-------------|
| task1_severity_ranking | Easy | Rank CVEs by CVSS score |
| task2_asset_prioritization | Medium | Prioritize by severity + asset criticality |
| task3_full_triage | Hard | Full triage with noise, red herrings, limited patches |

## Setup

### Local
```bash
pip install -r requirements.txt
uvicorn api.server:app --host 0.0.0.0 --port 7860
```

### Docker
```bash
docker build -t security-triage-env .
docker run -p 7860:7860 security-triage-env
```

### Inference
```bash
export API_BASE_URL=https://api.openai.com/v1
export HF_TOKEN=your_key
export MODEL_NAME=gpt-4o-mini
export ENV_URL=http://localhost:7860
python inference.py
```

## Baseline Scores
| Task | Score |
|------|-------|
| task1_severity_ranking | ~0.72 |
| task2_asset_prioritization | ~0.58 |
| task3_full_triage | ~0.41 |
