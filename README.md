---
title: Security Vulnerability Triage
emoji: 🛡️
colorFrom: red
colorTo: slate
sdk: docker
app_port: 7860
pinned: false
---

# Security Vulnerability Triage — RL Agent Environment

This repository contains an environment for training and evaluating RL agents on security vulnerability triage tasks. It features a FastAPI backend and a React-based frontend for visualization.

## Architecture

- **Backend**: FastAPI server providing an OpenAI Gym-like interface for the environment.
- **Frontend**: React application for monitoring the agent's progress and inspecting vulnerability data.
- **Agent**: A sample Python agent using LLMs to prioritize vulnerabilities.

## How to Run

### Docker (Recommended)

```bash
docker build -t security-triage .
docker run -p 7860:7860 security-triage
```

Access the application at `http://localhost:7860`.

## License

This project is licensed under the MIT License.
