# 🔐 Security Vulnerability Triage — OpenEnv

An active OpenEnv simulator where an AI agent works alongside a **Deterministic Threat Intel Engine** to triage real-world CVEs across a simulated company's asset inventory.

Please refer to [setup.md](setup.md) for comprehensive setup and running instructions, and [detail.md](detail.md) for deep-dives into the mathematical RL priorities.

---

## 📖 What is it?
Every piece of software has bugs. Some bugs are harmless, some can be exploited by hackers to steal data, crash systems, or take control of servers. These exploitable bugs are called **vulnerabilities** (CVEs).

The problem? A large company gets **hundreds of new CVEs every week**. They can't patch everything at once. 

That job is called **Vulnerability Triage**.

### What This Environment Does
This project simulates the exact pressures of a Security Operations Center (SOC). It:
1. Streams real vulnerabilities out of the National Vulnerability Database.
2. Dynamically enriches them with **Live Threat Intelligence**:
    - **EPSS:** Exploit Prediction Scoring System probabilities.
    - **CISA KEV:** Real-time Known Exploited Vulnerability flags.
3. Tests an AI Agent's capacity to digest this context, rank the vulnerabilities mathematically by *actual business risk*, and justify its patching decisions into a JSON structure!

---

## 🗂️ The 3 Tasks

### 🟢 Task 1 — Basic Severity Ranking (Easy)
**Scenario:** Agent receives 10 CVEs with primitive CVSS severity scores and must sort them safely.
**Grader:** Sort-Accuracy metric vs True Context Ranking.

### 🟡 Task 2 — Asset-Aware Prioritization (Medium)
**Scenario:** Agent receives CVEs and a live Company Asset Manifest detailing server systems and importance weight constraints. 
**Grader:** Multi-dimensional scoring evaluating severity mapping to correct asset criticalities, plus EPSS/KEV probability weightings.

### 🔴 Task 3 — Full Triage Under Noise + AI Fallback (Hard)
**Scenario:** Agent receives noise (Duplicate logs, 2013-era outdated vulnerabilities, disputed vulnerabilities) and massive threat flags.
**Grader:** Severe multi-criteria evaluation punishing duplicates correctly formatting exactly 5 true actionable vulnerabilities out of a sea of 20 parameters.

---

## 🎨 Interactive Frontend Dashboard
This environment now comes with a fully engineered **Drag-and-Drop React Dashboard** seamlessly served by FastAPI!
- View rich CVE cards complete with **CISA KEV alarms** and sliding **EPSS visual probability bars**!
- Manually run triage and immediately view how the RL Grader responds through a dynamic **Radial Score breakdown**!
- Navigate to `http://localhost:7860/` after running the backend to interact live with the OpenEnv server visually.

---

## 📁 Project Structure

Here's the complete layout including the SOC visual layer:

```text
security-triage-env/
│
├── 📄 detail.md                     ← Explains mathematical models & engine
├── 📄 setup.md                      ← Quickstart
├── 📄 openenv.yaml
├── 📄 inference.py                  ← OpenAI AI Baseline
├── 📄 .env                          ← Secure secrets
│
├── frontend/                        ← Interactive Drag-and-Drop UI (Vite/React)
│   ├── src/
│   │   ├── components/              ← SOC-themed visual layers (CVECard, Assets, Reward)
│   │   └── api/envClient.js         ← Axios bridge to FastAPI env endpoints
│   └── dist/                        ← Re-compiled UI assets
│
├── env/                             ← Core RL components
│   ├── environment.py               
│   ├── models.py                    ← Typings for CVE, Asset, Observation
│   └── reward.py                    ← Formula scoring engines
│
├── data/                            ← Live Information Engine
│   ├── nvd_fetcher.py               ← Baseline cache
│   ├── asset_generator.py           ← Synthetic infra configs
│   ├── threat_intel.py              ← EPSS and CISA KEV fetchers
│   └── cache/                       
│
├── tasks/                           ← Mission Definitions
│   ├── task1_severity_ranking.py    
│   ├── task2_asset_prioritization.py 
│   └── task3_full_triage.py         
│
├── api/
│   └── server.py                    ← FastAPI logic bridging Python to Frontend
│
└── tests/
```

---

## 🔑 Key Design Innovations

**Threat Intel Enrichment:** Our CVEs don't just sit statically. When the server launches, `threat_intel.py` fires off batch queries, indexing hundreds of active exploit rates from CISA, actively upgrading all models.

**Intelligent Deterministic Fallback:** What happens if the `inference.py` OpenAI API key gets rated-limited or depleted? Our pipeline intercepts the `429` failure and defaults into an internal logic processor that calculates triage scores deterministically — continuing the pipeline without ever crashing!

**Single-Container Static React Build:** `FastAPI` statically mounts our React single-page application out of `frontend/dist/`. Simply launching the standard OpenEnv API server spins up the fully interactive frontend instantly for judging!

---

## 🚀 Quick Run Guide

**1. Install Dependencies**
```bash
pip install -r requirements.txt
```

**2. Compile Frontend (Optional if already compiled)**
```bash
cd frontend
npm install
npm run build
cd ..
```

**3. Fire Up the Server + Dashboard**
```bash
uvicorn api.server:app --host 0.0.0.0 --port 7860
```
Then visit `http://localhost:7860` to play the triage game visually!

**4. Run Automated AI Benchmark**
Fill your `.env` securely with `HF_TOKEN=your_openai_key`.
```bash
python inference.py
```
