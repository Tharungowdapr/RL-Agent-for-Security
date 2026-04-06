from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from env.environment import SecurityTriageEnv
from env.models import Action, StepResult, ResetResult
from typing import Optional
import uvicorn

app = FastAPI(
    title="Security Vulnerability Triage — OpenEnv",
    description="An OpenEnv environment for AI security triage agents",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"]
)

env = SecurityTriageEnv()


@app.get("/")
def root():
    return {"status": "ok", "env": "security-vulnerability-triage", "version": "1.0.0"}


@app.post("/reset", response_model=ResetResult)
def reset(task_id: Optional[str] = "task1_severity_ranking"):
    try:
        result = env.reset(task_id=task_id)
        return result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/step", response_model=StepResult)
def step(action: Action):
    result = env.step(action)
    return result


@app.get("/state")
def state():
    return env.get_state()


@app.get("/tasks")
def list_tasks():
    return {
        "tasks": [
            {"id": "task1_severity_ranking", "difficulty": "easy"},
            {"id": "task2_asset_prioritization", "difficulty": "medium"},
            {"id": "task3_full_triage", "difficulty": "hard"}
        ]
    }


if __name__ == "__main__":
    uvicorn.run("api.server:app", host="0.0.0.0", port=7860, reload=False)
