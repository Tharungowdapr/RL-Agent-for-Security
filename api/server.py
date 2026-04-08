import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from env.security_env import SecurityEnv
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

env = SecurityEnv()

@app.get("/health")
def root():
    return {"status": "ok", "env": "security-vulnerability-triage", "version": "1.0.0"}


@app.post("/reset", response_model=ResetResult)
def reset(task_id: Optional[str] = "easy"):
    try:
        # Determine simple task difficulty if it's full string
        if "easy" in task_id or "task1" in task_id:
            env.task = "easy"
        elif "medium" in task_id or "task2" in task_id:
            env.task = "medium"
        else:
            env.task = "hard"

        obs = env.reset()
        return ResetResult(observation=obs, info={"task_id": env.task})
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/step", response_model=StepResult)
def step(action: Action):
    obs, reward, done, info = env.step(action)
    return StepResult(observation=obs, reward=reward, done=done, info=info)


@app.get("/state")
def state():
    return env.state()


@app.get("/tasks")
def list_tasks():
    return {
        "tasks": [
            {"id": "easy", "difficulty": "easy"},
            {"id": "medium", "difficulty": "medium"},
            {"id": "hard", "difficulty": "hard"}
        ]
    }


# Serve frontend static files
# Mount the dist folder that will be created by the build process
frontend_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "../frontend/dist"))

if os.path.exists(frontend_path):
    app.mount("/", StaticFiles(directory=frontend_path, html=True), name="static")

    @app.exception_handler(404)
    async def custom_404_handler(request, __):
        return FileResponse(os.path.join(frontend_path, "index.html"))
else:
    @app.get("/")
    def root_no_frontend():
        return {"message": "Server is running, but frontend was not found. Build the frontend first."}

if __name__ == "__main__":
    uvicorn.run("api.server:app", host="0.0.0.0", port=7860, reload=False)
