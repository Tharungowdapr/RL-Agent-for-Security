from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any

class Observation(BaseModel):
    vulnerabilities: List[Dict[str, Any]]
    step: int
    task: str
    message: str = ""
    done: bool = False

class Action(BaseModel):
    action_type: str = "prioritize"
    target_id: str

class StepResult(BaseModel):
    observation: Observation
    reward: float
    done: bool
    info: Dict[str, Any] = {}

class ResetResult(BaseModel):
    observation: Observation
    info: Dict[str, Any] = {}
