from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any


class CVERecord(BaseModel):
    cve_id: str
    description: str
    cvss_score: float = Field(ge=0.0, le=10.0)
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    exploitability_score: float = Field(ge=0.0, le=10.0)
    patch_available: bool
    affected_software: List[str]
    published_date: str
    # Threat intelligence fields (enriched post-fetch)
    epss_score: float = Field(default=0.0, ge=0.0, le=1.0,
                              description="EPSS exploit probability (0-1)")
    in_kev: bool = Field(default=False,
                         description="Present in CISA KEV catalog")


class CompanyAsset(BaseModel):
    asset_id: str
    name: str
    software: List[str]
    criticality: str  # LOW, MEDIUM, HIGH, CRITICAL
    criticality_score: float = Field(ge=0.0, le=10.0)
    description: str


class Observation(BaseModel):
    task_id: str
    step: int
    cves: List[CVERecord]
    assets: List[CompanyAsset]
    patches_available_count: int
    message: str
    done: bool = False


class Action(BaseModel):
    priority_order: List[str] = Field(
        description="CVE IDs ordered from highest to lowest priority"
    )
    justifications: Optional[Dict[str, str]] = Field(
        default=None,
        description="Optional justification per CVE ID"
    )


class Reward(BaseModel):
    score: float = Field(ge=0.0, le=1.0)
    breakdown: Dict[str, float]
    feedback: str


class StepResult(BaseModel):
    observation: Observation
    reward: float
    done: bool
    info: Dict[str, Any] = {}


class ResetResult(BaseModel):
    observation: Observation
    info: Dict[str, Any] = {}
