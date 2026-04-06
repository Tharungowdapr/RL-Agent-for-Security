from typing import List, Optional, Dict, Any
from env.models import CVERecord, CompanyAsset, Action


class EpisodeState:
    def __init__(self):
        self.task_id: str = ""
        self.step: int = 0
        self.max_steps: int = 3
        self.cves: List[CVERecord] = []
        self.assets: List[CompanyAsset] = []
        self.patches_available: int = 5
        self.actions_taken: List[Action] = []
        self.done: bool = False
        self.total_reward: float = 0.0
        self.metadata: Dict[str, Any] = {}

    def reset(
        self,
        task_id: str,
        cves: List[CVERecord],
        assets: List[CompanyAsset],
        patches_available: int = 5,
        max_steps: int = 3
    ):
        self.task_id = task_id
        self.step = 0
        self.max_steps = max_steps
        self.cves = cves
        self.assets = assets
        self.patches_available = patches_available
        self.actions_taken = []
        self.done = False
        self.total_reward = 0.0
        self.metadata = {}

    def record_action(self, action: Action, reward: float):
        self.actions_taken.append(action)
        self.step += 1
        self.total_reward += reward
        if self.step >= self.max_steps:
            self.done = True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "task_id": self.task_id,
            "step": self.step,
            "max_steps": self.max_steps,
            "done": self.done,
            "total_reward": self.total_reward,
            "cve_count": len(self.cves),
            "asset_count": len(self.assets),
            "actions_taken": len(self.actions_taken),
        }
