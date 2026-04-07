import random
from typing import Optional
from env.models import (
    Observation, Action, StepResult, ResetResult
)
from env.state_manager import EpisodeState
from env.reward import compute_reward
from data.nvd_fetcher import load_or_fetch_cves
from data.asset_generator import generate_assets
from data.threat_intel import enrich_cves_with_threat_intel
from tasks import task1_severity_ranking, task2_asset_prioritization, task3_full_triage

TASK_MODULES = {
    "task1_severity_ranking": task1_severity_ranking,
    "task2_asset_prioritization": task2_asset_prioritization,
    "task3_full_triage": task3_full_triage,
}


class SecurityTriageEnv:
    def __init__(self):
        self.state = EpisodeState()
        self._all_cves = load_or_fetch_cves()
        # Enrich with live threat intelligence (EPSS + CISA KEV)
        enrich_cves_with_threat_intel(self._all_cves)

    def reset(self, task_id: Optional[str] = None) -> ResetResult:
        if task_id is None:
            task_id = "task1_severity_ranking"

        task = TASK_MODULES.get(task_id)
        if task is None:
            raise ValueError(f"Unknown task_id: {task_id}")

        cves, assets = task.build_scenario(self._all_cves)

        self.state.reset(
            task_id=task_id,
            cves=cves,
            assets=assets,
            patches_available=5,
            max_steps=3
        )

        obs = task.build_observation(cves, assets, step=0)
        return ResetResult(observation=obs, info={"task_id": task_id})

    def step(self, action: Action) -> StepResult:
        if self.state.done:
            obs = self._current_observation()
            return StepResult(
                observation=obs, reward=0.0, done=True,
                info={"message": "Episode already done"}
            )

        reward_obj = compute_reward(
            task_id=self.state.task_id,
            action=action,
            cves=self.state.cves,
            assets=self.state.assets
        )

        self.state.record_action(action, reward_obj.score)

        obs = self._current_observation()
        obs.done = self.state.done

        return StepResult(
            observation=obs,
            reward=reward_obj.score,
            done=self.state.done,
            info={
                "feedback": reward_obj.feedback,
                "breakdown": reward_obj.breakdown,
                "step": self.state.step
            }
        )

    def get_state(self) -> dict:
        return self.state.to_dict()

    def _current_observation(self) -> Observation:
        task = TASK_MODULES[self.state.task_id]
        return task.build_observation(
            self.state.cves,
            self.state.assets,
            self.state.step
        )
