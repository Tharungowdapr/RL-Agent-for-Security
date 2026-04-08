from typing import Tuple, Dict
from env.models import Observation, Action

from threat_intel.cve_loader import load_cves
from threat_intel.epss import get_epss_scores
from threat_intel.kev import get_kev_list

class SecurityEnv:

    def __init__(self, task="easy"):
        self.task = task
        self.step_count = 0
        self.done = False
        self.vulnerabilities = []
        self.selected = set()

    def reset(self):
        import random
        random.seed(42)
        
        self.step_count = 0
        self.done = False
        self.selected.clear()

        # REAL DATA PIPELINE
        cves = load_cves()[:10]

        epss = get_epss_scores()
        kev = get_kev_list()

        self.vulnerabilities = []

        # Map to common dict for observation so pydantic can parse
        for cve in cves:
            self.vulnerabilities.append({
                "id": cve["id"],
                "severity": cve.get("cvss", 5),
                "epss": epss.get(cve["id"], 0.0),
                "kev": cve["id"] in kev,
                "asset_criticality": 5,
                "description": cve.get("description", ""),
                "severity_label": cve.get("severity_label", "MEDIUM")
            })

        self.vulnerabilities = sorted(self.vulnerabilities, key=lambda x: x["id"])

        return Observation(
            vulnerabilities=self.vulnerabilities,
            step=self.step_count,
            task=self.task,
            message="Environment reset.",
            done=self.done
        )

    def step(self, action: Action) -> Tuple[Observation, float, bool, Dict]:
        self.step_count += 1

        reward = 0.0
        error = None
        rank = -1
        selected_vuln = {}

        # ❌ invalid ID
        valid_ids = [v["id"] for v in self.vulnerabilities]
        if action.target_id not in valid_ids:
            reward = -0.5
            error = "invalid_id"
        else:
            # 🔥 Compute ranking
            if self.task == "easy":
                key_fn = lambda v: v["severity"]
            elif self.task == "medium":
                key_fn = lambda v: v["severity"] * 0.6 + v["epss"] * 0.4
            else:
                from core.scoring import compute_priority
                key_fn = compute_priority

            sorted_vulns = sorted(self.vulnerabilities, key=key_fn, reverse=True)
            top_ids = [v["id"] for v in sorted_vulns]

            # 🎯 Reward shaping (TOP-K)
            if action.target_id == top_ids[0]:
                reward = 1.0
                rank = 1
            elif action.target_id in top_ids[:3]:
                reward = 0.7
                rank = top_ids.index(action.target_id) + 1
            elif action.target_id in top_ids[:5]:
                reward = 0.4
                rank = top_ids.index(action.target_id) + 1
            else:
                reward = -0.2
                rank = top_ids.index(action.target_id) + 1

            selected_vuln = next(v for v in self.vulnerabilities if v["id"] == action.target_id)

            # 🔥 KEV BONUS
            if selected_vuln.get("kev", False):
                reward += 0.2

            # ❌ duplicate penalty
            if action.target_id in self.selected:
                reward -= 0.3
                error = "duplicate"
            else:
                self.selected.add(action.target_id)

        if self.step_count >= 3:
            self.done = True

        obs = Observation(
            vulnerabilities=self.vulnerabilities,
            step=self.step_count,
            task=self.task,
            message=error if error else "",
            done=self.done
        )

        info = {
            "error": error,
            "selected_rank": rank,
            "kev": selected_vuln.get("kev", False)
        }

        return obs, round(reward, 2), self.done, info

    def state(self):
        return {
            "step": self.step_count,
            "selected": list(self.selected)
        }
