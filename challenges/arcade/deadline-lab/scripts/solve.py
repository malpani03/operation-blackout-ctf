import itertools
import json
from pathlib import Path

artifact = Path(__file__).resolve().parents[1] / "assets" / "artifact.json"
data = json.loads(artifact.read_text(encoding="utf-8"))
jobs = {job["id"]: job for job in data["jobs"]}

best = None
for order in itertools.permutations(jobs):
    if not all(order.index(before) < order.index(after) for before, after in data["precedence"]):
        continue
    elapsed = 0
    cost = 0
    breakdown = []
    for job_id in order:
        elapsed += jobs[job_id]["duration"]
        contribution = elapsed * jobs[job_id]["weight"]
        cost += contribution
        breakdown.append((job_id, elapsed, contribution))
    candidate = (cost, "".join(order), breakdown)
    if best is None or candidate[:2] < best[:2]:
        best = candidate

print(f"order={best[1]}")
for job_id, completion, contribution in best[2]:
    print(f"{job_id}: completion={completion} weighted={contribution}")
print(f"cost={best[0]}")
