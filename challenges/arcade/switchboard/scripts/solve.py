import json
from pathlib import Path

artifact = Path(__file__).resolve().parents[1] / "assets" / "artifact.json"
data = json.loads(artifact.read_text(encoding="utf-8"))

graph = {variable: [] for variable in data["variables"]}
for left, right, difference in data["relations"]:
    graph[left].append((right, difference))
    graph[right].append((left, difference))

anchor, value = data["anchor"]
values = {anchor: value}
queue = [anchor]
while queue:
    left = queue.pop(0)
    for right, difference in graph[left]:
        expected = values[left] ^ difference
        if right in values and values[right] != expected:
            raise RuntimeError("inconsistent relation set")
        if right not in values:
            values[right] = expected
            queue.append(right)

answer = "".join(str(values[variable]) for variable in data["variables"])
print(" ".join(f"{variable}={values[variable]}" for variable in data["variables"]))
print("answer=" + answer)
