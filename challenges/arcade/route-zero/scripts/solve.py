import heapq
import json
from pathlib import Path

artifact = Path(__file__).resolve().parents[1] / "assets" / "artifact.json"
data = json.loads(artifact.read_text(encoding="utf-8"))

graph = {}
for source, destination, cost in data["edges"]:
    graph.setdefault(source, []).append((destination, cost))

queue = [(0, data["start"], [data["start"]])]
best = {}
while queue:
    cost, node, path = heapq.heappop(queue)
    if node in best:
        continue
    best[node] = cost
    if node == data["finish"]:
        print(f"path={'->'.join(path)}")
        print(f"cost={cost}")
        break
    for destination, edge_cost in graph.get(node, []):
        if destination not in best:
            heapq.heappush(queue, (cost + edge_cost, destination, path + [destination]))
