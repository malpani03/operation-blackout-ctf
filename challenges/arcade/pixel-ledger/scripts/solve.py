import itertools
import json
from pathlib import Path

artifact = Path(__file__).resolve().parents[1] / "assets" / "artifact.json"
data = json.loads(artifact.read_text(encoding="utf-8"))
n = data["size"]

def runs(values):
    result = []
    length = 0
    for value in values + [0]:
        if value:
            length += 1
        elif length:
            result.append(length)
            length = 0
    return result or [0]

solutions = []
for bits in itertools.product((0, 1), repeat=n * n):
    grid = [list(bits[offset:offset + n]) for offset in range(0, n * n, n)]
    if [runs(row) for row in grid] != data["rows"]:
        continue
    columns = [[grid[row][column] for row in range(n)] for column in range(n)]
    if [runs(column) for column in columns] == data["columns"]:
        solutions.append(grid)

if len(solutions) != 1:
    raise RuntimeError(f"expected one solution, found {len(solutions)}")

for row in solutions[0]:
    print("".join(map(str, row)))
print("answer=" + "".join(str(value) for row in solutions[0] for value in row))
