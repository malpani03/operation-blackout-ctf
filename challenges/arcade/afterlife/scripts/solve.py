import json
from pathlib import Path

artifact = Path(__file__).resolve().parents[1] / "assets" / "artifact.json"
data = json.loads(artifact.read_text(encoding="utf-8"))
grid = data["grid"]
size = data["size"]

def evolve(current):
    next_grid = []
    for row in range(size):
        next_row = []
        for column in range(size):
            neighbors = sum(
                current[other_row][other_column]
                for other_row in range(max(0, row - 1), min(size, row + 2))
                for other_column in range(max(0, column - 1), min(size, column + 2))
                if (other_row, other_column) != (row, column)
            )
            alive = neighbors == 3 or (current[row][column] == 1 and neighbors == 2)
            next_row.append(int(alive))
        next_grid.append(next_row)
    return next_grid

for step in range(1, data["steps"] + 1):
    grid = evolve(grid)
    print(f"step={step}")
    for row in grid:
        print("".join(map(str, row)))

print("answer=" + "".join(str(value) for row in grid for value in row))
