import json
import re
from pathlib import Path

artifact = Path(__file__).resolve().parents[1] / "assets" / "artifact.json"
data = json.loads(artifact.read_text(encoding="utf-8"))
cells = [" "] * data["width"]
cursor = 0
stream = data["stream"]
offset = 0

while offset < len(stream):
    if stream[offset] == "\x1b":
        match = re.match(r"\x1b\[(\d+)G", stream[offset:])
        if not match:
            raise RuntimeError(f"unsupported escape at offset {offset}")
        cursor = int(match.group(1)) - 1
        offset += len(match.group(0))
    elif stream[offset] == "\b":
        cursor = max(0, cursor - 1)
        offset += 1
    else:
        cells[cursor] = stream[offset]
        cursor = min(len(cells), cursor + 1)
        offset += 1

print("answer=" + "".join(cells))
