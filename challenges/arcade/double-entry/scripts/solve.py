import json
from pathlib import Path

artifact = Path(__file__).resolve().parents[1] / "assets" / "artifact.json"
data = json.loads(artifact.read_text(encoding="utf-8"))

balance = data["opening_cents"]
seen = set()
for event in data["events"]:
    if event["event"] in seen:
        print(f"duplicate event {event['event']} ignored")
        continue
    seen.add(event["event"])
    sign = 1 if event["kind"] == "charge" else -1
    balance += sign * event["cents"]

print(f"unique_events={len(seen)}")
print(f"final_balance_cents={balance}")
