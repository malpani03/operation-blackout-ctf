import hashlib
import hmac
import itertools
import json
from pathlib import Path


payload = Path("analysis/cipher-envelope.bin").read_bytes()
frame = Path("analysis/cipher-transport-frame.bin").read_bytes()
checksum = Path("analysis/cipher-transport-checksum.bin").read_bytes()
document = Path("../../forensics/the-evidence/analysis/recovered-document.bin").read_bytes()
handover = json.loads(Path("../../forensics/the-evidence/analysis/evidence-case-handover.json").read_text())
doc = json.loads(document)

registered = bytes.fromhex("388b6eb595bbe45a34137849ecfbebce3e581f5312c3514e")
sorted_cals = bytes.fromhex("ce5849781f5351b5344e3e6e95fb8bbbeceb12e4135ac338")

archives = {
    "archive-id-hex": bytes.fromhex("7ac51adc827f"),
    "archive-id-ascii": b"7ac51adc827f",
    "archive-key-hex": bytes.fromhex(doc["archive_key"]),
    "archive-key-ascii": doc["archive_key"].encode(),
    "proof-hex": bytes.fromhex(doc["archive_key"][:24]),
    "proof-ascii": doc["archive_key"][:24].encode(),
    "document": document,
    "task-hex": bytes.fromhex(doc["task"]),
    "task-ascii": doc["task"].encode(),
    "receipt-hex": bytes.fromhex(handover["receipt"]),
    "receipt-ascii": handover["receipt"].encode(),
}
cals = {
    "registered-raw-first16": registered[:16],
    "sorted-raw-first16": sorted_cals[:16],
    "registered-hex-first16": registered.hex()[:16].encode(),
    "sorted-hex-first16": sorted_cals.hex()[:16].encode(),
    "registration-file-first16": Path("assets/cipher-acquisition/registrations.log").read_bytes()[:16],
    "sensors-file-first16": Path("assets/cipher-acquisition/sensors.yaml").read_bytes()[:16],
}
messages = {
    "payload": payload,
    "header-payload": frame[:-20],
    "header": frame[:8],
}

matches = []
keys = {}
for (archive_name, archive), (cal_name, cal) in itertools.product(archives.items(), cals.items()):
    for order, pieces in {
        "archive-cal": (archive, cal),
        "cal-archive": (cal, archive),
        "archive-pipes-cal": (archive, b"||", cal),
        "cal-pipes-archive": (cal, b"||", archive),
        "archive-colon-cal": (archive, b":", cal),
    }.items():
        digest = hashlib.sha256(b"".join(pieces)).digest()
        for trunc, key in {"first": digest[:16], "last": digest[-16:]}.items():
            key_name = f"{archive_name}/{cal_name}/{order}/{trunc}"
            keys[key_name] = key
            for msg_name, message in messages.items():
                candidates = {
                    "hmac-sha1": hmac.new(key, message, hashlib.sha1).digest(),
                    "hmac-sha256-20": hmac.new(key, message, hashlib.sha256).digest()[:20],
                    "sha1-key-msg": hashlib.sha1(key + message).digest(),
                    "sha1-msg-key": hashlib.sha1(message + key).digest(),
                    "sha256-key-msg-20": hashlib.sha256(key + message).digest()[:20],
                    "sha256-msg-key-20": hashlib.sha256(message + key).digest()[:20],
                }
                for algorithm, candidate in candidates.items():
                    if candidate == checksum:
                        matches.append((key_name, key.hex(), msg_name, algorithm))

print(json.dumps({"key_count": len(keys), "checksum": checksum.hex(), "matches": matches}, indent=2))
