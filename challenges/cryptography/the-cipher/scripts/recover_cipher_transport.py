import datetime as dt
import hashlib
import json
from pathlib import Path

from analyze_cipher_pcap import packets


SOURCE_IP = "10.27.7.29"
SENSOR_ID = "F-2F9E"
PHASE_THRESHOLD_MS = 40
MAGIC = b"TRP2"


samples = []
for row in packets():
    if row[3] != SOURCE_IP:
        continue
    record = json.loads(row[8])
    if record["id"] != SENSOR_ID:
        raise ValueError(f"Unexpected sensor identity: {record['id']}")
    transmitter = dt.datetime.fromisoformat(record["ts"].replace("Z", "+00:00")).timestamp()
    phase_ms = (row[1] - transmitter) * 1000
    samples.append(1 if phase_ms > PHASE_THRESHOLD_MS else 0)

magic_bits = "".join(f"{value:08b}" for value in MAGIC)
bitstream = "".join(str(value) for value in samples)
start = bitstream.find(magic_bits)
if start < 0:
    raise ValueError("TRP2 frame marker not found")

aligned = samples[start:]
frame = bytes(
    sum(aligned[offset + bit] << (7 - bit) for bit in range(8))
    for offset in range(0, len(aligned) - 7, 8)
)
if frame[:4] != MAGIC:
    raise AssertionError("Frame alignment failed")

version = frame[4]
flags = frame[5]
payload_length = int.from_bytes(frame[6:8], "big")
payload = frame[8:8 + payload_length]
checksum = frame[8 + payload_length:8 + payload_length + 20]
padding = frame[8 + payload_length + 20:]
if len(payload) != payload_length:
    raise ValueError("Truncated TRP2 payload")
if any(padding):
    raise ValueError("Non-zero data follows TRP2 checksum")

outputs = {
    Path("analysis/cipher-transport-frame.bin"): frame[:8 + payload_length + 20],
    Path("analysis/cipher-envelope.bin"): payload,
    Path("analysis/cipher-transport-checksum.bin"): checksum,
}
for path, data in outputs.items():
    path.write_bytes(data)

print(json.dumps({
    "source_ip": SOURCE_IP,
    "sensor_id": SENSOR_ID,
    "samples": len(samples),
    "frame_bit_offset": start,
    "version": version,
    "flags": flags,
    "payload_bytes": len(payload),
    "checksum_hex": checksum.hex(),
    "zero_padding_bytes": len(padding),
    "frame_sha256": hashlib.sha256(outputs[Path("analysis/cipher-transport-frame.bin")]).hexdigest(),
    "payload_sha256": hashlib.sha256(payload).hexdigest(),
}, indent=2))
