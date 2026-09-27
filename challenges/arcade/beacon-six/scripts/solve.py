import struct
import wave
from pathlib import Path

artifact = Path(__file__).resolve().parents[1] / "assets" / "beacon-six.wav"

with wave.open(str(artifact), "rb") as source:
    if source.getnchannels() != 1 or source.getsampwidth() != 2:
        raise RuntimeError("expected mono 16-bit PCM")
    rate = source.getframerate()
    samples = struct.unpack(f"<{source.getnframes()}h", source.readframes(source.getnframes()))

# The acquisition uses an 80 ms Morse unit. Classify each complete unit by
# energy, then collapse adjacent active units into dot/dash durations.
unit_samples = round(rate * 0.08)
units = []
for offset in range(0, len(samples), unit_samples):
    window = samples[offset:offset + unit_samples]
    energy = sum(value * value for value in window)
    units.append(energy > 1_000_000)

runs = []
start = 0
state = units[0]
for index, next_state in enumerate(units[1:], 1):
    if next_state != state:
        runs.append((state, index - start))
        state = next_state
        start = index
runs.append((state, len(units) - start))

groups = []
current = []
for active, length in runs:
    if active:
        current.append("-" if length >= 3 else ".")
    elif length >= 3 and current:
        groups.append("".join(current))
        current = []
if current:
    groups.append("".join(current))

digits = {
    "-----": "0", ".----": "1", "..---": "2", "...--": "3", "....-": "4",
    ".....": "5", "-....": "6", "--...": "7", "---..": "8", "----.": "9",
}
answer = "".join(digits[group] for group in groups)
print("groups=" + " ".join(groups))
print("answer=" + answer)
