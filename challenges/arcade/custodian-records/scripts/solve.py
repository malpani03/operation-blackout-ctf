import json
from pathlib import Path

artifact = Path(__file__).resolve().parents[1] / "assets" / "artifact.json"
data = json.loads(artifact.read_text(encoding="utf-8"))
prime = data["prime"]
shares = data["shares"]

secret = 0
for index, (x_i, y_i) in enumerate(shares):
    numerator = 1
    denominator = 1
    for other, (x_j, _) in enumerate(shares):
        if index == other:
            continue
        numerator = numerator * (-x_j) % prime
        denominator = denominator * (x_i - x_j) % prime
    basis = numerator * pow(denominator, -1, prime) % prime
    contribution = y_i * basis % prime
    print(f"share=({x_i},{y_i}) basis={basis} contribution={contribution}")
    secret = (secret + contribution) % prime

print(f"answer={secret}")
