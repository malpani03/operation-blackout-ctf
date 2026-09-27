import json
import math
from pathlib import Path

artifact = Path(__file__).resolve().parents[1] / "assets" / "artifact.json"
data = json.loads(artifact.read_text(encoding="utf-8"))
n1, n2 = data["moduli"]
shared = math.gcd(n1, n2)
if shared in (1, n1, n2):
    raise RuntimeError("moduli do not expose one non-trivial common factor")

other = n1 // shared
phi = (shared - 1) * (other - 1)
private_exponent = pow(data["exponent"], -1, phi)
plaintext = pow(data["ciphertext"], private_exponent, n1)

print(f"gcd={shared}")
print(f"n1={shared}*{other}")
print(f"phi={phi}")
print(f"d={private_exponent}")
print(f"answer={plaintext}")
