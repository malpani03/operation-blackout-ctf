import json
import struct

import forge_cipher_release as forge


base = forge.AAD
epoch = 20260927
epoch_encodings = {
    "epoch-ascii": str(epoch).encode(),
    "epoch-be32": struct.pack(">I", epoch),
    "epoch-le32": struct.pack("<I", epoch),
    "epoch-be64": struct.pack(">Q", epoch),
    "epoch-le64": struct.pack("<Q", epoch),
}

aad_candidates = {
    "empty": b"",
    "base": base,
    "base-hex-ascii": base.hex().encode(),
    "base-nul": base + b"\0",
    "epoch-field": f"epoch={epoch}".encode(),
    "epoch-field-pipes": f"|epoch={epoch}|".encode(),
}
for name, encoded in epoch_encodings.items():
    aad_candidates[name] = encoded
    aad_candidates[f"base-{name}"] = base + encoded
    aad_candidates[f"{name}-base"] = encoded + base
    aad_candidates[f"base-pipe-{name}"] = base + b"|" + encoded
    aad_candidates[f"base-colon-{name}"] = base + b":" + encoded
aad_candidates["base-epoch-field"] = base + f"|epoch={epoch}".encode()
aad_candidates["epoch-field-base"] = f"epoch={epoch}|".encode() + base

delta_cipher = int.from_bytes(
    forge.xor(forge.PEEK_CIPHERTEXT[:16], forge.LIST_CIPHERTEXT[:16]), "big"
)
delta_tag = int.from_bytes(forge.xor(forge.PEEK_TAG, forge.LIST_TAG), "big")
h_fourth = forge.gf_mul(delta_tag, forge.gf_inv(delta_cipher))
h = forge.gf_pow(h_fourth, 1 << 126)
keystream = forge.xor(forge.PEEK_CIPHERTEXT, forge.PEEK_PLAINTEXT)
ciphertext = forge.xor(forge.RELEASE_PLAINTEXT, keystream)

items = []
for name, aad in aad_candidates.items():
    mask = forge.xor(forge.PEEK_TAG, forge.ghash(h, aad, forge.PEEK_CIPHERTEXT))
    tag = forge.xor(mask, forge.ghash(h, aad, ciphertext))
    items.append({"name": name, "aad": aad.hex(), "tag": tag.hex()})

print(json.dumps({
    "nonce": forge.NONCE.hex(),
    "ciphertext": ciphertext.hex(),
    "candidates": items,
}, indent=2))
