from __future__ import annotations

import json
import random
import struct

import forge_cipher_release as g


ZERO = 0
ONE = g.ONE


def ptrim(poly: list[int]) -> list[int]:
    while len(poly) > 1 and poly[-1] == 0:
        poly.pop()
    return poly


def padd(left: list[int], right: list[int]) -> list[int]:
    out = [0] * max(len(left), len(right))
    for index in range(len(out)):
        out[index] = (left[index] if index < len(left) else 0) ^ (
            right[index] if index < len(right) else 0
        )
    return ptrim(out)


def pmul(left: list[int], right: list[int]) -> list[int]:
    out = [0] * (len(left) + len(right) - 1)
    for i, a in enumerate(left):
        for j, b in enumerate(right):
            out[i + j] ^= g.gf_mul(a, b)
    return ptrim(out)


def pdivmod(numerator: list[int], denominator: list[int]):
    numerator = numerator[:]
    denominator = ptrim(denominator[:])
    if denominator == [0]:
        raise ZeroDivisionError
    quotient = [0] * max(1, len(numerator) - len(denominator) + 1)
    inverse_lead = g.gf_inv(denominator[-1])
    while len(numerator) >= len(denominator) and numerator != [0]:
        shift = len(numerator) - len(denominator)
        scale = g.gf_mul(numerator[-1], inverse_lead)
        quotient[shift] ^= scale
        for index, value in enumerate(denominator):
            numerator[index + shift] ^= g.gf_mul(scale, value)
        ptrim(numerator)
    return ptrim(quotient), ptrim(numerator)


def pmod(poly: list[int], modulus: list[int]) -> list[int]:
    return pdivmod(poly, modulus)[1]


def pgcd(left: list[int], right: list[int]) -> list[int]:
    while right != [0]:
        left, right = right, pmod(left, right)
    inverse = g.gf_inv(left[-1])
    return ptrim([g.gf_mul(value, inverse) for value in left])


def psquare_mod(poly: list[int], modulus: list[int]) -> list[int]:
    squared = [0] * (2 * len(poly) - 1)
    for index, value in enumerate(poly):
        squared[index * 2] = g.gf_mul(value, value)
    return pmod(ptrim(squared), modulus)


def roots_in_field(poly: list[int]) -> list[int]:
    poly = ptrim(poly)
    inverse = g.gf_inv(poly[-1])
    poly = [g.gf_mul(value, inverse) for value in poly]

    # Keep only factors dividing x^(2^128) - x, i.e. linear factors over GF(2^128).
    x_poly = [0, ONE]
    frobenius = x_poly
    for _ in range(128):
        frobenius = psquare_mod(frobenius, poly)
    linear_product = pgcd(poly, padd(frobenius, x_poly))
    if len(linear_product) == 1:
        return []

    rng = random.Random(0xC1F3)
    factors = [linear_product]
    while any(len(factor) > 2 for factor in factors):
        factor = next(item for item in factors if len(item) > 2)
        factors.remove(factor)
        while True:
            candidate = [rng.getrandbits(128) for _ in range(len(factor) - 1)]
            trace = [0]
            current = pmod(candidate, factor)
            for _ in range(128):
                trace = padd(trace, current)
                current = psquare_mod(current, factor)
            divisor = pgcd(trace, factor)
            if 1 < len(divisor) < len(factor):
                quotient, remainder = pdivmod(factor, divisor)
                if remainder != [0]:
                    raise AssertionError("polynomial split left a remainder")
                factors.extend([divisor, quotient])
                break

    roots = []
    for factor in factors:
        if len(factor) != 2:
            continue
        roots.append(g.gf_mul(factor[0], g.gf_inv(factor[1])))
    return roots


def ghash_polynomial(aad: bytes, ciphertext: bytes) -> list[int]:
    values = [*g.blocks(aad), *g.blocks(ciphertext)]
    values.append((len(aad) * 8 << 64) | (len(ciphertext) * 8))
    poly = [0] * (len(values) + 1)
    for index, value in enumerate(values):
        poly[len(values) - index] ^= value
    return ptrim(poly)


def aad_formats(sequence: int) -> dict[str, bytes]:
    epoch = 20260927
    base = g.AAD
    metadata = {
        "be32-be32": struct.pack(">II", epoch, sequence),
        "be32-be64": struct.pack(">IQ", epoch, sequence),
        "be64-be32": struct.pack(">QI", epoch, sequence),
        "be64-be64": struct.pack(">QQ", epoch, sequence),
        "le32-le32": struct.pack("<II", epoch, sequence),
        "le32-le64": struct.pack("<IQ", epoch, sequence),
        "le64-le32": struct.pack("<QI", epoch, sequence),
        "le64-le64": struct.pack("<QQ", epoch, sequence),
        "ascii-colon": f"{epoch}:{sequence}".encode(),
        "ascii-pipe": f"{epoch}|{sequence}".encode(),
        "ascii-comma": f"{epoch},{sequence}".encode(),
        "fields-pipe": f"epoch={epoch}|queue_seq={sequence}".encode(),
        "fields-comma": f"epoch={epoch},queue_seq={sequence}".encode(),
        "json": json.dumps({"epoch": epoch, "queue_seq": sequence}, separators=(",", ":")).encode(),
    }
    out = {}
    for name, value in metadata.items():
        out[f"base+{name}"] = base + value
        out[f"base|{name}"] = base + b"|" + value
        out[f"{name}+base"] = value + base
    return out


preferred = {
    "base+ascii-colon", "base|ascii-colon", "ascii-colon+base",
    "base+ascii-pipe", "base|ascii-pipe", "ascii-pipe+base",
    "base+ascii-comma", "base|ascii-comma", "ascii-comma+base",
    "base+fields-pipe", "base|fields-pipe", "fields-pipe+base",
    "base+fields-comma", "base|fields-comma", "fields-comma+base",
    "base+json", "base|json", "json+base",
}
formats7 = {name: value for name, value in aad_formats(7).items() if name in preferred}
formats14 = {name: value for name, value in aad_formats(14).items() if name in preferred}
formats19 = {name: value for name, value in aad_formats(19).items() if name in preferred}
forgeries = []
delta_tag = int.from_bytes(g.xor(g.PEEK_TAG, g.LIST_TAG), "big")

for format_name in formats7:
    aad7 = formats7[format_name]
    aad14 = formats14[format_name]
    equation = padd(
        padd(
            ghash_polynomial(aad7, g.PEEK_CIPHERTEXT),
            ghash_polynomial(aad14, g.LIST_CIPHERTEXT),
        ),
        [delta_tag],
    )
    for root_index, h in enumerate(roots_in_field(equation)):
        mask7 = g.xor(g.PEEK_TAG, g.ghash(h, aad7, g.PEEK_CIPHERTEXT))
        mask14 = g.xor(g.LIST_TAG, g.ghash(h, aad14, g.LIST_CIPHERTEXT))
        if mask7 != mask14:
            continue
        for mapping_name, known_plaintext in (
            ("record7-is-peek", g.PEEK_PLAINTEXT),
            ("record7-is-list", g.LIST_PLAINTEXT),
        ):
            keystream = g.xor(g.PEEK_CIPHERTEXT, known_plaintext)
            ciphertext = g.xor(g.RELEASE_PLAINTEXT, keystream)
            for source_name, target_aad in (("seq7", aad7), ("seq14", aad14), ("seq19", formats19[format_name])):
                tag = g.xor(mask7, g.ghash(h, target_aad, ciphertext))
                forgeries.append({
                    "format": format_name,
                    "root": root_index,
                    "h": h.to_bytes(16, "big").hex(),
                    "mapping": mapping_name,
                    "target_metadata": source_name,
                    "nonce": g.NONCE.hex(),
                    "ciphertext": ciphertext.hex(),
                    "tag": tag.hex(),
                })

with open("analysis/cipher-record-aad-forgeries.json", "w", encoding="utf-8") as handle:
    json.dump(forgeries, handle, indent=2)
print(json.dumps({"formats": len(formats7), "forgeries": len(forgeries)}, indent=2))
