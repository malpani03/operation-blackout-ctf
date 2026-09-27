from __future__ import annotations


AAD = bytes.fromhex("48582d313937377c6a6f75726e616c7c376163353161646338323766")
NONCE = bytes.fromhex("18a36dba1453cb10180bc217")

PEEK_PLAINTEXT = b"action=peek     |archive=7ac51adc827f           "
PEEK_CIPHERTEXT = bytes.fromhex(
    "1b944dd2b1309d9798e385f0ed3c72055cf773a556e7281b599aed06e7f27f5"
    "6aa9ca92889a76752f388a7b2259776c4"
)
PEEK_TAG = bytes.fromhex("8eda894fdf7078d99d341428e3191b47")

LIST_PLAINTEXT = b"action=list     |archive=7ac51adc827f           "
LIST_CIPHERTEXT = bytes.fromhex(
    "1b944dd2b1309d8b94f59af0ed3c72055cf773a556e7281b599aed06e7f27f5"
    "6aa9ca92889a76752f388a7b2259776c4"
)
LIST_TAG = bytes.fromhex("614d8d08bea732084076df28e060184d")

RELEASE_PLAINTEXT = b"action=release  |proof=a7bcdb38d64c8b780d31fab5|"

R = 0xE1000000000000000000000000000000
ONE = 1 << 127


def gf_mul(left: int, right: int) -> int:
    result = 0
    value = right
    for bit in range(128):
        if left & (1 << (127 - bit)):
            result ^= value
        value = (value >> 1) ^ (R if value & 1 else 0)
    return result


def gf_pow(value: int, exponent: int) -> int:
    result = ONE
    while exponent:
        if exponent & 1:
            result = gf_mul(result, value)
        value = gf_mul(value, value)
        exponent >>= 1
    return result


def gf_inv(value: int) -> int:
    if value == 0:
        raise ZeroDivisionError("zero has no multiplicative inverse")
    return gf_pow(value, (1 << 128) - 2)


def blocks(data: bytes):
    for offset in range(0, len(data), 16):
        yield int.from_bytes(data[offset:offset + 16].ljust(16, b"\0"), "big")


def ghash(h: int, aad: bytes, ciphertext: bytes) -> bytes:
    state = 0
    for block in (*blocks(aad), *blocks(ciphertext)):
        state = gf_mul(state ^ block, h)
    lengths = (len(aad) * 8 << 64) | (len(ciphertext) * 8)
    state = gf_mul(state ^ lengths, h)
    return state.to_bytes(16, "big")


def xor(left: bytes, right: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(left, right))


if len(PEEK_PLAINTEXT) != 48 or len(LIST_PLAINTEXT) != 48 or len(RELEASE_PLAINTEXT) != 48:
    raise AssertionError("command ABI must be exactly 48 bytes")
if xor(PEEK_PLAINTEXT, LIST_PLAINTEXT) != xor(PEEK_CIPHERTEXT, LIST_CIPHERTEXT):
    raise AssertionError("retained activity does not match the colliding ciphertext pair")

# AAD occupies two GHASH blocks, followed by three ciphertext blocks and the
# length block. The reused records differ only in ciphertext block one, so:
#   tag1 xor tag2 = (cipher1[0] xor cipher2[0]) * H^4
delta_cipher = int.from_bytes(xor(PEEK_CIPHERTEXT[:16], LIST_CIPHERTEXT[:16]), "big")
delta_tag = int.from_bytes(xor(PEEK_TAG, LIST_TAG), "big")
h_fourth = gf_mul(delta_tag, gf_inv(delta_cipher))
h = gf_pow(h_fourth, 1 << 126)  # inverse of x -> x^4 in GF(2^128)
if gf_pow(h, 4) != h_fourth:
    raise AssertionError("failed to recover the GCM authentication subkey")

mask = xor(PEEK_TAG, ghash(h, AAD, PEEK_CIPHERTEXT))
if xor(mask, ghash(h, AAD, LIST_CIPHERTEXT)) != LIST_TAG:
    raise AssertionError("recovered authentication state does not validate both records")

keystream = xor(PEEK_CIPHERTEXT, PEEK_PLAINTEXT)
release_ciphertext = xor(RELEASE_PLAINTEXT, keystream)
release_tag = xor(mask, ghash(h, AAD, release_ciphertext))

print(f"aad={AAD.hex()}")
print(f"nonce={NONCE.hex()}")
print(f"H={h.to_bytes(16, 'big').hex()}")
print(f"ciphertext={release_ciphertext.hex()}")
print(f"tag={release_tag.hex()}")
