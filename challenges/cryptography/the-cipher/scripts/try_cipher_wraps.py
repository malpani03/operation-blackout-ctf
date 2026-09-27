import hashlib
import hmac
import re
from pathlib import Path


payload = Path("analysis/cipher-envelope.bin").read_bytes()
checksum = Path("analysis/cipher-transport-checksum.bin").read_bytes()
calibration = bytes.fromhex("388b6eb595bbe45a34137849ecfbebce")
archive_values = {
    "archive-id-hex": bytes.fromhex("7ac51adc827f"),
    "archive-id-ascii": b"7ac51adc827f",
    "proof-hex": bytes.fromhex("a7bcdb38d64c8b780d31fab5"),
    "archive-key-hex": bytes.fromhex(
        "a7bcdb38d64c8b780d31fab5502551314137f7593df9b7269b29499458be1c6e"
    ),
    "archive-key-ascii": b"a7bcdb38d64c8b780d31fab5502551314137f7593df9b7269b29499458be1c6e",
    "document": Path("../../forensics/the-evidence/analysis/recovered-document.bin").read_bytes(),
}


def xor(left, right):
    return bytes(a ^ b for a, b in zip(left, right))


def repeated_windows(data, width=12):
    seen = {}
    repeats = []
    for offset in range(len(data) - width + 1):
        block = data[offset:offset + width]
        if block in seen:
            repeats.append((seen[block], offset, block.hex()))
        else:
            seen[block] = offset
    return repeats


def evaluate(label, key, plaintext):
    direct = hashlib.sha1(plaintext).digest() == checksum
    keyed = hmac.new(key, plaintext, hashlib.sha1).digest() == checksum
    repeats = repeated_windows(plaintext)
    runs = re.findall(rb"[\x20-\x7e]{5,}", plaintext)
    run_bytes = sum(map(len, runs))
    if direct or keyed or repeats or run_bytes >= 140:
        print(label, key.hex(), "sha1=", direct, "hmac=", keyed,
              "repeats=", repeats[:5], "ascii_bytes=", run_bytes,
              "head=", plaintext[:32].hex(), "runs=", runs[:8])


def hash_stream(key, counter_bytes, counter_first, keyed, truncate):
    stream = bytearray()
    counter = 0
    while len(stream) < len(payload):
        encoded = counter.to_bytes(counter_bytes, "big" if counter_first else "little")
        if keyed:
            block = hmac.new(key, encoded, hashlib.sha256).digest()
        elif counter_first:
            block = hashlib.sha256(encoded + key).digest()
        else:
            block = hashlib.sha256(key + encoded).digest()
        stream.extend(block[:truncate])
        counter += 1
    return xor(payload, stream)


for archive_name, archive in archive_values.items():
    for reverse in (False, True):
        material = calibration + archive if reverse else archive + calibration
        digest = hashlib.sha256(material).digest()
        keys = {
            "first": digest[:16],
            "last": digest[16:],
            "hex-first": digest.hex()[:16].encode(),
            "hex-last": digest.hex()[-16:].encode(),
        }
        for key_name, key in keys.items():
            prefix = f"{archive_name}/{reverse}/{key_name}"
            evaluate(prefix + "/repeat", key, xor(payload, (key * ((len(payload) + 15) // 16))[:len(payload)]))
            for counter_bytes in (4, 8, 16):
                for counter_first in (False, True):
                    for keyed in (False, True):
                        for truncate in (16, 32):
                            plaintext = hash_stream(key, counter_bytes, counter_first, keyed, truncate)
                            label = f"{prefix}/hash/{counter_bytes}/{counter_first}/{keyed}/{truncate}"
                            evaluate(label, key, plaintext)
