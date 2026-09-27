import itertools
import struct
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[4] / '.tools'))
from elftools.elf.elffile import ELFFile

ROOT = Path('assets/evidence-acquisition')


def crc16(data):
    value = 0xFFFF
    for byte in data:
        value ^= byte << 8
        for _ in range(8):
            value = ((value << 1) ^ 0x1021) & 0xFFFF if value & 0x8000 else (value << 1) & 0xFFFF
    return value


with (ROOT / 'r9capture.so').open('rb') as stream:
    elf = ELFFile(stream)
    rodata = elf.get_section_by_name('.rodata')
    ro_addr = rodata['sh_addr']
    ro = rodata.data()


def rel32(address):
    return struct.unpack_from('<i', ro, address - ro_addr)[0]


target_to_slot = {
    0x1386: 0, 0x1455: 1, 0x138B: 2, 0x14E1: 3, 0x147D: 4,
    0x14B9: 5, 0x1487: 6, 0x149B: 7, 0x14F5: 8, 0x1469: 9,
    0x13B6: 10, 0x14EB: 11, 0x145F: 12, 0x14CD: 13, 0x1491: 14,
    0x14D7: 15, 0x14AF: 16, 0x1473: 17, 0x14A5: 18, 0x14C3: 19,
}


def tag_slot(tag):
    if tag == 0x84:
        target = 0x14E1
    elif tag < 0x84 and 0x22 <= tag <= 0x6D:
        base = 0x2120
        target = base + rel32(base + (tag - 0x22) * 4)
    elif tag > 0x84 and ((tag + 0x70) & 0xFF) <= 0x45:
        index = (tag + 0x70) & 0xFF
        base = 0x2008
        target = base + rel32(base + index * 4)
    else:
        raise ValueError(f'unsupported tag 0x{tag:02x}')
    if target not in target_to_slot:
        raise ValueError(f'tag 0x{tag:02x} jumps to unknown 0x{target:x}')
    return target_to_slot[target]


def parse_profile(record):
    values = [0] * 20
    tags = {}
    pos = 8
    while pos + 2 <= len(record) - 2:
        tag = record[pos]
        length = record[pos + 1]
        value_bytes = record[pos + 2:pos + 2 + length]
        value = int.from_bytes(value_bytes, 'little')
        slot = tag_slot(tag)
        values[slot] = value
        tags[tag] = (slot, value)
        pos += 2 + length
    return values, tags


def shuffled_permutations(seed):
    permutations = [list(p) for p in itertools.permutations(range(4))]
    state = seed & 0xFFFFFFFF
    for count in range(24, 1, -1):
        state = (state * 1664525 + 1013904223) & 0xFFFFFFFF
        index = state % count
        permutations[count - 1], permutations[index] = permutations[index], permutations[count - 1]
    return permutations


def calibration(path):
    data = path.read_bytes()
    assert data[:4] == b'R9CL'
    assert crc16(data[:-2]) == int.from_bytes(data[-2:], 'big')
    return [(data[pos], list(data[pos + 1:pos + 5])) for pos in range(8, len(data) - 2, 5)]


blob = (ROOT / 'historian.db').read_bytes()
profiles = []
seen = set()
offset = 0
while True:
    offset = blob.find(b'R9CF', offset)
    if offset < 0:
        break
    size = int.from_bytes(blob[offset + 5:offset + 7], 'little')
    record = blob[offset:offset + size]
    valid = len(record) == size and size >= 10 and crc16(record[:-2]) == int.from_bytes(record[-2:], 'big')
    if valid and record not in seen:
        seen.add(record)
        values, tags = parse_profile(record)
        profiles.append((offset, record, values, tags))
    offset += 1

calibrations = {
    0: calibration(ROOT / 'lane_0.cal'),
    1: calibration(ROOT / 'lane_1.cal'),
}

print('TAG TO SLOT')
for tag in sorted(profiles[0][3]):
    print(f'0x{tag:02x} -> slot {profiles[0][3][tag][0]}')

print('\nUNIQUE VALID PROFILES')
for index, (offset, record, values, tags) in enumerate(profiles):
    permutations = shuffled_permutations(values[14])
    matches = {}
    for lane, records in calibrations.items():
        matches[lane] = sum(permutations[symbol] == expected for symbol, expected in records)
    print(f'profile={index} offset=0x{offset:x} generation={values[13]} seed14=0x{values[14]:08x} calibration_matches={matches}')
    print(' slots:', ' '.join(f'{slot}={value:#x}' for slot, value in enumerate(values)))
    print(' tags :', ' '.join(f'{tag:02x}->s{slot}:{value:#x}' for tag, (slot, value) in sorted(tags.items())))

print('\nCALIBRATION RECORDS')
for lane, records in calibrations.items():
    print('lane', lane, records)
