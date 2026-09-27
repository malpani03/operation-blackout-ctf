import struct
from pathlib import Path

image = Path('assets/evidence-acquisition/workstation.img').read_bytes()
bps = struct.unpack_from('<H', image, 11)[0]
spc = image[13]
reserved = struct.unpack_from('<H', image, 14)[0]
fats = image[16]
root_entries = struct.unpack_from('<H', image, 17)[0]
spf = struct.unpack_from('<H', image, 22)[0]
root_sectors = (root_entries * 32 + bps - 1) // bps
fat_offset = reserved * bps
root_offset = (reserved + fats * spf) * bps
data_offset = (reserved + fats * spf + root_sectors) * bps
cluster_size = bps * spc
fat = image[fat_offset:fat_offset + spf * bps]


def fat12(cluster):
    pos = cluster + cluster // 2
    word = fat[pos] | (fat[pos + 1] << 8)
    return (word >> 4) & 0xFFF if cluster & 1 else word & 0xFFF


def read_file(start, size):
    result = bytearray()
    seen = set()
    current = start
    while len(result) < size and 2 <= current < 0xFF8 and current not in seen:
        seen.add(current)
        pos = data_offset + (current - 2) * cluster_size
        result.extend(image[pos:pos + cluster_size])
        current = fat12(current)
    if len(result) < size:
        raise ValueError(f'cluster chain ended early: start={start} size={size} recovered={len(result)}')
    return bytes(result[:size])


out = Path('analysis/fat-live')
out.mkdir(parents=True, exist_ok=False)
root = image[root_offset:root_offset + root_entries * 32]
for pos in range(0, len(root), 32):
    entry = root[pos:pos + 32]
    if entry[0] in (0x00, 0xE5) or entry[11] in (0x0F, 0x08) or entry[11] & 0x10:
        continue
    name = entry[:8].decode('ascii').rstrip()
    ext = entry[8:11].decode('ascii').rstrip()
    filename = name + ('.' + ext if ext else '')
    start = struct.unpack_from('<H', entry, 26)[0]
    size = struct.unpack_from('<I', entry, 28)[0]
    content = read_file(start, size)
    (out / filename).write_bytes(content)
    print(filename, size, start)
