import hashlib
import itertools
import lzma
import sqlite3
import struct
import zlib
from pathlib import Path


def shuffled_permutations(seed):
    permutations = [tuple(p) for p in itertools.permutations(range(4))]
    state = seed & 0xFFFFFFFF
    for count in range(24, 1, -1):
        state = (state * 1664525 + 1013904223) & 0xFFFFFFFF
        index = state % count
        permutations[count - 1], permutations[index] = permutations[index], permutations[count - 1]
    return permutations


def rank_vector(group):
    return tuple(
        sum(other < value or (other == value and other_index < index)
            for other_index, other in enumerate(group))
        for index, value in enumerate(group)
    )


def hamming_code(nibble, width):
    bit0 = nibble & 1
    bit1 = (nibble >> 1) & 1
    bit2 = (nibble >> 2) & 1
    bit3 = (nibble >> 3) & 1
    code = [
        bit2 ^ bit3 ^ bit0,
        bit1 ^ bit3 ^ bit0,
        bit3,
        bit1 ^ bit2 ^ bit0,
        bit2,
        bit1,
        bit0,
    ]
    if width == 8:
        code.append(sum(code) & 1)
    return code


def invert_interleave(bits, width, mode):
    block_size = width * width
    restored = []
    for block_start in range(0, len(bits) - block_size + 1, block_size):
        block = bits[block_start:block_start + block_size]
        source = [None] * block_size
        for row in range(width):
            source_column = width - 1 - row if mode == 2 else row
            for item in range(width):
                source[item * width + source_column] = block[row * width + item]
        restored.extend(source)
    return restored


def descramble(bits, mode, asset, slot0, slot8, slot11):
    output = []
    if mode == 0:
        state = (zlib.crc32(asset.encode('ascii')) ^ slot8 ^ slot11) & 0xFFFFFFFF
        for bit in bits:
            state ^= (state << 13) & 0xFFFFFFFF
            state ^= state >> 17
            state ^= (state << 5) & 0xFFFFFFFF
            state &= 0xFFFFFFFF
            output.append(None if bit is None else bit ^ (state & 1))
    else:
        state = slot0 & 0xFF
        if state == 0:
            state = 1
        polynomial = slot8 & 0xFF
        for bit in bits:
            mask = state & 1
            output.append(None if bit is None else bit ^ mask)
            state = (state >> 1) ^ (polynomial if mask else 0)
    return output


def decode_hamming(bits, width):
    codebook = [(nibble, hamming_code(nibble, width)) for nibble in range(16)]
    nibbles = []
    diagnostics = []
    for pos in range(0, len(bits) - width + 1, width):
        received = bits[pos:pos + width]
        scores = []
        for nibble, code in codebook:
            distance = sum(actual is not None and actual != expected for actual, expected in zip(received, code))
            scores.append((distance, nibble))
        best_distance = min(score[0] for score in scores)
        best = [nibble for distance, nibble in scores if distance == best_distance]
        nibbles.append(best[0] if len(best) == 1 else None)
        diagnostics.append((best_distance, sum(bit is None for bit in received), len(best)))
    return nibbles, diagnostics


LANES = [
    {
        'lane': 0,
        'asset': 'RX.55368F.TEMP',
        'perm_seed': 0x260892B8,
        'alignment': 3,
        'differential': 'sub',
        'sync_symbol': 139,
        'width': 8,
        'interleave': 2,
        'mode': 0,
        'slot0': 0x351F8C35,
        'slot8': 0x9AFFF7AA,
        'slot11': 0xB80A4933,
    },
    {
        'lane': 1,
        'asset': 'RX.20B4AC.FLOW',
        'perm_seed': 0x19762AFE,
        'alignment': 0,
        'differential': 'xor',
        'sync_symbol': 142,
        'width': 7,
        'interleave': 1,
        'mode': 1,
        'slot0': 0x94A47EDE,
        'slot8': 0xA6,
        'slot11': 0xB80A4933,
    },
]

conn = sqlite3.connect('file:assets/evidence-acquisition/historian.db?mode=ro', uri=True)
output_dir = Path('analysis/recovered-lanes')
output_dir.mkdir(parents=True, exist_ok=True)

for config in LANES:
    asset = config['asset']
    times = [row[0] for row in conn.execute(
        'SELECT gateway_time_ns FROM samples WHERE asset_tag=? ORDER BY seq_no', (asset,)
    )]
    deltas = [times[index] - times[index - 1] for index in range(1, len(times))]
    mapping = {
        permutation: symbol
        for symbol, permutation in enumerate(shuffled_permutations(config['perm_seed'])[:16])
    }
    observed = []
    for start in range(config['alignment'], len(deltas) - 3, 4):
        observed.append(mapping.get(rank_vector(deltas[start:start + 4])))

    decoded_symbols = []
    for index in range(1, len(observed)):
        previous, current = observed[index - 1], observed[index]
        if previous is None or current is None:
            decoded_symbols.append(None)
        elif config['differential'] == 'sub':
            decoded_symbols.append((current - previous) & 0xF)
        else:
            decoded_symbols.append(current ^ previous)

    sync_start = config['sync_symbol']
    sync = decoded_symbols[sync_start:sync_start + 16]
    expected_sync = list(bytes.fromhex('c81a444bbbb372c4'))
    expected_sync = [int(character, 16) for character in 'c81a444bbbb372c4']
    if sync != expected_sync:
        raise ValueError(f'lane {config["lane"]} synchronization mismatch: {sync}')

    encoded_symbols = decoded_symbols[sync_start + 16:]
    scrambled_bits = [
        None if symbol is None else (symbol >> bit) & 1
        for symbol in encoded_symbols
        for bit in range(4)
    ]
    interleaved_bits = descramble(
        scrambled_bits, config['mode'], asset,
        config['slot0'], config['slot8'], config['slot11'],
    )
    code_bits = invert_interleave(interleaved_bits, config['width'], config['interleave'])
    nibbles, diagnostics = decode_hamming(code_bits, config['width'])
    packet = bytearray()
    byte_diagnostics = []
    for index in range(0, len(nibbles) - 1, 2):
        high, low = nibbles[index:index + 2]
        packet.append(0 if high is None or low is None else (high << 4) | low)
        byte_diagnostics.append((diagnostics[index], diagnostics[index + 1], high is None or low is None))

    print(f'\nLANE {config["lane"]} asset={asset}')
    print('sync_symbol=', sync_start, 'decoded_packet_prefix=', packet[:32].hex())
    if packet[:2] != b'\xB2\xBD' or packet[2] != config['mode'] or packet[3] != 2:
        raise ValueError(f'lane {config["lane"]} packet header mismatch: {packet[:8].hex()}')
    share_size = int.from_bytes(packet[4:6], 'big')
    total_size = share_size + 10
    recovered = bytes(packet[:total_size])
    share = recovered[6:6 + share_size]
    stored_crc = int.from_bytes(recovered[6 + share_size:10 + share_size], 'big')
    calculated_crc = zlib.crc32(share) & 0xFFFFFFFF
    affected = [index for index, diagnostic in enumerate(byte_diagnostics[:total_size]) if diagnostic[2]]
    corrected = sum(
        item[0] > 0
        for pair in diagnostics[:total_size * 2]
        for item in [pair]
    )
    print('share_size=', share_size, 'stored_crc32=', f'{stored_crc:08x}', 'calculated_crc32=', f'{calculated_crc:08x}')
    print('ambiguous_bytes=', affected[:30], 'corrected_codewords=', corrected)
    target = output_dir / f'lane_{config["lane"]}_share.bin'
    target.write_bytes(share)
    print('share_sha256=', hashlib.sha256(share).hexdigest(), 'path=', target)

lane_0 = (output_dir / 'lane_0_share.bin').read_bytes()
lane_1 = (output_dir / 'lane_1_share.bin').read_bytes()
if len(lane_0) != len(lane_1):
    raise ValueError(f'lane sizes differ: {len(lane_0)} != {len(lane_1)}')

combined = bytes(left ^ right for left, right in zip(lane_0, lane_1))
xz_offset = combined.find(b'\xfd7zXZ\x00')
if xz_offset < 0:
    raise ValueError('XZ stream signature not found in combined shares')
document = lzma.decompress(combined[xz_offset:])

document_bin = Path('analysis/recovered-document.bin')
document_json = Path('analysis/recovered-document.json')
document_bin.write_bytes(document)
document_json.write_bytes(document)

print('\nCOMBINED DOCUMENT')
print('combined_size=', len(combined), 'combined_sha256=', hashlib.sha256(combined).hexdigest())
print('xz_offset=', xz_offset, 'xz_size=', len(combined) - xz_offset)
print('document_size=', len(document), 'document_sha256=', hashlib.sha256(document).hexdigest())
print('document=', document.decode('utf-8'))
