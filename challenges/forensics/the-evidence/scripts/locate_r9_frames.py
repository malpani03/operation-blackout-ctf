import itertools
import sqlite3


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


lanes = [
    (0, 'RX.55368F.TEMP', 0x260892B8),
    (1, 'RX.20B4AC.FLOW', 0x19762AFE),
]
sync = 0x32E4DCDD2D228531
sync_bits = [
    (byte >> bit) & 1
    for byte in sync.to_bytes(8, 'little')
    for bit in range(7, -1, -1)
]
sync_symbols = [sum(sync_bits[pos + bit] << bit for bit in range(4)) for pos in range(0, 64, 4)]

conn = sqlite3.connect('file:assets/evidence-acquisition/historian.db?mode=ro', uri=True)
for lane, asset, seed in lanes:
    times = [row[0] for row in conn.execute(
        'SELECT gateway_time_ns FROM samples WHERE asset_tag=? ORDER BY seq_no', (asset,)
    )]
    deltas = [times[index] - times[index - 1] for index in range(1, len(times))]
    mapping = {perm: symbol for symbol, perm in enumerate(shuffled_permutations(seed)[:16])}
    print(f'\nLANE {lane} {asset}')
    for alignment in range(4):
        symbols = []
        for start in range(alignment, len(deltas) - 3, 4):
            symbols.append(mapping.get(rank_vector(deltas[start:start + 4])))
        variants = {'identity': symbols}
        for name, operation in {
            'xor_prev': lambda current, previous: current ^ previous,
            'sub_prev': lambda current, previous: (current - previous) & 0xF,
            'prev_sub': lambda current, previous: (previous - current) & 0xF,
            'add_prev': lambda current, previous: (current + previous) & 0xF,
        }.items():
            variants[name] = [
                None if symbols[index] is None or symbols[index - 1] is None else operation(symbols[index], symbols[index - 1])
                for index in range(1, len(symbols))
            ]
        for name, candidate_symbols in variants.items():
            candidates = []
            for position in range(0, len(candidate_symbols) - len(sync_symbols) + 1):
                window = candidate_symbols[position:position + len(sync_symbols)]
                mismatches = sum(actual is not None and actual != expected for actual, expected in zip(window, sync_symbols))
                unknowns = sum(actual is None for actual in window)
                candidates.append((mismatches, unknowns, position))
            print('alignment', alignment, name, sorted(candidates)[:5])
