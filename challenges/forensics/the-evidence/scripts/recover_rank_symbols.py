import itertools
import sqlite3
from pathlib import Path


def shuffled_permutations(seed):
    permutations = [tuple(p) for p in itertools.permutations(range(4))]
    state = seed & 0xFFFFFFFF
    for count in range(24, 1, -1):
        state = (state * 1664525 + 1013904223) & 0xFFFFFFFF
        index = state % count
        permutations[count - 1], permutations[index] = permutations[index], permutations[count - 1]
    return permutations


lanes = [
    (0, 'RX.55368F.TEMP', 0x260892B8),
    (1, 'RX.20B4AC.FLOW', 0x19762AFE),
]
conn = sqlite3.connect('file:assets/evidence-acquisition/historian.db?mode=ro', uri=True)
for lane, asset, seed in lanes:
    rows = list(conn.execute(
        'SELECT sensor_value,device_time_ns,gateway_time_ns FROM samples WHERE asset_tag=? ORDER BY seq_no', (asset,)
    ))
    mapping = {perm: symbol for symbol, perm in enumerate(shuffled_permutations(seed)[:16])}
    print(f'\nLANE {lane} {asset} samples={len(rows)}')
    metrics = {
        'value': [row[0] for row in rows],
        'latency': [row[2] - row[1] for row in rows],
        'gateway_low': [row[2] % 1_000_000 for row in rows],
    }
    for metric_name, values in metrics.items():
      for alignment in range(4):
        symbols = []
        valid = []
        for start in range(alignment, len(values) - 3, 4):
            group = values[start:start + 4]
            perm = tuple(
                sum(other < value or (other == value and other_index < index)
                    for other_index, other in enumerate(group))
                for index, value in enumerate(group)
            )
            symbol = mapping.get(perm)
            symbols.append(symbol)
            valid.append(symbol is not None)
        longest = (0, 0)
        run_start = None
        for index, ok in enumerate(valid + [False]):
            if ok and run_start is None:
                run_start = index
            elif not ok and run_start is not None:
                if index - run_start > longest[1] - longest[0]:
                    longest = (run_start, index)
                run_start = None
        first_bad = [i for i, ok in enumerate(valid) if not ok][:12]
        print(f' metric={metric_name:11} alignment={alignment} groups={len(symbols)} valid={sum(valid)} longest={longest} first_bad={first_bad}')
        preview = ''.join('?' if value is None else f'{value:x}' for value in symbols[:80])
        print('  symbols', preview)
