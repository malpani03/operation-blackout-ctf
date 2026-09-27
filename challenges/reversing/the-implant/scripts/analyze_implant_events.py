import struct
import sys
import zlib
from collections import Counter, defaultdict
from pathlib import Path

from analyze_implant import load_segments, scan_headers


RECORD = struct.Struct('<QQIIQII')


def parse_records(data):
    records = []
    for position in range(0, len(data), RECORD.size):
        raw = data[position:position + RECORD.size]
        if len(raw) != RECORD.size:
            continue
        sequence, identity, operation, status, reference, flags, stored_crc = RECORD.unpack(raw)
        calculated_crc = zlib.crc32(raw[:-4]) & 0xffffffff
        records.append({
            'position': position // RECORD.size,
            'sequence': sequence,
            'identity': identity,
            'owner': identity & 0xffffffff,
            'generation': identity >> 32,
            'operation': operation,
            'flags': flags,
            'reference': reference,
            'status': status,
            'crc_ok': stored_crc == calculated_crc,
            'stored_crc': stored_crc,
            'calculated_crc': calculated_crc,
        })
    return records


def record_text(record):
    return (
        f"seq={record['sequence']} pos={record['position']} op={record['operation']} "
        f"flags=0x{record['flags']:x} ref=0x{record['reference']:016x} "
        f"status={record['status']} crc={'ok' if record['crc_ok'] else 'BAD'}"
    )


def candidate_sequences(records):
    grouped = defaultdict(list)
    for record in sorted((item for item in records if item['crc_ok']), key=lambda item: item['sequence']):
        grouped[record['identity']].append(record)

    candidates = []
    for identity, items in grouped.items():
        # The acquisition format describes one causal lifecycle per identity/generation,
        # but tolerate unrelated or repeated records and look for ordered chains.
        for begin_index, begin in enumerate(items):
            if begin['operation'] != 1 or begin['status'] != 0:
                continue
            handle = begin['reference']
            for load_index in range(begin_index + 1, len(items)):
                load = items[load_index]
                if load['operation'] != 2 or load['reference'] != handle or load['status'] != 0:
                    continue
                for connect_index in range(load_index + 1, len(items)):
                    connect = items[connect_index]
                    if connect['operation'] != 3 or connect['reference'] != handle or connect['status'] != 0:
                        continue
                    for stage_index in range(connect_index + 1, len(items)):
                        stage = items[stage_index]
                        if stage['operation'] != 4 or stage['status'] != 0:
                            continue
                        for transmit_index in range(stage_index + 1, len(items)):
                            transmit = items[transmit_index]
                            if transmit['operation'] != 5 or transmit['reference'] != stage['reference'] or transmit['status'] != 0:
                                continue
                            cleanups = [
                                item for item in items[transmit_index + 1:]
                                if item['operation'] == 6 and item['reference'] == handle and item['status'] == 0
                            ]
                            candidates.append({
                                'identity': identity,
                                'owner': identity & 0xffffffff,
                                'generation': identity >> 32,
                                'unsigned': (load['flags'] & 1) == 0,
                                'unapproved': (connect['flags'] & 1) == 0,
                                'records': [begin, load, connect, stage, transmit] + cleanups[:1],
                            })
    return candidates


def main():
    core_path = Path(sys.argv[1] if len(sys.argv) > 1 else 'assets/implant-process.core')
    segments = load_segments(core_path)
    headers = scan_headers(segments)
    header_map = {(item['owner'], item['generation']): (index, item) for index, item in enumerate(headers)}
    records = parse_records(segments[1]['data'])
    print(f'records={len(records)} valid={sum(item["crc_ok"] for item in records)} invalid={sum(not item["crc_ok"] for item in records)}')
    print('invalid records:')
    for record in records:
        if not record['crc_ok']:
            print(f"  owner={record['owner']} generation={record['generation']} {record_text(record)} stored=0x{record['stored_crc']:08x} calculated=0x{record['calculated_crc']:08x}")

    candidates = candidate_sequences(records)
    print(f'\ncompleted chains={len(candidates)}')
    counts = Counter((item['unsigned'], item['unapproved']) for item in candidates)
    print('policy classes:', dict(counts))
    policy_violations = [item for item in candidates if item['unsigned'] or item['unapproved']]
    selected = [item for item in candidates if item['unsigned'] and item['unapproved']]
    print(f'completed policy-violating chains={len(policy_violations)}')
    print(f'\ncompleted full-incident chains={len(selected)}')
    for candidate in selected:
        current = header_map.get((candidate['owner'], candidate['generation']))
        current_text = 'no current header'
        if current:
            header_index, header = current
            current_text = (
                f"header={header_index} current_head=0x{header['head']:016x} "
                f"stage_matches_current={candidate['records'][3]['reference'] == header['head']}"
            )
        print(f"\nowner={candidate['owner']} generation={candidate['generation']} {current_text}")
        for record in candidate['records']:
            print(' ', record_text(record))


if __name__ == '__main__':
    main()
