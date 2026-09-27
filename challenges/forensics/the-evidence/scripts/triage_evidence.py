import datetime as dt
import ipaddress
import json
import sqlite3
import struct
from pathlib import Path

ROOT = Path('assets/evidence-acquisition')


def display(value):
    if isinstance(value, bytes):
        return f'<blob {len(value)} bytes {value[:32].hex()}>'
    text = repr(value)
    return text if len(text) <= 240 else text[:237] + '...'


def sqlite_triage():
    print('\n=== HISTORIAN ===')
    conn = sqlite3.connect(f'file:{(ROOT / "historian.db").as_posix()}?mode=ro', uri=True)
    objects = conn.execute(
        "SELECT type,name,sql FROM sqlite_master WHERE type IN ('table','view') ORDER BY name"
    ).fetchall()
    for obj_type, name, sql in objects:
        print(f'\n{obj_type} {name}: {sql}')
        if obj_type != 'table' or name.startswith('sqlite_'):
            continue
        count = conn.execute(f'SELECT COUNT(*) FROM "{name}"').fetchone()[0]
        columns = [row[1] for row in conn.execute(f'PRAGMA table_info("{name}")')]
        print(f'count={count} columns={columns}')
        for row in conn.execute(f'SELECT * FROM "{name}" LIMIT 12'):
            print('  ' + ' | '.join(display(v) for v in row))


def pcap_triage():
    print('\n=== PCAP ===')
    data = (ROOT / 'capture.pcap').read_bytes()
    magic = data[:4]
    formats = {
        b'\xd4\xc3\xb2\xa1': ('<', 1_000_000),
        b'\xa1\xb2\xc3\xd4': ('>', 1_000_000),
        b'\x4d\x3c\xb2\xa1': ('<', 1_000_000_000),
        b'\xa1\xb2\x3c\x4d': ('>', 1_000_000_000),
    }
    endian, resolution = formats[magic]
    offset = 24
    index = 0
    while offset + 16 <= len(data):
        sec, frac, captured, original = struct.unpack_from(endian + 'IIII', data, offset)
        offset += 16
        packet = data[offset:offset + captured]
        offset += captured
        index += 1
        stamp = dt.datetime.fromtimestamp(sec + frac / resolution, dt.timezone.utc).isoformat()
        summary = f'{index:03d} {stamp} cap={captured}'
        payload = b''
        if len(packet) >= 14:
            ethertype = struct.unpack_from('!H', packet, 12)[0]
            network = 14
            if ethertype == 0x8100 and len(packet) >= 18:
                ethertype = struct.unpack_from('!H', packet, 16)[0]
                network = 18
            if ethertype == 0x0800 and len(packet) >= network + 20:
                ihl = (packet[network] & 0x0F) * 4
                proto = packet[network + 9]
                src = str(ipaddress.ip_address(packet[network + 12:network + 16]))
                dst = str(ipaddress.ip_address(packet[network + 16:network + 20]))
                transport = network + ihl
                if proto == 17 and len(packet) >= transport + 8:
                    sport, dport, length, _ = struct.unpack_from('!HHHH', packet, transport)
                    payload = packet[transport + 8:transport + length]
                    summary += f' UDP {src}:{sport} -> {dst}:{dport} data={len(payload)}'
                elif proto == 6 and len(packet) >= transport + 20:
                    sport, dport = struct.unpack_from('!HH', packet, transport)
                    hlen = (packet[transport + 12] >> 4) * 4
                    payload = packet[transport + hlen:]
                    summary += f' TCP {src}:{sport} -> {dst}:{dport} data={len(payload)}'
                else:
                    summary += f' IP proto={proto} {src} -> {dst}'
            elif ethertype == 0x0806:
                summary += ' ARP'
            else:
                summary += f' ethertype=0x{ethertype:04x}'
        print(summary)
        if payload:
            ascii_preview = ''.join(chr(b) if 32 <= b < 127 else '.' for b in payload[:96])
            print(f'    hex={payload[:96].hex()} ascii={ascii_preview}')


def fat_timestamp(date_value, time_value=0, tenths=0):
    if not date_value:
        return None
    year = 1980 + ((date_value >> 9) & 0x7F)
    month = (date_value >> 5) & 0x0F
    day = date_value & 0x1F
    hour = (time_value >> 11) & 0x1F
    minute = (time_value >> 5) & 0x3F
    second = (time_value & 0x1F) * 2 + tenths // 100
    try:
        return dt.datetime(year, month, day, hour, minute, second).isoformat()
    except ValueError:
        return f'invalid(date=0x{date_value:04x},time=0x{time_value:04x})'


def fat_triage():
    print('\n=== FAT IMAGE ===')
    image = (ROOT / 'workstation.img').read_bytes()
    bps = struct.unpack_from('<H', image, 11)[0]
    spc = image[13]
    reserved = struct.unpack_from('<H', image, 14)[0]
    fats = image[16]
    root_entries = struct.unpack_from('<H', image, 17)[0]
    total16 = struct.unpack_from('<H', image, 19)[0]
    spf = struct.unpack_from('<H', image, 22)[0]
    total32 = struct.unpack_from('<I', image, 32)[0]
    total = total16 or total32
    root_sectors = (root_entries * 32 + bps - 1) // bps
    fat_offset = reserved * bps
    root_offset = (reserved + fats * spf) * bps
    data_offset = (reserved + fats * spf + root_sectors) * bps
    cluster_size = bps * spc
    print({
        'oem': image[3:11].decode('ascii', 'replace'), 'bytes_per_sector': bps,
        'sectors_per_cluster': spc, 'reserved': reserved, 'fats': fats,
        'root_entries': root_entries, 'sectors_per_fat': spf, 'total_sectors': total,
        'volume_label': image[43:54].decode('ascii', 'replace'),
        'fs_type': image[54:62].decode('ascii', 'replace'),
    })
    fat = image[fat_offset:fat_offset + spf * bps]

    def fat12(cluster):
        pos = cluster + cluster // 2
        word = fat[pos] | (fat[pos + 1] << 8)
        return (word >> 4) & 0xFFF if cluster & 1 else word & 0xFFF

    def cluster_bytes(cluster):
        pos = data_offset + (cluster - 2) * cluster_size
        return image[pos:pos + cluster_size]

    def chain(start):
        seen = set()
        current = start
        while 2 <= current < 0xFF8 and current not in seen:
            seen.add(current)
            yield current
            current = fat12(current)

    def parse_directory(blob, parent=''):
        for pos in range(0, len(blob) - 31, 32):
            entry = blob[pos:pos + 32]
            first = entry[0]
            if first == 0x00:
                continue
            attr = entry[11]
            if attr == 0x0F:
                continue
            deleted = first == 0xE5
            name_raw = bytearray(entry[:8])
            if deleted:
                name_raw[0] = ord('?')
            name = name_raw.decode('ascii', 'replace').rstrip()
            ext = entry[8:11].decode('ascii', 'replace').rstrip()
            short = name + ('.' + ext if ext else '')
            start = struct.unpack_from('<H', entry, 26)[0]
            size = struct.unpack_from('<I', entry, 28)[0]
            created = fat_timestamp(struct.unpack_from('<H', entry, 16)[0], struct.unpack_from('<H', entry, 14)[0], entry[13])
            accessed = fat_timestamp(struct.unpack_from('<H', entry, 18)[0])
            modified = fat_timestamp(struct.unpack_from('<H', entry, 24)[0], struct.unpack_from('<H', entry, 22)[0])
            flags = []
            if deleted: flags.append('DELETED')
            if attr & 0x10: flags.append('DIR')
            if attr & 0x08: flags.append('VOLUME')
            path = f'{parent}/{short}' if parent else short
            print(f'{path:32} attr=0x{attr:02x} cluster={start:4} size={size:7} {",".join(flags)} c={created} a={accessed} m={modified}')
            if attr & 0x10 and not deleted and short not in ('.', '..') and start >= 2:
                directory = b''.join(cluster_bytes(c) for c in chain(start))
                parse_directory(directory, path)

    root = image[root_offset:root_offset + root_entries * 32]
    parse_directory(root)


if __name__ == '__main__':
    sqlite_triage()
    pcap_triage()
    fat_triage()
