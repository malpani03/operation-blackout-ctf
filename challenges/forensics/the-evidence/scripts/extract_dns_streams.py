import collections
import datetime
import hashlib
import ipaddress
import struct
from pathlib import Path

pcap = Path('assets/evidence-acquisition/capture.pcap').read_bytes()
endian = '<' if pcap[:4] in (b'\xd4\xc3\xb2\xa1', b'\x4d\x3c\xb2\xa1') else '>'
offset = 24
streams = collections.defaultdict(bytearray)
records = collections.defaultdict(list)
while offset + 16 <= len(pcap):
    sec, frac, captured, original = struct.unpack_from(endian + 'IIII', pcap, offset)
    offset += 16
    packet = pcap[offset:offset + captured]
    offset += captured
    if len(packet) < 42 or struct.unpack_from('!H', packet, 12)[0] != 0x0800:
        continue
    ip = 14
    ihl = (packet[ip] & 0x0f) * 4
    if packet[ip + 9] != 17:
        continue
    src = str(ipaddress.ip_address(packet[ip + 12:ip + 16]))
    udp = ip + ihl
    sport, dport, length, _ = struct.unpack_from('!HHHH', packet, udp)
    if dport != 53:
        continue
    dns = packet[udp + 8:udp + length]
    if len(dns) < 13:
        continue
    label_len = dns[12]
    label = dns[13:13 + label_len].decode('ascii')
    if not label.startswith('s'):
        continue
    chunk = bytes.fromhex(label[1:])
    streams[src].extend(chunk)
    records[src].append((sec, frac, sport, label, chunk))

out = Path('analysis/dns-streams')
out.mkdir(parents=True, exist_ok=True)
for src, stream in sorted(streams.items()):
    target = out / f'{src}.bin'
    target.write_bytes(stream)
    print(src, 'packets=', len(records[src]), 'bytes=', len(stream), 'sha256=', hashlib.sha256(stream).hexdigest())
    print(' first=', stream[:32].hex(), 'last=', stream[-32:].hex())
    counts = collections.Counter(stream)
    print(' byte_range=', (min(stream), max(stream)), 'unique=', len(counts), 'most_common=', counts.most_common(12))
    for row in records[src][:3] + records[src][-3:]:
        print(' ', row[0], row[2], row[3])
    print(' packets within two seconds of 2026-09-27T08:42:11Z:')
    for row in records[src]:
        if abs(row[0] - 1790498531) <= 2:
            when = datetime.datetime.fromtimestamp(row[0], datetime.timezone.utc)
            print(' ', when.isoformat(), 'source_port=', row[2], 'label=', row[3])
