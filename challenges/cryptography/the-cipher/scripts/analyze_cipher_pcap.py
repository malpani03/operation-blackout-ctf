import collections
import datetime as dt
import ipaddress
import struct
from pathlib import Path


PCAP = Path("assets/cipher-acquisition/receiver.pcap")


def packets():
    data = PCAP.read_bytes()
    formats = {
        b"\xd4\xc3\xb2\xa1": ("<", 1_000_000),
        b"\xa1\xb2\xc3\xd4": (">", 1_000_000),
        b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000),
        b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),
    }
    endian, resolution = formats[data[:4]]
    offset = 24
    index = 0
    while offset + 16 <= len(data):
        sec, frac, captured, original = struct.unpack_from(endian + "IIII", data, offset)
        offset += 16
        frame = data[offset:offset + captured]
        offset += captured
        index += 1
        if len(frame) < 14:
            continue
        ethertype = struct.unpack_from("!H", frame, 12)[0]
        network = 14
        if ethertype == 0x8100 and len(frame) >= 18:
            ethertype = struct.unpack_from("!H", frame, 16)[0]
            network = 18
        if ethertype != 0x0800 or len(frame) < network + 20:
            continue
        ihl = (frame[network] & 0x0F) * 4
        proto = frame[network + 9]
        src = str(ipaddress.ip_address(frame[network + 12:network + 16]))
        dst = str(ipaddress.ip_address(frame[network + 16:network + 20]))
        transport = network + ihl
        if proto == 17 and len(frame) >= transport + 8:
            sport, dport, length, checksum = struct.unpack_from("!HHHH", frame, transport)
            payload = frame[transport + 8:transport + length]
            yield index, sec + frac / resolution, "UDP", src, sport, dst, dport, checksum, payload
        elif proto == 6 and len(frame) >= transport + 20:
            sport, dport = struct.unpack_from("!HH", frame, transport)
            hlen = (frame[transport + 12] >> 4) * 4
            payload = frame[transport + hlen:]
            yield index, sec + frac / resolution, "TCP", src, sport, dst, dport, None, payload


def preview(payload):
    shown = payload[:96]
    text = "".join(chr(value) if 32 <= value < 127 else "." for value in shown)
    return f"hex={shown.hex()} ascii={text}"


def main():
    rows = list(packets())
    print("packets", len(rows))
    by_flow = collections.Counter((row[2], row[3], row[4], row[5], row[6]) for row in rows)
    by_size = collections.Counter((row[2], len(row[8])) for row in rows)
    print("flows")
    for key, count in by_flow.most_common():
        print(count, key)
    print("payload sizes")
    for key, count in sorted(by_size.items()):
        print(count, key)

    groups = collections.defaultdict(list)
    for row in rows:
        groups[(row[2], row[3], row[4], row[5], row[6])].append(row)

    for key, group in groups.items():
        print("\nflow", key, "count", len(group))
        for row in group[:5] + group[-5:]:
            stamp = dt.datetime.fromtimestamp(row[1], dt.timezone.utc).isoformat()
            print(row[0], stamp, "checksum", row[7], "length", len(row[8]), preview(row[8]))


if __name__ == "__main__":
    main()
