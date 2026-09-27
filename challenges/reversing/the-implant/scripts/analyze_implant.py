import argparse
import struct
import sys
import zlib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[4] / '.tools'))
from elftools.elf.elffile import ELFFile


HEADER = struct.Struct('<4sIIIQQQ16s16s12sII')


def load_segments(path):
    with path.open('rb') as stream:
        elf = ELFFile(stream)
        return [
            {
                'offset': segment['p_offset'],
                'vaddr': segment['p_vaddr'],
                'data': segment.data(),
                'flags': segment['p_flags'],
            }
            for segment in elf.iter_segments()
            if segment['p_type'] == 'PT_LOAD'
        ]


def file_location(segment, relative):
    return segment['offset'] + relative, segment['vaddr'] + relative


def scan_headers(segments):
    found = []
    for segment_index, segment in enumerate(segments):
        data = segment['data']
        start = 0
        while True:
            relative = data.find(b'RCTX', start)
            if relative < 0:
                break
            start = relative + 1
            if relative + HEADER.size > len(data):
                continue
            values = HEADER.unpack_from(data, relative)
            (magic, version, owner, generation, encoded_head, head_cookie,
             byte_count, token_a, token_b, nonce, node_count, crc) = values
            raw = data[relative:relative + HEADER.size]
            calculated = zlib.crc32(raw[:-4]) & 0xffffffff
            file_offset, vaddr = file_location(segment, relative)
            decoded_head = ((encoded_head << 23) | (encoded_head >> (64 - 23))) & ((1 << 64) - 1)
            decoded_head ^= head_cookie
            found.append({
                'segment': segment_index,
                'file_offset': file_offset,
                'vaddr': vaddr,
                'version': version,
                'owner': owner,
                'generation': generation,
                'encoded_head': encoded_head,
                'head_cookie': head_cookie,
                'head': decoded_head,
                'bytes': byte_count,
                'token_a': token_a.hex(),
                'token_b': token_b.hex(),
                'nonce': nonce.hex(),
                'nodes': node_count,
                'crc': crc,
                'calculated_crc': calculated,
                'crc_ok': crc == calculated,
            })
    return found


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('core', type=Path)
    args = parser.parse_args()
    segments = load_segments(args.core)
    print('segments:')
    for index, segment in enumerate(segments):
        print(
            f"  {index}: file=0x{segment['offset']:x} "
            f"vaddr=0x{segment['vaddr']:016x} size=0x{len(segment['data']):x} "
            f"flags={segment['flags']}"
        )
    headers = scan_headers(segments)
    print(f'\ncontext headers: {len(headers)}')
    for index, header in enumerate(headers):
        print(
            f"[{index:02d}] file=0x{header['file_offset']:x} va=0x{header['vaddr']:016x} "
            f"owner={header['owner']} gen={header['generation']} "
            f"head=0x{header['head']:016x} bytes={header['bytes']} nodes={header['nodes']} "
            f"crc={'ok' if header['crc_ok'] else 'BAD'}"
        )
        print(
            f"     encoded=0x{header['encoded_head']:016x} cookie=0x{header['head_cookie']:016x} "
            f"a={header['token_a']} b={header['token_b']} nonce={header['nonce']}"
        )


if __name__ == '__main__':
    main()
