import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / '.tools'))
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from elftools.elf.elffile import ELFFile


def ascii_strings(data, minimum=4):
    pattern = re.compile(rb'[\x20-\x7e]{%d,}' % minimum)
    return [(match.start(), match.group().decode('ascii')) for match in pattern.finditer(data)]


def inspect(path):
    print(f'\n===== {path.name} =====')
    raw = path.read_bytes()
    for offset, value in ascii_strings(raw):
        print(f'STR 0x{offset:04x}: {value}')
    with path.open('rb') as stream:
        elf = ELFFile(stream)
        print('ELF', elf.header)
        print('SECTIONS')
        for section in elf.iter_sections():
            print(f'  {section.name:20} addr=0x{section["sh_addr"]:x} off=0x{section["sh_offset"]:x} size=0x{section["sh_size"]:x}')
        symbols = {}
        for table_name in ('.dynsym', '.symtab'):
            table = elf.get_section_by_name(table_name)
            if table is None:
                continue
            print(f'SYMBOLS {table_name}')
            for symbol in table.iter_symbols():
                if symbol.name:
                    print(f'  0x{symbol["st_value"]:x} {symbol["st_size"]:5} {symbol["st_info"]["type"]:10} {symbol.name}')
                if symbol['st_info']['type'] == 'STT_FUNC' and symbol['st_size'] and isinstance(symbol['st_shndx'], int):
                    symbols[(symbol['st_value'], symbol.name)] = symbol
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        md.detail = False
        if not symbols:
            text = elf.get_section_by_name('.text')
            print(f'\nDISASSEMBLY .text @ 0x{text["sh_addr"]:x} size={text["sh_size"]}')
            for insn in md.disasm(text.data(), text['sh_addr']):
                print(f'  {insn.address:08x}: {insn.mnemonic:8} {insn.op_str}')
        for (_, name), symbol in sorted(symbols.items()):
            section = elf.get_section(symbol['st_shndx'])
            start = symbol['st_value'] - section['sh_addr']
            code = section.data()[start:start + symbol['st_size']]
            print(f'\nDISASSEMBLY {name} @ 0x{symbol["st_value"]:x} size={symbol["st_size"]}')
            for insn in md.disasm(code, symbol['st_value']):
                print(f'  {insn.address:08x}: {insn.mnemonic:8} {insn.op_str}')


for arg in sys.argv[1:]:
    inspect(Path(arg))
