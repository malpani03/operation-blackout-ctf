import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / '.tools'))
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from elftools.elf.elffile import ELFFile

path = Path(sys.argv[1])
start = int(sys.argv[2], 0)
end = int(sys.argv[3], 0)
with path.open('rb') as stream:
    elf = ELFFile(stream)
    section = next(s for s in elf.iter_sections() if s['sh_addr'] <= start < s['sh_addr'] + s['sh_size'])
    offset = start - section['sh_addr']
    code = section.data()[offset:offset + end - start]
md = Cs(CS_ARCH_X86, CS_MODE_64)
for insn in md.disasm(code, start):
    print(f'{insn.address:08x}: {insn.mnemonic:8} {insn.op_str}')
