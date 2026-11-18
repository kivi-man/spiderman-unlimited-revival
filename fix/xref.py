"""Find code that references strings (adrp+add / adrp+ldr pairs) in an arm64 .so.
Usage: python xref.py lib.so "string1" ["string2" ...]
Prints each string's address and the code addresses that load it."""
import struct
import sys

from elftools.elf.elffile import ELFFile

path = sys.argv[1]
data = open(path, 'rb').read()
elf = ELFFile(open(path, 'rb'))
text = elf.get_section_by_name('.text')
ta, to, ts = text['sh_addr'], text['sh_offset'], text['sh_size']


def o2v(off):
    for seg in elf.iter_segments():
        if seg['p_type'] == 'PT_LOAD' and seg['p_offset'] <= off < seg['p_offset'] + seg['p_filesz']:
            return off - seg['p_offset'] + seg['p_vaddr']


targets = {}
for s in sys.argv[2:]:
    needle = b'\0' + s.encode() + b'\0'
    start = 0
    while (i := data.find(needle, start)) >= 0:
        targets[o2v(i + 1)] = s
        start = i + 1
for v, s in targets.items():
    print(f'string {s!r} at {v:#x}')

got_targets = {}
for rel in elf.get_section_by_name('.rela.dyn').iter_relocations():
    if rel['r_addend'] in targets:
        got_targets[rel['r_offset']] = targets[rel['r_addend']]

words = struct.unpack_from(f'<{ts // 4}I', data, to)
page = {}  # reg -> (page, pc)
for idx, w in enumerate(words):
    pc = ta + idx * 4
    if (w & 0x9F000000) == 0x90000000:  # ADRP
        rd = w & 31
        imm = ((w >> 29) & 3) | (((w >> 5) & 0x7FFFF) << 2)
        if imm & (1 << 20):
            imm -= 1 << 21
        page[rd] = ((pc & ~0xFFF) + (imm << 12), pc)
    elif (w & 0xFF800000) == 0x91000000:  # ADD Xd, Xn, #imm (64-bit, no shift)
        rn = (w >> 5) & 31
        if rn in page and pc - page[rn][1] < 1024:
            t = page[rn][0] + ((w >> 10) & 0xFFF)
            if t in targets:
                print(f'  {pc:#x}  loads {targets[t]!r}')
    elif (w & 0xFFC00000) == 0xF9400000:  # LDR Xt, [Xn, #imm] (GOT slot holding the string)
        rn = (w >> 5) & 31
        if rn in page and pc - page[rn][1] < 1024:
            slot = page[rn][0] + ((w >> 10) & 0xFFF) * 8
            if slot in got_targets:
                print(f'  {pc:#x}  loads {got_targets[slot]!r} via GOT {slot:#x}')
