"""dis.py BIN BASE START END [thumb|arm] -- annotated disassembly (pc-relative literals + strings)"""
import struct, sys
from capstone import *
path, base, start, end = sys.argv[1], int(sys.argv[2], 0), int(sys.argv[3], 0), int(sys.argv[4], 0)
mode = CS_MODE_ARM if (len(sys.argv) > 5 and sys.argv[5] == 'arm') else CS_MODE_THUMB
d = open(path, 'rb').read()
md = Cs(CS_ARCH_ARM, mode); md.skipdata = True
def lit(a): return struct.unpack_from('<I', d, a - base)[0]
def s(a):
    o = a - base
    if 0 <= o < len(d):
        e = d.find(b'\0', o); t = d[o:e]
        if 3 < len(t) < 100 and all(32 <= c < 127 for c in t): return repr(t.decode())
    return ''
for i in md.disasm(d[start - base:end - base], start):
    extra = ''
    if i.mnemonic.startswith('ldr') and '[pc' in i.op_str and '#' in i.op_str:
        t = ((i.address + (4 if mode == CS_MODE_THUMB else 8)) & ~3) + int(i.op_str.split('#')[-1].rstrip(']'), 0)
        try: v = lit(t); extra = f'  ; ={v:#x} {s(v)}'
        except Exception: pass
    print(f'{i.address:#x} {i.mnemonic} {i.op_str}{extra}')
