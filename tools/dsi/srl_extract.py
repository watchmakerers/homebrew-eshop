#!/usr/bin/env python3
"""Extract header info, ARM9/ARM7 binaries and NitroFS files from a DS/DSi SRL (.app)."""
import struct, sys, os
src, out = sys.argv[1], sys.argv[2]
d = open(src, 'rb').read()
os.makedirs(out, exist_ok=True)
u32 = lambda o: struct.unpack_from('<I', d, o)[0]
print('title  :', d[0:12].decode('ascii', 'replace').strip('\0'), 'code', d[12:16].decode('ascii', 'replace'))
a9o, a9e, a9r, a9s = u32(0x20), u32(0x24), u32(0x28), u32(0x2C)
a7o, a7e, a7r, a7s = u32(0x30), u32(0x34), u32(0x38), u32(0x3C)
fnto, fnts, fato, fats = u32(0x40), u32(0x44), u32(0x48), u32(0x4C)
print(f'arm9 off {a9o:#x} ram {a9r:#x} size {a9s:#x}; arm7 off {a7o:#x} ram {a7r:#x} size {a7s:#x}')
open(f'{out}/arm9.bin', 'wb').write(d[a9o:a9o+a9s])
open(f'{out}/arm7.bin', 'wb').write(d[a7o:a7o+a7s])
if d[0x12] & 2 or u32(0x1C0):  # DSi extended header
    a9io, a9ir, a9is = u32(0x1C0), u32(0x1C8), u32(0x1CC)
    a7io, a7ir, a7is = u32(0x1D0), u32(0x1D8), u32(0x1DC)
    print(f'arm9i off {a9io:#x} ram {a9ir:#x} size {a9is:#x}; arm7i off {a7io:#x} size {a7is:#x}')
    print('modcrypt1', hex(u32(0x220)), hex(u32(0x224)), 'modcrypt2', hex(u32(0x228)), hex(u32(0x22C)))
    open(f'{out}/arm9i.bin', 'wb').write(d[a9io:a9io+a9is])
    open(f'{out}/arm7i.bin', 'wb').write(d[a7io:a7io+a7is])
fat = [struct.unpack_from('<II', d, fato + 8*i) for i in range(fats // 8)]
def walk(dir_id, path):
    off, first, _ = struct.unpack_from('<IHH', d, fnto + 8*(dir_id & 0xFFF))
    p, fid = fnto + off, first
    while True:
        b = d[p]; p += 1
        if b == 0: break
        name = d[p:p + (b & 0x7F)].decode('latin-1'); p += b & 0x7F
        if b & 0x80:
            sub = struct.unpack_from('<H', d, p)[0]; p += 2
            os.makedirs(os.path.join(path, name), exist_ok=True)
            walk(sub, os.path.join(path, name))
        else:
            s, e = fat[fid]
            open(os.path.join(path, name), 'wb').write(d[s:e]); fid += 1
if fnts:
    os.makedirs(f'{out}/data', exist_ok=True); walk(0xF000, f'{out}/data')
