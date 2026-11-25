#!/usr/bin/env python3
"""Decompress a Nintendo DS BLZ (backward LZ) compressed binary: blz.py in out"""
import struct, sys
d = bytearray(open(sys.argv[1], 'rb').read())
end = len(d)
info, extra = struct.unpack_from('<II', d, end - 8)
hdr, clen = info >> 24, info & 0xFFFFFF
if hdr < 8 or clen > end:
    sys.exit(f'not BLZ (hdr={hdr} clen={clen:#x})')
start = end - clen
src = d[start:end - hdr]
out = bytearray(clen + extra)
s, o = len(src), len(out)
while s > 0 and o > 0:
    s -= 1; flags = src[s]
    for _ in range(8):
        if s <= 0 or o <= 0: break
        if flags & 0x80:
            s -= 2; v = src[s] | src[s+1] << 8
            n, disp = (v >> 12) + 3, (v & 0xFFF) + 3
            for _ in range(n):
                if o <= 0: break
                o -= 1; out[o] = out[o + disp]
        else:
            s -= 1; o -= 1; out[o] = src[s]
        flags <<= 1
open(sys.argv[2], 'wb').write(bytes(d[:start]) + bytes(out))
print(f'{sys.argv[1]}: {end:#x} -> {start + len(out):#x}')
