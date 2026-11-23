"""Extract and BLZ-decompress .code from a decrypted CXI. Usage: cxi_code.py in.cxi out.code"""
import struct, sys

def blz_decompress(buf):
    buf = bytearray(buf)
    enc_and_hdr, inc = struct.unpack_from('<II', buf, len(buf) - 8)
    hdr_len = enc_and_hdr >> 24
    enc_len = enc_and_hdr & 0xFFFFFF
    out = bytearray(len(buf) + inc)
    out[:len(buf)] = buf
    src = len(buf) - hdr_len
    dst = len(out)
    end = len(buf) - enc_len
    while src > end:
        src -= 1; flags = out[src]
        for _ in range(8):
            if src <= end: break
            if flags & 0x80:
                src -= 2
                v = out[src] | (out[src+1] << 8)
                n = (v >> 12) + 3
                disp = (v & 0xFFF) + 3
                for _ in range(n):
                    dst -= 1; out[dst] = out[dst + disp]
            else:
                src -= 1; dst -= 1; out[dst] = out[src]
            flags = (flags << 1) & 0xFF
    return bytes(out)

d = open(sys.argv[1], 'rb').read()
ex = d[0x200:0x600]
compressed = ex[0xD] & 1
text_addr, text_pages, text_size = struct.unpack_from('<III', ex, 0x10)
ro_addr, ro_pages, ro_size = struct.unpack_from('<III', ex, 0x20)
da_addr, da_pages, da_size = struct.unpack_from('<III', ex, 0x30)
print('name', ex[:8], 'compressed', compressed)
print(f'text {text_addr:#x}+{text_size:#x} ro {ro_addr:#x}+{ro_size:#x} data {da_addr:#x}+{da_size:#x}')
exefs_off = struct.unpack_from('<I', d, 0x1A0)[0] * 0x200
for i in range(10):
    name, off, size = struct.unpack_from('<8sII', d, exefs_off + i*16)
    if name.rstrip(b'\0') == b'.code':
        code = d[exefs_off + 0x200 + off: exefs_off + 0x200 + off + size]
        if compressed: code = blz_decompress(code)
        open(sys.argv[2], 'wb').write(code)
        print('wrote', len(code), 'bytes')
