"""keyrefs.py code key [window]: find ARM code loading the string `key` (via literal pool), print all string
literals loaded within +-window bytes of each site, in order. Base 0x100000."""
import sys, struct, re
B=0x100000
d=open(sys.argv[1],'rb').read(); key=sys.argv[2].encode(); W=int(sys.argv[3],0) if len(sys.argv)>3 else 0x300
def cstr(a):
    o=a-B
    if not (0<=o<len(d)): return None
    z=d.find(b'\0',o)
    if z<0 or z-o>60 or z==o: return None
    t=d[o:z]
    return t.decode() if all(32<=c<127 for c in t) else None
addrs=[B+m.start() for m in re.finditer(rb'(?<=\x00)'+re.escape(key)+rb'\x00', d)]
def loads(lo,hi):
    out=[]
    for o in range(lo-B,hi-B,4):
        w=struct.unpack_from('<I',d,o)[0]
        if (w&0x0F7F0000)==0x051F0000:
            imm=w&0xFFF; t=B+o+8+(imm if (w>>23)&1 else -imm)
            v=struct.unpack_from('<I',d,t-B)[0]; s=cstr(v)
            if s: out.append((B+o,s))
        elif (w&0x0FFF0000)==0x028F0000:  # add rX, pc, #imm (rotated)
            rot=((w>>8)&0xF)*2; imm=w&0xFF; imm=(imm>>rot)|(imm<<(32-rot))&0xFFFFFFFF
            s=cstr(B+o+8+imm)
            if s: out.append((B+o,s))
    return out
for a in addrs:
    sites=[s for s,_ in loads(B,B+0x2b3000) if False]
    # find literal pools holding a
    p=struct.pack('<I',a); i=d.find(p); hits=[]
    while i!=-1:
        if i%4==0:
            pool=B+i
            for o in range(max(0,i-0x1000),i,4):
                w=struct.unpack_from('<I',d,o)[0]
                if (w&0x0F7F0000)==0x051F0000:
                    imm=w&0xFFF
                    if B+o+8+(imm if (w>>23)&1 else -imm)==pool: hits.append(B+o)
        i=d.find(p,i+1)
    for h in hits:
        print(f'== {key.decode()}@{a:#x} loaded at {h:#x}')
        print('   ', ' '.join(f'{s}' for _,s in loads(h-W,h+W)))
