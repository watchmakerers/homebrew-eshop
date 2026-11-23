"""dis.py code start end [arm]: disassemble NIM-style code (base 0x100000), Thumb by default; annotate pc-rel literals."""
import sys, struct
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_ARM
BASE=0x100000
d=open(sys.argv[1],'rb').read()
s,e=int(sys.argv[2],16),int(sys.argv[3],16)
ARM=len(sys.argv)>4
md=Cs(CS_ARCH_ARM, CS_MODE_ARM if ARM else CS_MODE_THUMB)
def pcbase(a): return a+8 if ARM else (a+4)&~3
def cstr(a):
    o=a-BASE
    if 0<=o<len(d):
        z=d.find(b'\0',o); t=d[o:z]
        if 3<=len(t)<80 and all(32<=c<127 for c in t): return repr(t.decode())
    return ''
a=s
while a<e:
    got=False
    for i in md.disasm(d[a-BASE:e-BASE],a):
        got=True; c=''
        if i.mnemonic.startswith('ldr') and '[pc, #' in i.op_str:
            imm=int(i.op_str.split('#')[1].rstrip(']'),0); p=pcbase(i.address)+imm
            v=struct.unpack_from('<I',d,p-BASE)[0]; c=f'  ; ={v:#x} {cstr(v)}'
        elif i.mnemonic in('adr','add') and 'pc' in i.op_str and '#' in i.op_str:
            imm=int(i.op_str.split('#')[1],0); p=pcbase(i.address)+imm; c=f'  ; {p:#x} {cstr(p)}'
        print(f'{i.address:#x}: {i.mnemonic} {i.op_str}{c}'); a=i.address+i.size
    if not got: print(f'{a:#x}: .byte'); a+=2
