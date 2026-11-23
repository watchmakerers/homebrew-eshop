"""callers.py code target...: find Thumb BL/BLX (and ARM BL) sites calling each target (hex)."""
import sys, struct
BASE=0x100000
d=open(sys.argv[1],'rb').read()
for t in sys.argv[2:]:
    T=int(t,16); hits=[]
    for o in range(0,len(d)-4,2):
        h1,h2=struct.unpack_from('<HH',d,o)
        if h1>>11==0b11110 and (h2>>11) in (0b11111,0b11101):
            S=(h1>>10)&1; J1=(h2>>13)&1; J2=(h2>>11)&1
            I1=1-(J1^S); I2=1-(J2^S)
            off=(S<<24)|(I1<<23)|(I2<<22)|((h1&0x3ff)<<12)|((h2&0x7ff)<<1)
            if S: off-=1<<25
            pc=BASE+o+4
            dst=pc+off if (h2>>11)==0b11111 else ((pc+off)&~3)
            if dst==T: hits.append(hex(BASE+o))
    print(t, hits)
