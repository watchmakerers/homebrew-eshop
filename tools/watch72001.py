# gdb -q -batch -x watch72001.py : wait for the eShop (tiger) to launch, attach, break on every load of error 72001.
import gdb, time, struct
SITES=[int(x,16) for x in open('/tmp/claude-1000/-home-nathan/a6d65e58-f851-46fa-b12c-3758e5b066c7/scratchpad/sites72001.txt').read().split()]
OLD=49
def run(c): return gdb.execute(c, to_string=True)
for c in ('set pagination off','set confirm off','set architecture arm','set arm fallback-mode arm','set arm force-mode arm'): run(c)
run('target extended-remote 192.168.68.56:4000')
import re
def proclist():
    data=''; off=0
    for _ in range(20):
        r=run(f'maint packet qXfer:osdata:read:processes:{off:x},3fb')
        m=re.search(r'received: "(.)(.*)"', r, re.S)
        if not m: break
        data+=m.group(2); off+=len(m.group(2))
        if m.group(1)!='m': break
    return re.findall(r'pid">(\d+)</column><column name="command">([^<]*)', data)
def pid():
    try:
        ps=[l.split()[:2] for l in run('info os processes').splitlines()[1:] if len(l.split())>=2]
    except gdb.error:
        ps=None
    if ps is None:
     try: ps=proclist()
     except gdb.error as e:
        print('list error', e, flush=True); return None
    for p_,n in ps:
        if n=='tiger' and int(p_)!=OLD: return int(p_)
print('waiting for eShop launch...', flush=True)
t0=time.time()
while (p:=pid()) is None:
    if time.time()-t0>600: raise SystemExit('timeout')
    time.sleep(0.3)
print('attaching to tiger pid', p, flush=True)
time.sleep(2)
for tries in range(8):
    try:
        run(f'attach {p}'); break
    except gdb.error as e:
        print('attach retry', e, flush=True)
        try: run('detach')
        except gdb.error: pass
        time.sleep(1)
else: raise SystemExit('could not attach')
for a in SITES: run(f'break *{a:#x}')
print('breakpoints set:', len(SITES), flush=True)
def cond_ok(insn, cpsr):
    c=insn>>28; N,Z,C,V=(cpsr>>31)&1,(cpsr>>30)&1,(cpsr>>29)&1,(cpsr>>28)&1
    return [Z,not Z,C,not C,N,not N,V,not V,C and not Z,not C or Z,N==V,N!=V,not Z and N==V,Z or N!=V,1,1][c]
hits=0
while hits<40:
    try: run('continue')
    except gdb.error as e: print('continue error', e, flush=True); break
    f=gdb.selected_frame(); pc=int(f.read_register('pc')); lr=int(f.read_register('lr')); cpsr=int(f.read_register('cpsr')); sp=int(f.read_register('sp'))
    insn=struct.unpack('<I', bytes(gdb.selected_inferior().read_memory(pc,4)))[0] if False else None
    regs={r:int(f.read_register(r)) for r in ('r0','r1','r2','r3','r4','r5','r6')}
    try: stack=struct.unpack('<16I', bytes(gdb.selected_inferior().read_memory(sp,64)))
    except Exception: stack=()
    print(f'HIT pc={pc:#x} lr={lr:#x} cpsr={cpsr:#x} regs={ {k:hex(v) for k,v in regs.items()} } stack={[hex(x) for x in stack]}', flush=True)
    hits+=1
run('delete'); run('detach'); print('detached', flush=True)
