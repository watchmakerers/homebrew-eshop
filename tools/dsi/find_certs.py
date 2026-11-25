import sys, re, subprocess
d = open(sys.argv[1], 'rb').read()
for m in re.finditer(rb'\x30\x82(..)\x30\x82', d, re.S):
    n = int.from_bytes(m.group(1), 'big') + 4
    der = d[m.start():m.start() + n]
    r = subprocess.run(['openssl', 'x509', '-inform', 'DER', '-noout', '-subject', '-issuer', '-dates', '-text'],
                       input=der, capture_output=True)
    if r.returncode: continue
    t = r.stdout.decode(errors='replace')
    key = [l.strip() for l in t.splitlines() if 'Public-Key' in l]
    hdr = [l for l in t.splitlines()[:4]]
    print(f'{m.start():#08x} len {n:#x}', key, *hdr, sep='\n  ')
