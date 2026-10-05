"""
משווה FDL2_patched.bin ו-fdl2_patched_v4.bin מול OEM FDL2.
מוצא בדיוק אילו bytes שונים.
גם בודק 4x4_CODES.pac — מה ה-FDL1/FDL2/UserImg שלו.
"""
import struct, hashlib, sys
from pathlib import Path

RESTORE  = r'C:\Users\USER\Desktop\ריקבה\4x4_RESTORE.pac'
FDL2_P1  = r'C:\Users\USER\Desktop\ריקבה\FDL2_patched.bin'
FDL2_P4  = r'C:\Users\USER\Desktop\ריקבה\fdl2_patched_v4.bin'
CODES_PAC = r'C:\Users\USER\Desktop\ריקבה\4x4_CODES.pac'

def list_entries(pac):
    entries = []
    off = 0x84C
    for _ in range(60):
        cs = struct.unpack_from('<I', pac, off)[0]
        if not cs or cs > 0x10000000: break
        name = pac[off+4:off+4+0x100].decode('utf-16-le','ignore').split('\x00')[0]
        sz   = struct.unpack_from('<I', pac, off+0x604)[0]
        doff = struct.unpack_from('<I', pac, off+0x610)[0]
        entries.append({'name':name,'off':off,'cs':cs,'doff':doff,'sz':sz})
        off += cs
    return entries

def get_img(pac, entries, name):
    e = next((x for x in entries if x['name'] == name), None)
    if not e: return None
    return pac[e['doff']: e['doff']+e['sz']]

def diff_bytes(a, b, label, max_diffs=30):
    mn = min(len(a), len(b))
    diffs = []
    for i in range(mn):
        if a[i] != b[i]:
            diffs.append((i, a[i], b[i]))
    if len(a) != len(b):
        print(f'  {label}: size diff!  a={len(a):#x}  b={len(b):#x}')
    print(f'  {label}: {len(diffs)} byte differences')
    for i, av, bv in diffs[:max_diffs]:
        print(f'    [{i:#08x}]  {av:02x} -> {bv:02x}')
    if len(diffs) > max_diffs:
        print(f'    ... and {len(diffs)-max_diffs} more')

restore = open(RESTORE,'rb').read()
re = list_entries(restore)
fdl2_oem = get_img(restore, re, 'FDL2')

print('=== FDL2 OEM md5:', hashlib.md5(fdl2_oem).hexdigest())
print()

for path, label in [(FDL2_P1,'FDL2_patched'), (FDL2_P4,'fdl2_patched_v4')]:
    p = Path(path)
    if not p.exists():
        print(f'{label}: NOT FOUND')
        continue
    data = p.read_bytes()
    print(f'=== {label} ===')
    print(f'  size={len(data):#x}  md5={hashlib.md5(data).hexdigest()}')
    diff_bytes(fdl2_oem, data, f'OEM vs {label}')
    # Also inspect cert
    code_sz = struct.unpack_from('<I', data, 0x30)[0]
    cert_off = 0x200 + code_sz
    if cert_off + 0x1a4 < len(data):
        payload_sz = struct.unpack_from('<I', data, cert_off+0x20)[0]
        sig_type   = struct.unpack_from('<I', data, cert_off+0x60)[0]
        mod4 = data[cert_off+0x6c: cert_off+0x70].hex()
        sha_stored = data[cert_off+0x16c: cert_off+0x16c+4].hex()
        sha_actual = hashlib.sha256(data[0x200:cert_off]).hexdigest()
        print(f'  cert: payload_sz={payload_sz:#x} sig_type={sig_type} mod={mod4} sha_stored={sha_stored} sha_actual={sha_actual[:8]}')
        match = sha_stored == sha_actual[:8]
        print(f'  cert hash match: {match}')
    print()

# 4x4_CODES.pac
print('=== 4x4_CODES.pac ===')
if Path(CODES_PAC).exists():
    codes = open(CODES_PAC,'rb').read()
    ce = list_entries(codes)
    print('Entries:')
    for e in ce:
        print(f'  {e["name"]:15s}  sz={e["sz"]:#x}')
    for name in ['FDL','FDL2','UserImg']:
        img = get_img(codes, ce, name)
        oem = get_img(restore, re, name)
        if img and oem:
            md5 = hashlib.md5(img).hexdigest()
            print(f'  {name}: md5={md5[:12]}  {"== OEM ==" if md5 == hashlib.md5(oem).hexdigest() else "!! DIFFERENT !!"}')
        elif img:
            print(f'  {name}: md5={hashlib.md5(img).hexdigest()[:12]}  (not in RESTORE)')
    # Inspect FDL2 cert
    fdl2_c = get_img(codes, ce, 'FDL2')
    if fdl2_c:
        code_sz = struct.unpack_from('<I', fdl2_c, 0x30)[0]
        cert_off = 0x200 + code_sz
        payload_sz = struct.unpack_from('<I', fdl2_c, cert_off+0x20)[0]
        sig_type   = struct.unpack_from('<I', fdl2_c, cert_off+0x60)[0]
        mod4 = fdl2_c[cert_off+0x6c: cert_off+0x70].hex()
        sha_stored = fdl2_c[cert_off+0x16c: cert_off+0x16c+4].hex()
        sha_actual = hashlib.sha256(fdl2_c[0x200:cert_off]).hexdigest()
        print(f'  FDL2 cert: payload_sz={payload_sz:#x} sig_type={sig_type} mod={mod4} sha_stored={sha_stored} sha_actual={sha_actual[:8]}')
        diff_bytes(fdl2_oem, fdl2_c, 'OEM vs CODES.pac FDL2')
