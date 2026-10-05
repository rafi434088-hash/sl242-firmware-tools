"""
בודק את ה-FDL2 ב-4x4_FULL_factory_SL242_GX2421.pac ומשווה לRESTORE.
שאלה: האם ה-factory FDL2 שונה (אולי debug/factory mode שלא בודק cert)?
"""
import struct, hashlib, sys
from pathlib import Path

RESTORE  = r'C:\Users\USER\Desktop\ריקבה\4x4_RESTORE.pac'
FACTORY  = r'C:\Users\USER\Desktop\ריקבה\4x4_FULL_factory_SL242_GX2421.pac'

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

restore = open(RESTORE,'rb').read()
factory = open(FACTORY,'rb').read()
re = list_entries(restore)
fe = list_entries(factory)

print('=== FACTORY PAC entries ===')
for e in fe:
    print(f'  {e["name"]:15s}  sz={e["sz"]:#x}  doff={e["doff"]:#x}')

print()
print('=== RESTORE PAC entries ===')
for e in re:
    print(f'  {e["name"]:15s}  sz={e["sz"]:#x}  doff={e["doff"]:#x}')

print()
for name in ['FDL','FDL2','UserImg']:
    r_img = get_img(restore, re, name)
    f_img = get_img(factory, fe, name)
    r_md5 = hashlib.md5(r_img).hexdigest() if r_img else 'N/A'
    f_md5 = hashlib.md5(f_img).hexdigest() if f_img else 'N/A'
    same = '== SAME ==' if r_img and f_img and r_md5 == f_md5 else '!! DIFFERENT !!'
    print(f'{name:10s}  RESTORE={r_md5[:12]}  FACTORY={f_md5[:12]}  {same}')

# Inspect FDL2 cert in factory PAC
print()
fdl2_f = get_img(factory, fe, 'FDL2')
if fdl2_f:
    code_sz = struct.unpack_from('<I', fdl2_f, 0x30)[0]
    cert_off = 0x200 + code_sz
    payload_sz = struct.unpack_from('<I', fdl2_f, cert_off+0x20)[0]
    sig_type   = struct.unpack_from('<I', fdl2_f, cert_off+0x60)[0]
    key_size   = struct.unpack_from('<I', fdl2_f, cert_off+0x64)[0]
    mod4 = fdl2_f[cert_off+0x6c: cert_off+0x70].hex()
    sha256_in_cert = fdl2_f[cert_off+0x16c: cert_off+0x16c+4].hex()
    sha256_actual = hashlib.sha256(fdl2_f[0x200:cert_off]).hexdigest()
    print(f'FACTORY FDL2 cert:')
    print(f'  code_sz={code_sz:#x}  cert_off={cert_off:#x}')
    print(f'  payload_sz={payload_sz:#x}')
    print(f'  sig_type={sig_type}')
    print(f'  key_size={key_size}')
    print(f'  mod[0:4]={mod4}')
    print(f'  cert+0x16c (SHA256 stored)={sha256_in_cert}...')
    print(f'  SHA256(code) actual       ={sha256_actual[:8]}...')
    match = sha256_actual[:8] == sha256_in_cert[:8]
    print(f'  hash match: {match}')
