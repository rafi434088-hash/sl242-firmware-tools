"""
בודק UserImg cert ב-4x4_CODES.pac — עם איזה מפתח חתום?
ומחפש bypass private key בספריות הפרויקט.
"""
import struct, hashlib, os
from pathlib import Path

RESTORE   = r'C:\Users\USER\Desktop\ריקבה\4x4_RESTORE.pac'
CODES_PAC = r'C:\Users\USER\Desktop\ריקבה\4x4_CODES.pac'
BYPASS_PAC = r'C:\Users\USER\Desktop\ריקבה\4x4_bypass_codes.pac'

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

def inspect_userimg_cert(img, label):
    code_sz  = struct.unpack_from('<I', img, 0x30)[0]
    cert_off = 0x200 + code_sz
    if cert_off + 0x200 > len(img):
        print(f'  {label}: cert out of range')
        return
    payload_sz = struct.unpack_from('<I', img, cert_off+0x20)[0]
    sig_type   = struct.unpack_from('<I', img, cert_off+0x60)[0]
    key_size   = struct.unpack_from('<I', img, cert_off+0x64)[0]
    mod        = img[cert_off+0x6c: cert_off+0x6c+8].hex()
    field8     = img[cert_off+0x18c: cert_off+0x18c+8].hex()
    sha_stored = img[cert_off+0x16c: cert_off+0x16c+32].hex()
    sha_actual = hashlib.sha256(img[0x200:cert_off]).hexdigest()
    sig_4b     = img[cert_off+0x194: cert_off+0x198].hex()
    print(f'  {label}:')
    print(f'    code_sz={code_sz:#x} cert_off={cert_off:#x} payload_sz={payload_sz:#x}')
    print(f'    sig_type={sig_type} key_size={key_size} mod={mod}')
    print(f'    field8={field8}')
    print(f'    sha_stored={sha_stored[:16]}...')
    print(f'    sha_actual={sha_actual[:16]}...')
    print(f'    hash_match={sha_stored == sha_actual}')
    print(f'    sig[0:4]={sig_4b}')

restore  = open(RESTORE,'rb').read()
codes    = open(CODES_PAC,'rb').read()
bypass   = open(BYPASS_PAC,'rb').read()

re = list_entries(restore)
ce = list_entries(codes)
be = list_entries(bypass)

print('=== UserImg cert comparison ===')
r_ui = get_img(restore, re, 'UserImg')
c_ui = get_img(codes,   ce, 'UserImg')
b_ui = get_img(bypass,  be, 'UserImg')

inspect_userimg_cert(r_ui, 'RESTORE UserImg')
print()
inspect_userimg_cert(b_ui, 'BYPASS UserImg')
print()
inspect_userimg_cert(c_ui, 'CODES UserImg')

# Check if CODES UserImg mod matches bypass UserImg mod
b_code_sz = struct.unpack_from('<I', b_ui, 0x30)[0]
c_code_sz = struct.unpack_from('<I', c_ui, 0x30)[0]
b_cert = 0x200 + b_code_sz
c_cert = 0x200 + c_code_sz
b_mod = b_ui[b_cert+0x6c: b_cert+0x6c+8].hex()
c_mod = c_ui[c_cert+0x6c: c_cert+0x6c+8].hex()
print()
print(f'BYPASS mod first 8B: {b_mod}')
print(f'CODES  mod first 8B: {c_mod}')
print(f'Same key: {b_mod == c_mod}')

# Search for bypass private key
print()
print('=== Searching for bypass private key ===')
search_dirs = [
    r'C:\Users\USER\Desktop\ריקבה',
    r'C:\Users\USER\Desktop\5555',
    r'C:\Users\USER\Documents\CLAOD\sl242-firmware-tools',
]
for d in search_dirs:
    for root, dirs, files in os.walk(d):
        for f in files:
            if any(kw in f.lower() for kw in ['key', 'pem', 'priv', 'bypass', 'jig']):
                fp = os.path.join(root, f)
                sz = os.path.getsize(fp)
                print(f'  {fp}  ({sz} bytes)')
