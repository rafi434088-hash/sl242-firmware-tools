"""
מוצא הבדלים בין CODES UserImg ל-RESTORE UserImg.
שאלה: האם ב-CODES UserImg כבר יש קוד חיוג? ומה בדיוק שונה?
"""
import struct, hashlib
from pathlib import Path

RESTORE   = r'C:\Users\USER\Desktop\ריקבה\4x4_RESTORE.pac'
CODES_PAC = r'C:\Users\USER\Desktop\ריקבה\4x4_CODES.pac'
BYPASS_PAC = r'C:\Users\USER\Desktop\ריקבה\4x4_bypass_codes.pac'
SRC_CODES  = r'C:\Users\USER\Desktop\ריקבה\src\user_codes.bin'

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

restore  = open(RESTORE,'rb').read()
codes    = open(CODES_PAC,'rb').read()
bypass   = open(BYPASS_PAC,'rb').read()

re = list_entries(restore)
ce = list_entries(codes)
be = list_entries(bypass)

r_ui = get_img(restore, re, 'UserImg')
c_ui = get_img(codes,   ce, 'UserImg')
b_ui = get_img(bypass,  be, 'UserImg')

# Find diffs between RESTORE and CODES UserImg (code section only)
r_code_sz = struct.unpack_from('<I', r_ui, 0x30)[0]
c_code_sz = struct.unpack_from('<I', c_ui, 0x30)[0]
b_code_sz = struct.unpack_from('<I', b_ui, 0x30)[0]

print(f'RESTORE UserImg code_sz={r_code_sz:#x}  total={len(r_ui):#x}')
print(f'BYPASS  UserImg code_sz={b_code_sz:#x}  total={len(b_ui):#x}')
print(f'CODES   UserImg code_sz={c_code_sz:#x}  total={len(c_ui):#x}')
print()

# Diff RESTORE code vs CODES code (first 0x200 bytes are DHTB header)
mn = min(r_code_sz, c_code_sz)
diffs_rc = []
for i in range(mn):
    file_off = 0x200 + i
    if r_ui[file_off] != c_ui[file_off]:
        diffs_rc.append((file_off, i, r_ui[file_off], c_ui[file_off]))

print(f'RESTORE vs CODES code diffs: {len(diffs_rc)} bytes')
for off, code_off, rv, cv in diffs_rc[:50]:
    print(f'  file[{off:#08x}] code[{code_off:#08x}]  {rv:02x} -> {cv:02x}')
if len(diffs_rc) > 50:
    print(f'  ... and {len(diffs_rc)-50} more')

print()

# Diff BYPASS code vs RESTORE code
diffs_br = []
for i in range(min(b_code_sz, r_code_sz)):
    file_off = 0x200 + i
    if b_ui[file_off] != r_ui[file_off]:
        diffs_br.append((file_off, i, r_ui[file_off], b_ui[file_off]))
print(f'RESTORE vs BYPASS code diffs: {len(diffs_br)} bytes')
for off, code_off, rv, bv in diffs_br[:30]:
    print(f'  file[{off:#08x}] code[{code_off:#08x}]  {rv:02x} -> {bv:02x}')
if len(diffs_br) > 30:
    print(f'  ... and {len(diffs_br)-30} more')

print()

# Check if src/user_codes.bin exists and how it relates
p = Path(SRC_CODES)
if p.exists():
    src = p.read_bytes()
    print(f'src/user_codes.bin: {len(src):#x} bytes  md5={hashlib.md5(src).hexdigest()}')
    # Is it same as c_ui?
    if src == bytes(c_ui):
        print('  == CODES.pac UserImg EXACT MATCH')
    else:
        print('  DIFFERENT from CODES.pac UserImg')
    # Does it start with DHTB?
    print(f'  magic: {src[:8].hex()}  (DHTB = 44485442 01000000)')
    src_code_sz = struct.unpack_from('<I', src, 0x30)[0]
    print(f'  code_sz={src_code_sz:#x}')
    # cert
    cert_off = 0x200 + src_code_sz
    if cert_off + 0x200 < len(src):
        payload_sz = struct.unpack_from('<I', src, cert_off+0x20)[0]
        mod4 = src[cert_off+0x6c: cert_off+0x70].hex()
        sha_stored = src[cert_off+0x16c: cert_off+0x16c+4].hex()
        sha_actual = hashlib.sha256(src[0x200:cert_off]).hexdigest()
        print(f'  cert: payload_sz={payload_sz:#x}  mod={mod4}')
        print(f'  hash match: {sha_stored == sha_actual[:8]}')
else:
    print(f'src/user_codes.bin: NOT FOUND')

# Search for *#7701# or similar patterns in CODES UserImg
print()
print('Searching for dial code patterns in CODES UserImg...')
ui_bytes = bytes(c_ui[:c_code_sz + 0x200])  # code section only
for pattern in [b'7701', b'7702', b'7703', b'*#7', b'\x37\x37\x30\x31']:
    idx = 0
    found = []
    while True:
        idx = ui_bytes.find(pattern, idx)
        if idx == -1: break
        found.append(idx)
        idx += 1
    if found:
        print(f'  {pattern!r}: found at {[hex(x) for x in found[:5]]}')
    else:
        print(f'  {pattern!r}: NOT FOUND')
