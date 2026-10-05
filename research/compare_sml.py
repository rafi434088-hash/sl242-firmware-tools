"""
Compare SML from RESTORE vs BYPASS.
If bypass SML has different code, it might patch FDL2 memory at runtime.
"""
import struct, hashlib, sys
sys.path.insert(0, r'C:\Users\USER\Documents\CLAOD\sl242-firmware-tools')

RESTORE = r'C:\Users\USER\Desktop\ריקבה\4x4_RESTORE.pac'
BYPASS  = r'C:\Users\USER\Desktop\ריקבה\4x4_bypass_codes.pac'

def list_entries(pac):
    entries = []
    off = 0x84C
    for _ in range(30):
        cs = struct.unpack_from('<I', pac, off)[0]
        if not cs or cs > 0x10000000: break
        name = pac[off+4:off+4+0x100].decode('utf-16-le','ignore').split('\x00')[0]
        sz   = struct.unpack_from('<I', pac, off+0x604)[0]
        doff = struct.unpack_from('<I', pac, off+0x610)[0]
        entries.append({'name':name,'off':off,'cs':cs,'doff':doff,'sz':sz})
        off += cs
    return entries

def get_data(pac, elist, name):
    e = next((x for x in elist if x['name'] == name), None)
    if not e: return None
    return bytes(pac[e['doff']: e['doff'] + e['sz']])

r = open(RESTORE,'rb').read()
b = open(BYPASS, 'rb').read()
re = list_entries(r)
be = list_entries(b)

print('RESTORE entries:', [x['name'] for x in re])
print('BYPASS entries: ', [x['name'] for x in be])

sml_r = get_data(r, re, 'SML')
sml_b = get_data(b, be, 'SML')

if not sml_r: print('SML not in RESTORE'); exit()
if not sml_b: print('SML not in BYPASS'); exit()

print(f'\nRESTORE SML: {len(sml_r):#x} bytes  md5={hashlib.md5(sml_r).hexdigest()}')
print(f'BYPASS  SML: {len(sml_b):#x} bytes  md5={hashlib.md5(sml_b).hexdigest()}')

# code section comparison (0x200 to 0x200+code_sz)
code_sz_r = struct.unpack_from('<I', sml_r, 0x30)[0]
code_sz_b = struct.unpack_from('<I', sml_b, 0x30)[0]
print(f'\nRESTORE SML code_sz={code_sz_r:#x}')
print(f'BYPASS  SML code_sz={code_sz_b:#x}')

code_r = sml_r[0x200: 0x200+code_sz_r]
code_b = sml_b[0x200: 0x200+code_sz_b]

print(f'\ncode SHA256:')
print(f'  RESTORE: {hashlib.sha256(code_r).hexdigest()}')
print(f'  BYPASS:  {hashlib.sha256(code_b).hexdigest()}')

if code_r == code_b[:len(code_r)]:
    print('\nCODE IS IDENTICAL (first min_len bytes)')
else:
    # find first diff
    diffs = 0
    first_diff = -1
    for i in range(min(len(code_r), len(code_b))):
        if code_r[i] != code_b[i]:
            diffs += 1
            if first_diff < 0:
                first_diff = i
    print(f'\nCODE DIFFERS: {diffs} byte differences, first at code[{first_diff:#x}]')
    print('First 10 diffs:')
    shown = 0
    for i in range(min(len(code_r), len(code_b))):
        if code_r[i] != code_b[i]:
            print(f'  code[{i:#07x}]: RESTORE={code_r[i]:02x}  BYPASS={code_b[i]:02x}')
            shown += 1
            if shown >= 10: break

# cert comparison
cert_off_r = 0x200 + code_sz_r
cert_off_b = 0x200 + code_sz_b
cert_r = sml_r[cert_off_r:]
cert_b = sml_b[cert_off_b:]

print(f'\ncert[+0x60..+0x70] RESTORE: {cert_r[0x60:0x70].hex()}  (sig_type + key_sz)')
print(f'cert[+0x60..+0x70] BYPASS:  {cert_b[0x60:0x70].hex()}')
print(f'\ncert[+0x6c..+0x7c] RESTORE modulus[0:16]: {cert_r[0x6c:0x7c].hex()}')
print(f'cert[+0x6c..+0x7c] BYPASS  modulus[0:16]: {cert_b[0x6c:0x7c].hex()}')
