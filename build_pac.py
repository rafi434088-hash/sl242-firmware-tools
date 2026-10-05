"""
PAC builder: patched FDL1 + patched FDL2 + resigned UserImg.

Two-layer NOP patch (UnisocBypass approach):

  FDL1 sig_type=1 path (FDL1 verifying FDL2):
    code1[0x2196]  04 D1  bne (Check3 length fail) -> 00 BF  NOP
    code1[0x21a0]  08 B1  cbz (Check3 memcmp pass) -> 01 E0  B always

  FDL2 sig_type=0 path (FDL2 verifying UserImg):
    code[0xb3b2]   CA D1  bne (Check2 fail)         -> 00 BF  NOP
    code[0xb3d0]   04 D1  bne (Check3 length fail)  -> 00 BF  NOP
    code[0xb3da]   30 B1  cbz (Check3 memcmp pass)  -> 06 E0  B always

  Both: update cert+0x16c = SHA256(patched_code).

  BROM in download mode only checks cert+0x16c (hash), not RSA.
  Patched FDL1: BROM accepts (hash updated).
  Patched FDL2: patched FDL1 accepts (Check3 bypassed, hash updated).
  Resigned UserImg: patched FDL2 accepts (Check2+3 bypassed, hash OK).

Boot chain: BROM -> patched FDL1 -> patched FDL2 -> UserImg
"""
import struct, hashlib, os, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from resign_4x4 import resign_image, inspect_cert

RESTORE = r'C:\Users\USER\Desktop\ריקבה\4x4_RESTORE.pac'
BYPASS  = r'C:\Users\USER\Desktop\ריקבה\4x4_bypass_codes.pac'
OUT     = r'C:\Users\USER\Desktop\ריקבה\4x4_user_codes.pac'

# FDL1 patches: sig_type=1 path, Check 3 only
FDL1_PATCHES = [
    (0x200 + 0x2196, bytes([0x04, 0xD1]), bytes([0x00, 0xBF]),
     'code1[0x2196] bne->NOP  Check3 length-fail (sig_type=1)'),
    (0x200 + 0x21a0, bytes([0x08, 0xB1]), bytes([0x01, 0xE0]),
     'code1[0x21a0] cbz->B    Check3 always-pass (sig_type=1)'),
]

# FDL2 patches: sig_type=0 path, Check 2+3
FDL2_PATCHES = [
    (0x200 + 0xb3b2, bytes([0xCA, 0xD1]), bytes([0x00, 0xBF]),
     'code[0xb3b2] bne->NOP  Check2 fail (sig_type=0)'),
    (0x200 + 0xb3d0, bytes([0x04, 0xD1]), bytes([0x00, 0xBF]),
     'code[0xb3d0] bne->NOP  Check3 length-fail (sig_type=0)'),
    (0x200 + 0xb3da, bytes([0x30, 0xB1]), bytes([0x06, 0xE0]),
     'code[0xb3da] cbz->B    Check3 always-pass (sig_type=0)'),
]


def crc16_ibm(data):
    crc = 0
    for b in data:
        crc ^= b
        for _ in range(8):
            if crc & 1: crc = (crc >> 1) ^ 0xA001
            else:       crc >>= 1
    return crc


def list_entries(pac):
    entries = []
    off = 0x84C
    for _ in range(30):
        cs = struct.unpack_from('<I', pac, off)[0]
        if not cs or cs > 0x10000000: break
        name = pac[off+4:off+4+0x100].decode('utf-16-le', 'ignore').split('\x00')[0]
        sz   = struct.unpack_from('<I', pac, off+0x604)[0]
        doff = struct.unpack_from('<I', pac, off+0x610)[0]
        entries.append({'name': name, 'off': off, 'cs': cs, 'doff': doff, 'sz': sz})
        off += cs
    return entries


def get_data(pac, elist, name):
    e = next((x for x in elist if x['name'] == name), None)
    if not e: return None
    return bytearray(pac[e['doff']: e['doff'] + e['sz']])


def apply_patches(img, patches, label):
    img = bytearray(img)
    code_sz = struct.unpack_from('<I', img, 0x30)[0]
    cert_off = 0x200 + code_sz
    print(f'  {label}: code_sz={code_sz:#x}  cert_off={cert_off:#x}')
    for (foff, expected, patch, desc) in patches:
        actual = bytes(img[foff: foff + len(expected)])
        if actual != expected:
            raise AssertionError(
                f'{label} patch MISMATCH @ file[{foff:#x}]: '
                f'expected {expected.hex()}  got {actual.hex()}')
        img[foff: foff + len(patch)] = patch
        print(f'  [OK] {desc}')
    new_hash = hashlib.sha256(bytes(img[0x200: cert_off])).digest()
    img[cert_off + 0x16c: cert_off + 0x16c + 32] = new_hash
    stored = bytes(img[cert_off + 0x16c: cert_off + 0x16c + 32])
    assert stored == new_hash, 'cert hash write failed'
    print(f'  cert+0x16c = {new_hash.hex()[:32]}...')
    return bytes(img)


print('=== loading ===')
restore = open(RESTORE, 'rb').read()
bypass  = open(BYPASS,  'rb').read()

restore_e = list_entries(restore)
bypass_e  = list_entries(bypass)

fdl1_orig = get_data(restore, restore_e, 'FDL')
fdl2_orig = get_data(bypass,  bypass_e,  'FDL2')
ui_bypass = get_data(bypass,  bypass_e,  'UserImg')

assert fdl1_orig, 'FDL not found in RESTORE'
assert fdl2_orig, 'FDL2 not found in BYPASS'
assert ui_bypass, 'UserImg not found in BYPASS'

print('FDL1 md5:', hashlib.md5(bytes(fdl1_orig)).hexdigest())
print('FDL2 md5:', hashlib.md5(bytes(fdl2_orig)).hexdigest())

print('\n=== patch FDL1 (Check3 bypass for sig_type=1) ===')
fdl1_patched = apply_patches(bytes(fdl1_orig), FDL1_PATCHES, 'FDL1')

print('\n=== patch FDL2 (Check2+3 bypass for sig_type=0) ===')
fdl2_patched = apply_patches(bytes(fdl2_orig), FDL2_PATCHES, 'FDL2')

print('\n=== resign UserImg ===')
inspect_cert(bytes(ui_bypass), 'bypass original')
ui_resigned = resign_image(bytes(ui_bypass))
inspect_cert(bytes(ui_resigned), 'resigned')
assert len(ui_resigned) == len(ui_bypass), 'UserImg size changed!'

code_sz_ui  = struct.unpack_from('<I', bytearray(ui_resigned), 0x30)[0]
cert_off_ui = 0x200 + code_sz_ui
sha_in  = ui_resigned[cert_off_ui+0x16c: cert_off_ui+0x16c+32]
sha_act = hashlib.sha256(ui_resigned[0x200: cert_off_ui]).digest()
assert sha_in == sha_act, 'UserImg SHA256 mismatch!'
print('  UserImg integrity OK')

# XML from RESTORE (FDL+FDL2+UserImg only, no SML)
xml_e     = restore_e[-1]
xml_bytes = bytearray(restore[xml_e['doff']: xml_e['doff'] + xml_e['sz']])
assert b'<ID>SML</ID>' not in xml_bytes, 'RESTORE XML has unexpected SML entry'

print('\n=== build PAC ===')
ENTRY_HDR   = 0xa14
NUM_ENTRIES = 4   # FDL, FDL2, UserImg, XML

r_fdl_e  = next(x for x in restore_e if x['name'] == 'FDL')
r_fdl2_e = next(x for x in restore_e if x['name'] == 'FDL2')
r_ui_e   = next(x for x in restore_e if x['name'] == 'UserImg')
r_xml_e  = restore_e[-1]

fdl_entry  = bytearray(restore[r_fdl_e['off']  : r_fdl_e['off']  + ENTRY_HDR])
fdl2_entry = bytearray(restore[r_fdl2_e['off'] : r_fdl2_e['off'] + ENTRY_HDR])
ui_entry   = bytearray(restore[r_ui_e['off']   : r_ui_e['off']   + ENTRY_HDR])
xml_entry  = bytearray(restore[r_xml_e['off']  : r_xml_e['off']  + ENTRY_HDR])

hdr_end  = 0x84C + NUM_ENTRIES * ENTRY_HDR
fdl_off  = hdr_end
fdl2_off = fdl_off  + len(fdl1_patched)
ui_off   = fdl2_off + len(fdl2_patched)
xml_off  = ui_off   + len(ui_resigned)


def set_doff(e, doff, sz):
    struct.pack_into('<I', e, 0x610, doff)
    struct.pack_into('<I', e, 0x604, sz)


set_doff(fdl_entry,  fdl_off,  len(fdl1_patched))
set_doff(fdl2_entry, fdl2_off, len(fdl2_patched))
set_doff(ui_entry,   ui_off,   len(ui_resigned))
set_doff(xml_entry,  xml_off,  len(xml_bytes))

pac = bytearray(restore[:0x84C])
pac += fdl_entry
pac += fdl2_entry
pac += ui_entry
pac += xml_entry
pac += bytes(fdl1_patched)
pac += bytes(fdl2_patched)
pac += bytes(ui_resigned)
pac += bytes(xml_bytes)

struct.pack_into('<I', pac, 0x30,  len(pac))
struct.pack_into('<I', pac, 0x434, NUM_ENTRIES)

crc1 = crc16_ibm(pac[0x000:0x848])
crc2 = crc16_ibm(pac[0x84C:])
struct.pack_into('<H', pac, 0x848, crc1)
struct.pack_into('<H', pac, 0x84A, crc2)

open(OUT, 'wb').write(bytes(pac))
md5 = hashlib.md5(bytes(pac)).hexdigest()

print(f'\n=== PAC ready ===')
print(f'  {len(pac)//1024} KB   crc1={crc1:#06x}   crc2={crc2:#06x}   md5={md5}')
print(f'  FDL1:    patched  ({len(fdl1_patched)//1024} KB)  Check3 bypassed')
print(f'  FDL2:    patched  ({len(fdl2_patched)//1024} KB)  Check2+3 bypassed')
print(f'  UserImg: resigned ({len(ui_resigned)//1024} KB)  dial codes *#7701#-*#7711#')
