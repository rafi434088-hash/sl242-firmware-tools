"""
PAC builder: FDL1(orig) + patched FDL2 + resigned UserImg.

גישת NOP (UnisocBypass):
  FDL2 מוטלא עם 3 patches שמבטלים Check 2 ו-Check 3 בפונקציית verify_cert:
    code[0xb3b2]  CA D1  bne (Check2 fail)          → 00 BF  NOP
    code[0xb3d0]  04 D1  bne (Check3 length fail)    → 00 BF  NOP
    code[0xb3da]  30 B1  cbz (Check3 memcmp to pass) → 06 E0  B always

  אחרי patch מעדכנים cert+0x16c = SHA256(patched_code).
  FDL1 מקבל FDL2 כי Check1 עובר (SHA256(code) נכון).
  FDL2 המוטלא מקבל UserImg כי Check2+3 מבוטלים, Check1 עובר.

Boot chain:
  BROM → FDL1 → patched FDL2 → UserImg runs
"""
import struct, hashlib, os, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from resign_4x4 import resign_image, inspect_cert

RESTORE = r'C:\Users\USER\Desktop\ריקבה\4x4_RESTORE.pac'
BYPASS  = r'C:\Users\USER\Desktop\ריקבה\4x4_bypass_codes.pac'
OUT     = r'C:\Users\USER\Desktop\ריקבה\4x4_user_codes.pac'

# NOP patches for FDL2 verify_cert (sig_type=0, UserImg path)
# Each tuple: (file_offset, expected_bytes, patch_bytes, description)
FDL2_PATCHES = [
    (0x200 + 0xb3b2, bytes([0xCA, 0xD1]), bytes([0x00, 0xBF]),
     'code[0xb3b2] bne->NOP  Check2 fail branch'),
    (0x200 + 0xb3d0, bytes([0x04, 0xD1]), bytes([0x00, 0xBF]),
     'code[0xb3d0] bne->NOP  Check3 length-fail branch'),
    (0x200 + 0xb3da, bytes([0x30, 0xB1]), bytes([0x06, 0xE0]),
     'code[0xb3da] cbz->B    Check3 memcmp always pass'),
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


def patch_fdl2(fdl2):
    """מוסיף NOPs ל-verify_cert של FDL2 ומעדכן cert hash."""
    fdl2 = bytearray(fdl2)
    code_sz = struct.unpack_from('<I', fdl2, 0x30)[0]
    cert_off = 0x200 + code_sz
    print(f'  FDL2 code_sz={code_sz:#x}  cert_off={cert_off:#x}')

    for (foff, expected, patch, desc) in FDL2_PATCHES:
        actual = bytes(fdl2[foff: foff + len(expected)])
        if actual != expected:
            raise AssertionError(
                f'FDL2 patch MISMATCH @ file[{foff:#x}]: '
                f'expected {expected.hex()}  got {actual.hex()}\n'
                f'  → {desc}')
        fdl2[foff: foff + len(patch)] = patch
        print(f'  patch OK: {desc}')

    # עדכון cert+0x16c = SHA256(patched code)
    code = bytes(fdl2[0x200: cert_off])
    new_hash = hashlib.sha256(code).digest()
    fdl2[cert_off + 0x16c: cert_off + 0x16c + 32] = new_hash
    print(f'  cert+0x16c updated: {new_hash.hex()[:32]}...')

    # בדיקת עצמית
    stored = bytes(fdl2[cert_off + 0x16c: cert_off + 0x16c + 32])
    assert stored == new_hash, 'cert hash write failed!'
    print(f'  FDL2 patch verified OK')
    return bytes(fdl2)


print('=== loading ===')
restore = open(RESTORE, 'rb').read()
bypass  = open(BYPASS,  'rb').read()

restore_e = list_entries(restore)
bypass_e  = list_entries(bypass)

print('RESTORE entries:', [x['name'] for x in restore_e])
print('BYPASS  entries:', [x['name'] for x in bypass_e])

fdl1_orig = get_data(restore, restore_e, 'FDL')
fdl2_orig = get_data(bypass,  bypass_e,  'FDL2')
ui_bypass = get_data(bypass,  bypass_e,  'UserImg')

assert fdl1_orig, 'FDL not found in RESTORE'
assert fdl2_orig, 'FDL2 not found in BYPASS'
assert ui_bypass, 'UserImg not found in BYPASS'

fdl2_md5 = hashlib.md5(bytes(fdl2_orig)).hexdigest()
print(f'\nFDL2 original md5={fdl2_md5}')

print('\n=== patching FDL2 ===')
fdl2_patched = patch_fdl2(bytes(fdl2_orig))
fdl2_patched_md5 = hashlib.md5(fdl2_patched).hexdigest()
print(f'  FDL2 patched md5={fdl2_patched_md5}')

print('\n=== resign UserImg ===')
inspect_cert(bytes(ui_bypass), 'before (bypass original)')
ui_resigned = resign_image(bytes(ui_bypass))
inspect_cert(bytes(ui_resigned), 'after (resigned)')

# integrity check
code_sz_ui  = struct.unpack_from('<I', bytearray(ui_resigned), 0x30)[0]
cert_off_ui = 0x200 + code_sz_ui
sha_in   = ui_resigned[cert_off_ui+0x16c: cert_off_ui+0x16c+32]
sha_act  = hashlib.sha256(ui_resigned[0x200: cert_off_ui]).digest()
assert sha_in == sha_act, 'UserImg SHA256 mismatch!'
print(f'  UserImg integrity OK')

# XML from RESTORE (no SML)
xml_e     = restore_e[-1]
xml_bytes = bytearray(restore[xml_e['doff']: xml_e['doff'] + xml_e['sz']])
assert b'<ID>SML</ID>' not in xml_bytes, 'RESTORE XML has SML entry!'
print(f'\n  XML: {len(xml_bytes)} bytes  (no SML)')

print('\n=== build PAC ===')
ENTRY_HDR  = 0xa14
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
fdl2_off = fdl_off  + len(fdl1_orig)
ui_off   = fdl2_off + len(fdl2_patched)
xml_off  = ui_off   + len(ui_resigned)


def set_doff(e, doff, sz):
    struct.pack_into('<I', e, 0x610, doff)
    struct.pack_into('<I', e, 0x604, sz)


set_doff(fdl_entry,  fdl_off,  len(fdl1_orig))
set_doff(fdl2_entry, fdl2_off, len(fdl2_patched))
set_doff(ui_entry,   ui_off,   len(ui_resigned))
set_doff(xml_entry,  xml_off,  len(xml_bytes))

pac = bytearray(restore[:0x84C])
pac += fdl_entry
pac += fdl2_entry
pac += ui_entry
pac += xml_entry
pac += bytes(fdl1_orig)
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
print(f'  {OUT}')
print(f'  {len(pac)//1024} KB   crc1={crc1:#06x}   crc2={crc2:#06x}')
print(f'  md5={md5}')
print(f'\ncontents:')
print(f'  FDL:     original OEM       ({len(fdl1_orig)//1024} KB)')
print(f'  FDL2:    NOP-patched         ({len(fdl2_patched)//1024} KB)  Check2+3 bypassed')
print(f'  UserImg: bypass + resigned  ({len(ui_resigned)//1024} KB)  dial codes *#7701#-*#7711#')
print(f'  XML:     RESTORE (no SML)')
