"""
PAC הכי פשוט — ללא patches בכלל.
OEM FDL1 (original) + OEM FDL2 (original) + bypass UserImg re-signed with our key.

תכלית: לבדוק אם FDL2 מאמת UserImg cert בזמן download mode.
  - אם passes: FDL2 לא מאמת cert -> כל UserImg עובר -> פשוט
  - אם fails at UserImg step: FDL2 מאמת -> צריך bypass key / cert-zero
  - אם fails at FDL2 step: FDL1 לא מקבל OEM FDL2 (לא צפוי)
"""
import struct, hashlib, os, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from resign_4x4 import resign_image, inspect_cert

RESTORE = r'C:\Users\USER\Desktop\ריקבה\4x4_RESTORE.pac'
BYPASS  = r'C:\Users\USER\Desktop\ריקבה\4x4_bypass_codes.pac'
OUT     = r'C:\Users\USER\Desktop\ריקבה\4x4_user_codes.pac'


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


print('=== loading ===')
restore = open(RESTORE, 'rb').read()
bypass  = open(BYPASS,  'rb').read()
restore_e = list_entries(restore)
bypass_e  = list_entries(bypass)

# FDL1 + FDL2: original OEM (from RESTORE, unmodified)
fdl1_orig = bytes(get_data(restore, restore_e, 'FDL'))
fdl2_orig = bytes(get_data(restore, restore_e, 'FDL2'))
ui_bypass = bytes(get_data(bypass, bypass_e, 'UserImg'))

assert fdl1_orig, 'FDL not found'
assert fdl2_orig, 'FDL2 not found'
assert ui_bypass, 'UserImg not found'

print(f'FDL1 md5: {hashlib.md5(fdl1_orig).hexdigest()}')
print(f'FDL2 md5: {hashlib.md5(fdl2_orig).hexdigest()}')

print('\n=== resign UserImg (no code patches) ===')
inspect_cert(ui_bypass, 'bypass original')
ui_resigned = resign_image(bytes(ui_bypass))
inspect_cert(bytes(ui_resigned), 'resigned')
assert len(ui_resigned) == len(ui_bypass), 'size changed'

ENTRY_HDR = 0xa14
NUM_ENTRIES = 4  # FDL, FDL2, UserImg, XML

r_fdl_e  = next(x for x in restore_e if x['name'] == 'FDL')
r_fdl2_e = next(x for x in restore_e if x['name'] == 'FDL2')
r_ui_e   = next(x for x in restore_e if x['name'] == 'UserImg')
r_xml_e  = restore_e[-1]

fdl_entry  = bytearray(restore[r_fdl_e['off']  : r_fdl_e['off']  + ENTRY_HDR])
fdl2_entry = bytearray(restore[r_fdl2_e['off'] : r_fdl2_e['off'] + ENTRY_HDR])
ui_entry   = bytearray(restore[r_ui_e['off']   : r_ui_e['off']   + ENTRY_HDR])
xml_entry  = bytearray(restore[r_xml_e['off']  : r_xml_e['off']  + ENTRY_HDR])
xml_bytes  = bytearray(restore[r_xml_e['doff'] : r_xml_e['doff'] + r_xml_e['sz']])

hdr_end  = 0x84C + NUM_ENTRIES * ENTRY_HDR
fdl_off  = hdr_end
fdl2_off = fdl_off  + len(fdl1_orig)
ui_off   = fdl2_off + len(fdl2_orig)
xml_off  = ui_off   + len(ui_resigned)

def set_doff(e, doff, sz):
    struct.pack_into('<I', e, 0x610, doff)
    struct.pack_into('<I', e, 0x604, sz)

set_doff(fdl_entry,  fdl_off,  len(fdl1_orig))
set_doff(fdl2_entry, fdl2_off, len(fdl2_orig))
set_doff(ui_entry,   ui_off,   len(ui_resigned))
set_doff(xml_entry,  xml_off,  len(xml_bytes))

pac = bytearray(restore[:0x84C])
pac += fdl_entry
pac += fdl2_entry
pac += ui_entry
pac += xml_entry
pac += fdl1_orig
pac += fdl2_orig
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
print(f'  FDL1:    OEM original  ({len(fdl1_orig)//1024} KB)  UNMODIFIED')
print(f'  FDL2:    OEM original  ({len(fdl2_orig)//1024} KB)  UNMODIFIED')
print(f'  UserImg: resigned      ({len(ui_resigned)//1024} KB)  our key, bypass code')
