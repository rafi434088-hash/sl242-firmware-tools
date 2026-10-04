"""
PAC builder: full structure from bypass_codes.pac, UserImg replaced with resigned copy.

Rationale:
  bypass_codes.pac flashes successfully. The only difference vs our mini PACs:
  it includes SML (+ PS, UBOOT, Fat, etc.). SML runs before UserImg and patches
  FDL2 in RAM to accept any/custom RSA key. Without SML, FDL2 enforces full
  cert check (Check1+Check2+Check3) and rejects non-OEM UserImg.

  FDL2 NOP approach (patching FDL2 binary) was attempted but rejected by FDL1,
  because FDL1 uses a hardcoded OEM key for Check3 on sig_type=1 (FDL2).
  Since we cannot resign FDL2 with the OEM private key, FDL2 must remain
  unpatched and SML must handle the runtime bypass.

Boot chain:
  BROM -> FDL1 (OEM, unchanged) -> FDL2 (OEM, unchanged)
       -> SML (bypass, patches FDL2 in RAM)
       -> FDL2 (patched by SML, accepts resigned UserImg)
       -> UserImg (bypass code + dial codes, resigned with our key)
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
bypass = open(BYPASS, 'rb').read()
bypass_e = list_entries(bypass)
print('BYPASS entries:', [x['name'] for x in bypass_e])

# Extract all data from bypass, will replace only UserImg
ui_bypass = get_data(bypass, bypass_e, 'UserImg')
assert ui_bypass, 'UserImg not found in BYPASS'

print('\n=== resign UserImg ===')
inspect_cert(bytes(ui_bypass), 'before (bypass original)')
ui_resigned = resign_image(bytes(ui_bypass))
inspect_cert(bytes(ui_resigned), 'after (resigned)')

# Integrity check
code_sz_ui  = struct.unpack_from('<I', bytearray(ui_resigned), 0x30)[0]
cert_off_ui = 0x200 + code_sz_ui
sha_in  = ui_resigned[cert_off_ui+0x16c: cert_off_ui+0x16c+32]
sha_act = hashlib.sha256(ui_resigned[0x200: cert_off_ui]).digest()
assert sha_in == sha_act, 'UserImg SHA256 mismatch!'
assert len(ui_resigned) == len(ui_bypass), 'UserImg size changed!'
print('  UserImg integrity OK')

print('\n=== build PAC (full, UserImg replaced) ===')
# Rebuild PAC keeping all entries from bypass, just replace UserImg data in place
pac = bytearray(bypass)

# Find UserImg entry and patch its data in place (same offset, same size)
ui_e = next(x for x in bypass_e if x['name'] == 'UserImg')
assert ui_e['sz'] == len(ui_resigned), (
    f'size mismatch: entry says {ui_e["sz"]:#x}, resigned is {len(ui_resigned):#x}')

pac[ui_e['doff']: ui_e['doff'] + ui_e['sz']] = ui_resigned

# Recompute PAC CRCs
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
print(f'\ncontents (all from bypass, UserImg replaced):')
for e in bypass_e:
    marker = ' *** resigned' if e['name'] == 'UserImg' else ''
    print(f'  {e["name"]:12s}  {e["sz"]//1024:6d} KB{marker}')
