"""
בניית PAC עם FDL2 מחתום מחדש + UserImg עם קודי חיוג.

גישה:
  1. FDL1 מ-RESTORE — ללא שינוי
  2. FDL2 מ-RESTORE → 3 NOP patches (eFUSE bypass לUserImg) + חתימה מחדש עם מפתח שלנו:
       - cert+0x16c = SHA256(patched code)
       - field8 = SHA256_km[0:8]   (SHA256_km = SHA256(key_size||e||our_modulus))
       - field32[0:24] = SHA256_km[8:32]
       - field32[24:32] = 00*8 (כולל anti-rollback=0)
       - cert+0x1b4 = RSA-sign(SHA256(code)||field8||field32, our_key) [72B M, sig_type=1]
     FDL1 בודק FDL2:
       code hash: SHA256(patched) == cert+0x16c ✓
       anchor:    field8||field32[0:24] == SHA256(key_material) ✓
       RSA verify: sig^e mod n == M ✓
  3. UserImg מ-bypass_codes → חתימה מחדש עם אותו מפתח
  4. FDL2 המתוקן מקבל UserImg: eFUSE check מנוטרל → RSA שלנו עובר ✓

cert FDL2 (sig_type=1) layout:
  cert+0x60: sig_type=1
  cert+0x64: key_size=0x800 (LE)
  cert+0x68: e=65537 (BE: 00010001)
  cert+0x6c: RSA-2048 modulus (256B, BE)
  cert+0x16c: SHA256(code) (32B)
  cert+0x18c: field8 (8B) ← anchor bytes 0-7
  cert+0x194: field32 (32B) ← anchor bytes 8-31 (first 24B), anti-rollback+zeros (last 8B)
  cert+0x1b0: anti-rollback version (=0)
  cert+0x1b4: RSA-2048 sig (256B)
"""
import struct, hashlib, os, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from resign_4x4 import resign_image, inspect_cert, load_or_make_key

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


def patch_fdl2_code(fdl2_orig):
    """Apply eFUSE-bypass NOP patches to FDL2 code (for FDL2 verifying UserImg)."""
    fdl2 = bytearray(fdl2_orig)
    code_sz = struct.unpack_from('<I', fdl2, 0x30)[0]
    print(f'  FDL2 code_size={code_sz:#x}  cert_off={0x200+code_sz:#x}')

    def nop(code_off, expected_bytes, label):
        abs_off = 0x200 + code_off
        actual = fdl2[abs_off: abs_off+2]
        if actual == bytearray.fromhex(expected_bytes):
            fdl2[abs_off: abs_off+2] = b'\x00\xbf'
            print(f'  [OK] NOP @ code[{code_off:#x}] ({expected_bytes} -> 00bf)  {label}')
        else:
            print(f'  [!!] code[{code_off:#x}] = {actual.hex()} (ציפינו {expected_bytes}) — SKIPPING {label}')
            return False
        return True

    ok = True
    ok &= nop(0xb3a4, 'd1d1', 'sig_type=0 eFUSE check #1 (bne)')
    ok &= nop(0xb3b2, 'cad1', 'sig_type=0 eFUSE check #2 (bne)')
    ok &= nop(0xb33c, '28b9', 'sig_type=1 eFUSE check (cbnz)')
    if not ok:
        raise SystemExit('NOP patches נכשלו — בדוק bytes')
    return bytes(fdl2)


def resign_fdl2_sig1(fdl2_code_patched, key):
    """
    חתימת FDL2 מחדש (sig_type=1) כך ש-FDL1 יקבל אותו:
      - cert+0x16c = SHA256(patched code)
      - field8 = SHA256_km[0:8]    ← anchor bytes 0-7
      - field32[0:24] = SHA256_km[8:32] ← anchor bytes 8-31
      - field32[24:32] = 00*8       ← anti-rollback = 0
      - cert+0x1b4 = RSA-sign(M=72B)
    """
    fdl2 = bytearray(fdl2_code_patched)
    code_sz = struct.unpack_from('<I', fdl2, 0x30)[0]
    cert_off = 0x200 + code_sz

    # בדיקת sig_type
    sig_type = struct.unpack_from('<I', fdl2, cert_off+0x60)[0]
    assert sig_type == 1, f'FDL2 sig_type={sig_type} — ציפינו 1'
    payload_sz = struct.unpack_from('<I', fdl2, cert_off+0x20)[0]
    assert payload_sz != 0, 'cert+0x20=0 — FDL1 יחזיר כישלון!'
    print(f'  sig_type={sig_type}  cert+0x20={payload_sz:#x}  cert_off={cert_off:#x}')

    # פרמטרי מפתח
    n   = key.public_key().public_numbers().n
    d   = key.private_numbers().d
    e_v = key.public_key().public_numbers().e
    mod_be = n.to_bytes(256, 'big')

    # עדכון modulus בcert+0x6c
    fdl2[cert_off+0x6c : cert_off+0x16c] = mod_be
    print(f'  modulus updated: {mod_be[:8].hex()}...')

    # SHA256_km = SHA256(cert+0x64[0:264]) = SHA256(key_size||e||modulus)
    km_bytes = bytes(fdl2[cert_off+0x64 : cert_off+0x164])
    sha256_km = hashlib.sha256(km_bytes).digest()
    print(f'  SHA256_km={sha256_km.hex()}')

    # anchor = field8(8B) + field32[0:24](24B) = SHA256_km[0:32]
    fdl2[cert_off+0x18c : cert_off+0x194] = sha256_km[0:8]    # field8
    fdl2[cert_off+0x194 : cert_off+0x1ac] = sha256_km[8:32]   # field32[0:24]
    fdl2[cert_off+0x1ac : cert_off+0x1b4] = b'\x00' * 8       # field32[24:32] + anti-rollback=0

    # SHA256(patched code) → cert+0x16c
    code_hash = hashlib.sha256(bytes(fdl2[0x200:cert_off])).digest()
    fdl2[cert_off+0x16c : cert_off+0x18c] = code_hash
    print(f'  SHA256(patched code)={code_hash.hex()}')

    # M = SHA256(code)||field8||field32 = 72 bytes
    field8   = bytes(fdl2[cert_off+0x18c : cert_off+0x194])
    field32  = bytes(fdl2[cert_off+0x194 : cert_off+0x1b4])
    M = code_hash + field8 + field32
    assert len(M) == 72, f'M len={len(M)} ≠ 72'

    # PKCS#1 v1.5 type 1 over M (72B), 2048-bit key
    pad = b'\x00\x01' + b'\xff' * (256 - 3 - len(M)) + b'\x00' + M
    assert len(pad) == 256
    sig_int = pow(int.from_bytes(pad, 'big'), d, n)
    sig = sig_int.to_bytes(256, 'big')

    # self-verify
    dec = pow(int.from_bytes(sig, 'big'), e_v, n)
    assert dec.to_bytes(256, 'big') == pad, 'self-verify FAILED!'

    fdl2[cert_off+0x1b4 : cert_off+0x2b4] = sig
    print(f'  [OK] FDL2 signed (sig_type=1, M=72B)')

    # אימות anchor
    anchor_check = bytes(fdl2[cert_off+0x18c : cert_off+0x18c+32])
    assert anchor_check == sha256_km, 'anchor mismatch!'
    print(f'  [OK] anchor = SHA256_km OK')

    return bytes(fdl2)


# ===== MAIN =====
print('=== טוען קבצים ===')
restore = open(RESTORE, 'rb').read()
bypass  = open(BYPASS,  'rb').read()

restore_e = list_entries(restore)
bypass_e  = list_entries(bypass)

print('RESTORE entries:')
for e in restore_e:
    print(f'  {e["name"]:20s}  sz={e["sz"]:#010x}  doff={e["doff"]:#010x}')

fdl1_data  = get_data(restore, restore_e, 'FDL')
fdl2_orig  = get_data(restore, restore_e, 'FDL2')
sml_bypass = get_data(bypass,  list_entries(bypass), 'SML')
ui_bypass  = get_data(bypass,  list_entries(bypass), 'UserImg')

assert fdl1_data,  'FDL לא נמצא ב-RESTORE'
assert fdl2_orig,  'FDL2 לא נמצא ב-RESTORE'
assert sml_bypass, 'SML לא נמצא ב-BYPASS'
assert ui_bypass,  'UserImg לא נמצא ב-BYPASS'

# XML מ-RESTORE
last_e = restore_e[-1]
xml_bytes = bytearray(restore[last_e['doff']: last_e['doff'] + last_e['sz']])
SML_XML = (
    b'<File backup="0"><ID>SML</ID><IDAlias>SML</IDAlias><Type>CODE</Type>'
    b'<Block><Base>0x80000002</Base><Size>0x0</Size></Block>'
    b'<Flag>1</Flag><CheckFlag>1</CheckFlag><Description>SML</Description></File>'
)
if b'<ID>SML</ID>' not in xml_bytes:
    idx = xml_bytes.find(b'</Scheme>')
    if idx >= 0:
        xml_bytes = xml_bytes[:idx] + b'\n      ' + SML_XML + b'\n    ' + xml_bytes[idx:]
        print('  SML XML entry הוסף')

# ===== מפתח RSA =====
print('\n=== מפתח RSA ===')
key = load_or_make_key()

# ===== patch FDL2 code =====
print('\n=== patch FDL2 code (eFUSE bypass) ===')
fdl2_code_patched = patch_fdl2_code(bytes(fdl2_orig))

# ===== חתימת FDL2 מחדש (sig_type=1) =====
print('\n=== חתימת FDL2 מחדש (sig_type=1) ===')
fdl2_resigned = resign_fdl2_sig1(fdl2_code_patched, key)

# ===== חתימה מחדש UserImg =====
print('\n=== UserImg מ-bypass ===')
inspect_cert(bytes(ui_bypass), 'לפני חתימה')
print('\n=== חתימה מחדש UserImg ===')
ui_resigned = resign_image(bytes(ui_bypass))
inspect_cert(bytes(ui_resigned), 'אחרי חתימה')

# אימות UserImg
code_sz_ui = struct.unpack_from('<I', bytearray(ui_resigned), 0x30)[0]
cert_off_ui = 0x200 + code_sz_ui
sha_in  = ui_resigned[cert_off_ui+0x16c: cert_off_ui+0x16c+32]
sha_act = hashlib.sha256(ui_resigned[0x200: cert_off_ui]).digest()
assert sha_in == sha_act, 'UserImg SHA256 mismatch!'
pay_sz = struct.unpack_from('<I', bytearray(ui_resigned), cert_off_ui+0x20)[0]
assert pay_sz != 0, 'UserImg cert+0x20=0!'
print(f'  UserImg integrity: OK   cert+0x20={pay_sz:#x}')

# ===== בניית PAC =====
print('\n=== בניית PAC ===')
ENTRY_HDR = 0xa14
NUM_ENTRIES = 5

bypass_e2 = list_entries(bypass)
r_fdl_e  = next(x for x in restore_e if x['name'] == 'FDL')
r_fdl2_e = next(x for x in restore_e if x['name'] == 'FDL2')
r_ui_e   = next(x for x in restore_e if x['name'] == 'UserImg')
r_xml_e  = restore_e[-1]
b_sml_e  = next(x for x in bypass_e2  if x['name'] == 'SML')

fdl_entry  = bytearray(restore[r_fdl_e['off']  : r_fdl_e['off']  + ENTRY_HDR])
fdl2_entry = bytearray(restore[r_fdl2_e['off'] : r_fdl2_e['off'] + ENTRY_HDR])
sml_entry  = bytearray(bypass [b_sml_e['off']  : b_sml_e['off']  + ENTRY_HDR])
ui_entry   = bytearray(restore[r_ui_e['off']   : r_ui_e['off']   + ENTRY_HDR])
xml_entry  = bytearray(restore[r_xml_e['off']  : r_xml_e['off']  + ENTRY_HDR])

hdr_end  = 0x84C + NUM_ENTRIES * ENTRY_HDR
fdl_off  = hdr_end
fdl2_off = fdl_off  + len(fdl1_data)
sml_off  = fdl2_off + len(fdl2_resigned)
ui_off   = sml_off  + len(sml_bypass)
xml_off  = ui_off   + len(ui_resigned)

def set_doff(e, doff, sz):
    struct.pack_into('<I', e, 0x610, doff)
    struct.pack_into('<I', e, 0x604, sz)

set_doff(fdl_entry,  fdl_off,  len(fdl1_data))
set_doff(fdl2_entry, fdl2_off, len(fdl2_resigned))
set_doff(sml_entry,  sml_off,  len(sml_bypass))
set_doff(ui_entry,   ui_off,   len(ui_resigned))
set_doff(xml_entry,  xml_off,  len(xml_bytes))

pac = bytearray(restore[:0x84C])
pac += fdl_entry
pac += fdl2_entry
pac += sml_entry
pac += ui_entry
pac += xml_entry
pac += bytes(fdl1_data)
pac += bytes(fdl2_resigned)
pac += bytes(sml_bypass)
pac += bytes(ui_resigned)
pac += bytes(xml_bytes)

struct.pack_into('<I', pac, 0x30, len(pac))
struct.pack_into('<I', pac, 0x434, NUM_ENTRIES)

crc1 = crc16_ibm(pac[0x000:0x848])
crc2 = crc16_ibm(pac[0x84C:])
struct.pack_into('<H', pac, 0x848, crc1)
struct.pack_into('<H', pac, 0x84A, crc2)

open(OUT, 'wb').write(bytes(pac))
md5 = hashlib.md5(bytes(pac)).hexdigest()

print(f'\n=== PAC מוכן ===')
print(f'  {OUT}')
print(f'  {len(pac)//1024} KB   crc1={crc1:#06x}   crc2={crc2:#06x}')
print(f'  md5={md5}')
print()
print('תוכן:')
print(f'  FDL1:    מקורי  ({len(fdl1_data)//1024} KB)')
print(f'  FDL2:    NOP patches + resigned sig_type=1  ({len(fdl2_resigned)//1024} KB)')
print(f'  SML:     cert-zero (bypass)  ({len(sml_bypass)//1024} KB)')
print(f'  UserImg: קודי חיוג + RSA חתום  ({len(ui_resigned)//1024} KB)')
print(f'  XML:     {len(xml_bytes)} bytes')
print()
print('offsets:')
print(f'  FDL1    @ {fdl_off:#010x}')
print(f'  FDL2    @ {fdl2_off:#010x}')
print(f'  SML     @ {sml_off:#010x}')
print(f'  UserImg @ {ui_off:#010x}')
print(f'  XML     @ {xml_off:#010x}')
