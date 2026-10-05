"""
Approach A: FDL2 cert-zero bypass for UserImg (UNTESTED — HIGH PRIORITY)

FDL2 code[0xc1d2] (file[0xc3d2]):
  ldrd r3, r2, [r4, #0x20]  ; load cert[+0x20..+0x27] of incoming UserImg
  orrs r3, r2
  beq  #0xc20a              ; if ALL 8 bytes zero -> jump to flash-success, SKIP verify_cert!

If cert[+0x20..+0x27] are all 0x00: FDL2 never calls verify_cert -> no Check1/2/3 -> flashes.
FDL1 and FDL2 are UNMODIFIED OEM binaries from RESTORE.pac.

See VULNERABILITIES.md Approach A for full analysis.
"""
import struct, hashlib
from pathlib import Path

RESTORE  = r'C:\Users\USER\Desktop\ריקבה\4x4_RESTORE.pac'
SRC_BIN  = r'C:\Users\USER\Desktop\ריקבה\src\user_codes.bin'
SRC_MENU = r'C:\Users\USER\Desktop\ריקבה\src\user_codes_menu.bin'
OUT_BIN  = r'C:\Users\USER\Desktop\ריקבה\4x4_zerocert.pac'
OUT_MENU = r'C:\Users\USER\Desktop\ריקבה\4x4_zerocert_menu.pac'


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
    for _ in range(60):
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


def make_zerocert_userimg(src_path, label):
    img = bytearray(Path(src_path).read_bytes())
    code_sz  = struct.unpack_from('<I', img, 0x30)[0]
    cert_off = 0x200 + code_sz

    # Check1 field: cert+0x16c must equal SHA256(code) for sanity
    sha_actual = hashlib.sha256(bytes(img[0x200:cert_off])).digest()
    sha_stored = bytes(img[cert_off+0x16c: cert_off+0x16c+32])
    if sha_stored != sha_actual:
        print(f'  WARNING: {label}: cert+0x16c mismatch — updating')
        img[cert_off+0x16c: cert_off+0x16c+32] = sha_actual

    # Approach A: zero cert[+0x20..+0x27] to trigger FDL2 cert-zero bypass
    before = bytes(img[cert_off+0x20: cert_off+0x28]).hex()
    img[cert_off+0x20: cert_off+0x28] = b'\x00' * 8
    after  = bytes(img[cert_off+0x20: cert_off+0x28]).hex()
    print(f'  {label}: cert+0x20..0x27  {before} -> {after}')

    mod4 = img[cert_off+0x6c: cert_off+0x70].hex()
    sig4 = img[cert_off+0x194: cert_off+0x198].hex()
    print(f'  mod={mod4}  sig[0:4]={sig4}  code_sz={code_sz:#x}')
    return bytes(img)


def build_pac(userimg_bytes, out_path, label):
    restore = open(RESTORE, 'rb').read()
    re = list_entries(restore)

    fdl1 = bytes(get_data(restore, re, 'FDL'))
    fdl2 = bytes(get_data(restore, re, 'FDL2'))
    assert fdl1 and fdl2, 'FDL/FDL2 not found in RESTORE'

    print(f'FDL1 md5={hashlib.md5(fdl1).hexdigest()[:12]}')
    print(f'FDL2 md5={hashlib.md5(fdl2).hexdigest()[:12]}')

    r_fdl_e  = next(x for x in re if x['name'] == 'FDL')
    r_fdl2_e = next(x for x in re if x['name'] == 'FDL2')
    r_ui_e   = next(x for x in re if x['name'] == 'UserImg')
    r_xml_e  = re[-1]
    xml_bytes = bytes(restore[r_xml_e['doff']: r_xml_e['doff'] + r_xml_e['sz']])

    ENTRY_HDR   = 0xa14
    NUM_ENTRIES = 4
    hdr_end  = 0x84C + NUM_ENTRIES * ENTRY_HDR
    fdl_off  = hdr_end
    fdl2_off = fdl_off  + len(fdl1)
    ui_off   = fdl2_off + len(fdl2)
    xml_off  = ui_off   + len(userimg_bytes)

    def patch_entry(src_off, doff, sz):
        e = bytearray(restore[src_off: src_off + ENTRY_HDR])
        struct.pack_into('<I', e, 0x610, doff)
        struct.pack_into('<I', e, 0x604, sz)
        return bytes(e)

    pac = bytearray(restore[:0x84C])
    pac += patch_entry(r_fdl_e['off'],  fdl_off,  len(fdl1))
    pac += patch_entry(r_fdl2_e['off'], fdl2_off, len(fdl2))
    pac += patch_entry(r_ui_e['off'],   ui_off,   len(userimg_bytes))
    pac += patch_entry(r_xml_e['off'],  xml_off,  len(xml_bytes))
    pac += fdl1
    pac += fdl2
    pac += userimg_bytes
    pac += xml_bytes

    struct.pack_into('<I', pac, 0x30,  len(pac))
    struct.pack_into('<I', pac, 0x434, NUM_ENTRIES)
    crc1 = crc16_ibm(pac[0x000:0x848])
    crc2 = crc16_ibm(pac[0x84C:])
    struct.pack_into('<H', pac, 0x848, crc1)
    struct.pack_into('<H', pac, 0x84A, crc2)

    open(out_path, 'wb').write(bytes(pac))
    print(f'Written: {out_path}  ({len(pac)//1024} KB)')
    return out_path


if __name__ == '__main__':
    print('=== Building cert-zero UserImg PAC (Approach A) ===\n')

    print('--- user_codes (11 codes) ---')
    ui = make_zerocert_userimg(SRC_BIN, 'user_codes.bin')
    build_pac(ui, OUT_BIN, '4x4_zerocert')

    print()
    print('--- user_codes_menu (11 codes + menu) ---')
    ui_menu = make_zerocert_userimg(SRC_MENU, 'user_codes_menu.bin')
    build_pac(ui_menu, OUT_MENU, '4x4_zerocert_menu')

    print('\nDone.')
    print('Flash with ResearchDownload. Watch for:')
    print('  SUCCESS at UserImage step -> Approach A confirmed!')
    print('  [UB1132] at UserImage step -> FDL2 cert-zero bypass does NOT work here')
    print('  Other error -> investigate further')
