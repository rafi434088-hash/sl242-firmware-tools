"""
PAC builder (final): OEM FDL1 + OEM FDL2 + pre-signed UserImg.

UserImg already signed with bypass key (mod=dce4c14f).
Device eFUSE programmed with bypass-key hash (70a5dcda).
OEM FDL2 Check2: SHA256(bypass_key_struct)==70a5dcda -> PASS.
OEM FDL2 Check3: RSA verify with bypass key -> PASS.

No patches, no resign needed.
"""
import struct, hashlib, sys
from pathlib import Path

RESTORE    = r'C:\Users\USER\Desktop\ריקבה\4x4_RESTORE.pac'
SRC_CODES  = r'C:\Users\USER\Desktop\ריקבה\src\user_codes.bin'
SRC_MENU   = r'C:\Users\USER\Desktop\ריקבה\src\user_codes_menu.bin'
OUT_CODES  = r'C:\Users\USER\Desktop\ריקבה\4x4_user_codes.pac'
OUT_MENU   = r'C:\Users\USER\Desktop\ריקבה\4x4_user_codes_menu.pac'


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


def verify_userimg(img, label):
    code_sz  = struct.unpack_from('<I', img, 0x30)[0]
    cert_off = 0x200 + code_sz
    mod4     = img[cert_off+0x6c: cert_off+0x70].hex()
    stored   = img[cert_off+0x16c: cert_off+0x16c+32]
    actual   = hashlib.sha256(img[0x200:cert_off]).digest()
    ok       = stored == actual
    print(f'  {label}: code_sz={code_sz:#x}  mod={mod4}  hash_ok={ok}')
    if not ok:
        raise AssertionError(f'{label}: SHA256 mismatch — UserImg is corrupt')


def build_pac(userimg_path, out_path, label):
    restore = open(RESTORE, 'rb').read()
    re = list_entries(restore)

    fdl1_orig = bytes(get_data(restore, re, 'FDL'))
    fdl2_orig = bytes(get_data(restore, re, 'FDL2'))
    ui_data   = Path(userimg_path).read_bytes()

    assert fdl1_orig, 'FDL not found in RESTORE'
    assert fdl2_orig, 'FDL2 not found in RESTORE'

    print(f'\n--- {label} ---')
    print(f'FDL1: {len(fdl1_orig)//1024} KB  md5={hashlib.md5(fdl1_orig).hexdigest()[:12]}')
    print(f'FDL2: {len(fdl2_orig)//1024} KB  md5={hashlib.md5(fdl2_orig).hexdigest()[:12]}')
    verify_userimg(ui_data, Path(userimg_path).name)

    xml_e    = re[-1]
    xml_bytes = bytearray(restore[xml_e['doff']: xml_e['doff'] + xml_e['sz']])

    r_fdl_e  = next(x for x in re if x['name'] == 'FDL')
    r_fdl2_e = next(x for x in re if x['name'] == 'FDL2')
    r_ui_e   = next(x for x in re if x['name'] == 'UserImg')
    r_xml_e  = re[-1]

    ENTRY_HDR   = 0xa14
    NUM_ENTRIES = 4

    fdl_entry  = bytearray(restore[r_fdl_e['off']  : r_fdl_e['off']  + ENTRY_HDR])
    fdl2_entry = bytearray(restore[r_fdl2_e['off'] : r_fdl2_e['off'] + ENTRY_HDR])
    ui_entry   = bytearray(restore[r_ui_e['off']   : r_ui_e['off']   + ENTRY_HDR])
    xml_entry  = bytearray(restore[r_xml_e['off']  : r_xml_e['off']  + ENTRY_HDR])

    hdr_end  = 0x84C + NUM_ENTRIES * ENTRY_HDR
    fdl_off  = hdr_end
    fdl2_off = fdl_off  + len(fdl1_orig)
    ui_off   = fdl2_off + len(fdl2_orig)
    xml_off  = ui_off   + len(ui_data)

    def set_doff(e, doff, sz):
        struct.pack_into('<I', e, 0x610, doff)
        struct.pack_into('<I', e, 0x604, sz)

    set_doff(fdl_entry,  fdl_off,  len(fdl1_orig))
    set_doff(fdl2_entry, fdl2_off, len(fdl2_orig))
    set_doff(ui_entry,   ui_off,   len(ui_data))
    set_doff(xml_entry,  xml_off,  len(xml_bytes))

    pac = bytearray(restore[:0x84C])
    pac += fdl_entry
    pac += fdl2_entry
    pac += ui_entry
    pac += xml_entry
    pac += fdl1_orig
    pac += fdl2_orig
    pac += bytes(ui_data)
    pac += bytes(xml_bytes)

    struct.pack_into('<I', pac, 0x30,  len(pac))
    struct.pack_into('<I', pac, 0x434, NUM_ENTRIES)

    crc1 = crc16_ibm(pac[0x000:0x848])
    crc2 = crc16_ibm(pac[0x84C:])
    struct.pack_into('<H', pac, 0x848, crc1)
    struct.pack_into('<H', pac, 0x84A, crc2)

    open(out_path, 'wb').write(bytes(pac))
    md5 = hashlib.md5(bytes(pac)).hexdigest()
    print(f'Written: {out_path}')
    print(f'  {len(pac)//1024} KB  crc1={crc1:#06x}  crc2={crc2:#06x}  md5={md5}')
    return out_path


if __name__ == '__main__':
    build_pac(SRC_CODES, OUT_CODES, '4x4_user_codes')
    build_pac(SRC_MENU,  OUT_MENU,  '4x4_user_codes_menu')
    print('\nDone.')
