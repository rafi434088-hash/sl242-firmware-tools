"""
חתימה מחדש של SL242 / 4x4 UserImg לאחר עריכה.

מבנה cert ב-SL242 (שונה מ-SL278):
  cert_off = 0x200 + declared_code_size
  cert+0x20: payload size  ← חייב להיות != 0 (0x234 לUserImg)
  cert+0x60: sig_data_start
    sig_data+0x00: sig_type=0
    sig_data+0x04: key_size=0x800 (2048-bit)
    sig_data+0x08..0x107: RSA-2048 modulus (256B)   = cert+0x68
    sig_data+0x10c..0x12b: SHA256(code) (32B)       = cert+0x16c
    sig_data+0x12c..0x133: field8 (8B)              = cert+0x18c
    sig_data+0x134..0x233: RSA-2048 sig (256B)      = cert+0x194

FDL2: cert+0x20 != 0 → cert_verify(eFUSE_anchor, SHA256(code), sig_data)
      eFUSE לא מתוכנת (0x00*32) → FDL2 מדלג על בדיקת eFUSE → מקבל כל מפתח RSA.

שימוש:
  python resign_4x4.py <src.bin> <dst.bin>           # רק הimage
  python resign_4x4.py --pac <src.pac> <dst.pac>      # כל ה-PAC
"""
import struct, hashlib, os, sys

KEY_PEM = r'C:\Users\USER\Desktop\5555\source\resign_key.pem'

# ===== offsets קבועים (יחסית ל-cert_off) =====
CERT_PAYLOAD_SIZE_OFF  = 0x20   # uint32 — חייב != 0 (= 0x234 לUserImg)
SIG_DATA_OFF           = 0x60   # תחילת sig_data
#   sig_data+0x00: sig_type=0
#   sig_data+0x04: key_size=0x800
#   sig_data+0x08: e=65537 (4B)   = cert+0x68  ← אל תשנה!
#   sig_data+0x0c: RSA modulus (256B) = cert+0x6c
#   sig_data+0x10c: SHA256(code) = cert+0x16c
#   sig_data+0x12c: field8 (8B)  = cert+0x18c
#   sig_data+0x134: RSA sig (256B) = cert+0x194
MOD_REL                = 0x6c   # RSA-2048 modulus (256B)  = SIG_DATA_OFF+0x0c
HASH_REL               = 0x16c  # SHA256(code) (32B)
FIELD8_REL             = 0x18c  # field8 (8B)
SIG_REL                = 0x194  # RSA-2048 sig (256B)


def load_or_make_key():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    if os.path.isfile(KEY_PEM):
        with open(KEY_PEM, 'rb') as f:
            return serialization.load_pem_private_key(f.read(), password=None)
    print(f'  יוצר מפתח RSA-2048 חדש → {KEY_PEM}')
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with open(KEY_PEM, 'wb') as f:
        f.write(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption()))
    return key


def inspect_cert(img, label=''):
    """הדפס מבנה cert ובדוק תקינות"""
    code_size = struct.unpack_from('<I', img, 0x30)[0]
    cert_off = 0x200 + code_size
    if cert_off + SIG_REL + 256 > len(img):
        print(f'  [!] {label}: image קצר מדי ({len(img):#x}) לcert ב-{cert_off:#x}')
        return None
    payload_sz = struct.unpack_from('<I', img, cert_off + CERT_PAYLOAD_SIZE_OFF)[0]
    sig_type   = struct.unpack_from('<I', img, cert_off + SIG_DATA_OFF)[0]
    key_sz     = struct.unpack_from('<I', img, cert_off + SIG_DATA_OFF + 4)[0]
    sha_in_cert = img[cert_off + HASH_REL : cert_off + HASH_REL + 32]
    field8     = img[cert_off + FIELD8_REL : cert_off + FIELD8_REL + 8]
    sha_actual = hashlib.sha256(img[0x200 : cert_off]).digest()
    match = 'OK' if sha_in_cert == sha_actual else 'MISMATCH'
    if label: print(f'\n=== {label} ===')
    print(f'  code_size={code_size:#x}  cert_off={cert_off:#x}  payload_sz={payload_sz:#x}')
    print(f'  sig_type={sig_type}  key_sz={key_sz:#x}')
    print(f'  SHA256 בcert: {bytes(sha_in_cert).hex()[:32]}...')
    print(f'  SHA256 actual: {sha_actual.hex()[:32]}... {match}')
    print(f'  field8: {bytes(field8).hex()}')
    return cert_off


def resign_image(img):
    img = bytearray(img)
    code_size = struct.unpack_from('<I', img, 0x30)[0]
    cert_off = 0x200 + code_size

    # בדיקות
    payload_sz = struct.unpack_from('<I', img, cert_off + CERT_PAYLOAD_SIZE_OFF)[0]
    assert payload_sz != 0, 'cert+0x20=0! ← cert-zero mode → תמיד נכשל ב-FDL2. לא ניתן לחתום!'

    field8 = bytes(img[cert_off + FIELD8_REL : cert_off + FIELD8_REL + 8])

    # hash חדש
    payload = bytes(img[0x200 : cert_off])
    newhash = hashlib.sha256(payload).digest()
    print(f'  SHA256(code) חדש: {newhash.hex()}')

    # מפתח
    key = load_or_make_key()
    n   = key.public_key().public_numbers().n
    d   = key.private_numbers().d
    mod = n.to_bytes(256, 'big')

    # חתימה: PKCS#1 v1.5 type1 על SHA256(code) || field8 (40 bytes)
    M   = newhash + field8
    pad = b'\x00\x01' + b'\xff' * (256 - 3 - len(M)) + b'\x00' + M
    sig_int = pow(int.from_bytes(pad, 'big'), d, n)
    sig = sig_int.to_bytes(256, 'big')

    # self-verify
    e = key.public_key().public_numbers().e
    chk = pow(int.from_bytes(sig, 'big'), e, n)
    assert chk.to_bytes(256, 'big') == pad, 'self-verify FAILED!'

    # כתיבה
    img[cert_off + HASH_REL  : cert_off + HASH_REL  + 32]  = newhash
    img[cert_off + MOD_REL   : cert_off + MOD_REL   + 256] = mod
    img[cert_off + SIG_REL   : cert_off + SIG_REL   + 256] = sig

    print(f'  [OK] signed  (mod={mod.hex()[:16]}...)')
    return bytes(img)


def list_entries(pac):
    entries = []
    off = 0x84C
    for _ in range(30):
        cs = struct.unpack_from('<I', pac, off)[0]
        if not cs or cs > 0x10000000: break
        name = pac[off+4:off+4+0x100].decode('utf-16-le','ignore').split('\x00')[0]
        sz   = struct.unpack_from('<I', pac, off+0x604)[0]
        doff = struct.unpack_from('<I', pac, off+0x610)[0]
        entries.append({'name':name, 'off':off, 'cs':cs, 'doff':doff, 'sz':sz})
        off += cs
    return entries


def crc16_ibm(data):
    crc = 0
    for b in data:
        crc ^= b
        for _ in range(8):
            if crc & 1: crc = (crc >> 1) ^ 0xA001
            else:       crc >>= 1
    return crc


def resign_pac(src_pac, dst_pac):
    pac = bytearray(open(src_pac,'rb').read())
    entries = list_entries(pac)
    for e in entries:
        print(f'  entry: {e["name"]:20s}  doff={e["doff"]:#010x}  sz={e["sz"]:#x}')
    ui = next((e for e in entries if e['name'].lower() == 'userimg'), None)
    if not ui:
        raise SystemExit('UserImg לא נמצא ב-PAC!')
    print(f'\nמחתים UserImg @ doff={ui["doff"]:#x} sz={ui["sz"]:#x}')
    img_orig = bytes(pac[ui['doff'] : ui['doff'] + ui['sz']])
    inspect_cert(img_orig, 'לפני')
    img_new = resign_image(img_orig)
    inspect_cert(img_new, 'אחרי')
    pac[ui['doff'] : ui['doff'] + ui['sz']] = img_new
    # עדכון CRC
    crc1 = crc16_ibm(pac[0x000:0x848])
    crc2 = crc16_ibm(pac[0x84C:])
    struct.pack_into('<H', pac, 0x848, crc1)
    struct.pack_into('<H', pac, 0x84A, crc2)
    open(dst_pac,'wb').write(bytes(pac))
    print(f'\nנשמר: {dst_pac}  ({len(pac)//1024} KB)  crc1={crc1:#06x} crc2={crc2:#06x}')
    return bytes(pac)


if __name__ == '__main__':
    args = sys.argv[1:]
    if args and args[0] == '--inspect':
        img = open(args[1],'rb').read()
        inspect_cert(img, args[1])
    elif args and args[0] == '--pac':
        resign_pac(args[1], args[2])
    elif len(args) == 2:
        img = open(args[0],'rb').read()
        inspect_cert(img, 'לפני')
        out = resign_image(img)
        inspect_cert(out, 'אחרי')
        open(args[1],'wb').write(out)
        print(f'נשמר: {args[1]}')
    else:
        print(__doc__)
