import struct, hashlib

RESTORE = r'C:\Users\USER\Desktop\ריקבה\4x4_RESTORE.pac'
OLD_SCRT = r'C:\Users\USER\AppData\Local\Temp\claude\C--Users-USER-Documents-CLAOD\b7c0cb54-c1f7-490c-be80-1f4d513da4c7\scratchpad'

restore = open(RESTORE, 'rb').read()
fdl1_patched = bytearray(open(rf'{OLD_SCRT}\fdl1_patched.bin', 'rb').read())

def get_entry(pac, want):
    off = 0x84C
    for _ in range(30):
        cs = struct.unpack_from('<I', pac, off)[0]
        if cs == 0 or cs > 0x10000000: break
        name = pac[off+4:off+4+0x100].decode('utf-16-le','ignore').split('\x00')[0]
        sz   = struct.unpack_from('<I', pac, off+0x604)[0]
        doff = struct.unpack_from('<I', pac, off+0x610)[0]
        if name == want: return doff, sz
        off += cs

# FDL1 מקורי מה-RESTORE
fdl1_doff, fdl1_sz = get_entry(restore, 'FDL')
fdl1_orig = bytearray(restore[fdl1_doff:fdl1_doff+fdl1_sz])

n_orig = struct.unpack_from('<I', fdl1_orig, 0x30)[0]
n_patch = struct.unpack_from('<I', fdl1_patched, 0x30)[0]
print(f'code_size מקורי: {n_orig:#x}')
print(f'code_size טלאי:  {n_patch:#x}')
assert n_orig == n_patch

# cert offset
cert_off = 0x200 + n_orig

# SHA256 בcert המקורי
orig_cert_sha = bytes(fdl1_orig[cert_off+0x16c:cert_off+0x16c+32])
# SHA256 בcert הטלאי
patch_cert_sha = bytes(fdl1_patched[cert_off+0x16c:cert_off+0x16c+32])
# SHA256 אמיתי של הקוד הטלאי
real_sha = hashlib.sha256(bytes(fdl1_patched[0x200:0x200+n_patch])).digest()

print(f'\nSHA256 בcert (מקורי):  {orig_cert_sha.hex()}')
print(f'SHA256 בcert (טלאי):   {patch_cert_sha.hex()}')
print(f'SHA256 אמיתי של קוד:   {real_sha.hex()}')
print(f'\nSHA256 בcert == אמיתי? {patch_cert_sha == real_sha}')

# מציג את הטלאי עצמו
code_orig = bytes(fdl1_orig[0x200:0x200+n_orig])
code_patch = bytes(fdl1_patched[0x200:0x200+n_patch])
diffs = [(i, code_orig[i], code_patch[i]) for i in range(min(len(code_orig), len(code_patch))) if code_orig[i] != code_patch[i]]
print(f'\nמספר הבדלים בקוד: {len(diffs)}')
for i, a, b in diffs:
    print(f'  code[{i:#06x}] file[{0x200+i:#06x}]: {a:02x} -> {b:02x}')
