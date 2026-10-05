"""
בודק cert[0x20..0x27] ב-SML/UserImg ומדיסאסמבל code[0xc1d0..0xc310] מ-FDL2
"""
import struct, hashlib, capstone

RESTORE = r'C:\Users\USER\Desktop\ריקבה\4x4_RESTORE.pac'
BYPASS  = r'C:\Users\USER\Desktop\ריקבה\4x4_bypass_codes.pac'

restore = open(RESTORE,'rb').read()
bypass  = open(BYPASS,'rb').read()

def get_e(pac, want):
    off = 0x84C
    for _ in range(30):
        cs = struct.unpack_from('<I', pac, off)[0]
        if not cs or cs > 0x10000000: break
        n = pac[off+4:off+4+0x100].decode('utf-16-le','ignore').split('\x00')[0]
        sz  = struct.unpack_from('<I', pac, off+0x604)[0]
        doff= struct.unpack_from('<I', pac, off+0x610)[0]
        if n == want: return pac[doff:doff+sz]
        off += cs

fdl2 = get_e(restore, 'FDL2')
sml  = get_e(bypass,  'SML')
uimg = get_e(bypass,  'UserImg')

cs = struct.unpack_from('<I', fdl2, 0x30)[0]
cert_off = 0x200 + cs
print(f'FDL2 code_size={cs:#x}  cert_off={cert_off:#x}')

sml_cs  = struct.unpack_from('<I', sml,  0x30)[0]
uimg_cs = struct.unpack_from('<I', uimg, 0x30)[0]
sml_cert  = sml_cs  + 0x200
uimg_cert = uimg_cs + 0x200
print(f'SML  cert[0x20..0x27]: {sml [sml_cert +0x20:sml_cert +0x28].hex()}')
print(f'UserImg cert[0x20..0x27]: {uimg[uimg_cert+0x20:uimg_cert+0x28].hex()}')

# בדיקה: מה ב-code[0xc20a] (נתיב ה-BEQ)
md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB)
code_chunk = fdl2[0x200+0xc1d0 : 0x200+0xc320]
print()
print('=== code[0xc1d0..0xc320] ===')
for insn in md.disasm(code_chunk, 0xc1d0):
    print(f'  code[{insn.address:06x}] file[{0x200+insn.address:06x}]: {insn.bytes.hex():8s}  {insn.mnemonic} {insn.op_str}')
