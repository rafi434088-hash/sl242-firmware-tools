"""
דיסאסמבלינג של אזורי FDL2 רלוונטיים:
1. code[0xac50..0xae50] - אזור הלולאה + ה-verify call
2. code[0xbfb4..0xc0a0] - פונקציית ה-verifier שקוראים אליה
"""
import struct
import capstone

RESTORE = r'C:\Users\USER\Desktop\ריקבה\4x4_RESTORE.pac'

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

restore = open(RESTORE,'rb').read()
fdl2 = get_e(restore, 'FDL2')

# בהנחה שFDL2 נטען לכתובת 0x40000000 (ניחוש — לבדיקת flow בלבד)
# אנחנו משתמשים בoffset קוד: קוד מתחיל ב-file[0x200] = code[0]
# כתובות ב-disasm הן code[] offsets (לא כתובות RAM)

md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB)
md.detail = True

def dis(data, start_code_off, length, label=''):
    if label:
        print(f'\n=== {label} ===')
    chunk = data[0x200 + start_code_off : 0x200 + start_code_off + length]
    for insn in md.disasm(chunk, start_code_off):
        addr = insn.address
        file_off = 0x200 + addr
        bytes_hex = insn.bytes.hex()
        print(f'  code[{addr:06x}] file[{file_off:06x}]: {bytes_hex:8s}  {insn.mnemonic} {insn.op_str}')

# אזור הלולאה הראשית (BL.W לverifier ב-code[0xad7e])
dis(fdl2, 0xac50, 0x1c0, 'לולאת verify ב-FDL2 [code 0xac50..0xae10]')

# פונקציית הverifier שנקראת ב-BL.W code[0xad7e] -> code[0xbfb4]
dis(fdl2, 0xbf90, 0x150, 'verifier code[0xbf90..0xc0e0]')
