"""
פענוח פונקציית אימות ב-FDL1 (code1[0x2100..0x2300]).
מטרה: להבין מה בדיוק FDL1 בודק בcert של FDL2, ומה BROM בודק בcert של FDL1.
"""
import struct, sys, os
sys.path.insert(0, r'C:\Users\USER\Documents\CLAOD\sl242-firmware-tools')

RESTORE = r'C:\Users\USER\Desktop\ריקבה\4x4_RESTORE.pac'

def list_entries(pac):
    entries = []
    off = 0x84C
    for _ in range(30):
        cs = struct.unpack_from('<I', pac, off)[0]
        if not cs or cs > 0x10000000: break
        name = pac[off+4:off+4+0x100].decode('utf-16-le','ignore').split('\x00')[0]
        sz   = struct.unpack_from('<I', pac, off+0x604)[0]
        doff = struct.unpack_from('<I', pac, off+0x610)[0]
        entries.append({'name':name,'off':off,'cs':cs,'doff':doff,'sz':sz})
        off += cs
    return entries

pac = open(RESTORE,'rb').read()
entries = list_entries(pac)
fdl1_e = next(x for x in entries if x['name']=='FDL')
fdl1 = pac[fdl1_e['doff']: fdl1_e['doff']+fdl1_e['sz']]

code_sz = struct.unpack_from('<I', fdl1, 0x30)[0]
print(f'FDL1 total={len(fdl1):#x}  code_sz={code_sz:#x}  cert_off={0x200+code_sz:#x}')

# הדפסת cert כדי להבין את המבנה
cert_off = 0x200 + code_sz
print(f'\nFDL1 cert bytes [+0x00..+0x30]:')
for i in range(0, 0x30, 16):
    line = fdl1[cert_off+i: cert_off+i+16]
    print(f'  cert+{i:#04x}: {line.hex()}')

print(f'\nFDL1 cert+0x20 = {struct.unpack_from("<I", fdl1, cert_off+0x20)[0]:#010x}')
print(f'FDL1 cert+0x60 = {struct.unpack_from("<I", fdl1, cert_off+0x60)[0]:#010x} (sig_type)')

try:
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
    cs = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    cs.detail = True

    # disassemble from code1[0x20f0] to code1[0x2280] — full verify function + context
    START = 0x20f0
    END   = 0x2280
    code_start = 0x200 + START
    code_bytes = bytes(fdl1[code_start: 0x200+END])

    # קביעת base address — BROM טוען FDL1 לכתובת מסויימת; נשתמש ב-0 לנוחות
    # כתובות יהיו יחסיות ל-code_start
    BASE = 0x10000 + START  # סתם offset סביר

    print(f'\n=== Disassembly code1[{START:#x}..{END:#x}] (Thumb) ===')
    for insn in cs.disasm(code_bytes, BASE):
        off = insn.address - BASE + START
        raw = insn.bytes.hex()
        print(f'  code1[{off:#06x}]  {raw:8s}  {insn.mnemonic:10s} {insn.op_str}')

except ImportError:
    print('\n[!] capstone לא מותקן — הדפסת hex בלבד')
    START = 0x20f0
    END   = 0x2280
    code_bytes = fdl1[0x200+START: 0x200+END]
    for i in range(0, len(code_bytes), 16):
        chunk = code_bytes[i:i+16]
        print(f'  code1[{START+i:#06x}]: {chunk.hex()}')

# גם: מציאת הפניות ל-cert+0x20 בקוד FDL1
# cert+0x20 נקרא ב-word = 0x20=32 byte offset. בThumb אפשר להחפש ldrd/ldr עם imm=32
print(f'\n=== חיפוש LDR/STR עם imm #0x20 בcert verify (code1[0x2000..0x2300]) ===')
AREA_START = 0x2000
AREA_END   = 0x2300
for off in range(AREA_START, AREA_END-1, 2):
    hw = struct.unpack_from('<H', fdl1, 0x200+off)[0]
    # Thumb LDR (imm8): 0x6800 + (imm5<<6) + (Rn<<3) + Rd
    # LDR Rd,[Rn,#imm5*4]:  bits 15-11=01101, bits 10-6=imm5, bits 5-3=Rn, bits 2-0=Rd
    if (hw >> 11) == 0b01101:
        imm5 = (hw >> 6) & 0x1f
        rn   = (hw >> 3) & 0x7
        rd   = hw & 0x7
        imm  = imm5 * 4
        if imm == 0x20:
            print(f'  code1[{off:#06x}]: {hw:#06x}  ldr r{rd},[r{rn},#{imm:#x}]')
    # Thumb-2 LDR.W (32-bit):
    elif hw >> 11 == 0b11111 and (hw & 0x7f) == 0b0000001:  # approx
        pass
