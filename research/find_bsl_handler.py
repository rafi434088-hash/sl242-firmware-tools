"""
מחפש ב-FDL1: BSL command handler + verify-fail behavior.
שאלה: אחרי שFDL2 נכשל verification, האם FDL1 מאפס את עצמו?
"""
import struct, sys
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
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

r = open(RESTORE,'rb').read()
re = list_entries(r)
fdl1_e = next(x for x in re if x['name']=='FDL')
fdl1 = r[fdl1_e['doff']: fdl1_e['doff']+fdl1_e['sz']]

FDL1_LOAD = 0x6200   # from PAC entry +0x61c

cs_eng = Cs(CS_ARCH_ARM, CS_MODE_THUMB)

def ram(code_off):
    """convert code offset to RAM address"""
    return FDL1_LOAD + 0x200 + code_off

def code_off(ram_addr):
    return ram_addr - FDL1_LOAD - 0x200

def disasm(start_code_off, end_code_off, label=''):
    if label: print(f'\n=== {label} ===')
    blob = bytes(fdl1[0x200+start_code_off: 0x200+end_code_off])
    for insn in cs_eng.disasm(blob, ram(start_code_off)):
        co = code_off(insn.address)
        print(f'  [{insn.address:#010x}] code1[{co:#06x}]  {insn.bytes.hex():8s}  {insn.mnemonic:10s} {insn.op_str}')

# The verify-fail call at code1[0x220a]:
#   code1[0x220a]: bl #0x10b8c  (error handler with string)
#   code1[0x220e]: movs r0, #0
#   code1[0x2210]: add sp, #0x134
#   code1[0x2212]: pop.w {r4-fp, pc}
#
# After inner verify returns 0 (fail), the OUTER wrapper also returns 0.
# Then WHOEVER called the wrapper checks the result.
# That caller is in FDL1's BSL command handler for END_DATA.
# If caller gets 0: sends NACK to PC? NACK = error response in BSL.
# ResearchDownload receives NACK → shows "Verify error" → STOPS.
# FDL1 after sending NACK: stays alive or resets?

# Let's find what calls the wrapper at code1[0x222a]
# Search for bl that branches to 0x222a or 0x222e (Thumb PC+4 calculation)
print('Search for calls to code1[0x222a] (FDL2 verify wrapper):')
TARGET_RAM = ram(0x222a)  # = 0x6200 + 0x200 + 0x222a = 0x882a
# Thumb BL instruction: word1 = 1111 0xxx xxxx xxxx, word2 = 1111 1xxx xxxx xxxx
# Encoding: imm32 = sign_extend(S:I1:I2:imm10:imm11 << 1)
code_bytes = fdl1[0x200:]
code_sz = struct.unpack_from('<I', fdl1, 0x30)[0]

found = []
for i in range(0, code_sz-3, 2):
    hw1 = struct.unpack_from('<H', code_bytes, i)[0]
    hw2 = struct.unpack_from('<H', code_bytes, i+2)[0]
    # BL: hw1 = 1111 0... ..., hw2 = 1111 1... ...
    if (hw1 >> 11) == 0b11110 and (hw2 >> 14) == 0b11:
        # decode
        S  = (hw1 >> 10) & 1
        J1 = (hw2 >> 13) & 1
        J2 = (hw2 >> 11) & 1
        I1 = 1 - (J1 ^ S)
        I2 = 1 - (J2 ^ S)
        imm10 = hw1 & 0x3ff
        imm11 = hw2 & 0x7ff
        imm32 = ((S << 24) | (I1 << 23) | (I2 << 22) | (imm10 << 12) | (imm11 << 1))
        if S: imm32 |= 0xfe000000  # sign extend
        pc = ram(i) + 4
        target = (pc + imm32) & 0xffffffff
        if target == TARGET_RAM or target == TARGET_RAM+2:
            co = code_off(pc - 4)
            found.append(co)
            print(f'  code1[{co:#06x}]  RAM={ram(co):#010x}  -> bl to {target:#010x} (code1[0x222a] wrapper)')

if not found:
    print('  not found by BL encoding; trying wider search...')
    # maybe called via function pointer or different encoding

# Also: disasm the error handler at code1[0x10b8c]
print()
disasm(0x10b8c, 0x10bb0, 'error handler at code1[0x10b8c]')

# disasm around after verify-fail returns in outer wrapper
# code1[0x2288]: add sp + pop = return to caller
# need to trace where execution goes after return
print()
print(f'FDL1 code1[0x222a] (verify wrapper) at RAM: {ram(0x222a):#010x}')
print(f'FDL1 code1[0x2168] (NOP target) at RAM: {ram(0x2168):#010x}')
print(f'FDL1 SRAM range: {FDL1_LOAD:#010x} .. {FDL1_LOAD+len(fdl1):#010x}')
