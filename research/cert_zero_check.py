"""
בודק cert-zero mode — מוצא beq target בFDL1 ו-FDL2 ומה קורה שם
"""
import struct
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB

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
cs_eng = Cs(CS_ARCH_ARM, CS_MODE_THUMB)

for name in ['FDL', 'FDL2']:
    e = next(x for x in entries if x['name'] == name)
    img = pac[e['doff']: e['doff'] + e['sz']]
    entry_hdr = pac[e['off']: e['off'] + 0xa14]
    load_addr = struct.unpack_from('<I', entry_hdr, 0x61c)[0]
    code_sz   = struct.unpack_from('<I', img, 0x30)[0]
    BASE = load_addr
    print(f'\n=== {name}  load={load_addr:#x}  code_sz={code_sz:#x} ===')

    for i in range(0, code_sz - 8, 2):
        hw1 = struct.unpack_from('<H', img, 0x200 + i)[0]
        hw2 = struct.unpack_from('<H', img, 0x200 + i + 2)[0]
        if (hw1 & 0xfff0) != 0xe9d0: continue
        hw3 = struct.unpack_from('<H', img, 0x200 + i + 4)[0]
        hw4 = struct.unpack_from('<H', img, 0x200 + i + 6)[0]
        if (hw3 & 0xffc0) != 0x4300: continue
        if (hw4 & 0xff00) != 0xd000: continue

        imm8 = hw4 & 0xff
        if imm8 >= 0x80: imm8 -= 0x100
        target_code_off = i + 6 + 4 + imm8 * 2
        target_ram = BASE + target_code_off

        print(f'  cert-zero beq @ code[{i:#x}]  ldrd={hw1:04x}{hw2:04x} orrs={hw3:04x} beq={hw4:04x}')
        print(f'  branch target: code[{target_code_off:#x}]  file[{0x200+target_code_off:#x}]  RAM={target_ram:#010x}')

        blob = bytes(img[0x200 + target_code_off: 0x200 + target_code_off + 16])
        print(f'  bytes: {blob.hex()}')
        for insn in cs_eng.disasm(blob, target_ram):
            print(f'    [{insn.address:#010x}]  {insn.bytes.hex():8s}  {insn.mnemonic} {insn.op_str}')
        break
