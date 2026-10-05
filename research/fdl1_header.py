"""
מבנה DHTB header של FDL1 ו-FDL2 — כתובת טעינה, גודל, entry point.
"""
import struct, sys
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

for name in ['FDL', 'FDL2']:
    e = next((x for x in re if x['name'] == name), None)
    if not e: continue
    data = r[e['doff']: e['doff']+e['sz']]
    print(f'\n=== {name} DHTB header (first 0x40 bytes) ===')
    for i in range(0, 0x40, 16):
        line = data[i:i+16]
        print(f'  +{i:#04x}: {line.hex()}')

    # known DHTB fields:
    magic    = data[0x00:0x08]
    hdr_size = struct.unpack_from('<I', data, 0x08)[0]
    load_addr= struct.unpack_from('<I', data, 0x10)[0]
    exec_addr= struct.unpack_from('<I', data, 0x14)[0]
    file_size= struct.unpack_from('<I', data, 0x18)[0]
    code_size= struct.unpack_from('<I', data, 0x30)[0]

    print(f'  magic:     {magic.hex()}')
    print(f'  hdr_size:  {hdr_size:#010x}')
    print(f'  load_addr: {load_addr:#010x}')
    print(f'  exec_addr: {exec_addr:#010x}')
    print(f'  file_size: {file_size:#010x}')
    print(f'  code_size: {code_size:#010x}')

# PAC entry header for FDL/FDL2 — load address stored there too
print('\n=== PAC entry headers ===')
for name in ['FDL', 'FDL2']:
    e = next((x for x in re if x['name'] == name), None)
    if not e: continue
    hdr = r[e['off']: e['off']+0xa14]
    # entry: +0x604=size, +0x610=doff, others?
    base  = struct.unpack_from('<I', hdr, 0x604)[0]  # partition size
    doff  = struct.unpack_from('<I', hdr, 0x610)[0]
    # base address of partition (flash offset or RAM load address)
    flash_base = struct.unpack_from('<I', hdr, 0x618)[0]
    load_base  = struct.unpack_from('<I', hdr, 0x61c)[0]
    print(f'  {name}: size={base:#x}  doff={doff:#x}  +0x618={flash_base:#x}  +0x61c={load_base:#x}')
    # print first few fields
    print(f'    entry[0x600..0x630]: {hdr[0x600:0x630].hex()}')
