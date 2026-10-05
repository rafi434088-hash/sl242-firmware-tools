"""
מוצא כל קודי *#7xxx# ב-CODES.pac UserImg וב-src/user_codes.bin.
גם דמפ של האזור 0x5bb3b0 כדי לראות את מבנה הטבלה.
"""
import struct, hashlib
from pathlib import Path

CODES_PAC = r'C:\Users\USER\Desktop\ריקבה\4x4_CODES.pac'
SRC_BIN   = r'C:\Users\USER\Desktop\ריקבה\src\user_codes.bin'

def list_entries(pac):
    entries = []
    off = 0x84C
    for _ in range(60):
        cs = struct.unpack_from('<I', pac, off)[0]
        if not cs or cs > 0x10000000: break
        name = pac[off+4:off+4+0x100].decode('utf-16-le','ignore').split('\x00')[0]
        sz   = struct.unpack_from('<I', pac, off+0x604)[0]
        doff = struct.unpack_from('<I', pac, off+0x610)[0]
        entries.append({'name':name,'off':off,'cs':cs,'doff':doff,'sz':sz})
        off += cs
    return entries

def get_img(pac, entries, name):
    e = next((x for x in entries if x['name'] == name), None)
    if not e: return None
    return pac[e['doff']: e['doff']+e['sz']]

codes = open(CODES_PAC,'rb').read()
ce = list_entries(codes)
c_ui = get_img(codes, ce, 'UserImg')

def scan_codes(data, label, around_offset=None):
    print(f'\n=== {label} ===')
    # Search for *#7 pattern (0x2a 0x23 0x37 in ASCII, or *#7 in UTF-16?)
    # ASCII: 2a 23 37
    pattern = b'\x2a\x23\x37'
    found = []
    idx = 0
    while True:
        idx = data.find(pattern, idx)
        if idx == -1: break
        # Read next ~8 bytes
        chunk = data[idx:idx+10]
        try:
            s = chunk.decode('ascii','ignore')
        except:
            s = chunk.hex()
        found.append((idx, s))
        idx += 1
    print(f'  ASCII *#7 occurrences: {len(found)}')
    for off, s in found:
        print(f'    [{off:#010x}]  {s!r}')

    # Also search for UTF-16LE *#7
    pattern16 = b'\x2a\x00\x23\x00\x37\x00'
    found16 = []
    idx = 0
    while True:
        idx = data.find(pattern16, idx)
        if idx == -1: break
        chunk = data[idx:idx+20]
        try:
            s = chunk.decode('utf-16-le','ignore')[:10]
        except:
            s = chunk.hex()
        found16.append((idx, s))
        idx += 1
    print(f'  UTF-16LE *#7 occurrences: {len(found16)}')
    for off, s in found16[:20]:
        print(f'    [{off:#010x}]  {s!r}')

    # Dump around the known table at code[0x5bb1b0] / file[0x5bb3b0]
    if around_offset is not None:
        start = around_offset - 0x10
        end   = around_offset + 0x100
        blob = data[start:end]
        print(f'\n  Dump around {around_offset:#x}:')
        for i in range(0, len(blob), 16):
            row = blob[i:i+16]
            hex_part = ' '.join(f'{b:02x}' for b in row)
            asc_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in row)
            print(f'    {start+i:#010x}:  {hex_part:<47}  {asc_part}')

scan_codes(bytes(c_ui), 'CODES.pac UserImg', around_offset=0x5bb3b0)

# Also scan src/user_codes.bin
if Path(SRC_BIN).exists():
    src = Path(SRC_BIN).read_bytes()
    scan_codes(src, 'src/user_codes.bin', around_offset=0x5bb3b0)
