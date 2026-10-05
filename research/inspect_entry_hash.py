"""
בדיקה: האם entry header (0xa14 bytes) מכיל hash/CRC של ה-data?
"""
import struct, hashlib, zlib

RESTORE = r'C:\Users\USER\Desktop\ריקבה\4x4_RESTORE.pac'
FACTORY = r'C:\Users\USER\Desktop\ריקבה\4x4_FULL_factory_SL242_GX2421.pac'
BYPASS  = r'C:\Users\USER\Desktop\ריקבה\4x4_bypass_codes.pac'
ENTRY_HDR = 0xa14   # header is always 0xa14 bytes (data_offset is absolute in PAC)

def list_entries(pac):
    entries = []
    off = 0x84C
    for _ in range(30):
        cs = struct.unpack_from('<I', pac, off)[0]
        if cs == 0 or cs > 0x10000000: break
        name = pac[off+4:off+4+0x100].decode('utf-16-le','ignore').split('\x00')[0]
        sz   = struct.unpack_from('<I', pac, off+0x604)[0]
        doff = struct.unpack_from('<I', pac, off+0x610)[0]
        base = struct.unpack_from('<I', pac, off+0x61c)[0]
        entries.append({'name':name, 'off':off, 'cs':cs, 'doff':doff, 'sz':sz, 'base':base})
        off += cs if cs == ENTRY_HDR else ENTRY_HDR  # safety
    return entries

restore = open(RESTORE,'rb').read()
factory = open(FACTORY,'rb').read()
bypass  = open(BYPASS,'rb').read()

r_e = {e['name']:e for e in list_entries(restore)}
f_e = {e['name']:e for e in list_entries(factory)}
b_e = {e['name']:e for e in list_entries(bypass)}

print('=== entries בRESTORE ===')
for e in list_entries(restore):
    print(f'  {e["name"]:20s}  cs={e["cs"]:#06x}  doff={e["doff"]:#010x}  sz={e["sz"]:#010x}  base={e["base"]:#010x}')
print()

def dump_entry_header(pac, e, label):
    off = e['off']
    hdr = pac[off : off + ENTRY_HDR]
    print(f'=== {label} (cs={e["cs"]:#x}) ===')
    # Fields ידועים
    KNOWN = set()
    KNOWN.update(range(0, 4))            # cs
    KNOWN.update(range(4, 0x104))        # name (utf-16)
    KNOWN.update(range(0x604, 0x608))    # data_size
    KNOWN.update(range(0x610, 0x614))    # data_offset
    KNOWN.update(range(0x61c, 0x620))    # base_address
    # הדפס non-zero fields שאינם ידועים
    unknown = {i: hdr[i] for i in range(ENTRY_HDR) if i not in KNOWN and hdr[i] != 0}
    if not unknown:
        print('  (אין שדות לא-ידועים עם ערך שונה מאפס)')
        return
    # קבץ לרצפים
    runs, cur_s, cur_b = [], None, []
    for i in sorted(unknown):
        if cur_s is None: cur_s, cur_b = i, [unknown[i]]
        elif i == cur_s + len(cur_b): cur_b.append(unknown[i])
        else: runs.append((cur_s, cur_b)); cur_s, cur_b = i, [unknown[i]]
    if cur_s is not None: runs.append((cur_s, cur_b))
    for (roff, rbytes) in runs:
        val = bytes(rbytes)
        desc = ''
        if len(rbytes) == 4:
            v = struct.unpack('<I', val)[0]
            desc = f' = {v:#010x} ({v})'
        elif len(rbytes) == 2:
            v = struct.unpack('<H', val)[0]
            desc = f' = {v:#06x} ({v})'
        elif len(rbytes) == 1:
            desc = f' = {rbytes[0]}'
        print(f'  hdr[0x{roff:03x}..0x{roff+len(rbytes)-1:03x}]: {val.hex()}{desc}')

for name in ['FDL', 'FDL2', 'SML', 'UserImg']:
    if name in r_e: dump_entry_header(restore, r_e[name], f'RESTORE {name}')
    elif name in f_e: dump_entry_header(factory, f_e[name], f'FACTORY {name}')
    print()

# בדיקת hash: האם hash/CRC של data קיים בheader?
print('\n=== בדיקת hash/CRC fields ===')
for pac_name, pac, enames in [('RESTORE', restore, r_e), ('FACTORY', factory, f_e), ('BYPASS', bypass, b_e)]:
    for name in ['FDL', 'FDL2', 'SML', 'UserImg']:
        if name not in enames: continue
        e = enames[name]
        if e['sz'] == 0 or e['doff'] == 0: continue
        data = pac[e['doff']:e['doff']+e['sz']]
        hdr  = pac[e['off']:e['off']+ENTRY_HDR]
        md5v    = hashlib.md5(data).digest()
        sha1v   = hashlib.sha1(data).digest()
        sha256v = hashlib.sha256(data).digest()
        crc32v  = struct.pack('<I', zlib.crc32(data) & 0xffffffff)
        print(f'  [{pac_name}] {name}  data_sz={e["sz"]:#x}  md5={md5v.hex()[:16]}...')
        for hname, hval in [('md5',md5v),('sha1',sha1v[:8]),('sha256',sha256v[:8]),('crc32',crc32v)]:
            idx = hdr.find(hval)
            if idx >= 0:
                print(f'    [!!] {hname} found at hdr[0x{idx:03x}]')

# השוואה בין entries של SML ו-UserImg בשדות הקריטיים
print('\n=== השוואה SML vs UserImg בשדות check/flag ===')
for src, pac, name in [('FACTORY SML', factory, 'SML'), ('RESTORE UserImg', restore, 'UserImg')]:
    enames = f_e if 'FACTORY' in src else r_e
    if name not in enames: continue
    e = enames[name]
    hdr = pac[e['off']:e['off']+ENTRY_HDR]
    print(f'\n  {src}:')
    for off in [0x604, 0x608, 0x60c, 0x610, 0x614, 0x618, 0x61c, 0x620, 0x624, 0x628, 0x62c, 0x630, 0x634, 0x638]:
        v = struct.unpack_from('<I', hdr, off)[0]
        if v:
            print(f'    hdr[0x{off:03x}] = {v:#010x}')
