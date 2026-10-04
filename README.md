# SL242 / 4x4 Escolls Firmware Patching Tools

Python tools for patching MOCOR firmware on UMS9117 (SPRD3) Spreadtrum feature phones — specifically the SL242 / 4x4 Escolls.

## What it does

- Injects hidden dial codes (`*#7701#`–`*#7711#`) that open hidden UserImg apps
- Re-signs FDL2 with a custom RSA-2048 key so FDL1 accepts it
- Patches FDL2 code to bypass its eFUSE key-anchor check when verifying UserImg
- Re-signs UserImg with the same custom RSA key (PKCS#1 v1.5)
- Builds a valid `.pac` file ready for flashing with ResearchDownload

## Boot chain

```
BROM → FDL1 (BROM verifies, unchanged) → FDL2 (FDL1 verifies our resigned FDL2) → UserImg (FDL2 accepts our key, eFUSE check NOPed)
```

## FDL2 cert structure (sig_type=1)

```
cert_off = 0x200 + code_size
cert+0x20 : payload_size (non-zero required)
cert+0x60 : sig_type = 1
cert+0x64 : key_size = 0x800 (LE)
cert+0x68 : e = 0x00010001 (BE, = 65537)
cert+0x6c : RSA-2048 modulus (256 B, BE)
cert+0x16c: SHA256(code) (32 B)
cert+0x18c: field8 (8 B)  ← anchor bytes 0-7
cert+0x194: field32 (32 B) ← anchor bytes 8-31 (first 24 B) + anti-rollback + zeros
cert+0x1b0: anti-rollback version (4 B)
cert+0x1b4: RSA-2048 sig (256 B)
```

## FDL1 verification of FDL2 (code1[0x2112], sig_type=1 path)

| Check | Condition | Solution |
|-------|-----------|---------|
| Code hash | `SHA256(code) == cert+0x16c` | Update cert+0x16c to `SHA256(patched_code)` |
| Key anchor | `field8 \|\| field32[0:24] == SHA256(cert+0x64..0x163)` | Set those bytes = `SHA256(key_size \|\| e \|\| our_modulus)` |
| RSA verify | `RSA_dec(sig, e, n) == cert+0x16c[0:72]` | Sign M = SHA256(code)||field8||field32 with our key |
| Anti-rollback | `cert+0x1b0 >= stored_version` | Keep cert+0x1b0 = 0 |

## FDL2 code patches (eFUSE bypass for UserImg)

| Offset in code | Original bytes | Patched | Reason |
|----------------|---------------|---------|--------|
| `code[0xb3a4]` | `d1 d1` (bne) | `00 bf` | sig_type=0 eFUSE anchor check #1 |
| `code[0xb3b2]` | `ca d1` (bne) | `00 bf` | sig_type=0 eFUSE anchor check #2 |
| `code[0xb33c]` | `28 b9` (cbnz)| `00 bf` | sig_type=1 eFUSE anchor check |

## Files

| File | Purpose |
|------|---------|
| `resign_4x4.py` | Re-signs a UserImg binary with a custom RSA-2048 key |
| `build_pac.py` | Full build: patch FDL2 + resign FDL2 (sig_type=1) + resign UserImg + assemble PAC |

## Requirements

```
pip install cryptography capstone
```

## Usage

Edit `RESTORE`, `BYPASS`, `OUT` paths in `build_pac.py`, then:

```bash
python build_pac.py
```

Outputs `4x4_user_codes.pac` ready to flash with ResearchDownload.

## Notes

- Tested on MOCOR_20A_MP_W20.29.5 firmware (SL242 / 4x4 Escolls)
- Does **not** touch NV / IMEI / calibration partitions
- FDL1 is used unchanged from the original firmware
- Requires the original RESTORE.pac and a bypass_codes.pac with dial-code patches in UserImg
