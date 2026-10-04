# SL242 / 4x4 Escolls Firmware Patching Tools

Python tools for patching MOCOR firmware on UMS9117 (SPRD3) Spreadtrum feature phones — specifically the SL242 / 4x4 Escolls.

## What it does

- Injects hidden dial codes (`*#7701#`–`*#7711#`) that open hidden UserImg apps
- Bypasses FDL2 eFUSE key-anchor check so a custom RSA-signed UserImg is accepted
- Applies cert-zero to FDL2 so FDL1 loads it without RSA verification
- Re-signs UserImg with a custom RSA-2048 key (PKCS#1 v1.5)
- Builds a valid `.pac` file ready for flashing with ResearchDownload

## Boot chain

```
BROM → FDL1 (BROM verifies) → FDL2 (FDL1 cert-zero bypass) → UserImg (FDL2 RSA verify, eFUSE check NOPed)
```

## Cert structure (SL242 DHTB)

```
cert_off = 0x200 + code_size
cert+0x20 : payload_size  (≠ 0 required for UserImg; zero = FDL1 skips FDL2 verify)
cert+0x60 : sig_data
  +0x00 sig_type=0
  +0x04 key_size=0x800 (2048 bits)
  +0x08 e=65537
  +0x0c modulus (256 B)
  +0x10c SHA256(code) (32 B)
  +0x12c field8 (8 B)
  +0x134 RSA-2048 signature (256 B)
```

## FDL2 patches (eFUSE bypass)

| Offset in code | Original bytes | Patched | Reason |
|----------------|---------------|---------|--------|
| `code[0xb3a4]` | `d1 d1` (bne) | `00 bf` | sig_type=0 eFUSE anchor check #1 |
| `code[0xb3b2]` | `ca d1` (bne) | `00 bf` | sig_type=0 eFUSE anchor check #2 |
| `code[0xb33c]` | `28 b9` (cbnz)| `00 bf` | sig_type=1 eFUSE anchor check |

Plus: `cert+0x20..+0x27 = 0x00*8` on FDL2 (triggers FDL1 cert-zero bypass).

## Files

| File | Purpose |
|------|---------|
| `resign_4x4.py` | Re-signs a UserImg binary with a custom RSA-2048 key |
| `build_pac.py` | Full build: patch FDL2 + resign UserImg + assemble PAC |

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

- Tested on MOCOR_20A_MP_W20.29.5 firmware
- Does **not** touch NV / IMEI / calibration partitions
- Requires the original RESTORE.pac and a bypass_codes.pac with the dial-code patches already applied to UserImg
