# SL242 (4×4) — Firmware Analysis: What We Know

Device: SL242 / GX2421, chip UMS9117 (SPRD3), firmware MOCOR_20A_MP_W20.29.5  
Goal: Flash custom UserImg with dial codes *#7701#–*#7711# that open hidden UserImg apps  
Status: **BLOCKED — bypass private key required**

---

## 1. File inventory (C:\Users\USER\Desktop\ריקבה\)

| File | Size | Notes |
|------|------|-------|
| 4x4_RESTORE.pac | small | OEM FDL + FDL2 + UserImg. **WORKS.** Used for restore. |
| 4x4_FULL_factory_SL242_GX2421.pac | 68 MB | Full factory flash. FDL/FDL2/UserImg = **identical** to RESTORE. |
| 4x4_bypass_codes.pac | 68 MB | Full PAC with patched UserImg (bypass key, stale RSA sig). Never tested. |
| 4x4_CODES.pac | ~10 MB | OEM FDL+FDL2 + UserImg with *#7701#–*#7710#. Bypass key, stale RSA sig. FAILS. |
| src/user_codes.bin | 10 MB | UserImg with *#7701#–*#7711#. Bypass key, stale RSA sig. **FAILS [UB1132].** |
| src/user_codes_menu.bin | 10 MB | Same with menu version. FAILS same reason. |
| FDL2_patched.bin | 73 KB | Patched FDL2: code patch at 0xc408, cert-zero (payload_sz=0). stale hash. Fails FDL1. |
| fdl2_patched_v4.bin | 73 KB | Patched FDL2: CBZ→B at code[0xc1ee], updated SHA256 hash, NO RSA sig update. Fails FDL1. |
| flash4x4_full.py / flash_codes.py | — | BSL flasher (serial). Handles END 0x84 = confirms RSA enforcement. |
| src/flash4x4_full.py | — | Same, with explicit "END 0x84 = secure boot locked" handler. |

---

## 2. DHTB container format

```
[0x000–0x1FF]  DHTB header (0x200 bytes)
  +0x00: magic "DHTB\x01\x00\x00\x00"
  +0x10: load_addr
  +0x14: exec_addr
  +0x30: code_size

[0x200–0x200+code_size]  Code (hashed by Check1)

[0x200+code_size]  Cert (variable)
  +0x20: payload_sz   (must be != 0; if 0 → cert-zero → FAIL/error handler)
  +0x60: sig_type     (0=UserImg, 1=FDL2/SML/FDL1)
  +0x64: key_size     (2048 = RSA-2048)
  +0x6c: RSA modulus  (256 bytes, public key N)
  +0x16c: SHA256(code)  ← Check1 field
  +0x18c: field8       (8 bytes, included in RSA verify comparison)
  +0x194: RSA signature (256 bytes)
```

---

## 3. Cert verification (verify_cert in FDL1 and FDL2)

FDL1 and FDL2 share the same `verify_cert` function pattern with three checks:

### Check 1 — Hash
```c
memcmp(SHA256(img[0x200:cert_off]), cert+0x16c, 32)
```
Passes when cert+0x16c = SHA256(code). Easy to satisfy — update this field after patching.

### Check 2 — eFUSE key match
```c
SHA256(cert+0x6c, key_struct_size) == eFUSE_anchor[sig_type]
```
eFUSE has a hash of the expected public key. cert+0x6c must be the matching key.
- For sig_type=0 (UserImg): eFUSE must have SHA256(dce4c14f key struct) = 70a5dcda...
- For sig_type=1 (FDL2): eFUSE must have SHA256(ad7e67e0 key struct)
- For FDL1 (sig_type=1): BROM eFUSE slot has SHA256(d0a0300a key struct)

### Check 3 — RSA signature
```c
RSA_decrypt(cert+0x194, cert+0x6c_key, e=65537) == PKCS1_or_raw(SHA256(code) || field8)
```
**This is the blocker.** Requires the PRIVATE KEY for the cert+0x6c modulus.

---

## 4. Key inventory

| Modulus (first 4B) | Used in | Role | Private key? |
|--------------------|---------|------|-------------|
| `dce4c14f` | All UserImg (RESTORE, BYPASS, CODES, src/*.bin) | "Bypass key" = SPRD universal jig key | **NOT FOUND** |
| `ad7e67e0` | OEM FDL2, OEM SML | OEM FDL2/SML signing key | NOT FOUND |
| `d0a0300a` | OEM FDL1 | FDL1 BROM verification key | NOT FOUND |
| `9ea39bb8` | Our resign_key.pem | Our generated test key | Available at Desktop\5555\source\resign_key.pem |

### eFUSE configuration (inferred)
- eFUSE slot for UserImg (sig_type=0): SHA256(dce4c14f key struct) = `70a5dcda...`
- RESTORE UserImg (dce4c14f signed, valid RSA) → FLASHES SUCCESSFULLY → confirms eFUSE has bypass key hash
- Any UserImg with modified code → stale RSA sig → Check3 FAILS → [UB1132]

---

## 5. The stale RSA signature problem — ROOT CAUSE

**All modified UserImgs (BYPASS, CODES, user_codes.bin) have IDENTICAL RSA signature:**
```
sig[0:16] = b591cfd52580578b8ba635bbd1403e67...
```
This signature was computed for RESTORE's hash (`c2502b7e...`) using the bypass private key.

When code is patched:
- cert+0x16c is updated to new hash ✓
- cert+0x194 (RSA sig) is NOT recomputed ✗ (private key unavailable)

Check1 passes, Check2 passes, **Check3 FAILS** → END 0x84 → [UB1132]

To fix: compute `sig = RSA_sign(SHA256(new_code) || field8, bypass_private_key)`

---

## 6. Flash test results

| Test | PAC | FDL1 | FDL2 | UserImg | Result | Cause |
|------|-----|------|------|---------|--------|-------|
| T1 | mini, patched FDL2 | OEM | patched (NOP Check2+3 in code) | OEM UserImg | [DL1139] FDL2 step | FDL1 Check3 rejects patched FDL2 (stale RSA sig) |
| T2 | bypass_codes + our UI | OEM | OEM | our-key resigned | [UB1132] SML step | FDL2 Check rejects (key mismatch or stale sig) |
| T3 | build_pac.py v1 | patched (no resign) | patched | resigned our-key | [SW2276] FDL step | BROM rejects or patched FDL1 crashes |
| T4 | build_pac.py v2 | patched+resigned (our key) | patched | resigned our-key | [SW2276] FDL step | Same as T3 |
| T5 | build_simple.py | OEM | OEM | our-key resigned bypass UI | [UB1132] UserImg | Check2 fails (our key hash ≠ eFUSE) |
| T6 | build_final.py | OEM | OEM | src/user_codes.bin (bypass key, stale sig) | [UB1132] UserImg | Check3 fails (stale RSA sig) |

---

## 7. FDL2 bypass patch offsets (for patched FDL2 approach)

In OEM FDL2 (md5=69410115d1fe16f93c8da64a19ad9e34), sig_type=0 (UserImg) path:

```
file[0x200+0xb3b2] = file[0xb5b2]:  CA D1  →  00 BF  (NOP bne = skip Check2 fail)
file[0x200+0xb3d0] = file[0xb5d0]:  04 D1  →  00 BF  (NOP bne = skip Check3 length fail)
file[0x200+0xb3da] = file[0xb5da]:  30 B1  →  06 E0  (B always = Check3 always passes)
```

After patching, update cert+0x16c = SHA256(patched code). Do NOT change cert+0x194 (irrelevant once Check3 is bypassed).

**Problem**: Patched FDL2 fails FDL1 Check3 (stale RSA sig). To get FDL1 to accept patched FDL2, need to also patch FDL1.

---

## 8. FDL1 bypass patch offsets (attempted, caused crash or BROM rejection)

In OEM FDL1 (md5=36c93543272e6f94fa8772ca254676b0), sig_type=1 path:

```
file[0x200+0x2196] = file[0x2396]:  04 D1  →  00 BF  (NOP bne = skip Check3 length fail)
file[0x200+0x21a0] = file[0x23a0]:  08 B1  →  01 E0  (B always = Check3 always passes)
```

**Problem**: Patched FDL1 was loaded but failed [SW2276] at FDL step (either BROM rejects or FDL1 crashes). BROM may use hardcoded d0a0300a key for RSA check of FDL1, OR the patches cause FDL1 to crash.

**Cert-zero mode**: If cert+0x20 == 0, FDL1/FDL2 go to error handler and return FAIL. NOT a bypass.

---

## 9. FDL2_patched_v4 analysis

Different approach seen in fdl2_patched_v4.bin:
- Code patch at file[0xc3ee]: `40 B1` (CBZ r0, #imm) → `08 E0` (B always)
  - This is NOT in the same verify_cert location as our patches
  - Could be in a different function, possibly the BSL END command handler
- cert+0x16c: updated to new hash (hash_match=True confirmed)
- cert+0x194: RSA sig NOT updated (same old OEM sig)
- **Still fails FDL1 Check3 because RSA sig is stale**

What code[0xc1ee] is: needs further disassembly (disasm_fdl2.py can help).

---

## 10. BROM behavior (inferred)

- BROM uses RSA verification for FDL1 (most likely with d0a0300a key or eFUSE-based key)
- Any patched FDL1 (modified code) → BROM or FDL1 startup fails → [SW2276] baud timeout
- We cannot patch FDL1 without d0a0300a private key for valid RSA sig

---

## 11. What is needed to proceed

### Option A: Bypass private key (dce4c14f modulus)
The "SPRD universal jig key" / "Spreadtrum bypass key" with N=dce4c14f...
- Use `resign_4x4.py` pattern but with bypass_key.pem
- Sign the modified UserImg (user_codes.bin / user_codes_menu.bin)
- Build PAC with OEM FDL1 + OEM FDL2 + properly signed UserImg

Expected to work because:
- Check1: SHA256 updated ✓
- Check2: bypass key modulus in cert, eFUSE has bypass key hash ✓
- Check3: new valid RSA sig with bypass private key ✓

### Option B: FDL2 patching via BROM vulnerability
Find a way to load modified FDL1 through BROM. Unlikely without access to BROM code.

### Option C: FDL2 runtime patching via another mechanism
Not found.

---

## 12. Research scripts (in research/ directory)

| Script | Purpose |
|--------|---------|
| inspect_factory_pac.py | Compares factory PAC vs RESTORE PAC entries |
| inspect_patched_fdl2.py | Diffs FDL2_patched.bin / fdl2_patched_v4.bin vs OEM |
| inspect_codes_userimg.py | Cert analysis of all UserImg variants |
| diff_codes_vs_restore_ui.py | Code diffs between RESTORE/BYPASS/CODES UserImgs |
| scan_dial_codes.py | Finds *#7xxx# strings in UserImg binaries |
| cert_zero_check.py | Proves cert-zero mode goes to error handler (FAIL) |
| check_cert_and_dis.py | Cert field dump + disassembly around cert area |
| disasm_fdl1.py / disasm_fdl2.py | Disassembly helpers for FDL1/FDL2 code |
| fdl1_header.py | DHTB header inspector |
| find_bsl_handler.py | Finds BSL END command handler in FDL1 |
| verify_fdl1_sha.py | Verifies SHA256 integrity of FDL1 cert |
| compare_sml.py | Compares SML between bypass and restore PACs |

All scripts expect source files in `C:\Users\USER\Desktop\ריקבה\`.

---

## 13. Confirmed working config

```python
# build_final.py
FDL1  = OEM FDL1 from 4x4_RESTORE.pac      # md5=36c93543272e
FDL2  = OEM FDL2 from 4x4_RESTORE.pac      # md5=69410115d1fe
UserImg = src/user_codes.bin OR src/user_codes_menu.bin
          # FAILS due to stale RSA sig
          # If bypass private key available: run resign_4x4.py with bypass key → WORKS
```
