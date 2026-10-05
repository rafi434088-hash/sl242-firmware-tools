# SL242 (UMS9117) — FDL Signature Bypass: Approaches & UNISOC Vulnerability Research

Device: SL242 / GX2421, chip UMS9117 (SPRD3), firmware MOCOR_20A_MP_W20.29.5  
Goal: Load a custom UserImg with added dial codes without the bypass private key.

---

## Quick Summary of Paths

| # | Approach | Components changed | Status |
|---|----------|--------------------|--------|
| **A** | **FDL2 cert-zero bypass (UserImg)** | UserImg cert+0x20..0x27 zeroed | **UNTESTED — TRY FIRST** |
| B | FDL2 code patches (Check2+3 NOP) | FDL2 patched, FDL1 OEM | Blocked: FDL1 rejects patched FDL2 |
| C | FDL1 + FDL2 combined patches | Both patched | Tested T3/T4: [SW2276] crash |
| D | BROM cert-zero for FDL1 | FDL1 cert-zero | Theoretical, BROM code not accessible |
| E | Bypass private key | OEM FDL1+FDL2, resigned UserImg | Needs key with modulus dce4c14f |

---

## Approach A — FDL2 cert-zero bypass (UNTESTED, HIGH PRIORITY)

### Discovery
From disassembly of OEM FDL2, the download partition handler (not verify_cert itself) contains:

```
FDL2 code[0xc1d2]  (file offset 0xc3d2):
  ldrd r3, r2, [r4, #0x20]   ; load 8 bytes: cert[+0x20..+0x27] of incoming partition
  orrs r3, r2                 ; OR both 32-bit halves
  beq  #0xc20a               ; if ALL 8 bytes are zero → jump to "success/flash" path
```

This check fires BEFORE `verify_cert` is called. If `cert[+0x20..+0x27] == 0x00*8`, the entire
cert verification chain (Check1 / Check2 / Check3) is bypassed and execution jumps directly to
the flash-write success path at code[0xc20a].

### Attack
1. Take `src/user_codes.bin` (or `src/user_codes_menu.bin`).
2. Locate `cert_off = 0x200 + code_size`.
3. Zero out `cert[+0x20..+0x27]` (8 bytes) — clears payload_sz and the following 4 bytes.
4. Update `cert[+0x16c]` with `SHA256(code)` (Check1 field — ensures cert magic is valid even though we never reach Check1 with this path).
5. Leave the RSA sig (`cert+0x194`) as-is (irrelevant — not reached).
6. Build PAC with **unmodified OEM FDL1 + unmodified OEM FDL2** + this UserImg.

Script: `build_zerocert_userimg.py` (see research/ directory).

### Why it might fail
- Code[0xc20a] ("success path") might not be a direct flash-write — it could be a different handler that still fails.
- The 8-byte zero check might be for a DIFFERENT cert field than we think (r4 might not point to cert+0 in all cases).
- Some code path after the beq might still verify the hash.

### Previous test that confused this path
`cert_zero_check.py` proved that inside `verify_cert`, if `payload_sz == 0` → error handler → FAIL.
But that is the INNER path (FDL1's verify_cert for FDL2, or FDL2's verify_cert for UserImg internal check).
The code at `code[0xc1d2]` is OUTER — it runs before `verify_cert` is invoked at all.
**These are two different code paths.** Only Approach A was not tested on device.

---

## Approach B — FDL2 code patches (NOP Check2 and Check3 in verify_cert)

### Patch offsets in OEM FDL2 (md5 = 69410115d1fe16f93c8da64a19ad9e34)

```
file[0xb5b2]  code[0xb3b2]:  CA D1  →  00 BF   (NOP: bne = skip Check2-fail branch)
file[0xb5d0]  code[0xb3d0]:  04 D1  →  00 BF   (NOP: bne = skip Check3 length error)
file[0xb5da]  code[0xb3da]:  30 B1  →  06 E0   (B always = Check3 always passes)
```

After patching: update `cert+0x16c = SHA256(patched code)`.

### Status
FDL1 (OEM, valid RSA sig for OEM FDL2) receives patched FDL2 → Check3 in FDL1's verify_cert
computes RSA_decrypt(stale sig) != new_hash → **[DL1139] at FDL2 step**.

To make this work you also need FDL1 to accept patched FDL2 → see Approach C or Approach D.

---

## Approach C — FDL1 code patches (bypass Check3 for incoming FDL2)

### Patch offsets in OEM FDL1 (md5 = 36c93543272e6f94fa8772ca254676b0)

```
file[0x2396]  code[0x2196]:  04 D1  →  00 BF   (NOP: skip Check3 length error)
file[0x23a0]  code[0x21a0]:  08 B1  →  01 E0   (B always: Check3 always passes)
```

These let FDL1 accept a patched FDL2 regardless of RSA sig validity.

### Status
Tested as T3 (build_pac.py, not resigned) and T4 (resigned with our key 9ea39bb8):
Both gave **[SW2276] at FDL step** — BROM rejects the modified FDL1, or the patched FDL1 crashes.

Two possible explanations:
1. **BROM RSA check**: BROM verifies FDL1 RSA using the d0a0300a key (eFUSE slot for sig_type=1).
   Patched FDL1 has stale RSA sig → BROM rejects it. Our resigned FDL1 (9ea39bb8 key) also fails
   because BROM's eFUSE does not have SHA256(9ea39bb8 key struct).
2. **FDL1 crash after loading**: BROM may accept FDL1 (hash-only check in download mode) but the
   patches corrupt a code flow that crashes FDL1 before it finishes handshake.

### To diagnose
Use a UART debug cable (if accessible). The BROM/FDL1 send error codes on UART in some SPRD devices.
Alternatively: try FDL1 with ONLY the cert-zero modification (cert+0x20=0) — if BROM has the same
cert-zero-bypass as FDL2, a cert-zero FDL1 would load even without matching RSA sig.

---

## Approach D — BROM cert-zero for FDL1 (theoretical)

### Hypothesis
If the UMS9117 BROM download handler also contains the same `ldrd/orrs/beq` sequence as FDL2
(code[0xc1d2]), then a FDL1 with `cert+0x20..0x27 = 0` would pass BROM verification without
RSA check — just like Approach A does for UserImg in FDL2.

### Steps (untested)
1. Take OEM FDL1.
2. Apply code patches (Approach C offsets).
3. Zero `cert+0x20..0x27` (8 bytes after code).
4. Update `cert+0x16c = SHA256(patched code)`.
5. Leave RSA sig as-is.
6. Use this FDL1 + patched FDL2 (Approach B offsets) + any UserImg.

### Problem
BROM code is locked ROM — we have no disassembly of it. The pattern was only confirmed in FDL2.
Whether BROM's FDL1 loader shares the same cert-zero bypass path is unknown.

---

## Approach E — Bypass private key (clean path)

If the SPRD "universal bypass key" private key (RSA-2048, modulus starts `dce4c14f`) is found:

```python
# resign_4x4.py already handles this:
resign(src_userimg, bypass_key_pem, dst_userimg)
# Then: build_final.py → OEM FDL1 + OEM FDL2 + resigned UserImg → WORKS
```

Sources to look for the key:
- Some Chinese factory flash tool packages (SPD_Flashtool, ResearchDownload internal DLLs)
- `msprd_bypass.pem` or similar in OEM developer leak repositories
- Published in some SC6531E/SC7731 jailbreak tool source code

This key is sometimes called "SPRD test/jig key" or "SC debug key". It is the same key used by
factory fixtures to flash test firmware, hence present in many SPRD factory tools.

---

## FDL2_patched_v4 alternative patch

`fdl2_patched_v4.bin` contains a DIFFERENT approach to FDL2 modification:

```
file[0xc3ee]  code[0xc1ee]:  40 B1  (CBZ r0, #0x20)  →  08 E0  (B #0x14)
```

This patch is at code[0xc1ee] — just 28 bytes after the cert-zero check at code[0xc1d2].
Likely in the same function, possibly converting a conditional "skip flash write" into "always flash write".

Noteworthy: this patch was used by the original `4x4_CODES.pac` author (who also had access to
the bypass private key to sign UserImg). They may have discovered a different code path.

The cert+0x16c was updated in fdl2_patched_v4.bin (hash_match=True), but RSA sig was NOT updated —
this FDL2 still needs Approach C or D to be loaded by FDL1.

---

## Known UNISOC/Spreadtrum Public Vulnerabilities

### 1. SC9832E / SC9863A BROM USB stack overflow
**Affected**: SC9832E, SC9863A, SC9850, and likely related T7-series chips (UMS9117 is T7-series)
**Summary**: During BSL BROM download mode, a malformed USB packet can overflow a stack buffer
in the cert parsing routine. Demonstrated by security researchers (2021–2022) to achieve arbitrary
code execution in BROM context before cert verification completes.
**Relevance**: UMS9117 shares BROM code lineage with SC9863A. If the same pattern exists, a crafted
FDL1 header could crash BROM in a controlled way and redirect execution.
**Reference**: Disclosed at security conferences; proof-of-concept tools exist for some variants.

### 2. SPRD calibration / "engineering mode" USB command
**Summary**: Some SPRD chips respond to a specific USB control transfer (before FDL1 loads) that
sets an "engineering/calibration mode" flag, causing BROM to load FDL1 without cert verification.
**Known on**: SC6531E, SC7731G (older MOCOR feature phone chips).
**Status for UMS9117**: Unconfirmed. The factory flash tool (`flash4x4_full.py`) does not send
any such pre-FDL1 command — it goes straight to BROM bootloader handshake.

### 3. BROM hash-only mode (community reports)
**Summary**: Some SPRD BROM in download mode performs only a hash check of FDL1 (cert+0x16c)
and skips RSA verification if a specific hardware strap or eFUSE bit is set.
**Evidence**: Multiple community reports for SC9832E and SC9850. "secure_boot_level" eFUSE field
controls whether BROM enforces RSA (level 2) or only hash (level 1) or nothing (level 0).
**Our device**: RESTORE PAC flashes successfully with bypass-key UserImg → suggests eFUSE is burnt
to sig_type=0 bypass key hash. Whether FDL1 eFUSE slot is at level 1 or 2 is unknown.
**Test**: A FDL1 with only cert+0x16c updated (no RSA sig change) would determine this definitively.

### 4. FDL2 verify_cert integer overflow
**Summary**: In some SPRD FDL2 implementations, the `key_size` field (cert+0x64) is used without
bounds checking in the RSA modular exponentiation loop. A crafted oversized key_size could cause
a buffer overflow in FDL2's heap, overwriting the return address after verify_cert.
**Relevance**: Hard to exploit reliably; requires return-oriented programming in FDL2 context.
**Prerequisite**: Ability to load arbitrary FDL2 (which requires FDL1 bypass first).

### 5. BSL protocol END command handler
**Summary**: Some SPRD FDL implementations process the BSL END (0xFE 0x00) command in a way
that does not validate the final data CRC before accepting the partition. Specifically, the
`sum_complement` check can be skipped by sending a frame with specific escape sequences.
**Evidence**: Seen in some SC8830-era devices; documented in the BSL protocol reverse engineering
community notes.
**Our device**: The `flash4x4_full.py` flasher uses standard BSL framing and does not attempt this.

---

## What to try next (priority order)

1. **Run `build_zerocert_userimg.py`** → flash result → if [SUCCESS] at UserImage: Approach A works.
2. If A fails: read UART output during [SW2276] to determine if BROM is rejecting patched FDL1
   or if FDL1 crashes after loading.
3. Search for bypass private key in SPD flash tool packages (ResearchDownload, SPD_Flashtool).
4. If BROM eFUSE is at secure_boot_level < 2: cert-zero FDL1 (Approach D) would load.

---

## File references

| File | Description |
|------|-------------|
| `build_final.py` | OEM FDL1+FDL2 + unmodified src/user_codes.bin → FAILS [UB1132] (stale RSA) |
| `research/build_zerocert_userimg.py` | **NEW**: OEM FDL1+FDL2 + cert-zero UserImg → try this |
| `research/inspect_patched_fdl2.py` | Disassembly diff of FDL2_patched.bin / fdl2_patched_v4.bin |
| `ANALYSIS.md` | Complete cert format, key inventory, all test results |
