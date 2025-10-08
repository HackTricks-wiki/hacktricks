# MediaTek bl2_ext Secure-Boot Bypass (EL3 Code Execution)

{{#include ../../banners/hacktricks-training.md}}

This page documents a practical secure-boot break on multiple MediaTek platforms by abusing a verification gap when the device bootloader configuration (seccfg) is "unlocked". The flaw allows running a patched bl2_ext at ARM EL3 to disable downstream signature verification, collapsing the chain of trust and enabling arbitrary unsigned TEE/GZ/LK/Kernel loading.

> Caution: Early-boot patching can permanently brick devices if offsets are wrong. Always keep full dumps and a reliable recovery path.

## Affected boot flow (MediaTek)

- Normal path: BootROM → Preloader → bl2_ext (EL3, verified) → TEE → GenieZone (GZ) → LK/AEE → Linux kernel (EL1)
- Vulnerable path: When seccfg is set to unlocked, Preloader may skip verifying bl2_ext. Preloader still jumps into bl2_ext at EL3, so a crafted bl2_ext can load unverified components thereafter.

Key trust boundary:
- bl2_ext executes at EL3 and is responsible for verifying TEE, GenieZone, LK/AEE and the kernel. If bl2_ext itself is not authenticated, the rest of the chain is trivially bypassed.

## Root cause

On affected devices, the Preloader does not enforce authentication of the bl2_ext partition when seccfg indicates an "unlocked" state. This allows flashing an attacker-controlled bl2_ext that runs at EL3.

Inside bl2_ext, the verification policy function can be patched to unconditionally report that verification is not required. A minimal conceptual patch is:

```c
// inside bl2_ext
int sec_get_vfy_policy(...) {
    return 0; // always: "no verification required"
}
```

With this change, all subsequent images (TEE, GZ, LK/AEE, Kernel) are accepted without cryptographic checks when loaded by the patched bl2_ext running at EL3.

## How to triage a target (expdb logs)

Dump/inspect boot logs (e.g., expdb) around the bl2_ext load. If img_auth_required = 0 and certificate verification time is ~0 ms, enforcement is likely off and the device is exploitable.

Example log excerpt:

```
[PART] img_auth_required = 0
[PART] Image with header, name: bl2_ext, addr: FFFFFFFFh, mode: FFFFFFFFh, size:654944, magic:58881688h
[PART] part: lk_a img: bl2_ext cert vfy(0 ms)
```

Note: Some devices reportedly skip bl2_ext verification even with a locked bootloader, which exacerbates the impact.

## Practical exploitation workflow (Fenrir PoC)

Fenrir is a reference exploit/patching toolkit for this class of issue. It supports Nothing Phone (2a) (Pacman) and is known working (incompletely supported) on CMF Phone 1 (Tetris). Porting to other models requires reverse engineering the device-specific bl2_ext.

High-level process:
- Obtain the device bootloader image for your target codename and place it as bin/<device>.bin
- Build a patched image that disables the bl2_ext verification policy
- Flash the resulting payload to the device (fastboot assumed by the helper script)

Commands:

```bash
# Build patched image (default path bin/[device].bin)
./build.sh pacman

# Build from a custom bootloader path
./build.sh pacman /path/to/your/bootloader.bin

# Flash the resulting lk.patched (fastboot required by helper script)
./flash.sh
```

If fastboot is unavailable, you must use a suitable alternative flashing method for your platform.

## Runtime payload capabilities (EL3)

A patched bl2_ext payload can:
- Register custom fastboot commands
- Control/override boot mode
- Dynamically call built‑in bootloader functions at runtime
- Spoof “lock state” as locked while actually unlocked to pass stronger integrity checks (some environments may still require vbmeta/AVB adjustments)

Limitation: Current PoCs note that runtime memory modification may fault due to MMU constraints; payloads generally avoid live memory writes until this is resolved.

## Porting tips

- Reverse engineer the device-specific bl2_ext to locate verification policy logic (e.g., sec_get_vfy_policy).
- Identify the policy return site or decision branch and patch it to “no verification required” (return 0 / unconditional allow).
- Keep offsets fully device- and firmware-specific; do not reuse addresses between variants.
- Validate on a sacrificial unit first. Prepare a recovery plan (e.g., EDL/BootROM loader/SoC-specific download mode) before you flash.

## Security impact

- EL3 code execution after Preloader and full chain-of-trust collapse for the rest of the boot path.
- Ability to boot unsigned TEE/GZ/LK/Kernel, bypassing secure/verified boot expectations and enabling persistent compromise.

## Detection and hardening ideas

- Ensure Preloader verifies bl2_ext regardless of seccfg state.
- Enforce authentication results and gather audit evidence (timings > 0 ms, strict errors on mismatch).
- Lock-state spoofing should be made ineffective for attestation (tie lock state to AVB/vbmeta verification decisions and fuse-backed state).

## Device notes

- Confirmed supported: Nothing Phone (2a) (Pacman)
- Known working (incomplete support): CMF Phone 1 (Tetris)
- Observed: Vivo X80 Pro reportedly did not verify bl2_ext even when locked

## References

- [Fenrir – MediaTek bl2_ext secure‑boot bypass (PoC)](https://github.com/R0rt1z2/fenrir)

{{#include ../../banners/hacktricks-training.md}}