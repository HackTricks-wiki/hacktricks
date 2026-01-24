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

Devices that ship the lk2 secondary bootloader have been observed with the same logic gap, so grab expdb logs for both bl2_ext and lk2 partitions to confirm whether either path enforces signatures before you attempt porting.

If a post-OTA Preloader now logs img_auth_required = 1 for bl2_ext even while seccfg is unlocked, the vendor likely closed the gap—see the OTA persistence notes below.

## Practical exploitation workflow (Fenrir PoC)

Fenrir is a reference exploit/patching toolkit for this class of issue. It supports Nothing Phone (2a) (Pacman) and is known working (incompletely supported) on CMF Phone 1 (Tetris). Porting to other models requires reverse engineering the device-specific bl2_ext.

High-level process:
- Obtain the device bootloader image for your target codename and place it as `bin/<device>.bin`
- Build a patched image that disables the bl2_ext verification policy
- Flash the resulting payload to the device (fastboot assumed by the helper script)

Commands:

```bash
# Build patched image (default path bin/[device].bin)
./build.sh pacman

# Build from a custom bootloader path
./build.sh pacman /path/to/your/bootloader.bin

# Flash the resulting lk.patched (fastboot required by the helper script)
./flash.sh
```

If fastboot is unavailable, you must use a suitable alternative flashing method for your platform.

### OTA-patched firmware: keeping the bypass alive (NothingOS 4, late 2025)

Nothing patched the Preloader in the November 2025 NothingOS 4 stable OTA (build BP2A.250605.031.A3) to enforce bl2_ext verification even when seccfg is unlocked. Fenrir `pacman-v2.0` works again by mixing the vulnerable Preloader from the NOS 4 beta with the stable LK payload:

```bash
# on Nothing Phone (2a), unlocked bootloader, in bootloader (not fastbootd)
fastboot flash preloader_a preloader_raw.img   # beta Preloader bundled with fenrir release
fastboot flash lk pacman-fenrir.bin            # patched LK containing stage hooks
fastboot reboot                                # factory reset may be needed
```

Important:
- Flash the provided Preloader **only** to the matching device/slot; a wrong preloader is an instant hard brick.
- Check expdb after flashing; img_auth_required should drop back to 0 for bl2_ext, confirming that the vulnerable Preloader is executing before your patched LK.
- If future OTAs patch both Preloader and LK, keep a local copy of a vulnerable Preloader to re‑introduce the gap.

### Build automation & payload debugging

- `build.sh` now auto-downloads and exports the Arm GNU Toolchain 14.2 (aarch64-none-elf) the first time you run it, so you do not have to juggle cross-compilers manually.
- Export `DEBUG=1` before invoking `build.sh` to compile payloads with verbose serial prints, which greatly helps when you are blind-patching EL3 code paths.
- Successful builds drop both `lk.patched` and `<device>-fenrir.bin`; the latter already has the payload injected and is what you should flash/boot-test.

## Runtime payload capabilities (EL3)

A patched bl2_ext payload can:
- Register custom fastboot commands
- Control/override boot mode
- Dynamically call built‑in bootloader functions at runtime
- Spoof “lock state” as locked while actually unlocked to pass stronger integrity checks (some environments may still require vbmeta/AVB adjustments)

Limitation: Current PoCs note that runtime memory modification may fault due to MMU constraints; payloads generally avoid live memory writes until this is resolved.

## Payload staging patterns (EL3)

Fenrir splits its instrumentation into three compile-time stages: stage1 runs before `platform_init()`, stage2 runs before LK signals fastboot entry, and stage3 executes immediately before LK loads Linux. Each device header under `payload/devices/` provides the addresses for these hooks plus fastboot helper symbols, so keep those offsets synchronized with your target build.

Stage2 is a convenient location to register arbitrary `fastboot oem` verbs:

```c
void cmd_r0rt1z2(const char *arg, void *data, unsigned int sz) {
    video_printf("r0rt1z2 was here...\n");
    fastboot_info("pwned by r0rt1z2");
    fastboot_okay("");
}

__attribute__((section(".text.main"))) void main(void) {
    fastboot_register("oem r0rt1z2", cmd_r0rt1z2, true, false);
    notify_enter_fastboot();
}
```

Stage3 demonstrates how to temporarily flip page-table attributes to patch immutable strings such as Android’s “Orange State” warning without needing downstream kernel access:

```c
set_pte_rwx(0xFFFF000050f9E3AE);
strcpy((char *)0xFFFF000050f9E3AE, "Patched by stage3");
```

Because stage1 fires prior to platform bring-up, it is the right place to call into OEM power/reset primitives or to insert additional integrity logging before the verified boot chain is torn down.

## Porting tips

- Reverse engineer the device-specific bl2_ext to locate verification policy logic (e.g., sec_get_vfy_policy).
- Identify the policy return site or decision branch and patch it to “no verification required” (return 0 / unconditional allow).
- Keep offsets fully device- and firmware-specific; do not reuse addresses between variants.
- Validate on a sacrificial unit first. Prepare a recovery plan (e.g., EDL/BootROM loader/SoC-specific download mode) before you flash.
- Devices using the lk2 secondary bootloader or reporting “img_auth_required = 0” for bl2_ext even while locked should be treated as vulnerable copies of this bug class; Vivo X80 Pro has already been observed skipping verification despite a reported lock state.
- When an OTA begins enforcing bl2_ext signatures (img_auth_required = 1) in the unlocked state, check whether an older Preloader (often available in beta OTAs) can be flashed to re-open the gap, then re-run fenrir with updated offsets for the newer LK.

## Security impact

- EL3 code execution after Preloader and full chain-of-trust collapse for the rest of the boot path.
- Ability to boot unsigned TEE/GZ/LK/Kernel, bypassing secure/verified boot expectations and enabling persistent compromise.

## Device notes

- Confirmed supported: Nothing Phone (2a) (Pacman)
- Known working (incomplete support): CMF Phone 1 (Tetris)
- Observed: Vivo X80 Pro reportedly did not verify bl2_ext even when locked
- NothingOS 4 stable (BP2A.250605.031.A3, Nov 2025) re-enabled bl2_ext verification; fenrir `pacman-v2.0` restores the bypass by flashing the beta Preloader plus patched LK as shown above
- Industry coverage highlights additional lk2-based vendors shipping the same logic flaw, so expect further overlap across 2024–2025 MTK releases.

## References

- [Fenrir – MediaTek bl2_ext secure‑boot bypass (PoC)](https://github.com/R0rt1z2/fenrir)
- [Cyber Security News – PoC Exploit Released For Nothing Phone Code Execution Vulnerability](https://cybersecuritynews.com/nothing-phone-code-execution-vulnerability/)
- [Fenrir pacman-v2.0 release (NothingOS 4 bypass bundle)](https://github.com/R0rt1z2/fenrir/releases/tag/pacman-v2.0)
- [The Cyber Express – Fenrir PoC breaks secure boot on Nothing Phone 2a/CMF1](https://thecyberexpress.com/fenrir-poc-for-nothing-phone-2a-cmf1/)

{{#include ../../banners/hacktricks-training.md}}
