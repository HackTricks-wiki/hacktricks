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

Inside bl2_ext, the verification policy function can be patched to unconditionally report that verification is not required (or always succeeds), forcing the boot chain to accept unsigned TEE/GZ/LK/Kernel images. Because this patch runs at EL3, it is effective even if downstream components implement their own checks.

## Practical exploit chain

1. Obtain bootloader partitions (Preloader, bl2_ext, LK/AEE, etc.) via OTA/firmware packages, EDL/DA readback, or hardware dumping.
2. Identify bl2_ext verification routine and patch it to always skip/accept verification.
3. Flash modified bl2_ext using fastboot, DA, or similar maintenance channels that are still allowed on unlocked devices.
4. Reboot; Preloader jumps to patched bl2_ext at EL3 which then loads unsigned downstream images (patched TEE/GZ/LK/Kernel) and disables signature enforcement.

If the device is configured as locked (seccfg locked), the Preloader is expected to verify bl2_ext. In that configuration, this attack will fail unless another vulnerability permits loading an unsigned bl2_ext.

## Triage (expdb boot logs)

- Dump boot/expdb logs around the bl2_ext load. If `img_auth_required = 0` and certificate verification time is ~0 ms, verification is likely skipped.

Example log excerpt:

```
[PART] img_auth_required = 0
[PART] Image with header, name: bl2_ext, addr: FFFFFFFFh, mode: FFFFFFFFh, size:654944, magic:58881688h
[PART] part: lk_a img: bl2_ext cert vfy(0 ms)
```

- Some devices skip bl2_ext verification even when locked; lk2 secondary bootloader paths have shown the same gap. If a post-OTA Preloader logs `img_auth_required = 1` for bl2_ext while unlocked, enforcement was likely restored.

## Verification logic locations

- The relevant check typically resides inside the bl2_ext image in functions named similarly to `verify_img` or `sec_img_auth`.
- The patched version forces the function to return success or to bypass the verification call entirely.

Example patch approach (conceptual):
- Locate the function that calls `sec_img_auth` on TEE, GZ, LK, and kernel images.
- Replace its body with a stub that immediately returns success, or overwrite the conditional branch that handles verification failure.

Ensure the patch preserves stack/frame setup and returns expected status codes to callers.

## Fenrir PoC workflow (Nothing/CMF)

Fenrir is a reference patching toolkit for this issue (Nothing Phone (2a) fully supported; CMF Phone 1 partially). High level:
- Place the device bootloader image as `bin/<device>.bin`.
- Build a patched image that disables the bl2_ext verification policy.
- Flash the resulting payload (fastboot helper provided).

```bash
./build.sh pacman                    # build from bin/pacman.bin
./build.sh pacman /path/to/boot.bin  # build from a custom bootloader path
./flash.sh                           # flash via fastboot
```

Use another flashing channel if fastboot is unavailable.

## EL3 patching notes

- bl2_ext executes in ARM EL3. Crashes here can brick a device until reflashed via EDL/DA or test points.
- Use board-specific logging/UART to validate execution path and diagnose crashes.
- Keep backups of all partitions being modified and test on disposable hardware first.

## Implications

- EL3 code execution after Preloader and full chain-of-trust collapse for the rest of the boot path.
- Ability to boot unsigned TEE/GZ/LK/Kernel, bypassing secure/verified boot expectations and enabling persistent compromise.

## Device notes

- Confirmed supported: Nothing Phone (2a) (Pacman)
- Known working (incomplete support): CMF Phone 1 (Tetris)
- Observed: Vivo X80 Pro reportedly did not verify bl2_ext even when locked
- NothingOS 4 stable (BP2A.250605.031.A3, Nov 2025) re-enabled bl2_ext verification; fenrir `pacman-v2.0` restores the bypass by mixing the beta Preloader with a patched LK
- Industry coverage highlights additional lk2-based vendors shipping the same logic flaw, so expect further overlap across 2024–2025 MTK releases.

## MTK DA readback and seccfg manipulation with Penumbra

Penumbra is a Rust crate/CLI/TUI that automates interaction with MTK preloader/bootrom over USB for DA-mode operations. With physical access to a vulnerable handset (DA extensions allowed), it can discover the MTK USB port, load a Download Agent (DA) blob, and issue privileged commands such as seccfg lock flipping and partition readback.

- **Environment/driver setup**: On Linux install `libudev`, add the user to the `dialout` group, and create udev rules or run with `sudo` if the device node is not accessible. Windows support is unreliable; it sometimes works only after replacing the MTK driver with WinUSB using Zadig (per project guidance).
- **Workflow**: Read a DA payload (e.g., `std::fs::read("../DA_penangf.bin")`), poll for the MTK port with `find_mtk_port()`, and build a session using `DeviceBuilder::with_mtk_port(...).with_da_data(...)`. After `init()` completes the handshake and gathers device info, check protections via `dev_info.target_config()` bitfields (bit 0 set → SBC enabled). Enter DA mode and attempt `set_seccfg_lock_state(LockFlag::Unlock)`—this only succeeds if the device accepts extensions. Partitions can be dumped with `read_partition("lk_a", &mut progress_cb, &mut writer)` for offline analysis or patching.
- **Security impact**: Successful seccfg unlocking reopens flashing paths for unsigned boot images, enabling persistent compromises such as the bl2_ext EL3 patching described above. Partition readback provides firmware artifacts for reverse engineering and crafting modified images.

<details>
<summary>Rust DA session + seccfg unlock + partition dump (Penumbra)</summary>

```rust
use tokio::fs::File;
use anyhow::Result;
use penumbra::{DeviceBuilder, LockFlag, find_mtk_port};
use tokio::io::{AsyncWriteExt, BufWriter};

#[tokio::main]
async fn main() -> Result<()> {
    let da = std::fs::read("../DA_penangf.bin")?;
    let mtk_port = loop {
        if let Some(port) = find_mtk_port().await {
            break port;
        }
    };

    let mut dev = DeviceBuilder::default()
        .with_mtk_port(mtk_port)
        .with_da_data(da)
        .build()?;

    dev.init().await?;
    let cfg = dev.dev_info.target_config().await;
    println!("SBC: {}", (cfg & 0x1) != 0);

    dev.set_seccfg_lock_state(LockFlag::Unlock).await?;

    let mut progress = |_read: usize, _total: usize| {};
    let mut writer = BufWriter::new(File::create("lk_a.bin")?);
    dev.read_partition("lk_a", &mut progress, &mut writer).await?;
    writer.flush().await?;
    Ok(())
}
```
</details>

## References

- [Fenrir – MediaTek bl2_ext secure‑boot bypass (PoC)](https://github.com/R0rt1z2/fenrir)
- [Cyber Security News – PoC Exploit Released For Nothing Phone Code Execution Vulnerability](https://cybersecuritynews.com/nothing-phone-code-execution-vulnerability/)
- [Fenrir pacman-v2.0 release (NothingOS 4 bypass bundle)](https://github.com/R0rt1z2/fenrir/releases/tag/pacman-v2.0)
- [The Cyber Express – Fenrir PoC breaks secure boot on Nothing Phone 2a/CMF1](https://thecyberexpress.com/fenrir-poc-for-nothing-phone-2a-cmf1/)
- [Penumbra – MTK DA flash/readback & seccfg tooling](https://github.com/shomykohai/penumbra)

{{#include ../../banners/hacktricks-training.md}}
