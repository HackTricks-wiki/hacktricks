# MediaTek bl2_ext Secure-Boot Bypass (EL3 Code Execution)

{{#include ../../banners/hacktricks-training.md}}

本页面记录了在多款 MediaTek 平台上利用引导加载器配置 (seccfg) 为 "unlocked" 时出现的验证缺口进行的实际 secure-boot 绕过。该缺陷允许在 ARM EL3 上运行被篡改的 bl2_ext 来禁用下游的签名验证，从而破坏信任链并允许任意未签名的 TEE/GZ/LK/Kernel 加载。

> 警告：Early-boot patching 可能在偏移量错误时永久损坏设备。始终保留完整转储和可靠的恢复路径。

## Affected boot flow (MediaTek)

- 正常路径：BootROM → Preloader → bl2_ext (EL3, verified) → TEE → GenieZone (GZ) → LK/AEE → Linux kernel (EL1)
- 易受攻击路径：当 seccfg 设置为 unlocked 时，Preloader 可能会跳过对 bl2_ext 的验证。Preloader 仍然会在 EL3 跳转到 bl2_ext，因此经过精心构造的 bl2_ext 可以随后加载未验证的组件。

关键信任边界：
- bl2_ext 在 EL3 执行并负责验证 TEE、GenieZone、LK/AEE 和 kernel。如果 bl2_ext 本身未被认证，其余链就可以轻易被绕过。

## Root cause

在受影响的设备上，当 seccfg 表示为 "unlocked" 状态时，Preloader 不会强制对 bl2_ext 分区进行认证。这允许刷新由攻击者控制的 bl2_ext 并在 EL3 上运行。

在 bl2_ext 内，可以对 verification policy 函数进行补丁，使其无条件地报告不需要验证。一个最小的概念性补丁是：
```c
// inside bl2_ext
int sec_get_vfy_policy(...) {
return 0; // always: "no verification required"
}
```
有了此更改，当运行于 EL3 的已修补 bl2_ext 加载后续镜像（TEE、GZ、LK/AEE、Kernel）时，这些镜像将被接受而不进行加密校验。

## 如何筛查目标（expdb 日志）

在 bl2_ext 加载前后转储/检查启动日志（例如 expdb）。如果 img_auth_required = 0 且 certificate verification time is ~0 ms，则很可能已关闭强制检查，设备可被利用。

示例日志摘录：
```
[PART] img_auth_required = 0
[PART] Image with header, name: bl2_ext, addr: FFFFFFFFh, mode: FFFFFFFFh, size:654944, magic:58881688h
[PART] part: lk_a img: bl2_ext cert vfy(0 ms)
```
注意：有报告称某些设备即使在 bootloader 锁定的情况下也会跳过 bl2_ext 验证，这会加剧影响。

## Practical exploitation workflow (Fenrir PoC)

Fenrir 是针对该类问题的参考 exploit/patching 工具包。它支持 Nothing Phone (2a) (Pacman)，并且已知在 CMF Phone 1 (Tetris) 上可用（支持不完整）。移植到其他机型需要对设备特定的 bl2_ext 进行逆向工程。

High-level process:
- 获取目标代号对应的设备 bootloader 镜像并将其放置为 bin/<device>.bin
- 构建一个禁用 bl2_ext 验证策略的修补镜像
- 将生成的 payload 刷写到设备上（辅助脚本假定使用 fastboot）

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

Limitation: Current PoCs note that MMU constraints may cause runtime memory modification to fault; payloads generally avoid live memory writes until this is resolved.

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
