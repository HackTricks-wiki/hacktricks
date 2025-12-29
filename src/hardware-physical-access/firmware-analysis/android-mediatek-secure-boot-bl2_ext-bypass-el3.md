# MediaTek bl2_ext Secure-Boot Bypass (EL3 Code Execution)

{{#include ../../banners/hacktricks-training.md}}

本页面记录了在多个 MediaTek 平台上利用 bootloader 配置 (seccfg) 处于 "unlocked" 时的验证缺口实施的实际 secure-boot break。该漏洞允许在 ARM EL3 上运行被篡改的 bl2_ext 来禁用后续的签名验证，瓦解信任链并使任意未签名的 TEE/GZ/LK/Kernel 加载成为可能。

> 注意：早期引导阶段打补丁如果偏移错误可能会永久使设备变砖。务必保留完整转储并确保可靠的恢复路径。

## Affected boot flow (MediaTek)

- 正常路径: BootROM → Preloader → bl2_ext (EL3, verified) → TEE → GenieZone (GZ) → LK/AEE → Linux kernel (EL1)
- 易受攻击的路径: 当 seccfg 被设置为 unlocked 时，Preloader 可能会跳过对 bl2_ext 的验证。Preloader 仍然会在 EL3 跳转到 bl2_ext，因此构造的 bl2_ext 可以随后加载未经验证的组件。

关键的信任边界：
- bl2_ext 在 EL3 执行，负责验证 TEE、GenieZone、LK/AEE 及内核。如果 bl2_ext 本身未被认证，剩余的链条可以被轻易绕过。

## Root cause

在受影响的设备上，当 seccfg 显示为 "unlocked" 状态时，Preloader 不会强制对 bl2_ext 分区进行认证。这允许刷入由攻击者控制的 bl2_ext 并在 EL3 上运行。

在 bl2_ext 内，验证策略函数可以被打补丁为无条件报告不需要验证。一个最小的概念性补丁如下：
```c
// inside bl2_ext
int sec_get_vfy_policy(...) {
return 0; // always: "no verification required"
}
```
通过此修改，当在 EL3 运行的已打补丁 bl2_ext 加载后续镜像（TEE、GZ、LK/AEE、Kernel）时，这些镜像将无需加密校验即被接受。

## 如何评估目标（expdb 日志）

转储/检查 bl2_ext 加载前后的引导日志（例如 expdb）。如果 img_auth_required = 0 且证书验证时间约为 ~0 ms，则签名强制可能已被关闭，设备可能可被利用。

示例日志摘录：
```
[PART] img_auth_required = 0
[PART] Image with header, name: bl2_ext, addr: FFFFFFFFh, mode: FFFFFFFFh, size:654944, magic:58881688h
[PART] part: lk_a img: bl2_ext cert vfy(0 ms)
```
注意：据报道，一些设备即便在锁定的 bootloader 情况下也会跳过 bl2_ext 验证，这会加剧影响。

配备 lk2 次级 bootloader 的设备也被观察到存在相同的逻辑漏洞，因此在尝试移植之前，请获取 bl2_ext 和 lk2 分区的 expdb 日志，以确认任一路径是否会强制执行签名。

## 实际利用工作流程 (Fenrir PoC)

Fenrir 是针对这类问题的参考 exploit/patching toolkit。它支持 Nothing Phone (2a) (Pacman)，并且已知可在 CMF Phone 1 (Tetris) 上工作（支持不完全）。将其移植到其他型号需要对设备特定的 bl2_ext 进行逆向工程。

高层流程：
- 获取目标代号对应的设备 bootloader 镜像，并将其放置为 `bin/<device>.bin`
- 构建一个禁用 bl2_ext 验证策略的修补镜像
- 将生成的 payload 刷写到设备上（helper 脚本假定使用 fastboot）

命令：
```bash
# Build patched image (default path bin/[device].bin)
./build.sh pacman

# Build from a custom bootloader path
./build.sh pacman /path/to/your/bootloader.bin

# Flash the resulting lk.patched (fastboot required by the helper script)
./flash.sh
```
如果 fastboot 不可用，必须为你的平台使用合适的替代 flashing 方法。

### 构建自动化 & payload 调试

- `build.sh` 现在会在首次运行时自动下载并导出 Arm GNU Toolchain 14.2 (aarch64-none-elf)，因此你不必手动切换交叉编译器。
- 在调用 `build.sh` 之前导出 `DEBUG=1`，以便编译 payloads 并启用详细的串口打印，这在你对 EL3 代码路径进行盲补丁时非常有帮助。
- 成功构建会生成 `lk.patched` 和 `<device>-fenrir.bin`；后者已注入 payload，应用于 flash/boot-test。

## 运行时 payload 功能 (EL3)

被修补的 bl2_ext payload 可以：
- 注册自定义 fastboot 命令
- 控制/覆盖 boot 模式
- 在运行时动态调用内置 bootloader 函数
- 欺骗 “lock state”为 locked（实际为 unlocked）以通过更严格的完整性检查（某些环境仍可能需要 vbmeta/AVB 调整）

限制：当前 PoCs 指出，由于 MMU 限制，运行时内存修改可能导致 fault；在该问题解决之前，payloads 通常避免实时内存写入。

## Payload staging patterns (EL3)

Fenrir 将其插桩分为三个编译时阶段：stage1 在 `platform_init()` 之前运行，stage2 在 LK 发出 fastboot 进入信号之前运行，stage3 在 LK 加载 Linux 之前立即执行。每个位于 `payload/devices/` 下的设备头文件提供了这些 hooks 的地址以及 fastboot helper 符号，因此请确保这些偏移量与你的目标构建保持同步。

Stage2 是注册任意 `fastboot oem` 动词的方便位置：
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
因为 stage1 在平台启动（platform bring-up）之前就会执行，所以这是在 verified boot 链被拆除前调用 OEM 电源/复位 primitives 或插入额外完整性日志记录的合适位置。

## Porting tips

- 逆向设备特定的 bl2_ext 以定位验证策略逻辑（例如 sec_get_vfy_policy）。
- 找到策略返回点或决策分支并将其补丁为“无需验证”（return 0 / unconditional allow）。
- 保持偏移完全针对具体设备和固件；不要在不同变体间重用地址。
- 首先在一台牺牲单元上验证。在刷写之前准备恢复计划（例如 EDL/BootROM loader/SoC-specific download mode）。
- 使用 lk2 作为 secondary bootloader 的设备，或在锁定状态下仍然报告 bl2_ext 的 “img_auth_required = 0” 的设备，应视为该类漏洞的易受影响副本；已观察到 Vivo X80 Pro 即便报告为已锁定也跳过了验证。
- 比较锁定与解锁状态下的 expdb 日志 —— 如果在重新上锁后证书计时从 0 ms 跳到非零值，你很可能补丁了正确的决策点，但仍需增强锁态伪装以隐藏修改。

## Security impact

- 在 Preloader 之后获得 EL3 代码执行，并导致引导路径其余部分的完整信任链完全崩溃。
- 能够引导未签名的 TEE/GZ/LK/Kernel，绕过 secure/verified boot 的期望并实现持久性妥协。

## Device notes

- Confirmed supported: Nothing Phone (2a) (Pacman)
- Known working (incomplete support): CMF Phone 1 (Tetris)
- Observed: Vivo X80 Pro reportedly did not verify bl2_ext even when locked
- 行业覆盖显示更多基于 lk2 的厂商存在相同逻辑缺陷，因此预计在 2024–2025 年的更多 MTK 版本中会有进一步重叠。

## References

- [Fenrir – MediaTek bl2_ext secure‑boot bypass (PoC)](https://github.com/R0rt1z2/fenrir)
- [Cyber Security News – PoC Exploit Released For Nothing Phone Code Execution Vulnerability](https://cybersecuritynews.com/nothing-phone-code-execution-vulnerability/)

{{#include ../../banners/hacktricks-training.md}}
