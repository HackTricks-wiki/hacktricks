# MediaTek bl2_ext Secure-Boot Bypass (EL3 Code Execution)

{{#include ../../banners/hacktricks-training.md}}

本页面记录了在多款 MediaTek 平台上通过滥用当设备 bootloader 配置 (seccfg) 处于“unlocked”时的验证缺口来进行的一个实际 secure-boot 绕过。该缺陷允许在 ARM EL3 上运行经过修补的 bl2_ext 以禁用后续的签名验证，从而破坏信任链并允许任意未签名的 TEE/GZ/LK/Kernel 被加载。

> 警告：早期引导阶段打补丁如果偏移量错误可能会永久性使设备变砖。务必保留完整的转储并准备可靠的恢复路径。

## Affected boot flow (MediaTek)

- Normal path: BootROM → Preloader → bl2_ext (EL3, verified) → TEE → GenieZone (GZ) → LK/AEE → Linux kernel (EL1)
- Vulnerable path: When seccfg is set to unlocked, Preloader may skip verifying bl2_ext. Preloader still jumps into bl2_ext at EL3, so a crafted bl2_ext can load unverified components thereafter.

关键信任边界：
- bl2_ext 在 EL3 执行，并负责验证 TEE、GenieZone、LK/AEE 和 kernel。如果 bl2_ext 本身未被认证，其余链条就可以被轻易绕过。

## Root cause

在受影响的设备上，当 seccfg 表示为 “unlocked” 状态时，Preloader 不会强制对 bl2_ext 分区进行认证。这允许刷入一个由攻击者控制的 bl2_ext 并在 EL3 运行。

在 bl2_ext 内，可以对验证策略函数进行补丁，使其无条件地报告不需要验证。一个最小的概念性补丁是：
```c
// inside bl2_ext
int sec_get_vfy_policy(...) {
return 0; // always: "no verification required"
}
```
有了这个更改，由运行在 EL3 的补丁 bl2_ext 加载的所有后续镜像（TEE、GZ、LK/AEE、Kernel）在加载时都会被接受，且不会进行加密校验。

## 如何评估目标（expdb 日志）

导出/检查 bl2_ext 加载前后的启动日志（例如 expdb）。如果 img_auth_required = 0 并且证书验证时间约为 ~0 ms，则表明强制检查很可能被关闭，设备可能可被利用。

示例日志摘录：
```
[PART] img_auth_required = 0
[PART] Image with header, name: bl2_ext, addr: FFFFFFFFh, mode: FFFFFFFFh, size:654944, magic:58881688h
[PART] part: lk_a img: bl2_ext cert vfy(0 ms)
```
注意：据报告，一些设备即使在锁定 bootloader 的情况下仍会跳过 bl2_ext 验证，这加剧了影响。

## 实用利用工作流程 (Fenrir PoC)

Fenrir 是一个针对该类问题的参考 exploit/patching 工具包。它支持 Nothing Phone (2a) (Pacman)，并且已知在 CMF Phone 1 (Tetris) 上可运行（支持不完整）。移植到其他型号需要对设备特定的 bl2_ext 进行 reverse engineering。

高级流程：
- 获取目标 codename 设备的 bootloader 镜像，并将其放置为 bin/<device>.bin
- 构建一个禁用 bl2_ext 验证策略的 patched image
- 将生成的 payload 刷入设备（helper 脚本假定使用 fastboot）

命令：
```bash
# Build patched image (default path bin/[device].bin)
./build.sh pacman

# Build from a custom bootloader path
./build.sh pacman /path/to/your/bootloader.bin

# Flash the resulting lk.patched (fastboot required by helper script)
./flash.sh
```
If fastboot is unavailable, you must use a suitable alternative flashing method for your platform.

## 运行时 payload 能力 (EL3)

A patched bl2_ext payload can:
- 注册自定义 fastboot 命令
- 控制/覆盖启动模式
- 在运行时动态调用内建 bootloader 函数
- 欺骗 “lock state”为 locked（实际上为 unlocked）以通过更严格的完整性检查（某些环境仍可能需要对 vbmeta/AVB 进行调整）

Limitation: Current PoCs note that runtime memory modification may fault due to MMU constraints; payloads generally avoid live memory writes until this is resolved.

## 移植提示

- 对设备特定的 bl2_ext 进行逆向工程以定位验证策略逻辑（例如 sec_get_vfy_policy）。
- 确定策略的返回位置或决策分支，并将其补丁为 “no verification required”（return 0 / unconditional allow）。
- 保持偏移完全针对设备和固件；不要在不同变体间重用地址。
- 先在牺牲性设备上验证。刷写前准备恢复方案（例如 EDL/BootROM loader/SoC-specific download mode）。

## 安全影响

- 在 Preloader 之后执行 EL3 代码，并导致后续启动路径的完整信任链完全崩溃。
- 能够启动未签名的 TEE/GZ/LK/Kernel，绕过 secure/verified boot 的预期，从而实现持久性妥协。

## 检测与加固建议

- 确保 Preloader 无论 seccfg 状态如何都验证 bl2_ext。
- 强制执行认证结果并收集审计证据（timings > 0 ms，对不匹配给出严格错误）。
- 应使 lock-state 欺骗对于 attestation 无效（将 lock state 绑定到 AVB/vbmeta 的验证决策和 fuse-backed 状态）。

## 设备说明

- 已确认支持：Nothing Phone (2a) (Pacman)
- 已知可行（支持不完整）：CMF Phone 1 (Tetris)
- 观测到：据报 Vivo X80 Pro 即使在 locked 时也未验证 bl2_ext

## References

- [Fenrir – MediaTek bl2_ext secure‑boot bypass (PoC)](https://github.com/R0rt1z2/fenrir)

{{#include ../../banners/hacktricks-training.md}}
