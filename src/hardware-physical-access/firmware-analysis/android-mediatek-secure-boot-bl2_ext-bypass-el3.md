# MediaTek bl2_ext Secure-Boot Bypass (EL3 Code Execution)

{{#include ../../banners/hacktricks-training.md}}

本页记录了在多个 MediaTek 平台上利用 bootloader 配置 (seccfg) 为“unlocked”时的验证缺口进行实际 secure-boot 绕过的过程。该漏洞允许在 ARM EL3 上运行被修改的 bl2_ext，从而禁用下游签名验证，破坏信任链并允许加载任意未签名的 TEE/GZ/LK/Kernel。

> 警告：在早期引导阶段打补丁如果偏移错误可能会永久使设备变砖。始终保留完整转储和可靠的恢复路径。

## Affected boot flow (MediaTek)

- Normal path: BootROM → Preloader → bl2_ext (EL3, verified) → TEE → GenieZone (GZ) → LK/AEE → Linux kernel (EL1)
- Vulnerable path: When seccfg is set to unlocked, Preloader may skip verifying bl2_ext. Preloader still jumps into bl2_ext at EL3, so a crafted bl2_ext can load unverified components thereafter.

关键信任边界：
- bl2_ext 在 EL3 运行并负责验证 TEE、GenieZone、LK/AEE 以及内核。如果 bl2_ext 本身未被认证，后续的信任链即可被轻易绕过。

## Root cause

在受影响的设备上，当 seccfg 指示为 “unlocked” 状态时，Preloader 不会强制对 bl2_ext 分区进行认证。这允许刷入受攻击者控制的 bl2_ext 并在 EL3 上运行。

在 bl2_ext 内，验证策略函数可以被打补丁，使其无条件报告不需要验证（或总是返回成功），强制引导链接受未签名的 TEE/GZ/LK/Kernel 镜像。因为该补丁在 EL3 运行，即使下游组件自身也实现了检查，这个绕过仍然有效。

## Practical exploit chain

1. 通过 OTA/firmware packages、EDL/DA 读回或硬件转储获取 bootloader 分区（Preloader、bl2_ext、LK/AEE 等）。
2. 定位 bl2_ext 的验证例程并打补丁，使其始终跳过/接受验证。
3. 使用 fastboot、DA 或在 unlocked 设备上仍被允许的类似维护通道刷写修改后的 bl2_ext。
4. 重启；Preloader 跳转到被修改的 bl2_ext（EL3），随后加载未签名的下游镜像（修改过的 TEE/GZ/LK/Kernel），并禁用签名强制执行。

如果设备配置为 locked（seccfg locked），Preloader 预计会验证 bl2_ext。在该配置下，除非存在其他漏洞允许加载未签名的 bl2_ext，否则此攻击将失败。

## Triage (expdb boot logs)

- 在 bl2_ext 加载周围转储 boot/expdb 日志。如果 `img_auth_required = 0` 且证书验证时间约为 ~0 ms，则很可能跳过了验证。

Example log excerpt:
```
[PART] img_auth_required = 0
[PART] Image with header, name: bl2_ext, addr: FFFFFFFFh, mode: FFFFFFFFh, size:654944, magic:58881688h
[PART] part: lk_a img: bl2_ext cert vfy(0 ms)
```
- 一些设备即便已锁定也会跳过 bl2_ext 验证；lk2 的 secondary bootloader 路径也显示出同样的缺口。如果 post-OTA Preloader 在已解锁状态下记录了 `img_auth_required = 1` 对 bl2_ext，说明强制执行很可能已恢复。

## Verification logic locations

- 相关检查通常位于 bl2_ext 镜像内部，函数名类似于 `verify_img` 或 `sec_img_auth`。
- 被修补的版本会强制该函数返回成功，或完全绕过验证调用。

Example patch approach (conceptual):
- 定位调用 `sec_img_auth` 对 TEE、GZ、LK 和 kernel 镜像进行验证的函数。
- 将其函数体替换为立即返回成功的存根，或覆盖处理验证失败的条件分支。

确保补丁保留栈/帧设置并向调用者返回预期的状态码。

## Fenrir PoC workflow (Nothing/CMF)

Fenrir 是针对该问题的参考修补工具集（Nothing Phone (2a) 完全支持；CMF Phone 1 部分支持）。总体流程：
- 将设备 bootloader 镜像放为 `bin/<device>.bin`。
- 构建一个禁用 bl2_ext 验证策略的已修补镜像。
- 刷写生成的 payload（提供 fastboot helper）。
```bash
./build.sh pacman                    # build from bin/pacman.bin
./build.sh pacman /path/to/boot.bin  # build from a custom bootloader path
./flash.sh                           # flash via fastboot
```
Use another flashing channel if fastboot is unavailable.

## EL3 patching notes

- bl2_ext executes in ARM EL3. Crashes here can brick a device until reflashed via EDL/DA or test points.
- 使用板级特定的 logging/UART 来验证执行路径并诊断崩溃。
- 保留所有被修改分区的备份，并首先在可丢弃的硬件上进行测试。

## Implications

- 在 Preloader 之后实现 EL3 代码执行，将导致剩余引导路径的完整信任链坍塌。
- 能够引导未签名的 TEE/GZ/LK/Kernel，绕过 secure/verified boot 的预期并实现持久妥协。

## Device notes

- 已确认支持：Nothing Phone (2a) (Pacman)
- 已知可工作（支持不完整）：CMF Phone 1 (Tetris)
- 观察到：据报道 Vivo X80 Pro 即使在锁定状态也不验证 bl2_ext
- NothingOS 4 stable (BP2A.250605.031.A3, Nov 2025) 重新启用 bl2_ext 验证；fenrir `pacman-v2.0` 通过将 beta Preloader 与已修补的 LK 混合来恢复该绕过
- 行业报道指出还有更多基于 lk2 的厂商带有相同的逻辑缺陷，因此预计 2024–2025 年的 MTK 版本会有更多重叠。

## MTK DA readback and seccfg manipulation with Penumbra

Penumbra is a Rust crate/CLI/TUI that automates interaction with MTK preloader/bootrom over USB for DA-mode operations. 在对易受影响的手持设备具有物理访问权限（允许 DA extensions）时，它可以发现 MTK USB 端口、加载 Download Agent (DA) blob，并发出特权命令，例如 seccfg 锁状态翻转和分区读回。

- **Environment/driver setup**: 在 Linux 上安装 `libudev`，将用户加入 `dialout` 组，并创建 udev 规则或在设备节点不可访问时使用 `sudo` 运行。Windows 支持不可靠；有时只有在使用 Zadig 将 MTK 驱动替换为 WinUSB 后才可工作（参见项目说明）。
- **Workflow**: 读取 DA 有效载荷（例如 `std::fs::read("../DA_penangf.bin")`），使用 `find_mtk_port()` 轮询 MTK 端口，并使用 `DeviceBuilder::with_mtk_port(...).with_da_data(...)` 构建会话。在 `init()` 完成握手并收集设备信息后，通过 `dev_info.target_config()` 的位字段检查保护（位 0 被设置 → SBC 已启用）。进入 DA 模式并尝试 `set_seccfg_lock_state(LockFlag::Unlock)`——只有在设备接受 extensions 时此操作才会成功。可以使用 `read_partition("lk_a", &mut progress_cb, &mut writer)` 将分区导出以便离线分析或修补。
- **Security impact**: 成功解除 seccfg 锁定会重新打开对未签名引导镜像的刷写路径，从而使如上所述的 bl2_ext EL3 打补丁之类的持久性妥协成为可能。分区读回提供了用于逆向工程和制作修改镜像的固件工件。

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

## 参考资料

- [Fenrir – MediaTek bl2_ext secure‑boot bypass (PoC)](https://github.com/R0rt1z2/fenrir)
- [Cyber Security News – PoC Exploit Released For Nothing Phone Code Execution Vulnerability](https://cybersecuritynews.com/nothing-phone-code-execution-vulnerability/)
- [Fenrir pacman-v2.0 release (NothingOS 4 bypass bundle)](https://github.com/R0rt1z2/fenrir/releases/tag/pacman-v2.0)
- [The Cyber Express – Fenrir PoC breaks secure boot on Nothing Phone 2a/CMF1](https://thecyberexpress.com/fenrir-poc-for-nothing-phone-2a-cmf1/)
- [Penumbra – MTK DA flash/readback & seccfg tooling](https://github.com/shomykohai/penumbra)

{{#include ../../banners/hacktricks-training.md}}
