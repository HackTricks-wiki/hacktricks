# MediaTek bl2_ext Secure-Boot Bypass（EL3 代码执行）

{{#include ../../banners/hacktricks-training.md}}

本页面记录了在多个 MediaTek 平台上，通过滥用设备 bootloader 配置（seccfg）处于“unlocked”状态时的验证缺口，实际突破 secure-boot 的方法。该缺陷允许在 ARM EL3 运行经过 patch 的 bl2_ext，从而禁用后续签名验证，破坏整条信任链，并允许加载任意未签名的 TEE/GZ/LK/Kernel。<sup>[[1]](#references)</sup>

> 注意：早期启动阶段的 patch 操作可能会在偏移错误时永久 brick 设备。务必保留完整 dump，并准备可靠的恢复路径。

## 受影响的启动流程（MediaTek）

- 正常路径：BootROM → Preloader → bl2_ext（EL3，已验证）→ TEE → GenieZone（GZ）→ LK/AEE → Linux kernel（EL1）
- 易受攻击路径：当 seccfg 设置为 unlocked 时，Preloader 可能会跳过对 bl2_ext 的验证。Preloader 仍会跳转到 EL3 中的 bl2_ext，因此经过构造的 bl2_ext 可以继续加载未经验证的组件。

关键的信任边界：
- bl2_ext 在 EL3 执行，负责验证 TEE、GenieZone、LK/AEE 和 kernel。如果 bl2_ext 本身未经过认证，后续整条链即可被轻易绕过。<sup>[[1]](#references)</sup>

## 根因

在受影响的设备上，当 seccfg 表示“unlocked”状态时，Preloader 不会强制验证 bl2_ext 分区。这允许刷入攻击者控制的、在 EL3 运行的 bl2_ext。

在 bl2_ext 内部，可以 patch 验证策略函数，使其无条件报告不需要验证（或始终验证成功），从而强制启动链接受未签名的 TEE/GZ/LK/Kernel 镜像。由于该 patch 在 EL3 执行，即使后续组件实现了自己的检查，也仍然有效。<sup>[[1]](#references)</sup>

## 实际 exploit chain

1. 通过 OTA/firmware 包、EDL/DA readback 或硬件 dumping 获取 bootloader 分区（Preloader、bl2_ext、LK/AEE 等）。
2. 定位 bl2_ext 验证例程，并将其 patch 为始终跳过或接受验证。
3. 使用 fastboot、DA 或其他在 unlocked 设备上仍可用的维护通道刷入修改后的 bl2_ext。
4. 重启；Preloader 在 EL3 跳转到经过 patch 的 bl2_ext，随后该组件会加载未签名的后续镜像（经过 patch 的 TEE/GZ/LK/Kernel），并禁用签名强制检查。<sup>[[1]](#references)</sup>

如果设备配置为 locked（seccfg locked），则预期 Preloader 会验证 bl2_ext。在这种配置下，除非存在其他允许加载未签名 bl2_ext 的漏洞，否则该攻击将失败。

## Triage（expdb 启动日志）

- Dump bl2_ext 加载前后的 boot/expdb 日志。如果 `img_auth_required = 0` 且证书验证耗时约为 0 ms，则很可能跳过了验证。<sup>[[1]](#references)</sup>

示例日志片段：
```
[PART] img_auth_required = 0
[PART] Image with header, name: bl2_ext, addr: FFFFFFFFh, mode: FFFFFFFFh, size:654944, magic:58881688h
[PART] part: lk_a img: bl2_ext cert vfy(0 ms)
```
- 一些设备即使处于锁定状态，也会跳过 bl2_ext verification；lk2 secondary bootloader 路径也出现过相同的缺口。如果 OTA 后的 Preloader 在设备解锁时记录 `img_auth_required = 1`（针对 bl2_ext），则很可能已恢复 enforcement。<sup>[[1]](#references)[[2]](#references)</sup>

## Verification logic locations

- 相关检查通常位于 bl2_ext image 内部，函数名称通常类似于 `verify_img` 或 `sec_img_auth`。
- patched version 会强制该函数返回 success，或完全绕过 verification call。<sup>[[1]](#references)</sup>

Example patch approach (conceptual):
- 定位在 TEE、GZ、LK 和 kernel images 上调用 `sec_img_auth` 的函数。
- 将其函数体替换为立即返回 success 的 stub，或覆写处理 verification failure 的 conditional branch。

确保 patch 保留 stack/frame setup，并向 callers 返回预期的 status codes。<sup>[[1]](#references)</sup>

## Fenrir PoC workflow（Nothing/CMF）

Fenrir 是针对该问题的 reference patching toolkit（完全支持 Nothing Phone (2a)；部分支持 CMF Phone 1）。<sup>[[1]](#references)</sup> High level:
- 将设备 bootloader image 放置为 `bin/<device>.bin`。
- 构建一个禁用 bl2_ext verification policy 的 patched image。
- Flash 生成的 payload（提供 fastboot helper）。
```bash
./build.sh pacman                    # build from bin/pacman.bin
./build.sh pacman /path/to/boot.bin  # build from a custom bootloader path
./flash.sh                           # flash via fastboot
```
在 fastboot 不可用时，使用其他 flashing channel。

## EL3 patching notes

- bl2_ext 在 ARM EL3 中执行。此处发生崩溃可能会导致设备变砖，直到通过 EDL/DA 或 test points 重新刷写。
- 使用特定于 board 的 logging/UART 验证执行路径并诊断崩溃。
- 备份所有正在修改的分区，并首先在可弃置的硬件上进行测试。<sup>[[1]](#references)</sup>

## Implications

- 在 Preloader 执行后获得 EL3 code execution，并使后续 boot path 的完整 chain-of-trust 失效。
- 能够启动 unsigned TEE/GZ/LK/Kernel，绕过 secure/verified boot 预期，并实现持久化 compromise。<sup>[[1]](#references)</sup>

## Device notes

- 已确认支持：Nothing Phone (2a) (Pacman)
- 已知可用（支持不完整）：CMF Phone 1 (Tetris)
- 观察结果：据报告，Vivo X80 Pro 即使处于 locked 状态，也不会验证 bl2_ext<sup>[[1]](#references)</sup>
- NothingOS 4 stable (BP2A.250605.031.A3, Nov 2025) 重新启用了 bl2_ext verification；fenrir `pacman-v2.0` 通过混合 beta Preloader 与 patched LK 恢复该 bypass<sup>[[3]](#references)</sup>
- 行业报道指出，其他基于 lk2 的 vendors 也在出厂产品中使用相同的 logic flaw，因此预计 2024–2025 年的 MTK releases 之间会有更多重叠。<sup>[[2]](#references)[[4]](#references)</sup>

## 使用 Penumbra 进行 MTK DA readback 和 seccfg manipulation

Penumbra 是一个 Rust crate/CLI/TUI，可通过 USB 自动化与 MTK preloader/bootrom 交互，以执行 DA-mode operations。在具备 physical access 且允许 DA extensions 的 vulnerable handset 上，它可以发现 MTK USB port、加载 Download Agent (DA) blob，并发出 seccfg lock flipping 和 partition readback 等 privileged commands。<sup>[[5]](#references)</sup>

- **Environment/driver setup**：在 Linux 上安装 `libudev`，将用户添加到 `dialout` group，并创建 udev rules；如果无法访问 device node，则使用 `sudo` 运行。Windows support 不可靠；根据项目 guidance，有时只有在使用 Zadig 将 MTK driver 替换为 WinUSB 后才能正常工作。
- **Workflow**：读取 DA payload（例如 `std::fs::read("../DA_penangf.bin")`），使用 `find_mtk_port()` 轮询 MTK port，并通过 `DeviceBuilder::with_mtk_port(...).with_da_data(...)` 构建 session。`init()` 完成 handshake 并收集 device info 后，通过 `dev_info.target_config()` bitfields 检查 protections（bit 0 被设置 → SBC enabled）。进入 DA mode 并尝试 `set_seccfg_lock_state(LockFlag::Unlock)`——只有在设备接受 extensions 时才会成功。可以使用 `read_partition("lk_a", &mut progress_cb, &mut writer)` dump partitions，以便进行 offline analysis 或 patching。
- **Security impact**：成功进行 seccfg unlocking 会重新开放 unsigned boot images 的 flashing paths，从而实现持久化 compromises，例如上述 bl2_ext EL3 patching。Partition readback 可提供用于 reverse engineering 和制作 modified images 的 firmware artifacts。

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

- [1] [Fenrir – MediaTek bl2_ext secure‑boot bypass (PoC)](https://github.com/R0rt1z2/fenrir)
- [2] [Cyber Security News – 针对 Nothing Phone 代码执行漏洞的 PoC Exploit 已发布](https://cybersecuritynews.com/nothing-phone-code-execution-vulnerability/)
- [3] [Fenrir pacman-v2.0 release (NothingOS 4 bypass bundle)](https://github.com/R0rt1z2/fenrir/releases/tag/pacman-v2.0)
- [4] [The Cyber Express – Fenrir PoC 破解 Nothing Phone 2a/CMF1 的 secure boot](https://thecyberexpress.com/fenrir-poc-for-nothing-phone-2a-cmf1/)
- [5] [Penumbra – MTK DA flash/readback & seccfg tooling](https://github.com/shomykohai/penumbra)

{{#include ../../banners/hacktricks-training.md}}
