# UEFI IFR 和 NVRAM 安全设置 Patching

{{#include ../../banners/hacktricks-training.md}}

设置密码可以保护 firmware 用户界面，但不一定会对存储在 SPI flash 中的配置字节进行身份验证。通过物理写入访问权限，评估人员可以将隐藏或锁定的 UEFI 设置从其 **Human Interface Infrastructure (HII) Internal Forms Representation (IFR)** 映射到对应的 NVRAM 变量，在离线状态下 patch 该值，然后重新刷写。在一台受影响的 Dell 系统上，这种方式更改了 pre-boot IOMMU 状态，而图形化设置界面仍显示 DMA protection 已启用。<sup>[[3]](#references)</sup>

> [!CAUTION]
> Firmware 写入可能会永久损坏目标设备。请在经过授权且可恢复的测试设备上操作；保留原始镜像；并在修改任何内容之前，至少获取三次独立读取结果，且确认其 cryptographic hashes 一致。<sup>[[3]](#references)</sup>

## 获取 firmware 镜像

当 Intel flash descriptor 允许主机访问时，仅读取 BIOS region；或者使用电压匹配的 external programmer 和 in-circuit clip。恢复无法启动的机器通常需要 external programmer。<sup>[[3]](#references)[[9]](#references)</sup>
```bash
flashrom -p internal -r dump.bin --ifd -i bios
sha256sum dump*.bin
```
不要假设 vendor update capsule 等同于芯片内容：它可能省略 NVRAM、包含封装，或经过加密。[UEFITool](https://github.com/LongSoft/UEFITool) 可以将原始 UEFI image 解析为 firmware volumes、files 和 sections。<sup>[[7]](#references)</sup>

## 将 IFR question 映射到 NVRAM

[IFRExtractor-RS](https://github.com/LongSoft/IFRExtractor-RS) 可将 HII form packages 转换为文本，并显示 vendor GUI 隐藏、重命名或抑制的设置。其输出可以识别 question、variable store、byte offset、storage width、有效值以及条件可见性。<sup>[[8]](#references)</sup>

1. 在 UEFITool 中打开 dump，搜索名为 `Setup` 的 firmware file，将其展开到 PE32 image section，然后使用 **Extract body**。
2. 对提取出的 EFI/PE32 body 运行 IFRExtractor-RS，然后在生成的文本中搜索 `DMA`、`IOMMU`、`VT-d`、`Secure Boot` 等 controls，或搜索 vendor-facing label。
3. 记录 `VarStoreId`、`VarOffset`、`Size`、有效选项和 question ID。不要仅根据 `Flags` 推断 value semantics。
4. 找到匹配的 `VarStore`/`VarStoreEfi` declaration，并将 numeric store ID 映射到其 variable **name 和 GUID**。
5. 在 UEFITool 中搜索该 GUID，直到找到对应的 NVRAM object。打开 **Body hex view**，并相对于 variable body 导航到 `VarOffset`，而不是相对于整个 flash image。<sup>[[3]](#references)</sup>
```bash
./ifrextractor Section_PE32_image_Setup_body.efi
rg -i 'dma|iommu|vt-d|secure boot' *.ifr.txt
```
例如，某个 Dell image 将相关问题描述为 `Control Iommu Pre-boot Behavior`，其 `VarStoreId: 0x1`、`VarOffset: 0x975`，并包含一个 8-bit 字段。Store `0x1` 映射到变量 `Setup` 和 GUID `EC87D643-EBA4-4BB5-A1E5-3F3E36B20DA9`；通过 differential dumps 确认，在该 firmware 中，`01` 表示 enabled，`00` 表示 disabled。<sup>[[3]](#references)</sup>

> [!WARNING]
> GUID、offset、structure layout、duplicate variable instance 以及 value encoding 可能因型号和 firmware 版本而变化。不要将示例 offset 作为通用的 Dell value 重复使用。

## 使用 differential dumps 验证

当等效 test unit 上可以使用 setup interface 时，分别在 enabled 和 disabled 状态下创建一个 dump。比较由 IFR 派生的 variable body，并确认只有预期字段发生变化。这样可以确定实际 encoding，并区分 active variable 与 stale/default/recovery copies。在已验证的原始 image 副本上执行 patch，重新在 UEFITool 中打开，并在 reflash 前确认编辑位置位于 authenticated 或 measured code ranges 之外。<sup>[[3]](#references)[[4]](#references)</sup>

与清除 firmware password 相比，targeted edit 可能产生更少的副作用；清除 firmware password 可能使设备进入 factory state、要求重新输入 device-specific data，或改变 TPM PCR measurements。然而，targeted offline edit 也可能造成危险的 **displayed-state/effective-state divergence**：UI 和 management tooling 可能显示旧值，而 early firmware 实际使用的是 patched byte。该示例中的 change 没有请求 BitLocker recovery，并且在 vendor BIOS update 后仍然保留，因为该 update 保留了被修改的 NVRAM state。<sup>[[3]](#references)</sup>

作者的 [Dell UEFI Patcher](https://github.com/craigsblackie/Dell_UEFI_Patcher) 展示了一个 model-specific patcher：它能够发现 Intel Boot Guard Initial Boot Block ranges，并拒绝在其中执行 normal writes。在使用 `--apply` 前，先使用其 analysis mode，检查每个 candidate match，并将其 defaults 视为示例，而不是可移植的 offsets。<sup>[[4]](#references)</sup>
```bash
python3 dell_bios_patcher.py bios_dump.bin
python3 dell_bios_patcher.py bios_dump.bin patched.bin --apply
```
## 使用 NVRAMap 自动完成映射

[NVRAMap](https://github.com/PN-Tester/NVRAMap) 可自动执行 IFR 提取，将问题的 `VarStoreId` 解析为 NVRAM GUID/名称，显示当前选项值，并编辑选定字段。它既可以处理完整的 firmware dump，也可以处理分别提取的 EFI 和 NVRAM blobs。<sup>[[5]](#references)</sup>
```bash
# EFI question -> backing NVRAM value
python3 NVRAMap.py -mode 1 -firmware dump.bin -terms DMA,IOMMU --dump-ifr ifr.txt

# Interactive editor after reviewing the mapping
python3 NVRAMap.py -mode 1 -firmware dump.bin -terms DMA,IOMMU --modify
```
自动化并不能消除对匹配转储、恢复硬件、区域完整性检查或刷写后验证的需求。

## 将 pre-boot IOMMU downgrade 链接到 Windows DMA 访问

如果 patched value 允许在 ExitBootServices 之前进行 PCIe DMA，[DMAReaper](https://github.com/PN-Tester/DMAReaper) 可以从 EFI System Table 遍历 ACPI root tables，定位 `DMAR` table，并在 Windows 解析之前将其覆盖。没有可用的 DMAR 数据时，Windows 可能无法初始化基于 IOMMU 的 Kernel DMA Protection。DMAReaper 本身**不会**禁用 VBS/HVCI。<sup>[[1]](#references)</sup>

在演示的 chain 中，目标随后以 Safe Mode 启动，以移除剩余的 VBS barrier；然后使用 [PCILeech](https://github.com/ufrisk/pcileech) 通过 Sticky Keys signature patch 了物理内存：<sup>[[2]](#references)[[3]](#references)</sup>
```bash
sudo ./pcileech patch -sig stickykeys_cmd_win
```
在成功完成与构建兼容的 patch 后，在 Windows 登录屏幕上调用 Sticky Keys 会以 `NT AUTHORITY\SYSTEM` 身份启动命令提示符。签名和可访问的内存范围取决于目标、构建版本和硬件；报告中的匹配结果并不意味着每个 Windows 版本都可被 exploit。<sup>[[2]](#references)[[3]](#references)</sup>

不要将 firmware 菜单视为验证依据。检查 **System Information (`msinfo32.exe`) → Kernel DMA Protection**，单独验证 VBS，检查 OS 是否接收到有效的 DMAR 表，并测试实际的 DMA 可达性。只有在平台和 firmware 支持所需的 IOMMU 配置时，Windows 才会报告 Kernel DMA Protection。<sup>[[6]](#references)</sup>

## References

- [1] [DMAReaper - 通过 pre-boot DMAR 覆盖禁用 Kernel DMA Protection](https://github.com/PN-Tester/DMAReaper)
- [2] [PCILeech - Direct Memory Access 攻击软件](https://github.com/ufrisk/pcileech)
- [3] [MDSec - 在锁定的 BIOS 中禁用安全功能](https://mdsec.co.uk/2026/03/disabling-security-features-in-a-locked-bios)
- [4] [Dell UEFI Patcher - 支持 IBB 的 NVRAM patching](https://github.com/craigsblackie/Dell_UEFI_Patcher)
- [5] [NVRAMap - 将 EFI 设置映射到 NVRAM 值](https://github.com/PN-Tester/NVRAMap)
- [6] [Microsoft Learn - Kernel DMA Protection](https://learn.microsoft.com/en-us/windows/security/hardware-security/kernel-dma-protection-for-thunderbolt)
- [7] [UEFITool - UEFI firmware 镜像查看器和解析器](https://github.com/LongSoft/UEFITool)
- [8] [IFRExtractor-RS - 将 UEFI IFR 提取为人类可读文本](https://github.com/LongSoft/IFRExtractor-RS)
- [9] [flashrom manual - programmers 以及读写操作](https://flashrom.org/classic_cli_manpage.html)
{{#include ../../banners/hacktricks-training.md}}
