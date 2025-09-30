# Analiza firmvera

{{#include ../../banners/hacktricks-training.md}}

## **Uvod**

### Povezani resursi


{{#ref}}
synology-encrypted-archive-decryption.md
{{#endref}}

{{#ref}}
../../network-services-pentesting/32100-udp-pentesting-pppp-cs2-p2p-cameras.md
{{#endref}}


Firmver je osnovni softver koji omogućava uređajima da pravilno funkcionišu tako što upravlja i olakšava komunikaciju između hardverskih komponenti i softvera sa kojim korisnici interaguju. Smešten je u trajnoj memoriji, što osigurava da uređaj može pristupiti ključnim instrukcijama od trenutka uključenja, vodeći do pokretanja operativnog sistema. Ispitivanje i eventualna modifikacija firmvera predstavlja ključni korak u otkrivanju bezbednosnih ranjivosti.

## **Prikupljanje informacija**

**Prikupljanje informacija** je kritični početni korak u razumevanju sastava uređaja i tehnologija koje koristi. Ovaj proces obuhvata sakupljanje podataka o:

- CPU arhitekturi i operativnom sistemu koji pokreće uređaj
- specifikacijama bootloader-a
- rasporedu hardvera i datasheet-ovima
- metriki codebase-a i lokacijama izvornog koda
- eksternim bibliotekama i tipovima licenci
- istoriji ažuriranja i regulatornim sertifikatima
- arhitektonskim i flow dijagramima
- bezbednosnim procenama i identifikovanim ranjivostima

Za ovu svrhu, alati za **open-source intelligence (OSINT)** su neprocenjivi, kao i analiza dostupnih open-source softverskih komponenti kroz manuelne i automatizovane procese pregleda. Alati kao što su [Coverity Scan](https://scan.coverity.com) i [Semmle’s LGTM](https://lgtm.com/#explore) nude besplatnu statičku analizu koja se može iskoristiti za pronalaženje potencijalnih problema.

## **Preuzimanje firmvera**

Dobijanje firmvera može se pristupiti na različite načine, svaki sa sopstvenim nivoom složenosti:

- **Direktno** od izvora (developer-i, proizvođači)
- **Sastavljanje** iz datih instrukcija
- **Preuzimanje** sa zvaničnih support sajtova
- Korišćenjem **Google dork** upita za pronalaženje hostovanih firmware fajlova
- Direktnim pristupom **cloud storage**, sa alatima poput [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Presretanjem **updates** putem man-in-the-middle tehnika
- **Ekstrakcijom** sa uređaja putem konekcija kao što su **UART**, **JTAG**, ili **PICit**
- **Snimanjem** update zahteva u komunikaciji uređaja
- Pronalaženjem i korišćenjem **hardcoded update endpoints**
- **Dump-ovanjem** iz bootloader-a ili mreže
- **Uklanjanjem i očitavanjem** čipa za skladištenje, kada sve ostalo zakaže, koristeći odgovarajuće hardverske alate

## Analiza firmvera

Sada kada **imate firmver**, potrebno je izvući informacije o njemu da biste znali kako da ga tretirate. Različiti alati koje možete koristiti za to:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
Ako ne nađete mnogo rezultata tim alatima, proverite **entropy** image-a sa `binwalk -E <bin>`; ako je entropy nizak, verovatno nije encrypted. Ako je entropy visok, verovatno je encrypted (ili na neki način compressed).

Pored toga, ove alate možete koristiti za ekstrakciju **files embedded inside the firmware**:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Ili [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) za pregled fajla.

### Dobijanje filesystem-a

Korišćenjem prethodno pomenutih alata kao što je `binwalk -ev <bin>` trebalo bi da budete u mogućnosti da **extract the filesystem**.\
Binwalk obično izdvaja sadržaj u **folder nazvan po tipu filesystem-a**, koji obično bude jedan od sledećih: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Ručna ekstrakcija filesystem-a

Ponekad binwalk neće imati **magic byte of the filesystem in its signatures**. U tim slučajevima, koristite binwalk da **find the offset of the filesystem and carve the compressed filesystem** iz binarne datoteke i **manually extract** filesystem prema njegovom tipu koristeći korake ispod.
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
Pokrenite sledeću **dd command** koja vrši carving Squashfs filesystem-a.
```
$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs

8257536+0 records in

8257536+0 records out

8257536 bytes (8.3 MB, 7.9 MiB) copied, 12.5777 s, 657 kB/s
```
Alternativno, sledeća komanda se takođe može izvršiti.

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

- Za squashfs (korišćen u primeru iznad)

`$ unsquashfs dir.squashfs`

Fajlovi će se nalaziti u direktorijumu `squashfs-root` nakon toga.

- CPIO arhive

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- Za jffs2 datotečne sisteme

`$ jefferson rootfsfile.jffs2`

- Za ubifs datotečne sisteme sa NAND flash-om

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Analiza firmvera

Kada se firmware dobije, važno ga je rastaviti kako bi se razumela njegova struktura i potencijalne ranjivosti. Ovaj proces podrazumeva korišćenje raznih alata za analizu i ekstrakciju korisnih podataka iz firmware image-a.

### Početni alati za analizu

Daje se skup komandi za početni pregled binarnog fajla (označenog kao `<bin>`). Ove komande pomažu u identifikaciji tipova fajlova, izdvajanja stringova, analizi binarnih podataka i razumevanju particija i detalja fajl-sistema:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
Da bi se procenio status enkripcije image-a, proverava se **entropija** pomoću `binwalk -E <bin>`. Niska entropija ukazuje na odsustvo enkripcije, dok visoka entropija sugeriše moguću enkripciju ili kompresiju.

Za izdvajanje **ugrađenih fajlova**, preporučuju se alati i resursi kao što su dokumentacija **file-data-carving-recovery-tools** i **binvis.io** za inspekciju fajlova.

### Izdvajanje datotečnog sistema

Korišćenjem `binwalk -ev <bin>` obično se može izdvojiti datotečni sistem, često u direktorijum nazvan prema tipu datotečnog sistema (npr. squashfs, ubifs). Međutim, kada **binwalk** ne uspe da prepozna tip datotečnog sistema zbog nedostajućih magic bytes, neophodno je ručno izdvajanje. To podrazumeva korišćenje `binwalk` za pronalaženje offseta datotečnog sistema, a zatim komande `dd` za izdvajanje datotečnog sistema:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
Nakon toga, u zavisnosti od tipa datotečnog sistema (npr. squashfs, cpio, jffs2, ubifs), koriste se različite komande za ručno izdvajanje sadržaja.

### Analiza datotečnog sistema

Kada je datotečni sistem izdvojen, započinje potraga za sigurnosnim propustima. Obratite pažnju na nesigurne mrežne daemone, hardkodovane kredencijale, API endpoints, funkcionalnosti update servera, nekompajlirani kod, startup scripts i kompajlirane binarne fajlove za offline analizu.

**Ključne lokacije** i **stavke** koje treba pregledati uključuju:

- **etc/shadow** i **etc/passwd** za korisničke kredencijale
- SSL sertifikati i ključevi u **etc/ssl**
- Konfiguracioni i skript fajlovi za potencijalne ranjivosti
- Ugrađeni binarni fajlovi za dalju analizu
- Uobičajeni IoT device web serveri i binarni fajlovi

Nekoliko alata pomaže u otkrivanju osetljivih informacija i ranjivosti unutar datotečnog sistema:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) i [**Firmwalker**](https://github.com/craigz28/firmwalker) za pretragu osetljivih informacija
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) za sveobuhvatnu analizu firmvera
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go), i [**EMBA**](https://github.com/e-m-b-a/emba) za statičku i dinamičku analizu

### Sigurnosne provere kompajliranih binarnih fajlova

I izvorni kod i kompajlirani binarni fajlovi pronađeni u datotečnom sistemu moraju biti pažljivo pregledani zbog ranjivosti. Alati poput **checksec.sh** za Unix binarne i **PESecurity** za Windows binarne pomažu u identifikaciji nezaštićenih binarnih fajlova koji bi mogli biti iskorišćeni.

## Emulacija firmvera za dinamičku analizu

Proces emulacije firmvera omogućava **dynamic analysis** rada uređaja ili pojedinačnog programa. Ovaj pristup može naići na probleme zbog hardverskih ili arhitektonskih zavisnosti, ali prebacivanje root datotečnog sistema ili specifičnih binarnih fajlova na uređaj sa odgovarajućom arhitekturom i redosledom bajtova (endianness), kao što je Raspberry Pi, ili na unapred pripremljenu virtuelnu mašinu, može olakšati dalja testiranja.

### Emulacija pojedinačnih binarnih fajlova

Za ispitivanje pojedinačnih programa, ključno je identifikovati redosled bajtova (endianness) programa i CPU arhitekturu.

#### Primer za MIPS arhitekturu

Za emulaciju MIPS arhitekture binarnog fajla može se koristiti komanda:
```bash
file ./squashfs-root/bin/busybox
```
I da instalirate neophodne alate za emulaciju:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
For MIPS (big-endian), `qemu-mips` is used, and for little-endian binaries, `qemu-mipsel` would be the choice.

#### Emulacija ARM arhitekture

Za ARM binarne fajlove proces je sličan — za emulaciju se koristi emulator `qemu-arm`.

### Emulacija celog sistema

Alati kao što su [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) i drugi olakšavaju potpunu emulaciju firmware-a, automatizuju proces i pomažu pri dinamičkoj analizi.

## Dinamička analiza u praksi

U ovoj fazi za analizu se koristi stvarno ili emulirano uređajno okruženje. Neophodno je zadržati pristup shell-u OS-a i filesystem-u. Emulacija možda neće savršeno oponašati interakcije sa hardverom, pa će povremeni restarti emulacije biti potrebni. Analiza bi trebalo da ponovo pregleda filesystem, iskoristi izložene web-stranice i mrežne servise, i istraži ranjivosti bootloader-a. Testovi integriteta firmware-a su ključni za otkrivanje potencijalnih backdoor ranjivosti.

## Tehnike runtime analize

Runtime analiza podrazumeva interakciju sa procesom ili binarnim fajlom u njegovom okruženju za izvršavanje, koristeći alate kao što su gdb-multiarch, Frida i Ghidra za postavljanje breakpoints-a i identifikovanje ranjivosti kroz fuzzing i druge tehnike.

## Binary Exploitation and Proof-of-Concept

Razvijanje PoC-a za identifikovane ranjivosti zahteva duboko razumevanje ciljne arhitekture i programiranje u niskonivou jezicima. Binary runtime protections u embedded systems su retke, ali kada postoje, tehnike poput Return Oriented Programming (ROP) mogu biti neophodne.

## Pripremljeni operativni sistemi za analizu firmware-a

Operativni sistemi kao što su [AttifyOS](https://github.com/adi0x90/attifyos) i [EmbedOS](https://github.com/scriptingxss/EmbedOS) pružaju unapred konfigurisana okruženja za firmware security testing, opremljena potrebnim alatima.

## Pripremljeni OS-ovi za analizu firmware-a

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS je distro namenjen da pomogne pri security assessment i penetration testing Internet of Things (IoT) uređaja. Štedi vreme pružajući unapred konfigurisano okruženje sa svim neophodnim alatima.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Embedded security testing operating system zasnovan na Ubuntu 18.04, unapred opremljen alatima za firmware security testing.

## Firmware downgrade napadi i nesigurni mehanizmi ažuriranja

Čak i kada proizvođač implementira kriptografske provere potpisa za firmware image-ove, **zaštita protiv version rollback (downgrade) često se izostavlja**. Ako boot- ili recovery-loader samo verifikuje potpis ugrađenim javnim ključem, ali ne upoređuje *verziju* (ili monotoni brojač) image-a koji se flash-uje, napadač može legitimno instalirati **stariji, ranjiv firmware koji i dalje nosi važeći potpis** i tako ponovo uneti ranjivosti koje su već bile ispravljene.

Tipični tok napada:

1. **Obtain an older signed image**
* Preuzmite ga sa javnog download portala proizvođača, CDN-a ili stranice za podršku.
* Ekstrahujte ga iz pratećih mobilnih/desktop aplikacija (npr. unutar Android APK-a pod `assets/firmware/`).
* Preuzmite ga iz repozitorijuma trećih strana kao što su VirusTotal, internet arhive, forumi, itd.
2. **Upload or serve the image to the device** via any exposed update channel:
* Web UI, mobile-app API, USB, TFTP, MQTT, etc.
* Mnogi consumer IoT uređaji izlažu *unauthenticated* HTTP(S) endpoint-e koji prihvataju Base64-encoded firmware blob-ove, dekodiraju ih server-side i pokreću recovery/upgrade.
3. Nakon downgrade-a, iskoristite ranjivost koja je ispravljena u novijem izdanju (na primer filter za command-injection koji je dodat kasnije).
4. Opcionalno ponovo flash-ujte najnoviji image ili onemogućite update-e da biste izbegli otkrivanje nakon uspostavljanja persistencije.

### Primer: Command Injection nakon downgrade-a
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
U ranjivom (downgraded) firmveru, parametar `md5` se direktno ubacuje u shell komandu bez sanitizacije, što omogućava injekciju proizvoljnih komandi (ovde – omogućavanje SSH key-based root access). Kasnije verzije firmvera su uvele osnovni filter karaktera, ali nedostatak zaštite od downgrade čini tu ispravku neefikasnom.

### Ekstrakcija firmvera iz mobilnih aplikacija

Mnogi proizvođači uključuju pune firmware slike u svoje prateće mobilne aplikacije kako bi aplikacija mogla ažurirati uređaj preko Bluetooth/Wi‑Fi. Ti paketi se obično čuvaju nešifrovani u APK/APEX pod putanjama kao što su `assets/fw/` ili `res/raw/`. Alati poput `apktool`, `ghidra` ili čak običnog `unzip` omogućavaju vam da izvučete potpisane slike bez fizičkog pristupa hardveru.
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### Kontrolna lista za procenu logike ažuriranja

* Da li je transport/autentifikacija *update endpoint*-a adekvatno zaštićena (TLS + autentifikacija)?
* Da li uređaj upoređuje **version numbers** ili **monotonic anti-rollback counter** pre flashing-a?
* Da li se image verifikuje unutar secure boot chain (npr. signatures checked by ROM code)?
* Da li userland code izvodi dodatne sanity checks (npr. allowed partition map, model number)?
* Da li *partial* ili *backup* update tokovi ponovo koriste istu validation logic?

> 💡  Ako bilo šta od navedenog nedostaje, platforma je verovatno ranjiva na rollback attacks.

## Ranjiv firmware za praksu

To practice discovering vulnerabilities in firmware, use the following vulnerable firmware projects as a starting point.

- OWASP IoTGoat
- [https://github.com/OWASP/IoTGoat](https://github.com/OWASP/IoTGoat)
- The Damn Vulnerable Router Firmware Project
- [https://github.com/praetorian-code/DVRF](https://github.com/praetorian-code/DVRF)
- Damn Vulnerable ARM Router (DVAR)
- [https://blog.exploitlab.net/2018/01/dvar-damn-vulnerable-arm-router.html](https://blog.exploitlab.net/2018/01/dvar-damn-vulnerable-arm-router.html)
- ARM-X
- [https://github.com/therealsaumil/armx#downloads](https://github.com/therealsaumil/armx#downloads)
- Azeria Labs VM 2.0
- [https://azeria-labs.com/lab-vm-2-0/](https://azeria-labs.com/lab-vm-2-0/)
- Damn Vulnerable IoT Device (DVID)
- [https://github.com/Vulcainreo/DVID](https://github.com/Vulcainreo/DVID)

## Reference

- [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [Practical IoT Hacking: The Definitive Guide to Attacking the Internet of Things](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [Exploiting zero days in abandoned hardware – Trail of Bits blog](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)

## Trening i certifikati

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

{{#include ../../banners/hacktricks-training.md}}
