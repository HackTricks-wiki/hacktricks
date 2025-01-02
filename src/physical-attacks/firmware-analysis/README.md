# Firmware Analysis

{{#include ../../banners/hacktricks-training.md}}

## **Uvod**

Firmware je osnovni softver koji omogućava uređajima da ispravno funkcionišu upravljanjem i olakšavanjem komunikacije između hardverskih komponenti i softvera s kojim korisnici interaguju. Čuva se u trajnoj memoriji, osiguravajući da uređaj može pristupiti vitalnim uputstvima od trenutka kada se uključi, što dovodi do pokretanja operativnog sistema. Istraživanje i potencijalno modifikovanje firmware-a je ključni korak u identifikaciji sigurnosnih ranjivosti.

## **Prikupljanje informacija**

**Prikupljanje informacija** je kritičan početni korak u razumevanju sastava uređaja i tehnologija koje koristi. Ovaj proces uključuje prikupljanje podataka o:

- Arhitekturi CPU-a i operativnom sistemu koji koristi
- Specifikacijama bootloader-a
- Rasporedu hardvera i tehničkim listovima
- Metrikama koda i lokacijama izvora
- Spoljim bibliotekama i tipovima licenci
- Istorijama ažuriranja i regulatornim sertifikatima
- Arhitektonskim i tokovnim dijagramima
- Procjenama sigurnosti i identifikovanim ranjivostima

U tu svrhu, **alatke za otvorene izvore (OSINT)** su neprocenjive, kao i analiza bilo kojih dostupnih komponenti otvorenog koda kroz manuelne i automatske procese pregleda. Alati poput [Coverity Scan](https://scan.coverity.com) i [Semmle’s LGTM](https://lgtm.com/#explore) nude besplatnu statičku analizu koja se može iskoristiti za pronalaženje potencijalnih problema.

## **Sticanje firmware-a**

Dobijanje firmware-a može se pristupiti na različite načine, svaki sa svojim nivoom složenosti:

- **Direktno** od izvora (razvijači, proizvođači)
- **Kreiranje** na osnovu datih uputstava
- **Preuzimanje** sa zvaničnih sajtova za podršku
- Korišćenje **Google dork** upita za pronalaženje hostovanih firmware datoteka
- Pristupanje **cloud storage** direktno, uz alate poput [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Presretanje **ažuriranja** putem tehnika man-in-the-middle
- **Ekstrakcija** sa uređaja putem konekcija kao što su **UART**, **JTAG**, ili **PICit**
- **Sniffing** za zahteve za ažuriranje unutar komunikacije uređaja
- Identifikovanje i korišćenje **hardkodiranih krajnjih tačaka za ažuriranje**
- **Dumping** sa bootloader-a ili mreže
- **Uklanjanje i čitanje** čipa za skladištenje, kada sve drugo ne uspe, koristeći odgovarajuće hardverske alate

## Analiza firmware-a

Sada kada **imate firmware**, potrebno je da izvučete informacije o njemu kako biste znali kako da ga obradite. Različiti alati koje možete koristiti za to:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
Ako ne pronađete mnogo sa tim alatima, proverite **entropiju** slike sa `binwalk -E <bin>`, ako je entropija niska, verovatno nije enkriptovana. Ako je entropija visoka, verovatno je enkriptovana (ili kompresovana na neki način).

Pored toga, možete koristiti ove alate za ekstrakciju **datoteka ugrađenih unutar firmvera**:

{{#ref}}
../../forensics/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Ili [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) za inspekciju datoteke.

### Dobijanje Datotečnog Sistema

Sa prethodno pomenutim alatima kao što je `binwalk -ev <bin>`, trebali ste biti u mogućnosti da **izvučete datotečni sistem**.\
Binwalk obično izvlači unutar **foldera nazvanog po tipu datotečnog sistema**, koji obično može biti jedan od sledećih: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Ručna Ekstrakcija Datotečnog Sistema

Ponekad, binwalk **neće imati magični bajt datotečnog sistema u svojim potpisima**. U tim slučajevima, koristite binwalk da **pronađete offset datotečnog sistema i izrezujete kompresovani datotečni sistem** iz binarnog fajla i **ručno ekstraktujete** datotečni sistem prema njegovom tipu koristeći korake u nastavku.
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
Pokrenite sledeću **dd komandu** za izdvajanje Squashfs datotečnog sistema.
```
$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs

8257536+0 records in

8257536+0 records out

8257536 bytes (8.3 MB, 7.9 MiB) copied, 12.5777 s, 657 kB/s
```
Alternativno, sledeća komanda se takođe može izvršiti.

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

- Za squashfs (koristi se u gornjem primeru)

`$ unsquashfs dir.squashfs`

Fajlovi će biti u "`squashfs-root`" direktorijumu nakon toga.

- CPIO arhivski fajlovi

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- Za jffs2 fajl sisteme

`$ jefferson rootfsfile.jffs2`

- Za ubifs fajl sisteme sa NAND flešom

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Analiza Firmvera

Kada se firmver dobije, važno je da se razloži kako bi se razumeo njegova struktura i potencijalne ranjivosti. Ovaj proces uključuje korišćenje različitih alata za analizu i ekstrakciju vrednih podataka iz slike firmvera.

### Alati za Početnu Analizu

Set komandi je obezbeđen za početnu inspekciju binarnog fajla (naziva `<bin>`). Ove komande pomažu u identifikaciji tipova fajlova, ekstrakciji stringova, analizi binarnih podataka i razumevanju detalja particija i fajl sistema:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
Da bi se procenio status enkripcije slike, **entropija** se proverava sa `binwalk -E <bin>`. Niska entropija sugeriše nedostatak enkripcije, dok visoka entropija ukazuje na moguću enkripciju ili kompresiju.

Za ekstrakciju **ugrađenih fajlova**, preporučuju se alati i resursi kao što su dokumentacija **file-data-carving-recovery-tools** i **binvis.io** za inspekciju fajlova.

### Ekstrakcija Fajl Sistema

Koristeći `binwalk -ev <bin>`, obično se može ekstraktovati fajl sistem, često u direktorijum nazvan po tipu fajl sistema (npr. squashfs, ubifs). Međutim, kada **binwalk** ne prepozna tip fajl sistema zbog nedostajućih magic bajtova, ručna ekstrakcija je neophodna. To uključuje korišćenje `binwalk` za lociranje ofseta fajl sistema, a zatim `dd` komandu za izdvajanje fajl sistema:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
Nakon toga, u zavisnosti od tipa datotečnog sistema (npr., squashfs, cpio, jffs2, ubifs), koriste se različite komande za ručno vađenje sadržaja.

### Analiza datotečnog sistema

Sa izvučenim datotečnim sistemom, počinje potraga za sigurnosnim propustima. Pažnja se posvećuje nesigurnim mrežnim demonima, hardkodiranim akreditivima, API krajnjim tačkama, funkcionalnostima servera za ažuriranje, nekompajliranom kodu, skriptama za pokretanje i kompajliranim binarnim datotekama za analizu van mreže.

**Ključne lokacije** i **stavke** koje treba pregledati uključuju:

- **etc/shadow** i **etc/passwd** za korisničke akreditive
- SSL sertifikate i ključeve u **etc/ssl**
- Konfiguracione i skriptne datoteke za potencijalne ranjivosti
- Ugrađene binarne datoteke za dalju analizu
- Uobičajene web servere i binarne datoteke IoT uređaja

NSeveral tools assist in uncovering sensitive information and vulnerabilities within the filesystem:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) i [**Firmwalker**](https://github.com/craigz28/firmwalker) za pretragu osetljivih informacija
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) za sveobuhvatnu analizu firmvera
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go), i [**EMBA**](https://github.com/e-m-b-a/emba) za statičku i dinamičku analizu

### Provere sigurnosti na kompajliranim binarnim datotekama

I izvorni kod i kompajlirane binarne datoteke pronađene u datotečnom sistemu moraju se pažljivo pregledati zbog ranjivosti. Alati poput **checksec.sh** za Unix binarne datoteke i **PESecurity** za Windows binarne datoteke pomažu u identifikaciji nezaštićenih binarnih datoteka koje bi mogle biti iskorišćene.

## Emulacija firmvera za dinamičku analizu

Proces emulacije firmvera omogućava **dinamičku analizu** ili rada uređaja ili pojedinačnog programa. Ovaj pristup može naići na izazove sa zavisnostima hardvera ili arhitekture, ali prenos korenskog datotečnog sistema ili specifičnih binarnih datoteka na uređaj sa odgovarajućom arhitekturom i redosledom bajtova, kao što je Raspberry Pi, ili na unapred izgrađenu virtuelnu mašinu, može olakšati dalja testiranja.

### Emulacija pojedinačnih binarnih datoteka

Za ispitivanje pojedinačnih programa, identifikacija redosleda bajtova programa i CPU arhitekture je ključna.

#### Primer sa MIPS arhitekturom

Da bi se emulirala binarna datoteka MIPS arhitekture, može se koristiti komanda:
```bash
file ./squashfs-root/bin/busybox
```
I da instalirate potrebne alate za emulaciju:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
Za MIPS (big-endian), koristi se `qemu-mips`, a za little-endian binarne datoteke, izbor bi bio `qemu-mipsel`.

#### Emulacija ARM arhitekture

Za ARM binarne datoteke, proces je sličan, koristeći emulator `qemu-arm` za emulaciju.

### Emulacija celog sistema

Alati kao što su [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) i drugi, olakšavaju potpunu emulaciju firmvera, automatizujući proces i pomažući u dinamičkoj analizi.

## Dinamička analiza u praksi

U ovoj fazi koristi se stvarno ili emulirano okruženje uređaja za analizu. Važno je održati pristup shell-u operativnom sistemu i datotečnom sistemu. Emulacija možda neće savršeno oponašati interakcije hardvera, što zahteva povremena ponovna pokretanja emulacije. Analiza treba da ponovo pregleda datotečni sistem, iskoristi izložene veb stranice i mrežne usluge, i istraži ranjivosti bootloader-a. Testovi integriteta firmvera su ključni za identifikaciju potencijalnih ranjivosti backdoor-a.

## Tehnike analize u vreme izvođenja

Analiza u vreme izvođenja uključuje interakciju sa procesom ili binarnom datotekom u njegovom operativnom okruženju, koristeći alate kao što su gdb-multiarch, Frida i Ghidra za postavljanje tačaka prekida i identifikaciju ranjivosti kroz fuzzing i druge tehnike.

## Eksploatacija binarnih datoteka i dokaz koncepta

Razvijanje PoC-a za identifikovane ranjivosti zahteva duboko razumevanje ciljne arhitekture i programiranje na jezicima nižeg nivoa. Zaštite u vreme izvođenja u ugrađenim sistemima su retke, ali kada su prisutne, tehnike kao što su Return Oriented Programming (ROP) mogu biti neophodne.

## Pripremljeni operativni sistemi za analizu firmvera

Operativni sistemi kao što su [AttifyOS](https://github.com/adi0x90/attifyos) i [EmbedOS](https://github.com/scriptingxss/EmbedOS) pružaju unapred konfigurisana okruženja za testiranje bezbednosti firmvera, opremljena potrebnim alatima.

## Pripremljeni OS-ovi za analizu firmvera

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS je distribucija namenjena da vam pomogne u izvođenju procene bezbednosti i penetracionog testiranja uređaja Interneta stvari (IoT). Štedi vam mnogo vremena pružajući unapred konfigurisano okruženje sa svim potrebnim alatima.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Operativni sistem za testiranje bezbednosti ugrađenih sistema zasnovan na Ubuntu 18.04, unapred učitan alatima za testiranje bezbednosti firmvera.

## Ranjivi firmver za vežbanje

Da biste vežbali otkrivanje ranjivosti u firmveru, koristite sledeće ranjive projekte firmvera kao polaznu tačku.

- OWASP IoTGoat
- [https://github.com/OWASP/IoTGoat](https://github.com/OWASP/IoTGoat)
- Projekat Damn Vulnerable Router Firmware
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

## Obuka i sertifikat

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

{{#include ../../banners/hacktricks-training.md}}
