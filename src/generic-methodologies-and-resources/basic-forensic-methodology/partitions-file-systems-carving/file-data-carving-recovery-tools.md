# Lêer-/data-carving- en herstelhulpmiddels

{{#include ../../../banners/hacktricks-training.md}}

## Carving- en herstelhulpmiddels

Carve altyd ’n **geverifieerde kopie**, nie die oorspronklike toestel nie. Sien [Image Acquisition & Mount](../image-acquisition-and-mount.md) vir leesalleen-verkryging- en hashing-werkvloeie.

Meer hulpmiddels by [https://github.com/Claudio-C/awesome-datarecovery](https://github.com/Claudio-C/awesome-datarecovery)

### Autopsy

Die algemeenste hulpmiddel wat in forensiese ondersoeke gebruik word om lêers uit images te onttrek, is [**Autopsy**](https://www.autopsy.com/download/). Laai dit af, installeer dit en laat dit die lêer inneem om "versteekte" lêers te vind. Let daarop dat Autopsy gebou is om skyfimages en ander soorte images te ondersteun, maar nie eenvoudige lêers nie.

### Binwalk <a href="#binwalk" id="binwalk"></a>

**Binwalk** is ’n hulpmiddel om binêre lêers te ontleed en ingebedde inhoud te vind. **Binwalk v3** is ’n Rust-herskrywing met outomatiese onttrekking (`-e`), raw carving van bekende en onbekende objekte (`-c`), rekursiewe/Matryoshka-skandering (`-M`) en konfigureerbare worker threads. Die projek beveel sy Docker-build aan wanneer alle eksterne extractors benodig word; `cargo install binwalk` installeer die Rust CLI, maar nie daardie eksterne afhanklikhede nie.<sup>[[11]](#references)</sup>

**Nuttige v3-opdragte**:

```bash
cargo install binwalk                 # CLI only; install extractors separately
binwalk firmware.bin                  # Identify embedded content
binwalk -e firmware.bin               # Extract recognised objects
binwalk -c -d carved firmware.bin     # Carve known and unknown objects
binwalk -Me -d extracted firmware.bin # Extract and recursively scan results
binwalk -e -l results.json firmware.bin
```

Die legacy v2-`--dd='.*'`-resep is **nie** die v3-ekwivalent van `-c` nie; kontroleer eers `binwalk --version` wanneer jy ou CTF-/write-up-opdragte volg.<sup>[[11]](#references)</sup>

⚠️  **Sekuriteitsnota** – Weergawes **2.1.2b tot en met 2.3.3** word deur ’n **Path Traversal**-kwesbaarheid (CVE-2022-4510) geraak; die advies lys geen gepaste pip-weergawe nie. Vermy dit om onvertroude monsters met geraakte weergawes uit te pak, of isoleer die nutsding met ’n container/nie-bevoorregte UID.<sup>[[4]](#references)</sup>

### Foremost

Nog ’n algemene nutsding om versteekte lêers te vind, is **foremost**. Jy kan foremost se konfigurasielêer vind by `/etc/foremost.conf`. As jy net na spesifieke lêers wil soek, verwyder die kommentaarmerkers daarvan. As jy niks se kommentaarmerkers verwyder nie, sal foremost na sy verstek-gekonfigureerde lêertipes soek.

```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
# Discovered files will appear inside the folder "output"
```

### **Scalpel**

**Scalpel** is nog ’n hulpmiddel waarmee jy **lêers wat in ’n lêer ingebed is** kan vind en onttrek. In hierdie geval moet jy die kommentaarmerkers verwyder van die lêertipes wat jy wil onttrek in die konfigurasielêer (_/etc/scalpel/scalpel.conf_).

```bash
sudo apt-get install scalpel
scalpel file.img -o output
```

### Gefragmenteerde carving met Scalpel3

Wanneer metadata-eerste herstel en aaneenlopende carvers gesplete lêers onvolledig laat, kan **Scalpel3** ondersteunde formate met lêer-/blokvalideerders weer saamstel. Dit is ’n ander kodebasis as die verouderde `scalpel`-opdrag hierbo. Skep eers die vereiste blockmap met **dieselfde blokgrootte** as dié wat vir carving gebruik word; gebruik die lêerstelsel se cluster-grootte uit `fsstat` indien dit bekend is, of bepaal ’n verdedigbare waarde voordat jy ’n partisieskyfbeeld skandeer. Voer dit slegs op ’n geverifieerde kopie uit en plaas die uitvoer op ’n aparte volume.<sup>[[13]](#references)[[14]](#references)[[15]](#references)</sup>

```bash
git clone https://github.com/nolaforensix/scalpel3-release.git
cd scalpel3-release && ./init_scalpel3.sh && cd src
./crblockmap -q 4096 /evidence/partition.img /analysis/partition.blockmap
./scalpel3 -Y cpu -q 4096 -w -b -o /analysis/scalpel3 \
  /evidence/partition.img /analysis/partition.blockmap
```

Vervang `4096` met die gekose blokgrootte. `-w` behou **PROMISING**-kandidate sowel as gevalideerde kandidate, en `-b` skryf blokvektore om gerekonstrueerde uitlegte te help nagaan. ’n Lêer in PROMISING, of een met ’n bekende uitbreiding, is nie bewys van volledige herstel nie; valideer die inhoud voor gebruik.<sup>[[13]](#references)[[14]](#references)</sup> Sien [Finding data outside listed partitions](./#finding-data-outside-listed-partitions) om uitgevee partisies of gapings op te spoor voordat jy carve.

### Bulk Extractor 2.x   

Hierdie nutsprogram is by Kali ingesluit, maar jy kan dit hier vind: <https://github.com/simsong/bulk_extractor>

Bulk Extractor kan ’n bewysbeeld skandeer en **pcap-fragmente**, **netwerkartefakte (URL’s, domeine, IP’s, MAC’s, e-posse)** en baie ander voorwerpe carve **in parallel met behulp van verskeie skandeerders**.

Die v2.1.1-vrystelling dokumenteer ’n Autotools-bouproses en die `-S jpeg_carve_mode=2`-instelling om alle aaneenlopende JPEG’s te carve.<sup>[[2]](#references)</sup>

```bash
# Build from source – v2.1.1 (April 2024) requires C++17
git clone --branch v2.1.1 --recurse-submodules https://github.com/simsong/bulk_extractor.git
cd bulk_extractor
./bootstrap.sh
./configure
make -j"$(nproc)"
sudo make install

# Scan an image and carve contiguous JPEGs
bulk_extractor -o out_folder -S jpeg_carve_mode=2 /evidence/disk.img
```

Die gebundelde `bulk_diff.py` vergelyk twee bulk_extractor-uitvoerings, terwyl `bulk_extractor_reader.py` die verslag- en kenmerklêers lees.<sup>[[3]](#references)</sup>

### PhotoRec

Jy kan dit vind by <https://www.cgsecurity.org/wiki/TestDisk_Download>

Dit kom met GUI- en CLI-weergawes. Jy kan die **lêertipes** kies waarvoor jy wil hê PhotoRec moet soek.

![Voer elke skandeerder uit, carve JPEGs aggressief en genereer ’n bodyfile - PhotoRec: Dit kom met GUI- en CLI-weergawes. Jy kan die lêertipes kies waarvoor jy wil hê PhotoRec moet soek](<../../../images/image (242).png>)

### The Sleuth Kit `tsk_recover` (metadata-eerste)

Voordat jy rou handtekening-carving doen, probeer lêerstelselbewuste herstel wanneer die volume se metadata steeds ontleedbaar is. `tsk_recover` voer by verstek slegs ongeallokeerde lêers uit; `-a` kies geallokeerde lêers en `-e` voer albei uit. Vir ’n heeleskyfbeeld, gee die partisie se **beginkersektor** vanaf `mmls` aan `-o` deur (moet dit nie na grepe omskakel nie). As die invoer reeds ’n partisiebeeld is, laat `-o` weg.<sup>[[12]](#references)</sup>

```bash
sudo apt install sleuthkit
mmls disk.img                         # Note the partition start sector, e.g. 2048
mkdir recovered-deleted recovered-all
tsk_recover -o 2048 disk.img recovered-deleted/
tsk_recover -e -o 2048 disk.img recovered-all/
```

Hierdie deurgang kan lêerstelsel-afgeleide name en paaie behou wat header/footer-carving nie kan nie; voer daarna Foremost, Scalpel of PhotoRec uit vir inskrywings waarvan die metadata ontbreek of onbruikbaar is.<sup>[[12]](#references)</sup>

### ddrescue + ddrescueview (beeldvorming van onstabiele skywe)

Wanneer ’n fisiese skyf onstabiel is, is dit die beste praktyk om **eers ’n image daarvan te maak** en carving-nutsgoed daarna slegs op die image uit te voer. `ddrescue` (GNU-projek) fokus daarop om beskadigde skywe betroubaar te kopieer terwyl ’n logboek van onleesbare sektore bygehou word.

```bash
sudo apt install gddrescue ddrescueview   # On Debian-based systems
# First pass – try to get as much data as possible without retries
sudo ddrescue -f -n /dev/sdX suspect.img suspect.log
# Second pass – aggressive, 3 retries on the remaining bad areas
sudo ddrescue -d -r3 /dev/sdX suspect.img suspect.log

# Visualise the status map (green=good, red=bad)
 ddrescueview suspect.log
```

Die **`--cluster-size`**-opsie bepaal hoeveel sektore op ’n slag gekopieer word; kleiner waardes kan help met stadige aandrywers.<sup>[[7]](#references)</sup>

### Extundelete / Ext4magic (EXT 3/4-herstel van geskrapte lêers)

As die bronlêerstelsel op Linux EXT gebaseer is, kan jy dalk onlangs geskrapte lêers **sonder volledige carving** herstel; hierdie joernaalgebaseerde nutsprogramme werk op ’n ontkoppelde lêerstelsel of ’n leesalleen-beeld.<sup>[[8]](#references)[[9]](#references)</sup>

```bash
# Attempt journal-based undelete (metadata must still be present)
extundelete disk.img --restore-all

# Multi-stage recovery from an ext4 image
ext4magic disk.img -M -d ./recovered
```

> **Verenigbaarheidsnota** – ext4magic is verlate; die projekblad waarsku dat huidige lêerstelsels nie meer daarmee versoenbaar is nie.<sup>[[10]](#references)</sup>

> 🛈 As die lêerstelsel ná die uitvee gemount is, is die datablocks dalk reeds hergebruik – in daardie geval is behoorlike carving (Foremost/Scalpel) steeds nodig.

### binvis

Kyk na die [code](https://code.google.com/archive/p/binvis/) en die [web page tool](https://binvis.io/#/).

#### Kenmerke van BinVis

- Visuele en aktiewe **struktuurkyker**
- Verskeie plotte vir verskillende fokusareas
- Fokus op gedeeltes van ’n sample
- **Sien strings en resources**, byvoorbeeld in PE- of ELF-executables
- Kry **patrone** vir kriptanalise op lêers
- **Spoor** packer- of encoder-algoritmes op
- **Identifiseer** steganografie deur patrone
- **Visuele** binary-diffing

BinVis is ’n uitstekende **beginpunt om met ’n onbekende teiken vertroud te raak** in ’n black-boxing-scenario.

## Spesifieke Data Carving-gereedskap

### FindAES

Soek na AES-sleutels deur hul key schedules te soek. Kan 128-, 192- en 256-bis-sleutels vind, soos dié wat TrueCrypt en BitLocker gebruik.

Laai [hier](https://sourceforge.net/projects/findaes/) af.

### YARA-X (triëring van carved artefakte)

[YARA-X](https://github.com/VirusTotal/yara-x) is ’n Rust-herskrywing van YARA wat in 2024 bekendgestel is; VirusTotal meld dat sommige reëlmatige-uitdrukking- en komplekse-lusreëls aansienlik vinniger kan loop.<sup>[[5]](#references)</sup> Die CLI heet `yr`, en die `scan`-opdrag ondersteun rekursiewe skanderings, ’n draadtelling en metadata-uitvoer.<sup>[[6]](#references)</sup>

```bash
# Scan every carved object produced by bulk_extractor
yr scan --recursive --threads 8 --print-meta rules/index.yar out_folder/
```

## Aanvullende nutsmiddels

Jy kan [**viu** ](https://github.com/atanunq/viu) gebruik om beelde vanaf die terminaal te sien.  \
Jy kan die Linux-opdraglyn-nutsmiddel **pdftotext** gebruik om ’n PDF na teks om te skakel en dit te lees.







## References

- [1] [Autopsy 4.21-vrystellingnotas](https://github.com/sleuthkit/autopsy/releases/tag/autopsy-4.21.0)
- [2] [bulk_extractor v2.1.1 README](https://github.com/simsong/bulk_extractor/blob/v2.1.1/README.md)
- [3] [bulk_extractor Python-nutsmiddels README](https://raw.githubusercontent.com/simsong/bulk_extractor/v2.1.1/python/README.txt)
- [4] [Padtraversering in binwalk (CVE-2022-4510) - GitHub-adviesdatabasis](https://github.com/advisories/GHSA-3cm8-v4mc-gppg)
- [5] [YARA is dood, lank lewe YARA-X - VirusTotal-blog](https://blog.virustotal.com/2024/05/yara-is-dead-long-live-yara-x.html)
- [6] [YARA-X CLI-opdragte](https://virustotal.github.io/yara-x/docs/cli/commands/)
- [7] [GNU ddrescue-handleiding](https://www.gnu.org/software/ddrescue/manual/ddrescue_manual.html)
- [8] [extundelete](https://extundelete.sourceforge.net/)
- [9] [ext4magic-handleiding](https://ext4magic.sourceforge.net/manpage_en.html)
- [10] [ext4magic-projekstatus](https://sourceforge.net/projects/ext4magic/)
- [11] [Binwalk v3 README](https://github.com/ReFirmLabs/binwalk/blob/master/README.md)
- [12] [The Sleuth Kit: tsk_recover-handleiding](https://sleuthkit.org/sleuthkit/man/tsk_recover.html)
- [13] [Scalpel3 README](https://github.com/nolaforensix/scalpel3-release/blob/main/README.md)
- [14] [Scalpel3-handleiding](https://github.com/nolaforensix/scalpel3-release/blob/main/man/scalpel3.1)
- [15] [Scalpel3-toetswerkvloei](https://github.com/nolaforensix/scalpel3-release/blob/main/src/TESTS/cmdline.test)
{{#include ../../../banners/hacktricks-training.md}}
