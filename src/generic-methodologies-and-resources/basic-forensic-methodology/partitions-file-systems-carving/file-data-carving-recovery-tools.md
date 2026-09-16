# File/Data Carving en Recovery Tools

{{#include ../../../banners/hacktricks-training.md}}

## Carving- en Recovery-tools

Carve altyd ’n **geverifieerde kopie**, nie die oorspronklike toestel nie. Sien [Image Acquisition & Mount](../image-acquisition-and-mount.md) vir verkryging in leesalleen-modus en hashing-werksvloeie.

Meer tools by [https://github.com/Claudio-C/awesome-datarecovery](https://github.com/Claudio-C/awesome-datarecovery)

### Autopsy

Die mees algemene tool wat in forensics gebruik word om lêers uit images te onttrek, is [**Autopsy**](https://www.autopsy.com/download/). Laai dit af, installeer dit en laat dit die lêer verwerk om "versteekte" lêers te vind. Let daarop dat Autopsy gebou is om disk images en ander soorte images te ondersteun, maar nie eenvoudige lêers nie.

### Binwalk <a href="#binwalk" id="binwalk"></a>

**Binwalk** is ’n tool vir die ontleding van binary files om ingebedde inhoud te vind. **Binwalk v3** is ’n Rust-herskrywing met outomatiese extraction (`-e`), raw carving van bekende en onbekende objects (`-c`), recursive/Matryoshka scanning (`-M`) en konfigureerbare worker threads. Die projek beveel sy Docker build aan wanneer alle external extractors benodig word; `cargo install binwalk` installeer die Rust CLI, maar nie daardie external dependencies nie.<sup>[[11]](#references)</sup>

**Nuttige v3-opdragte**:
```bash
cargo install binwalk                 # CLI only; install extractors separately
binwalk firmware.bin                  # Identify embedded content
binwalk -e firmware.bin               # Extract recognised objects
binwalk -c -d carved firmware.bin     # Carve known and unknown objects
binwalk -Me -d extracted firmware.bin # Extract and recursively scan results
binwalk -e -l results.json firmware.bin
```
Die legacy v2 `--dd='.*'`-resep is **nie** die v3-ekwivalent van `-c` nie; kyk eers na `binwalk --version` wanneer jy ou CTF/write-up-opdragte volg.<sup>[[11]](#references)</sup>

⚠️  **Sekuriteitsnota** – Weergawes **2.1.2b tot en met 2.3.3** word deur ’n **Path Traversal**-kwesbaarheid (CVE-2022-4510) geraak; die advies lys geen gelapte pip-weergawe nie. Vermy die ekstraksie van onbetroubare monsters met geraakte weergawes, of isoleer die tool met ’n container/nie-bevoorregte UID.<sup>[[4]](#references)</sup>

### Foremost

Nog ’n algemene tool om versteekte lêers te vind, is **foremost**. Jy kan die konfigurasielêer van foremost in `/etc/foremost.conf` vind. As jy net vir sekere spesifieke lêers wil soek, verwyder die kommentaar daarvoor. As jy niks se kommentaar verwyder nie, sal foremost vir sy verstek-gekonfigureerde lêertipes soek.
```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
# Discovered files will appear inside the folder "output"
```
### **Scalpel**

**Scalpel** is nog ’n hulpmiddel wat gebruik kan word om **lêers wat in ’n lêer ingebed is** te vind en te onttrek. In hierdie geval moet jy die lêertipes wat jy wil onttrek, uit die konfigurasielêer (_/etc/scalpel/scalpel.conf_) se kommentaar haal.
```bash
sudo apt-get install scalpel
scalpel file.img -o output
```
### Bulk Extractor 2.x

Hierdie tool kom saam met Kali, maar jy kan dit hier vind: <https://github.com/simsong/bulk_extractor>

Bulk Extractor kan ’n evidence image skandeer en **pcap-fragmente**, **netwerkartefakte (URL’s, domeine, IP’s, MAC’s, e-posse)** en baie ander objekte **parallel met behulp van veelvuldige scanners** carve.

Die v2.1.1-release dokumenteer ’n Autotools-build en die `-S jpeg_carve_mode=2`-instelling vir carving van alle aaneengrensende JPEG’s.<sup>[[2]](#references)</sup>
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
Die ingeslote `bulk_diff.py` vergelyk twee bulk_extractor-runs, terwyl `bulk_extractor_reader.py` die verslag- en feature-lêers lees.<sup>[[3]](#references)</sup>

### PhotoRec

Jy kan dit by <https://www.cgsecurity.org/wiki/TestDisk_Download> vind.

Dit kom met GUI- en CLI-weergawes. Jy kan die **lêertipes** kies waarna PhotoRec moet soek.

![Run every scanner, carve JPEGs aggressively and generate a bodyfile - PhotoRec: Dit kom met GUI- en CLI-weergawes. Jy kan die lêertipes kies waarna PhotoRec moet soek](<../../../images/image (242).png>)

### Die Sleuth Kit `tsk_recover` (metadata-eerste)

Probeer lêerstelselbewuste herstel voordat rou handtekening-carving uitgevoer word, wanneer die volume se metadata nog ontleedbaar is. `tsk_recover` voer by verstek slegs ongeallokeerde lêers uit; `-a` kies geallokeerde lêers en `-e` voer albei uit. Vir ’n hele-skyfbeeld, gee die partisie se **beginsektor** vanaf `mmls` aan `-o` deur (moenie dit na grepe omskakel nie). As die invoer reeds ’n partisieskyfbeeld is, laat `-o` weg.<sup>[[12]](#references)</sup>
```bash
sudo apt install sleuthkit
mmls disk.img                         # Note the partition start sector, e.g. 2048
mkdir recovered-deleted recovered-all
tsk_recover -o 2048 disk.img recovered-deleted/
tsk_recover -e -o 2048 disk.img recovered-all/
```
Hierdie proses kan lêerstelsel-afgeleide name en paaie behou wat header/footer carving nie kan nie; voer Foremost, Scalpel of PhotoRec daarna uit vir inskrywings waarvan die metadata ontbreek of onbruikbaar is.<sup>[[12]](#references)</sup>

### ddrescue + ddrescueview (beeldskepping van foutiewe aandrywers)

Wanneer ’n fisiese aandrywer onstabiel is, is dit beste praktyk om dit **eers te beeld** en carving-nutsgoed slegs teen die beeld uit te voer. `ddrescue` (GNU-projek) fokus daarop om beskadigde skywe betroubaar te kopieer terwyl ’n logboek van onleesbare sektore behou word.
```bash
sudo apt install gddrescue ddrescueview   # On Debian-based systems
# First pass – try to get as much data as possible without retries
sudo ddrescue -f -n /dev/sdX suspect.img suspect.log
# Second pass – aggressive, 3 retries on the remaining bad areas
sudo ddrescue -d -r3 /dev/sdX suspect.img suspect.log

# Visualise the status map (green=good, red=bad)
ddrescueview suspect.log
```
Die **`--cluster-size`**-opsie beheer hoeveel sektore op ’n slag gekopieer word; kleiner waardes kan help met stadige aandrywers.<sup>[[7]](#references)</sup>

### Extundelete / Ext4magic (EXT 3/4 undelete)

As die bronlêerstelsel Linux EXT-gebaseer is, kan jy moontlik onlangs geskrapte lêers **sonder volledige carving** herstel; hierdie joernaal-gebaseerde nutsmiddels werk op ’n ontkoppelde lêerstelsel of ’n leesalleenbeeld.<sup>[[8]](#references)[[9]](#references)</sup>
```bash
# Attempt journal-based undelete (metadata must still be present)
extundelete disk.img --restore-all

# Multi-stage recovery from an ext4 image
ext4magic disk.img -M -d ./recovered
```
> **Verenigbaarheidsnota** – ext4magic is verlate; sy projekblad waarsku dat huidige lêerstelsels nie meer daarmee versoenbaar is nie.<sup>[[10]](#references)</sup>

> 🛈 Indien die lêerstelsel ná uitvee gemount is, is die datablokke moontlik reeds hergebruik – in daardie geval word behoorlike carving (Foremost/Scalpel) steeds vereis.

### binvis

Kyk na die [code](https://code.google.com/archive/p/binvis/) en die [webblad-instrument](https://binvis.io/#/).

#### Kenmerke van BinVis

- Visuele en aktiewe **struktuurkyker**
- Veelvuldige plots vir verskillende fokuspunte
- Fokus op gedeeltes van ’n sample
- **Sien van strings en hulpbronne**, byvoorbeeld in PE- of ELF-executables
- Verkryging van **patrone** vir cryptanalysis op lêers
- **Opspoor** van packer- of encoder-algoritmes
- **Identifisering** van Steganography volgens patrone
- **Visuele** binary-diffing

BinVis is ’n uitstekende **beginpunt om vertroud te raak met ’n onbekende teiken** in ’n black-boxing-scenario.

## Spesifieke Data Carving Tools

### FindAES

Soek AES-sleutels deur na hul sleutel-skedules te soek. Kan 128-, 192- en 256-bis-sleutels vind, soos dié wat deur TrueCrypt en BitLocker gebruik word.

Laai [hier](https://sourceforge.net/projects/findaes/) af.

### YARA-X (triage van carved artefakte)

[YARA-X](https://github.com/VirusTotal/yara-x) is ’n Rust-herskrywing van YARA wat in 2024 bekendgestel is; VirusTotal rapporteer dat sommige regular-expression- en complex-loop-reëls aansienlik vinniger kan loop.<sup>[[5]](#references)</sup> Die CLI se naam is `yr`, en die `scan`-command ondersteun recursive scans, ’n thread count en metadata-uitset.<sup>[[6]](#references)</sup>
```bash
# Scan every carved object produced by bulk_extractor
yr scan --recursive --threads 8 --print-meta rules/index.yar out_folder/
```
## Aanvullende tools

Jy kan [**viu** ](https://github.com/atanunq/viu) gebruik om beelde vanaf die terminale te sien.  \
Jy kan die Linux-command-line-tool **pdftotext** gebruik om ’n PDF na teks om te skakel en dit te lees.





## References

- [1] [Autopsy 4.21-vrystellingsnotas](https://github.com/sleuthkit/autopsy/releases/tag/autopsy-4.21.0)
- [2] [bulk_extractor v2.1.1 README](https://github.com/simsong/bulk_extractor/blob/v2.1.1/README.md)
- [3] [bulk_extractor Python-tools README](https://raw.githubusercontent.com/simsong/bulk_extractor/v2.1.1/python/README.txt)
- [4] [Pad-traversering in binwalk (CVE-2022-4510) - GitHub Advisory Database](https://github.com/advisories/GHSA-3cm8-v4mc-gppg)
- [5] [YARA is dood, lank lewe YARA-X - VirusTotal Blog](https://blog.virustotal.com/2024/05/yara-is-dead-long-live-yara-x.html)
- [6] [YARA-X CLI-opdragte](https://virustotal.github.io/yara-x/docs/cli/commands/)
- [7] [GNU ddrescue-handleiding](https://www.gnu.org/software/ddrescue/manual/ddrescue_manual.html)
- [8] [extundelete](https://extundelete.sourceforge.net/)
- [9] [ext4magic-handleiding](https://ext4magic.sourceforge.net/manpage_en.html)
- [10] [ext4magic-projekstatus](https://sourceforge.net/projects/ext4magic/)
- [11] [Binwalk v3 README](https://github.com/ReFirmLabs/binwalk/blob/master/README.md)
- [12] [The Sleuth Kit: tsk_recover-handleiding](https://sleuthkit.org/sleuthkit/man/tsk_recover.html)
{{#include ../../../banners/hacktricks-training.md}}
