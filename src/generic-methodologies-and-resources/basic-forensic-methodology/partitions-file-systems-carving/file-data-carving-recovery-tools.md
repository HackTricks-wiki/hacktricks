# Lêer-/datacarving- en herstelnutsgoed

{{#include ../../../banners/hacktricks-training.md}}

## Carving- en hersteltools

Meer tools by [https://github.com/Claudio-C/awesome-datarecovery](https://github.com/Claudio-C/awesome-datarecovery)

### Autopsy

Die mees algemene tool wat in forensiese ondersoeke gebruik word om lêers uit images te onttrek, is [**Autopsy**](https://www.autopsy.com/download/). Laai dit af, installeer dit en laat dit die lêer verwerk om "versteekte" lêers te vind. Let daarop dat Autopsy gebou is om disk images en ander soorte images te ondersteun, maar nie eenvoudige lêers nie.

### Binwalk <a href="#binwalk" id="binwalk"></a>

**Binwalk** is 'n tool vir die ontleding van binary files om ingebedde inhoud te vind. Dit kan via `apt` geïnstalleer word, en die bronkode daarvan is op [GitHub](https://github.com/ReFirmLabs/binwalk).

**Nuttige opdragte**:
```bash
sudo apt install binwalk         # Installation
binwalk firmware.bin             # Display embedded data
binwalk -e firmware.bin          # Extract recognised objects (safe-default)
binwalk --dd " .* " firmware.bin  # Extract *everything* (use with care)
```
⚠️  **Sekuriteitsnota** – Weergawes **2.1.2b tot en met 2.3.3** word deur ’n **Path Traversal**-kwesbaarheid (CVE-2022-4510) geraak; die advies lys geen gelapte pip-weergawe nie. Vermy die onttrekking van onvertroude samples met geraakte weergawes, of isoleer die tool met ’n container/nie-bevoorregte UID.<sup>[[4]](#references)</sup>

### Foremost

Nog ’n algemene tool om versteekte lêers te vind, is **foremost**. Jy kan die konfigurasielêer van foremost in `/etc/foremost.conf` vind. As jy net vir spesifieke lêers wil soek, verwyder die kommentaarmerkers daarvoor. As jy niks se kommentaarmerker verwyder nie, sal foremost na sy verstek-gekonfigureerde lêertipes soek.
```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
# Discovered files will appear inside the folder "output"
```
### **Scalpel**

**Scalpel** is nog ’n hulpmiddel wat gebruik kan word om **lêers wat in ’n lêer ingebed is** te vind en te onttrek. In hierdie geval moet jy die kommentaartekens in die konfigurasielêer (_/etc/scalpel/scalpel.conf_) verwyder vir die lêertipes wat jy wil onttrek.
```bash
sudo apt-get install scalpel
scalpel file.img -o output
```
### Bulk Extractor 2.x

Hierdie instrument is ingesluit by kali, maar jy kan dit hier vind: <https://github.com/simsong/bulk_extractor>

Bulk Extractor kan ’n bewysbeeld skandeer en **pcap-fragmente**, **netwerkartefakte (URL's, domeine, IP's, MAC's, e-posse)** en baie ander objekte **parallel met behulp van veelvuldige skandeerders carve**.

Die v2.1.1-vrystelling dokumenteer ’n Autotools-bouproses en die `-S jpeg_carve_mode=2`-instelling om alle aaneenlopende JPEG's te carve.<sup>[[2]](#references)</sup>
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
Die gebundelde `bulk_diff.py` vergelyk twee bulk_extractor-lopies, terwyl `bulk_extractor_reader.py` die verslag- en feature-lêers lees.<sup>[[3]](#references)</sup>

### PhotoRec

Jy kan dit by <https://www.cgsecurity.org/wiki/TestDisk_Download> vind.

Dit kom met GUI- en CLI-weergawes. Jy kan die **lêertipes** kies waarna PhotoRec moet soek.

![Laat elke scanner loop, carve JPEG's aggressief en genereer 'n bodyfile - PhotoRec: Dit kom met GUI- en CLI-weergawes. Jy kan die lêertipes kies waarna PhotoRec moet soek](<../../../images/image (242).png>)

### ddrescue + ddrescueview (beeldskepping van falende aandrywers)

Wanneer 'n fisiese aandrywer onstabiel is, is dit beste praktyk om **eers 'n image daarvan te skep** en slegs daarna carving-tools teen die image te laat loop. `ddrescue` (GNU-projek) fokus daarop om foutiewe skywe betroubaar te kopieer terwyl 'n log van onleesbare sektore bygehou word.
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

As die bronlêerstelsel Linux EXT-gebaseer is, kan jy dalk onlangs verwyderde lêers **sonder volledige carving** herwin; hierdie joernaalgebaseerde nutsmiddels werk op ’n ontkoppelde lêerstelsel of ’n leesalleen-beeld.<sup>[[8]](#references)[[9]](#references)</sup>
```bash
# Attempt journal-based undelete (metadata must still be present)
extundelete disk.img --restore-all

# Multi-stage recovery from an ext4 image
ext4magic disk.img -M -d ./recovered
```
> **Versoenbaarheidsnota** – ext4magic is verlate; sy projekblad waarsku dat huidige lêerstelsels nie meer daarmee versoenbaar is nie.<sup>[[10]](#references)</sup>

> 🛈 Indien die lêerstelsel ná uitvee gemount is, is die datablokke moontlik reeds hergebruik – in daardie geval is behoorlike carving (Foremost/Scalpel) steeds nodig.

### binvis

Kyk na die [code](https://code.google.com/archive/p/binvis/) en die [webblad-nutsmiddel](https://binvis.io/#/).

#### Kenmerke van BinVis

- Visuele en aktiewe **struktuurkyker**
- Veelvuldige plotte vir verskillende fokuspunte
- Fokus op gedeeltes van ’n sample
- **Sien van strings en hulpbronne**, byvoorbeeld in PE- of ELF-uitvoerbare lêers
- Verkryging van **patrone** vir kriptanalise op lêers
- **Opspoor** van packer- of encoder-algoritmes
- **Identifisering** van steganografie deur patrone
- **Visuele** binêre diffing

BinVis is ’n uitstekende **beginpunt om vertroud te raak met ’n onbekende teiken** in ’n black-boxing-scenario.

## Spesifieke Data Carving-nutsmiddels

### FindAES

Soek AES-sleutels deur na hul sleutelroosters te soek. Kan 128-, 192- en 256-bis-sleutels vind, soos dié wat deur TrueCrypt en BitLocker gebruik word.

Laai [hier](https://sourceforge.net/projects/findaes/) af.

### YARA-X (triage van carved artefacts)

[YARA-X](https://github.com/VirusTotal/yara-x) is ’n Rust-herskrywing van YARA wat in 2024 bekendgestel is; VirusTotal rapporteer dat sommige regular-expression- en komplekse-lusreëls aansienlik vinniger kan loop.<sup>[[5]](#references)</sup> Die CLI daarvan heet `yr`, en die `scan`-opdrag ondersteun rekursiewe scans, ’n thread-telling en metadata-uitset.<sup>[[6]](#references)</sup>
```bash
# Scan every carved object produced by bulk_extractor
yr scan --recursive --threads 8 --print-meta rules/index.yar out_folder/
```
## Aanvullende gereedskap

Jy kan [**viu** ](https://github.com/atanunq/viu) gebruik om beelde vanaf die terminaal te sien.  \
Jy kan die Linux-command-line-nutsding **pdftotext** gebruik om ’n PDF in teks om te skakel en dit te lees.



## References

- [1] [Autopsy 4.21-vrystellingsnotas](https://github.com/sleuthkit/autopsy/releases/tag/autopsy-4.21.0)
- [2] [bulk_extractor v2.1.1 README](https://github.com/simsong/bulk_extractor/blob/v2.1.1/README.md)
- [3] [bulk_extractor Python-tools README](https://raw.githubusercontent.com/simsong/bulk_extractor/v2.1.1/python/README.txt)
- [4] [Path traversal in binwalk (CVE-2022-4510) - GitHub Advisory Database](https://github.com/advisories/GHSA-3cm8-v4mc-gppg)
- [5] [YARA is dead, long live YARA-X - VirusTotal Blog](https://blog.virustotal.com/2024/05/yara-is-dead-long-live-yara-x.html)
- [6] [YARA-X CLI commands](https://virustotal.github.io/yara-x/docs/cli/commands/)
- [7] [GNU ddrescue-handleiding](https://www.gnu.org/software/ddrescue/manual/ddrescue_manual.html)
- [8] [extundelete](https://extundelete.sourceforge.net/)
- [9] [ext4magic-handleiding](https://ext4magic.sourceforge.net/manpage_en.html)
- [10] [ext4magic-projekstatus](https://sourceforge.net/projects/ext4magic/)
{{#include ../../../banners/hacktricks-training.md}}
