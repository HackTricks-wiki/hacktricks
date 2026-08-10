# File/Data Carving- en Herstelnutsgoed

## Carving- en hersteltools

Meer tools by [https://github.com/Claudio-C/awesome-datarecovery](https://github.com/Claudio-C/awesome-datarecovery)

### Autopsy

Die algemeenste tool wat in forensics gebruik word om lêers uit images te onttrek, is [**Autopsy**](https://www.autopsy.com/download/). Laai dit af, installeer dit en laat dit die lêer ingest om "verborge" lêers te vind. Let daarop dat Autopsy ontwerp is om disk images en ander soorte images te ondersteun, maar nie eenvoudige lêers nie.

### Binwalk <a href="#binwalk" id="binwalk"></a>

**Binwalk** is 'n tool vir die ontleding van binary files om ingebedde inhoud te vind. Dit kan via `apt` geïnstalleer word en die bronkode daarvan is op [GitHub](https://github.com/ReFirmLabs/binwalk).

**Nuttige opdragte**:
```bash
sudo apt install binwalk         # Installation
binwalk firmware.bin             # Display embedded data
binwalk -e firmware.bin          # Extract recognised objects (safe-default)
binwalk --dd " .* " firmware.bin  # Extract *everything* (use with care)
```
⚠️  **Sekuriteitsnota** – Weergawes **2.1.2b tot en met 2.3.3** word deur ’n **Path Traversal**-kwesbaarheid (CVE-2022-4510) geraak; die advies lys geen reggestelde pip-weergawe nie. Vermy die onttrekking van onbetroubare samples met geraakte vrystellings, of isoleer die tool met ’n container/nie-bevoorregte UID.<sup>[[4]](#references)</sup>

### Foremost

Nog ’n algemene hulpmiddel om versteekte lêers te vind, is **foremost**. Jy kan die konfigurasielêer van foremost in `/etc/foremost.conf` vind. As jy net vir sekere lêers wil soek, verwyder die kommentaartekens daarvan. As jy niks se kommentaartekens verwyder nie, sal foremost vir sy verstek-gekonfigureerde lêertipes soek.
```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
# Discovered files will appear inside the folder "output"
```
### **Scalpel**

**Scalpel** is nog ’n instrument wat gebruik kan word om **lêers wat in ’n lêer ingebed is** te vind en te onttrek. In hierdie geval moet jy die lêertipes wat jy wil onttrek uit die konfigurasielêer (_/etc/scalpel/scalpel.conf_) se kommentaar verwyder.
```bash
sudo apt-get install scalpel
scalpel file.img -o output
```
### Bulk Extractor 2.x

Hierdie tool is ingesluit by kali, maar jy kan dit hier vind: <https://github.com/simsong/bulk_extractor>

Bulk Extractor kan ’n bewysbeeld skandeer en **pcap fragments**, **network artefacts (URLs, domains, IPs, MACs, e-mails)** en baie ander objekte **parallel met behulp van multiple scanners** carve.

Die v2.1.1-vrystelling dokumenteer ’n Autotools-build en die `-S jpeg_carve_mode=2`-setting vir die carving van alle aaneenlopende JPEGs.<sup>[[2]](#references)</sup>
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
Die ingeslote `bulk_diff.py` vergelyk twee bulk_extractor-uitvoerings, terwyl `bulk_extractor_reader.py` die verslag- en feature-lêers lees.<sup>[[3]](#references)</sup>

### PhotoRec

Jy kan dit by <https://www.cgsecurity.org/wiki/TestDisk_Download> vind.

Dit kom met GUI- en CLI-weergawes. Jy kan die **lêertipes** kies waarna PhotoRec moet soek.

![Run every scanner, carve JPEGs aggressively and generate a bodyfile - PhotoRec: Dit kom met GUI- en CLI-weergawes. Jy kan die lêertipes kies waarna PhotoRec moet soek](<../../../images/image (242).png>)

### ddrescue + ddrescueview (beeldskepping van falende drywe)

Wanneer ’n fisiese skyf onstabiel is, is dit beste praktyk om dit **eers af te beeld** en slegs daarna carving-tools teen die beeld te laat loop. `ddrescue` (GNU-projek) fokus daarop om beskadigde skywe betroubaar te kopieer terwyl ’n logboek van onleesbare sektore behou word.
```bash
sudo apt install gddrescue ddrescueview   # On Debian-based systems
# First pass – try to get as much data as possible without retries
sudo ddrescue -f -n /dev/sdX suspect.img suspect.log
# Second pass – aggressive, 3 retries on the remaining bad areas
sudo ddrescue -d -r3 /dev/sdX suspect.img suspect.log

# Visualise the status map (green=good, red=bad)
ddrescueview suspect.log
```
Die **`--cluster-size`**-opsie beheer hoeveel sektore op ’n slag gekopieer word; kleiner waardes kan met stadige aandrywers help.<sup>[[7]](#references)</sup>

### Extundelete / Ext4magic (EXT 3/4 undelete)

As die bronlêerstelsel Linux EXT-gebaseer is, kan jy moontlik onlangs geskrapte lêers **sonder volledige carving** herwin; hierdie joernaalgebaseerde nutsprogramme werk op ’n ontkoppelde lêerstelsel of ’n leesalleenbeeld.<sup>[[8]](#references)[[9]](#references)</sup>
```bash
# Attempt journal-based undelete (metadata must still be present)
extundelete disk.img --restore-all

# Multi-stage recovery from an ext4 image
ext4magic disk.img -M -d ./recovered
```
> **Verenigbaarheidsnota** – ext4magic is verlate; sy projekblad waarsku dat huidige lêerstelsels nie meer daarmee versoenbaar is nie.<sup>[[10]](#references)</sup>

> 🛈 Indien die lêerstelsel ná uitvee gemonteer is, is die datablokke moontlik reeds hergebruik – in daardie geval is behoorlike carving (Foremost/Scalpel) steeds nodig.

### binvis

Kyk na die [code](https://code.google.com/archive/p/binvis/) en die [webblad-nutsding](https://binvis.io/#/).

#### Kenmerke van BinVis

- Visuele en aktiewe **struktuurkyker**
- Veelvuldige grafieke vir verskillende fokuspunte
- Fokus op gedeeltes van ’n monster
- **Sienings van strings en hulpbronne**, byvoorbeeld in PE- of ELF-uitvoerbare lêers
- Kry **patrone** vir kriptanalise op lêers
- **Identifisering** van packer- of encoder-algoritmes
- **Identifiseer** Steganography volgens patrone
- **Visuele** binêre diffing

BinVis is ’n uitstekende **beginpunt om met ’n onbekende teiken vertroud te raak** in ’n black-boxing-scenario.

## Spesifieke Data Carving Tools

### FindAES

Soek AES-sleutels deur na hul sleutelroosters te soek. Kan 128-, 192- en 256-bis-sleutels vind, soos dié wat deur TrueCrypt en BitLocker gebruik word.

Laai [hier](https://sourceforge.net/projects/findaes/) af.

### YARA-X (triaging van carved artefakte)

[YARA-X](https://github.com/VirusTotal/yara-x) is ’n Rust-herskrywing van YARA wat in 2024 bekendgestel is; VirusTotal rapporteer dat sommige regular-expression- en komplekse-lus-reëls aansienlik vinniger kan loop.<sup>[[5]](#references)</sup> Die CLI heet `yr`, en die `scan`-opdrag ondersteun rekursiewe skanderings, ’n aantal threads en metadata-uitvoer.<sup>[[6]](#references)</sup>
```bash
# Scan every carved object produced by bulk_extractor
yr scan --recursive --threads 8 --print-meta rules/index.yar out_folder/
```
## Aanvullende gereedskap

Jy kan [**viu** ](https://github.com/atanunq/viu) gebruik om beelde vanaf die terminale te sien.  \
Jy kan die Linux-opdragreëlnutsding **pdftotext** gebruik om 'n pdf na teks om te skakel en dit te lees.



## References

- [1] [Autopsy 4.21-vrystellingsnotas](https://github.com/sleuthkit/autopsy/releases/tag/autopsy-4.21.0)
- [2] [bulk_extractor v2.1.1 README](https://github.com/simsong/bulk_extractor/blob/v2.1.1/README.md)
- [3] [bulk_extractor Python-nutsgoed README](https://raw.githubusercontent.com/simsong/bulk_extractor/v2.1.1/python/README.txt)
- [4] [Path traversal in binwalk (CVE-2022-4510) - GitHub Advisory Database](https://github.com/advisories/GHSA-3cm8-v4mc-gppg)
- [5] [YARA is dood, lank lewe YARA-X - VirusTotal Blog](https://blog.virustotal.com/2024/05/yara-is-dead-long-live-yara-x.html)
- [6] [YARA-X CLI-opdragte](https://virustotal.github.io/yara-x/docs/cli/commands/)
- [7] [GNU ddrescue-handleiding](https://www.gnu.org/software/ddrescue/manual/ddrescue_manual.html)
- [8] [extundelete](https://extundelete.sourceforge.net/)
- [9] [ext4magic-handleiding](https://ext4magic.sourceforge.net/manpage_en.html)
- [10] [ext4magic-projekstatus](https://sourceforge.net/projects/ext4magic/)
{{#include ../../../banners/hacktricks-training.md}}
