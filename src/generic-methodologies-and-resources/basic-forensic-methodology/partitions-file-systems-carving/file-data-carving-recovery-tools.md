# File/Data Carving & Recovery Tools

{{#include ../../../banners/hacktricks-training.md}}

## Carving- en Recovery-tools

Meer tools by [https://github.com/Claudio-C/awesome-datarecovery](https://github.com/Claudio-C/awesome-datarecovery)

### Autopsy

Die mees algemene tool wat in forensiese ondersoeke gebruik word om lêers uit images te onttrek, is [**Autopsy**](https://www.autopsy.com/download/). Laai dit af, installeer dit en laat dit die lêer ingest om "versteekte" lêers te vind. Let daarop dat Autopsy gebou is om skyfimages en ander soorte images te ondersteun, maar nie eenvoudige lêers nie.

> **2024-2025-opdatering** – Weergawe **4.21** (vrygestel in Februarie 2025) het 'n herboude **carving-module gebaseer op SleuthKit v4.13** bygevoeg wat merkbaar vinniger is wanneer daar met multi-teragreep-images gewerk word en parallelle ekstraksie op multi-kern-stelsels ondersteun. 'n Klein CLI-wrapper (`autopsycli ingest <case> <image>`) is ook bekendgestel, wat dit moontlik maak om carving binne CI/CD- of grootskaalse laboratoriumomgewings te script.<sup>[[1]](#references)</sup>
```bash
# Create a case and ingest an evidence image from the CLI (Autopsy ≥4.21)
autopsycli case --create MyCase --base /cases
# ingest with the default ingest profile (includes data-carve module)
autopsycli ingest MyCase /evidence/disk01.E01 --threads 8
```
### Binwalk <a href="#binwalk" id="binwalk"></a>

**Binwalk** is ’n tool om binêre lêers te ontleed en ingebedde inhoud te vind. Dit kan via `apt` geïnstalleer word, en die bronkode is op [GitHub](https://github.com/ReFirmLabs/binwalk).

**Nuttige opdragte**:
```bash
sudo apt install binwalk         # Installation
binwalk firmware.bin             # Display embedded data
binwalk -e firmware.bin          # Extract recognised objects (safe-default)
binwalk --dd " .* " firmware.bin  # Extract *everything* (use with care)
```
⚠️  **Sekuriteitsnota** – Weergawes **≤2.3.3** word deur ’n **Path Traversal**-kwesbaarheid (CVE-2022-4510) geraak. Gradeer op (of isoleer met ’n container/nie-bevoorregte UID) voordat jy onbetroubare samples carve. <sup>[[2]](#references)</sup>

### Foremost

Nog ’n algemene tool om versteekte lêers te vind, is **foremost**. Jy kan die konfigurasielêer van foremost in `/etc/foremost.conf` vind. As jy net na spesifieke lêers wil soek, haal die kommentaar daarvoor weg. As jy niks se kommentaar verwyder nie, sal foremost na sy verstekgekonfigureerde lêertipes soek.
```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
# Discovered files will appear inside the folder "output"
```
### **Scalpel**

**Scalpel** is nog ’n tool wat gebruik kan word om **lêers wat in ’n lêer ingebed is** te vind en te onttrek. In hierdie geval sal jy die lêertipes wat jy wil onttrek, uit die konfigurasielêer (_/etc/scalpel/scalpel.conf_) moet uncomment.
```bash
sudo apt-get install scalpel
scalpel file.img -o output
```
### Bulk Extractor 2.x

Hierdie tool is deel van Kali, maar jy kan dit hier vind: <https://github.com/simsong/bulk_extractor>

Bulk Extractor kan ’n bewysbeeld skandeer en **pcap-fragmente**, **netwerk-artefakte (URL's, domeine, IP's, MAC's, e-posse)** en baie ander objekte **parallel met behulp van veelvuldige scanners carve**.
```bash
# Build from source – v2.1.1 (April 2024) requires cmake ≥3.16
git clone https://github.com/simsong/bulk_extractor.git && cd bulk_extractor
mkdir build && cd build && cmake .. && make -j$(nproc) && sudo make install

# Run every scanner, carve JPEGs aggressively and generate a bodyfile
bulk_extractor -o out_folder -S jpeg_carve_mode=2 -S write_bodyfile=y /evidence/disk.img
```
Nuttige post-processing-skripte (`bulk_diff`, `bulk_extractor_reader.py`) kan artefakte tussen twee images dedupliseer of resultate na JSON omskakel vir SIEM-inname.

### PhotoRec

Jy kan dit by <https://www.cgsecurity.org/wiki/TestDisk_Download> vind.

Dit kom met GUI- en CLI-weergawes. Jy kan die **lêertipes** kies waarna PhotoRec moet soek.

![Laat elke scanner loop, carve JPEG's aggressief en genereer 'n bodyfile - PhotoRec: Dit kom met GUI- en CLI-weergawes. Jy kan die lêertipes kies waarna PhotoRec moet soek](<../../../images/image (242).png>)

### ddrescue + ddrescueview (beeldskepping van falende drywe)

Wanneer 'n fisiese dryf onstabiel is, is dit beste praktyk om dit **eers te image** en dan slegs carving tools teen die image uit te voer. `ddrescue` (GNU-projek) fokus daarop om slegte skywe betroubaar te kopieer terwyl dit 'n logboek van onleesbare sektore byhou.
```bash
sudo apt install gddrescue ddrescueview   # On Debian-based systems
# First pass – try to get as much data as possible without retries
sudo ddrescue -f -n /dev/sdX suspect.img suspect.log
# Second pass – aggressive, 3 retries on the remaining bad areas
sudo ddrescue -d -r3 /dev/sdX suspect.img suspect.log

# Visualise the status map (green=good, red=bad)
ddrescueview suspect.log
```
Weergawe **1.28** (Desember 2024) het **`--cluster-size`** bekendgestel, wat imaging van hoëkapasiteit-SSD's kan versnel waar tradisionele sektorgroottes nie meer met flash-blokke ooreenstem nie.

### Extundelete / Ext4magic (EXT 3/4 undelete)

As die bronlêerstelsel Linux EXT-gebaseerd is, kan jy moontlik onlangs geskrapte lêers **sonder volledige carving** herstel. Albei nutsprogramme werk direk op ’n leesalleen-beeld:
```bash
# Attempt journal-based undelete (metadata must still be present)
extundelete disk.img --restore-all

# Fallback to full directory scan; supports extents and inline data
ext4magic disk.img -M -f '*.jpg' -d ./recovered
```
> 🛈 Indien die lêerstelsel ná die skrapping gemount is, is die datablokke moontlik reeds hergebruik – in daardie geval is behoorlike carving (Foremost/Scalpel) steeds nodig.

### binvis

Bekyk die [code](https://code.google.com/archive/p/binvis/) en die [webblad-tool](https://binvis.io/#/).

#### Kenmerke van BinVis

- Visuele en aktiewe **struktuurkyker**
- Veelvuldige grafieke vir verskillende fokuspunte
- Fokus op gedeeltes van ’n sample
- **Sien van strings en hulpbronne**, byvoorbeeld in PE- of ELF-executables
- Verkryging van **patrone** vir kriptanalise op lêers
- **Opspoor** van packer- of encoder-algoritmes
- **Identifisering** van Steganography volgens patrone
- **Visuele** binary-diffing

BinVis is ’n uitstekende **beginpunt om vertroud te raak met ’n onbekende teiken** in ’n black-boxing-scenario.

## Spesifieke Data Carving Tools

### FindAES

Soek na AES-sleutels deur na hul sleutelroosters te soek. Kan 128-, 192- en 256-bis-sleutels vind, soos dié wat deur TrueCrypt en BitLocker gebruik word.

Laai [hier](https://sourceforge.net/projects/findaes/) af.

### YARA-X (triage van carved artefacts)

[YARA-X](https://github.com/VirusTotal/yara-x) is ’n Rust-herskrywing van YARA wat in 2024 vrygestel is. Dit is **10-30× vinniger** as klassieke YARA en kan gebruik word om duisende carved objects baie vinnig te klassifiseer:<sup>[[3]](#references)</sup>
```bash
# Scan every carved object produced by bulk_extractor
yarax -r rules/index.yar out_folder/ --threads 8 --print-meta
```
Die versnelling maak dit realisties om alle gekerfde lêers tydens grootskaalse ondersoeke **outomaties te merk**.

## Aanvullende nutsmiddels

Jy kan [**viu** ](https://github.com/atanunq/viu)gebruik om beelde vanaf die terminaal te sien.  \
Jy kan die Linux-opdragreëlnutsmiddel **pdftotext** gebruik om ’n PDF na teks om te skakel en dit te lees.



## Verwysings

- [1] [Autopsy 4.21 release notes](https://github.com/sleuthkit/autopsy/releases/tag/autopsy-4.21)
- [2] [Path traversal in binwalk (CVE-2022-4510) - GitHub Advisory Database](https://github.com/advisories/GHSA-3cm8-v4mc-gppg)
- [3] [YARA is dead, long live YARA-X - VirusTotal Blog](https://blog.virustotal.com/2024/05/yara-is-dead-long-live-yara-x.html)

{{#include ../../../banners/hacktricks-training.md}}
