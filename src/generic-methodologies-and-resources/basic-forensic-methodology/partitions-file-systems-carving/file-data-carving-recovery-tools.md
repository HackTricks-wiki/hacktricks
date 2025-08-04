# File/Data Carving & Recovery Tools

{{#include ../../../banners/hacktricks-training.md}}

## Carving & Recovery tools

Meer gereedskap in [https://github.com/Claudio-C/awesome-datarecovery](https://github.com/Claudio-C/awesome-datarecovery)

### Autopsy

Die mees algemene gereedskap wat in forensiese ondersoeke gebruik word om lêers uit beelde te onttrek, is [**Autopsy**](https://www.autopsy.com/download/). Laai dit af, installeer dit en laat dit die lêer verwerk om "versteekte" lêers te vind. Let daarop dat Autopsy gebou is om skyfbeelde en ander soorte beelde te ondersteun, maar nie eenvoudige lêers nie.

> **2024-2025 opdatering** – Weergawe **4.21** (vrygestel Februarie 2025) het 'n herboude **carving-module gebaseer op SleuthKit v4.13** bygevoeg wat merkbaar vinniger is wanneer dit met multi-terabyte beelde werk en parallelle onttrekking op multi-kern stelsels ondersteun.¹ 'n Klein CLI-wrapper (`autopsycli ingest <case> <image>`) is ook bekendgestel, wat dit moontlik maak om carving binne CI/CD of groot skaal laboratoriumomgewings te skryf.
```bash
# Create a case and ingest an evidence image from the CLI (Autopsy ≥4.21)
autopsycli case --create MyCase --base /cases
# ingest with the default ingest profile (includes data-carve module)
autopsycli ingest MyCase /evidence/disk01.E01 --threads 8
```
### Binwalk <a href="#binwalk" id="binwalk"></a>

**Binwalk** is 'n hulpmiddel om binêre lêers te analiseer om ingebedde inhoud te vind. Dit kan geïnstalleer word via `apt` en sy bron is op [GitHub](https://github.com/ReFirmLabs/binwalk).

**Nuttige opdragte**:
```bash
sudo apt install binwalk         # Installation
binwalk firmware.bin             # Display embedded data
binwalk -e firmware.bin          # Extract recognised objects (safe-default)
binwalk --dd " .* " firmware.bin  # Extract *everything* (use with care)
```
⚠️  **Sekuriteitsnota** – Weergawes **≤2.3.3** is geraak deur 'n **Pad Traversal** kwesbaarheid (CVE-2022-4510). Opgradeer (of isoleer met 'n houer/nie-bevoegde UID) voordat jy onbetroubare monsters karve.

### Foremost

Nog 'n algemene hulpmiddel om verborge lêers te vind is **foremost**. Jy kan die konfigurasielêer van foremost in `/etc/foremost.conf` vind. As jy net vir 'n paar spesifieke lêers wil soek, ontkommentaar hulle. As jy niks ontkommentaar nie, sal foremost vir sy standaard geconfigureerde lêertipes soek.
```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
# Discovered files will appear inside the folder "output"
```
### **Scalpel**

**Scalpel** is 'n ander hulpmiddel wat gebruik kan word om **lêers wat in 'n lêer ingebed is** te vind en te onttrek. In hierdie geval sal jy die lêertipes wat jy wil hê dit moet onttrek, uit die konfigurasielêer (_/etc/scalpel/scalpel.conf_) moet ontkommentaar.
```bash
sudo apt-get install scalpel
scalpel file.img -o output
```
### Bulk Extractor 2.x

Hierdie hulpmiddel kom binne kali, maar jy kan dit hier vind: <https://github.com/simsong/bulk_extractor>

Bulk Extractor kan 'n bewysbeeld skandeer en **pcap fragmente**, **netwerk artefakte (URL's, domeine, IP's, MAC's, e-posse)** en baie ander voorwerpe **gelyktydig met verskeie skandeerders** karve.
```bash
# Build from source – v2.1.1 (April 2024) requires cmake ≥3.16
git clone https://github.com/simsong/bulk_extractor.git && cd bulk_extractor
mkdir build && cd build && cmake .. && make -j$(nproc) && sudo make install

# Run every scanner, carve JPEGs aggressively and generate a bodyfile
bulk_extractor -o out_folder -S jpeg_carve_mode=2 -S write_bodyfile=y /evidence/disk.img
```
Nuttige post-verwerkingskripte (`bulk_diff`, `bulk_extractor_reader.py`) kan artefakte tussen twee beelde de-dupliseer of resultate na JSON omskakel vir SIEM-inname.

### PhotoRec

Jy kan dit vind in <https://www.cgsecurity.org/wiki/TestDisk_Download>

Dit kom met GUI en CLI weergawes. Jy kan die **lêer-tipes** kies waarvoor jy wil hê PhotoRec moet soek.

![](<../../../images/image (242).png>)

### ddrescue + ddrescueview (beelde van faalende skywe)

Wanneer 'n fisiese skyf onstabiel is, is dit die beste praktyk om dit **eers te beeld** en slegs karweergereedskap teen die beeld te gebruik. `ddrescue` (GNU projek) fokus op die betroubare kopieer van slegte skywe terwyl 'n log van onleesbare sektore gehou word.
```bash
sudo apt install gddrescue ddrescueview   # On Debian-based systems
# First pass – try to get as much data as possible without retries
sudo ddrescue -f -n /dev/sdX suspect.img suspect.log
# Second pass – aggressive, 3 retries on the remaining bad areas
sudo ddrescue -d -r3 /dev/sdX suspect.img suspect.log

# Visualise the status map (green=good, red=bad)
ddrescueview suspect.log
```
Version **1.28** (Desember 2024) het **`--cluster-size`** bekendgestel wat die beeldvorming van hoë kapasiteit SSD's kan versnel waar tradisionele sektor groottes nie meer met flitsblokke ooreenstem nie.

### Extundelete / Ext4magic (EXT 3/4 ongedaan maak)

As die bron lêerstelsel op Linux EXT-gebaseer is, kan jy dalk onlangs verwyderde lêers herstel **sonder volledige karving**. Beide gereedskap werk direk op 'n lees-slegs beeld:
```bash
# Attempt journal-based undelete (metadata must still be present)
extundelete disk.img --restore-all

# Fallback to full directory scan; supports extents and inline data
ext4magic disk.img -M -f '*.jpg' -d ./recovered
```
> 🛈 As die lêerstelsel gemonteer is na verwydering, mag die datablokke reeds hergebruik wees – in daardie geval is behoorlike carving (Foremost/Scalpel) steeds nodig.

### binvis

Kyk na die [code](https://code.google.com/archive/p/binvis/) en die [webblad hulpmiddel](https://binvis.io/#/).

#### Kenmerke van BinVis

- Visuele en aktiewe **struktuurkyker**
- Meerdere grafieke vir verskillende fokuspunte
- Fokus op gedeeltes van 'n monster
- **Sien stings en hulpbronne**, in PE of ELF uitvoerbare lêers bv.
- Kry **patrone** vir kriptoanalise op lêers
- **Identifiseer** pakker of kodering algoritmes
- **Identifiseer** Steganografie deur patrone
- **Visuele** binêre-diffing

BinVis is 'n uitstekende **beginpunt om bekend te raak met 'n onbekende teiken** in 'n swart-doos scenario.

## Spesifieke Data Carving Gereedskap

### FindAES

Soek na AES sleutels deur hul sleutel skedules te soek. In staat om 128, 192, en 256 bit sleutels te vind, soos dié wat deur TrueCrypt en BitLocker gebruik word.

Laai [hier](https://sourceforge.net/projects/findaes/) af.

### YARA-X (triaging carved artefacts)

[YARA-X](https://github.com/VirusTotal/yara-x) is 'n Rust herskrywing van YARA wat in 2024 vrygestel is. Dit is **10-30× vinniger** as klassieke YARA en kan gebruik word om duisende gegraveerde voorwerpe baie vinnig te klassifiseer:
```bash
# Scan every carved object produced by bulk_extractor
yarax -r rules/index.yar out_folder/ --threads 8 --print-meta
```
Die spoedverhoging maak dit realisties om **auto-tag** al die gegraveerde lêers in grootmaat ondersoeke.

## Aanvullende gereedskap

Jy kan [**viu** ](https://github.com/atanunq/viu) gebruik om beelde vanaf die terminal te sien.  \
Jy kan die Linux-opdraglyn gereedskap **pdftotext** gebruik om 'n pdf in teks te omskep en dit te lees.

## Verwysings

1. Autopsy 4.21 vrylating notas – <https://github.com/sleuthkit/autopsy/releases/tag/autopsy-4.21>
{{#include ../../../banners/hacktricks-training.md}}
