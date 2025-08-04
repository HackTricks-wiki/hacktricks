# File/Data Carving & Recovery Tools

{{#include ../../../banners/hacktricks-training.md}}

## Carving & Recovery tools

Zana zaidi zinapatikana katika [https://github.com/Claudio-C/awesome-datarecovery](https://github.com/Claudio-C/awesome-datarecovery)

### Autopsy

Zana inayotumika sana katika uchunguzi wa kidijitali kutoa faili kutoka kwa picha ni [**Autopsy**](https://www.autopsy.com/download/). Pakua, sakinisha na fanya iweze kuchukua faili ili kupata faili "zilizofichwa". Kumbuka kwamba Autopsy imejengwa kusaidia picha za diski na aina nyingine za picha, lakini si faili rahisi.

> **2024-2025 sasisho** – Toleo **4.21** (lililotolewa Februari 2025) limeongeza moduli mpya ya **carving iliyojengwa upya kulingana na SleuthKit v4.13** ambayo ni ya haraka zaidi inaposhughulikia picha za multi-terabyte na inasaidia utoaji wa sambamba kwenye mifumo ya multi-core.¹  Wrapper ndogo ya CLI (`autopsycli ingest <case> <image>`) pia ilianzishwa, ikifanya iwezekane kuandika carving ndani ya mazingira ya CI/CD au maabara makubwa.
```bash
# Create a case and ingest an evidence image from the CLI (Autopsy ≥4.21)
autopsycli case --create MyCase --base /cases
# ingest with the default ingest profile (includes data-carve module)
autopsycli ingest MyCase /evidence/disk01.E01 --threads 8
```
### Binwalk <a href="#binwalk" id="binwalk"></a>

**Binwalk** ni chombo cha kuchambua faili za binary ili kupata maudhui yaliyojumuishwa. Inaweza kusakinishwa kupitia `apt` na chanzo chake kiko kwenye [GitHub](https://github.com/ReFirmLabs/binwalk).

**Amri muhimu**:
```bash
sudo apt install binwalk         # Installation
binwalk firmware.bin             # Display embedded data
binwalk -e firmware.bin          # Extract recognised objects (safe-default)
binwalk --dd " .* " firmware.bin  # Extract *everything* (use with care)
```
⚠️  **Kumbuka Usalama** – Matoleo **≤2.3.3** yanakabiliwa na udhaifu wa **Path Traversal** (CVE-2022-4510). Pandisha (au tengeneza mazingira na kontena/UID isiyo na mamlaka) kabla ya kuchonga sampuli zisizoaminika.

### Foremost

Chombo kingine cha kawaida cha kutafuta faili zilizofichwa ni **foremost**. Unaweza kupata faili ya usanidi ya foremost katika `/etc/foremost.conf`. Ikiwa unataka tu kutafuta faili fulani, ondoa alama ya maoni. Ikiwa hutaondoa alama ya maoni, foremost itatafuta aina zake za faili zilizopangwa kwa default.
```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
# Discovered files will appear inside the folder "output"
```
### **Scalpel**

**Scalpel** ni chombo kingine ambacho kinaweza kutumika kupata na kutoa **faili zilizojumuishwa ndani ya faili**. Katika kesi hii, utahitaji kuondoa maoni kutoka kwa faili ya usanidi (_/etc/scalpel/scalpel.conf_) aina za faili unazotaka ikatoe.
```bash
sudo apt-get install scalpel
scalpel file.img -o output
```
### Bulk Extractor 2.x

Zana hii inapatikana ndani ya kali lakini unaweza kuipata hapa: <https://github.com/simsong/bulk_extractor>

Bulk Extractor inaweza kuskan picha ya ushahidi na kuchonga **pcap fragments**, **vitu vya mtandao (URLs, domains, IPs, MACs, e-mails)** na vitu vingine vingi **kwa pamoja kwa kutumia skana nyingi**.
```bash
# Build from source – v2.1.1 (April 2024) requires cmake ≥3.16
git clone https://github.com/simsong/bulk_extractor.git && cd bulk_extractor
mkdir build && cd build && cmake .. && make -j$(nproc) && sudo make install

# Run every scanner, carve JPEGs aggressively and generate a bodyfile
bulk_extractor -o out_folder -S jpeg_carve_mode=2 -S write_bodyfile=y /evidence/disk.img
```
Useful post-processing scripts (`bulk_diff`, `bulk_extractor_reader.py`) zinaweza kuondoa nakala za artefacts kati ya picha mbili au kubadilisha matokeo kuwa JSON kwa ajili ya upokeaji wa SIEM.

### PhotoRec

Unaweza kuipata katika <https://www.cgsecurity.org/wiki/TestDisk_Download>

Inakuja na toleo la GUI na CLI. Unaweza kuchagua **aina za faili** unazotaka PhotoRec itafute.

![](<../../../images/image (242).png>)

### ddrescue + ddrescueview (kuunda picha za diski zinazoshindwa)

Wakati diski ya kimwili haiko imara, ni bora kufanya **picha yake kwanza** na kisha kutumia zana za carving dhidi ya picha hiyo. `ddrescue` (mradi wa GNU) inazingatia kunakili diski mbovu kwa uaminifu huku ikihifadhi kumbukumbu ya sehemu zisizoweza kusomwa.
```bash
sudo apt install gddrescue ddrescueview   # On Debian-based systems
# First pass – try to get as much data as possible without retries
sudo ddrescue -f -n /dev/sdX suspect.img suspect.log
# Second pass – aggressive, 3 retries on the remaining bad areas
sudo ddrescue -d -r3 /dev/sdX suspect.img suspect.log

# Visualise the status map (green=good, red=bad)
ddrescueview suspect.log
```
Version **1.28** (Desemba 2024) ilianzisha **`--cluster-size`** ambayo inaweza kuongeza kasi ya picha za SSD zenye uwezo mkubwa ambapo saizi za sekta za jadi hazifanani tena na vizuizi vya flash.

### Extundelete / Ext4magic (EXT 3/4 undelete)

Ikiwa mfumo wa faili wa chanzo ni wa Linux EXT, unaweza kuwa na uwezo wa kurejesha faili zilizofutwa hivi karibuni **bila kuchonga kabisa**. Zana zote mbili zinafanya kazi moja kwa moja kwenye picha isiyoandikwa:
```bash
# Attempt journal-based undelete (metadata must still be present)
extundelete disk.img --restore-all

# Fallback to full directory scan; supports extents and inline data
ext4magic disk.img -M -f '*.jpg' -d ./recovered
```
> 🛈 Ikiwa mfumo wa faili ulitolewa baada ya kufutwa, vizuizi vya data vinaweza kuwa vimekwishatumika tena - katika kesi hiyo, kuchora vizuri (Foremost/Scalpel) bado kunahitajika.

### binvis

Angalia [code](https://code.google.com/archive/p/binvis/) na [web page tool](https://binvis.io/#/).

#### Vipengele vya BinVis

- Mtazamaji wa **muundo** wa kuona na wa kazi
- Njia nyingi za kuzingatia maeneo tofauti
- Kuangazia sehemu za sampuli
- **Kuona stings na rasilimali**, katika PE au ELF executable n.k.
- Kupata **mifumo** ya uchambuzi wa kificho kwenye faili
- **Kugundua** algorithms za pakka au encoder
- **Tambua** Steganography kwa mifumo
- **Kiona** tofauti za binary

BinVis ni **nukta ya kuanzia nzuri ili kufahamiana na lengo lisilojulikana** katika hali ya black-boxing.

## Zana Maalum za Kuchora Data

### FindAES

Inatafuta funguo za AES kwa kutafuta ratiba zao za funguo. Inaweza kupata funguo za 128, 192, na 256 bit, kama zile zinazotumiwa na TrueCrypt na BitLocker.

Pakua [hapa](https://sourceforge.net/projects/findaes/).

### YARA-X (kuangalia artefacts zilizochorwa)

[YARA-X](https://github.com/VirusTotal/yara-x) ni upya wa YARA ulioandikwa kwa Rust ulioachiliwa mwaka 2024. Ni **10-30× haraka** kuliko YARA ya jadi na inaweza kutumika kuainisha maelfu ya vitu vilivyopatikana haraka sana:
```bash
# Scan every carved object produced by bulk_extractor
yarax -r rules/index.yar out_folder/ --threads 8 --print-meta
```
Kuongeza kasi kunafanya iwe halisi **auto-tag** faili zote zilizokatwa katika uchunguzi wa kiwango kikubwa.

## Zana za nyongeza

Unaweza kutumia [**viu** ](https://github.com/atanunq/viu)kuona picha kutoka kwenye terminal.  \
Unaweza kutumia zana ya mistari ya amri ya linux **pdftotext** kubadilisha pdf kuwa maandiko na kuisoma.

## Marejeleo

1. Maelezo ya kutolewa kwa Autopsy 4.21 – <https://github.com/sleuthkit/autopsy/releases/tag/autopsy-4.21>
{{#include ../../../banners/hacktricks-training.md}}
