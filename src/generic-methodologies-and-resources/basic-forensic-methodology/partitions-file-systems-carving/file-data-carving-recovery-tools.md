# Zana za File/Data Carving na Recovery

{{#include ../../../banners/hacktricks-training.md}}

## Zana za Carving na Recovery

Zana zaidi zinapatikana kwenye [https://github.com/Claudio-C/awesome-datarecovery](https://github.com/Claudio-C/awesome-datarecovery)

### Autopsy

Zana inayotumika zaidi katika forensics kuchota files kutoka kwenye images ni [**Autopsy**](https://www.autopsy.com/download/). Ipakue, isakinishe, kisha ifanye iingest file ili itafute files "zilizofichwa". Kumbuka kuwa Autopsy imeundwa kusaidia disk images na aina nyingine za images, lakini si files rahisi.

> **Sasisho la 2024-2025** – Version **4.21** (iliyotolewa Februari 2025) iliongeza **carving module** iliyoundwa upya kulingana na **SleuthKit v4.13**, ambayo ni ya haraka zaidi inaposhughulikia images zenye ukubwa wa multi-terabyte na inasaidia parallel extraction kwenye mifumo yenye multi-core. CLI wrapper ndogo (`autopsycli ingest <case> <image>`) pia ilianzishwa, na kufanya iwezekane kuscript carving ndani ya CI/CD au mazingira makubwa ya maabara.<sup>[[1]](#references)</sup>
```bash
# Create a case and ingest an evidence image from the CLI (Autopsy ≥4.21)
autopsycli case --create MyCase --base /cases
# ingest with the default ingest profile (includes data-carve module)
autopsycli ingest MyCase /evidence/disk01.E01 --threads 8
```
### Binwalk <a href="#binwalk" id="binwalk"></a>

**Binwalk** ni tool ya kuchanganua binary files ili kupata maudhui yaliyopachikwa. Inaweza kusakinishwa kupitia `apt`, na source code yake inapatikana kwenye [GitHub](https://github.com/ReFirmLabs/binwalk).

**Commands muhimu**:
```bash
sudo apt install binwalk         # Installation
binwalk firmware.bin             # Display embedded data
binwalk -e firmware.bin          # Extract recognised objects (safe-default)
binwalk --dd " .* " firmware.bin  # Extract *everything* (use with care)
```
⚠️  **Dokezo la usalama** – Matoleo **≤2.3.3** yanaathiriwa na udhaifu wa **Path Traversal** (CVE-2022-4510). Fanya upgrade (au tenga kwa kutumia container/non-privileged UID) kabla ya kuchanganua samples zisizoaminika.<sup>[[2]](#references)</sup>

### Foremost

Zana nyingine ya kawaida ya kutafuta files zilizofichwa ni **foremost**. Unaweza kupata configuration file ya foremost katika `/etc/foremost.conf`. Ikiwa unataka tu kutafuta files mahususi, ziondoe alama ya maoni. Usipoondoa alama yoyote ya maoni, foremost itatafuta aina za files zilizosanidiwa kwa default.
```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
# Discovered files will appear inside the folder "output"
```
### **Scalpel**

**Scalpel** ni zana nyingine inayoweza kutumika kutafuta na kutoa **faili zilizopachikwa ndani ya faili**. Katika hali hii, utahitaji kuondoa alama za maoni kwenye aina za faili unazotaka zitoe kutoka kwenye faili ya usanidi (_/etc/scalpel/scalpel.conf_).
```bash
sudo apt-get install scalpel
scalpel file.img -o output
```
### Bulk Extractor 2.x

Tool hii inapatikana ndani ya kali, lakini unaweza kuipata hapa: <https://github.com/simsong/bulk_extractor>

Bulk Extractor inaweza kuchanganua picha ya ushahidi na ku-carve **pcap fragments**, **network artefacts (URLs, domains, IPs, MACs, e-mails)** pamoja na vitu vingine vingi **kwa wakati mmoja kwa kutumia scanners nyingi**.
```bash
# Build from source – v2.1.1 (April 2024) requires cmake ≥3.16
git clone https://github.com/simsong/bulk_extractor.git && cd bulk_extractor
mkdir build && cd build && cmake .. && make -j$(nproc) && sudo make install

# Run every scanner, carve JPEGs aggressively and generate a bodyfile
bulk_extractor -o out_folder -S jpeg_carve_mode=2 -S write_bodyfile=y /evidence/disk.img
```
Useful post-processing scripts (`bulk_diff`, `bulk_extractor_reader.py`) zinaweza kuondoa artefacts zinazojirudia kati ya images mbili au kubadilisha matokeo kuwa JSON kwa ajili ya SIEM ingestion.

### PhotoRec

Unaweza kuipata kwenye <https://www.cgsecurity.org/wiki/TestDisk_Download>

Inakuja na matoleo ya GUI na CLI. Unaweza kuchagua **aina za faili** unazotaka PhotoRec itafute.

![Endesha scanners zote, carva JPEGs kwa ukali na utengeneze bodyfile - PhotoRec: Inakuja na matoleo ya GUI na CLI. Unaweza kuchagua aina za faili unazotaka PhotoRec itafute](<../../../images/image (242).png>)

### ddrescue + ddrescueview (imaging drives zinazoshindwa)

Drive ya kimwili inapokuwa unstable, best practice ni **kuifanya image kwanza** na kuendesha carving tools dhidi ya image pekee. `ddrescue` (GNU project) inalenga kunakili disks mbovu kwa uaminifu huku ikihifadhi log ya sectors zisizosomika.
```bash
sudo apt install gddrescue ddrescueview   # On Debian-based systems
# First pass – try to get as much data as possible without retries
sudo ddrescue -f -n /dev/sdX suspect.img suspect.log
# Second pass – aggressive, 3 retries on the remaining bad areas
sudo ddrescue -d -r3 /dev/sdX suspect.img suspect.log

# Visualise the status map (green=good, red=bad)
ddrescueview suspect.log
```
Version **1.28** (Desemba 2024) ilianzisha **`--cluster-size`**, ambayo inaweza kuharakisha uundaji wa image wa SSD zenye uwezo mkubwa ambapo sector sizes za kawaida haziendani tena na flash blocks.

### Extundelete / Ext4magic (EXT 3/4 undelete)

Ikiwa file system ya chanzo inategemea Linux EXT, unaweza kurejesha files zilizofutwa hivi karibuni **bila kufanya carving kamili**. Tools zote mbili hufanya kazi moja kwa moja kwenye image ya read-only:
```bash
# Attempt journal-based undelete (metadata must still be present)
extundelete disk.img --restore-all

# Fallback to full directory scan; supports extents and inline data
ext4magic disk.img -M -f '*.jpg' -d ./recovered
```
> 🛈 Ikiwa mfumo wa faili uliwekwa (mounted) baada ya kufutwa, data blocks huenda tayari zimetumiwa tena – katika hali hiyo bado inahitajika carving sahihi (Foremost/Scalpel).

### binvis

Angalia [code](https://code.google.com/archive/p/binvis/) na [web page tool](https://binvis.io/#/).

#### Features of BinVis

- **Muonyeshaji wa muundo** wa kuona na wa kiamilifu
- Ploti nyingi kwa sehemu mbalimbali za kuzingatia
- Kuzingatia sehemu za sample
- **Kuona strings na resources**, kwa mfano katika executables za PE au ELF
- Kupata **patterns** kwa cryptanalysis kwenye files
- **Kutambua** algorithms za packer au encoder
- **Kutambua** Steganography kupitia patterns
- **Binary-diffing** ya kuona

BinVis ni **start-point** nzuri ya kufahamiana na **target isiyojulikana** katika scenario ya black-boxing.

## Specific Data Carving Tools

### FindAES

Hutafuta AES keys kwa kutafuta key schedules zao. Inaweza kupata keys za biti 128, 192 na 256, kama zile zinazotumiwa na TrueCrypt na BitLocker.

Pakua [hapa](https://sourceforge.net/projects/findaes/).

### YARA-X (triaging carved artefacts)

[YARA-X](https://github.com/VirusTotal/yara-x) ni rewrite ya YARA katika Rust iliyotolewa mwaka wa 2024. Ni **mara 10-30× kwa kasi** kuliko YARA ya kawaida na inaweza kutumika kuainisha maelfu ya carved objects kwa haraka sana:<sup>[[3]](#references)</sup>.
```bash
# Scan every carved object produced by bulk_extractor
yarax -r rules/index.yar out_folder/ --threads 8 --print-meta
```
Ongezeko la kasi hufanya iwezekane kwa uhalisia **auto-tag** faili zote zilizocarve katika uchunguzi wa kiwango kikubwa.

## Zana saidizi

Unaweza kutumia [**viu** ](https://github.com/atanunq/viu)kuona picha kutoka kwenye terminal.  \
Unaweza kutumia zana ya linux ya command line **pdftotext** kubadilisha pdf kuwa maandishi na kuyasoma.



## Marejeleo

- [1] [Maelezo ya toleo la Autopsy 4.21](https://github.com/sleuthkit/autopsy/releases/tag/autopsy-4.21)
- [2] [Path traversal in binwalk (CVE-2022-4510) - GitHub Advisory Database](https://github.com/advisories/GHSA-3cm8-v4mc-gppg)
- [3] [YARA is dead, long live YARA-X - VirusTotal Blog](https://blog.virustotal.com/2024/05/yara-is-dead-long-live-yara-x.html)

{{#include ../../../banners/hacktricks-training.md}}
