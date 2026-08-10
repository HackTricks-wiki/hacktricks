# Zana za File/Data Carving na Recovery

## Zana za Carving na Recovery

Zana zaidi zinapatikana kwenye [https://github.com/Claudio-C/awesome-datarecovery](https://github.com/Claudio-C/awesome-datarecovery)

### Autopsy

Zana inayotumika zaidi katika forensics kwa ajili ya kutoa files kutoka kwenye images ni [**Autopsy**](https://www.autopsy.com/download/). Ipakue, isakinishe na uifanye iingest file ili kutafuta files "zilizofichwa". Kumbuka kuwa Autopsy imeundwa kusaidia disk images na aina nyingine za images, lakini si files rahisi.

### Binwalk <a href="#binwalk" id="binwalk"></a>

**Binwalk** ni tool ya kuchanganua binary files ili kutafuta content iliyopachikwa. Inaweza kusakinishwa kupitia `apt`, na source yake iko kwenye [GitHub](https://github.com/ReFirmLabs/binwalk).

**Amri muhimu**:
```bash
sudo apt install binwalk         # Installation
binwalk firmware.bin             # Display embedded data
binwalk -e firmware.bin          # Extract recognised objects (safe-default)
binwalk --dd " .* " firmware.bin  # Extract *everything* (use with care)
```
⚠️  **Security note** – Versions **2.1.2b through 2.3.3** zimeathiriwa na vulnerability ya **Path Traversal** (CVE-2022-4510); advisory haijaorodhesha toleo la pip lililorekebishwa. Epuka kutoa samples zisizoaminika kwa kutumia releases zilizoathiriwa, au tenga tool hiyo kwa kutumia container/non-privileged UID.<sup>[[4]](#references)</sup>

### Foremost

Tool nyingine ya kawaida ya kutafuta files zilizofichwa ni **foremost**. Unaweza kupata configuration file ya foremost katika `/etc/foremost.conf`. Ikiwa unataka tu kutafuta files maalum, ziondoe alama ya maoni. Usipoondoa alama yoyote ya maoni, foremost itatafuta file types zake za default zilizosanidiwa.
```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
# Discovered files will appear inside the folder "output"
```
### **Scalpel**

**Scalpel** ni tool nyingine inayoweza kutumiwa kutafuta na kutoa **files zilizopachikwa ndani ya file**. Katika hali hii, utahitaji kuondoa alama za maoni kwenye file ya configuration (_/etc/scalpel/scalpel.conf_) kwa aina za files unazotaka itoe.
```bash
sudo apt-get install scalpel
scalpel file.img -o output
```
### Bulk Extractor 2.x

Tool hii inakuja ndani ya kali lakini unaweza kuipata hapa: <https://github.com/simsong/bulk_extractor>

Bulk Extractor inaweza kuchanganua picha ya ushahidi na kuchopoa **pcap fragments**, **mabaki ya mtandao (URLs, domains, IPs, MACs, e-mails)** na vitu vingine vingi **kwa sambamba kwa kutumia scanners nyingi**.

Toleo la v2.1.1 linaweka kumbukumbu ya build ya Autotools na mpangilio wa `-S jpeg_carve_mode=2` wa kuchopoa JPEG zote zilizo contiguous.<sup>[[2]](#references)</sup>
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
The bundled `bulk_diff.py` compares two bulk_extractor runs, while `bulk_extractor_reader.py` reads the report and feature files.<sup>[[3]](#references)</sup>

### PhotoRec

Unaweza kuipata kwenye <https://www.cgsecurity.org/wiki/TestDisk_Download>

Inakuja na matoleo ya GUI na CLI. Unaweza kuchagua **file-types** unazotaka PhotoRec itafute.

![Endesha scanner zote, carve JPEGs kwa ukali na tengeneza bodyfile - PhotoRec: Inakuja na matoleo ya GUI na CLI. Unaweza kuchagua file-types unazotaka itafute](<../../../images/image (242).png>)

### ddrescue + ddrescueview (imaging failing drives)

Wakati drive ya kimwili haijatulia, ni best practice **kuifanya image kwanza** na kuendesha carving tools dhidi ya image hiyo pekee. `ddrescue` (GNU project) inalenga kunakili disks mbovu kwa kutegemeka huku ikihifadhi logi ya sectors ambazo hazijasomeka.
```bash
sudo apt install gddrescue ddrescueview   # On Debian-based systems
# First pass – try to get as much data as possible without retries
sudo ddrescue -f -n /dev/sdX suspect.img suspect.log
# Second pass – aggressive, 3 retries on the remaining bad areas
sudo ddrescue -d -r3 /dev/sdX suspect.img suspect.log

# Visualise the status map (green=good, red=bad)
ddrescueview suspect.log
```
Chaguo la **`--cluster-size`** hudhibiti idadi ya sectors zinazonakiliwa kwa wakati mmoja; thamani ndogo zinaweza kusaidia kwenye drives zenye kasi ndogo.<sup>[[7]](#references)</sup>

### Extundelete / Ext4magic (EXT 3/4 undelete)

Ikiwa mfumo wa faili chanzo unatokana na Linux EXT, unaweza kurejesha files zilizofutwa hivi karibuni **bila full carving**; tools hizi za journal-based hufanya kazi kwenye mfumo wa faili ambao hauja-mountiwa au image ya kusoma-tu.<sup>[[8]](#references)[[9]](#references)</sup>
```bash
# Attempt journal-based undelete (metadata must still be present)
extundelete disk.img --restore-all

# Multi-stage recovery from an ext4 image
ext4magic disk.img -M -d ./recovered
```
> **Dokezo la uoanifu** – ext4magic imeachwa; ukurasa wa mradi wake unaonya kwamba mifumo ya sasa ya faili haiendani tena nayo.<sup>[[10]](#references)</sup>

> 🛈 Ikiwa mfumo wa faili uliwekwa mount baada ya kufutwa, data blocks huenda tayari zilitumiwa tena – katika hali hiyo, data carving sahihi (Foremost/Scalpel) bado inahitajika.

### binvis

Angalia [code](https://code.google.com/archive/p/binvis/) na [web page tool](https://binvis.io/#/).

#### Vipengele vya BinVis

- **Muonekano wa muundo** wa kuona na unaotumika
- Ploti nyingi kwa maeneo tofauti ya umakini
- Kuelekeza umakini kwenye sehemu za sample
- **Kuona strings na resources**, katika executable za PE au ELF, kwa mfano
- Kupata **patterns** kwa cryptanalysis kwenye files
- **Kutambua** algorithms za packer au encoder
- **Kutambua** Steganography kupitia patterns
- **Binary-diffing** ya kuona

BinVis ni **mwanzo mzuri wa kuufahamu target isiyojulikana** katika hali ya black-boxing.

## Zana Mahususi za Data Carving

### FindAES

Hutafuta AES keys kwa kutafuta key schedules zake. Inaweza kupata keys za biti 128, 192 na 256, kama zile zinazotumiwa na TrueCrypt na BitLocker.

Pakua [hapa](https://sourceforge.net/projects/findaes/).

### YARA-X (triaging artefacts zilizofanyiwa carving)

[YARA-X](https://github.com/VirusTotal/yara-x) ni uandishi upya wa YARA kwa Rust ulioanzishwa mwaka 2024; VirusTotal inaripoti kwamba baadhi ya regular-expression na complex-loop rules zinaweza kuendeshwa kwa kasi kubwa zaidi.<sup>[[5]](#references)</sup> CLI yake inaitwa `yr`, na command ya `scan` inasaidia scans za kujirudia, kuweka idadi ya threads, na kutoa metadata.<sup>[[6]](#references)</sup>
```bash
# Scan every carved object produced by bulk_extractor
yr scan --recursive --threads 8 --print-meta rules/index.yar out_folder/
```
## Zana za ziada

Unaweza kutumia [**viu** ](https://github.com/atanunq/viu)kuona picha kutoka kwenye terminali.  \
Unaweza kutumia zana ya mstari wa amri ya Linux **pdftotext** kubadilisha pdf kuwa maandishi na kuyasoma.



## References

- [1] [Vidokezo vya toleo la Autopsy 4.21](https://github.com/sleuthkit/autopsy/releases/tag/autopsy-4.21.0)
- [2] [README ya bulk_extractor v2.1.1](https://github.com/simsong/bulk_extractor/blob/v2.1.1/README.md)
- [3] [README ya zana za Python za bulk_extractor](https://raw.githubusercontent.com/simsong/bulk_extractor/v2.1.1/python/README.txt)
- [4] [Path traversal katika binwalk (CVE-2022-4510) - GitHub Advisory Database](https://github.com/advisories/GHSA-3cm8-v4mc-gppg)
- [5] [YARA imekufa, iishi kwa muda mrefu YARA-X - Blogu ya VirusTotal](https://blog.virustotal.com/2024/05/yara-is-dead-long-live-yara-x.html)
- [6] [Amri za CLI za YARA-X](https://virustotal.github.io/yara-x/docs/cli/commands/)
- [7] [Mwongozo wa GNU ddrescue](https://www.gnu.org/software/ddrescue/manual/ddrescue_manual.html)
- [8] [extundelete](https://extundelete.sourceforge.net/)
- [9] [Mwongozo wa ext4magic](https://ext4magic.sourceforge.net/manpage_en.html)
- [10] [Hali ya mradi wa ext4magic](https://sourceforge.net/projects/ext4magic/)
{{#include ../../../banners/hacktricks-training.md}}
