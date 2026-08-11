# Zana za File/Data Carving na Recovery

{{#include ../../../banners/hacktricks-training.md}}

## Zana za Carving na Recovery

Zana zaidi zinapatikana kwenye [https://github.com/Claudio-C/awesome-datarecovery](https://github.com/Claudio-C/awesome-datarecovery)

### Autopsy

Zana inayotumika zaidi katika forensics kutoa files kutoka kwenye images ni [**Autopsy**](https://www.autopsy.com/download/). Ipakue, isakinishe na iifanye iingize file ili kutafuta files "zilizofichwa". Kumbuka kwamba Autopsy imeundwa kusaidia disk images na aina nyingine za images, lakini si files rahisi.

### Binwalk <a href="#binwalk" id="binwalk"></a>

**Binwalk** ni zana ya kuchanganua binary files ili kupata maudhui yaliyopachikwa. Inaweza kusakinishwa kupitia `apt` na source yake iko kwenye [GitHub](https://github.com/ReFirmLabs/binwalk).

**Useful commands**:
```bash
sudo apt install binwalk         # Installation
binwalk firmware.bin             # Display embedded data
binwalk -e firmware.bin          # Extract recognised objects (safe-default)
binwalk --dd " .* " firmware.bin  # Extract *everything* (use with care)
```
⚠️  **Security note** – Versions **2.1.2b through 2.3.3** zimeathiriwa na vulnerability ya **Path Traversal** (CVE-2022-4510); advisory hainaorodhesha pip version iliyorekebishwa. Epuka kutoa samples zisizoaminika kwa kutumia releases zilizoathiriwa, au tenga tool hiyo kwa container/non-privileged UID.<sup>[[4]](#references)</sup>

### Foremost

Tool nyingine ya kawaida ya kutafuta files zilizofichwa ni **foremost**. Unaweza kupata configuration file ya foremost katika `/etc/foremost.conf`. Ikiwa unataka tu kutafuta files maalum, ziondoe maoni kwa kuzifungua. Usipofungua chochote, foremost itatafuta aina za files zilizosanidiwa kwa default.
```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
# Discovered files will appear inside the folder "output"
```
### **Scalpel**

**Scalpel** ni zana nyingine inayoweza kutumiwa kutafuta na kutoa **files zilizopachikwa ndani ya file**. Katika hali hii, utahitaji kuondoa alama za maoni kwenye aina za files unazotaka izitoe kutoka kwenye configuration file (_/etc/scalpel/scalpel.conf_).
```bash
sudo apt-get install scalpel
scalpel file.img -o output
```
### Bulk Extractor 2.x

Tool hii huja ndani ya kali, lakini unaweza kuipata hapa: <https://github.com/simsong/bulk_extractor>

Bulk Extractor inaweza kuchanganua image ya ushahidi na kufanya carving ya **pcap fragments**, **network artefacts (URLs, domains, IPs, MACs, e-mails)** pamoja na vitu vingine vingi **kwa wakati mmoja kwa kutumia scanners nyingi**.

Toleo la v2.1.1 linaandika kuhusu build ya Autotools na setting ya `-S jpeg_carve_mode=2` kwa ajili ya kufanya carving ya JPEG zote zilizo contiguous.<sup>[[2]](#references)</sup>
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
`bulk_diff.py` iliyojumuishwa hulinganisha matokeo ya runs mbili za bulk_extractor, huku `bulk_extractor_reader.py` ikisoma report na feature files.<sup>[[3]](#references)</sup>

### PhotoRec

Unaweza kuipata katika <https://www.cgsecurity.org/wiki/TestDisk_Download>

Inakuja na matoleo ya GUI na CLI. Unaweza kuchagua **aina za faili** unazotaka PhotoRec izitafute.

![Run every scanner, carve JPEGs aggressively and generate a bodyfile - PhotoRec: Inakuja na matoleo ya GUI na CLI. Unaweza kuchagua aina za faili unazotaka itafute](<../../../images/image (242).png>)

### ddrescue + ddrescueview (imaging failing drives)

Wakati drive halisi haiko thabiti, ni best practice **kuunda image yake kwanza** na kuendesha carving tools dhidi ya image hiyo pekee. `ddrescue` (GNU project) inalenga kunakili disks zenye hitilafu kwa kutegemewa huku ikihifadhi log ya sectors zisizoweza kusomeka.
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

Ikiwa file system chanzo inategemea Linux EXT, unaweza kurecover files zilizofutwa hivi karibuni **bila full carving**; tools hizi zinazotumia journal hufanya kazi kwenye filesystem ambayo haija-mountiwa au image ya read-only.<sup>[[8]](#references)[[9]](#references)</sup>
```bash
# Attempt journal-based undelete (metadata must still be present)
extundelete disk.img --restore-all

# Multi-stage recovery from an ext4 image
ext4magic disk.img -M -d ./recovered
```
> **Dokezo la uoanifu** – ext4magic imeachwa; ukurasa wa mradi wake unaonya kwamba filesystems za sasa haziendani nayo tena.<sup>[[10]](#references)</sup>

> 🛈 Ikiwa file system ili-mountiwa baada ya kufutwa, data blocks huenda zilikuwa zimetumika tena – katika hali hiyo proper carving (Foremost/Scalpel) bado inahitajika.

### binvis

Angalia [code](https://code.google.com/archive/p/binvis/) na [web page tool](https://binvis.io/#/).

#### Vipengele vya BinVis

- **Muonyeshaji wa structure** wa kuona na kuingiliana nao
- Plots nyingi kwa focus points tofauti
- Kuweka focus kwenye sehemu za sample
- **Kuona strings na resources**, kwa mfano katika PE au ELF executables
- Kupata **patterns** kwa cryptanalysis kwenye files
- **Kubaini** packer au encoder algorithms
- **Kutambua** Steganography kupitia patterns
- **Visual** binary-diffing

BinVis ni **start-point** nzuri ya kufahamu **target isiyojulikana** katika scenario ya black-boxing.

## Zana Maalum za Data Carving

### FindAES

Hutafuta AES keys kwa kutafuta key schedules zao. Inaweza kupata keys za 128, 192, na 256 bits, kama zile zinazotumiwa na TrueCrypt na BitLocker.

Pakua [hapa](https://sourceforge.net/projects/findaes/).

### YARA-X (triaging carved artefacts)

[YARA-X](https://github.com/VirusTotal/yara-x) ni rewrite ya YARA katika Rust iliyoanzishwa mwaka wa 2024; VirusTotal inaripoti kwamba baadhi ya regular-expression na complex-loop rules zinaweza kuendeshwa kwa kasi kubwa zaidi.<sup>[[5]](#references)</sup> CLI yake inaitwa `yr`, na command ya `scan` inaunga mkono recursive scans, thread count, na metadata output.<sup>[[6]](#references)</sup>
```bash
# Scan every carved object produced by bulk_extractor
yr scan --recursive --threads 8 --print-meta rules/index.yar out_folder/
```
## Zana za ziada

Unaweza kutumia [**viu** ](https://github.com/atanunq/viu)kuona picha kutoka kwenye terminali.  \
Unaweza kutumia zana ya mstari wa amri ya linux **pdftotext** kubadilisha pdf kuwa maandishi na kuyasoma.



## References

- [1] [Maelezo ya toleo la Autopsy 4.21](https://github.com/sleuthkit/autopsy/releases/tag/autopsy-4.21.0)
- [2] [README ya bulk_extractor v2.1.1](https://github.com/simsong/bulk_extractor/blob/v2.1.1/README.md)
- [3] [README ya zana za Python za bulk_extractor](https://raw.githubusercontent.com/simsong/bulk_extractor/v2.1.1/python/README.txt)
- [4] [Path traversal katika binwalk (CVE-2022-4510) - Hifadhidata ya Ushauri ya GitHub](https://github.com/advisories/GHSA-3cm8-v4mc-gppg)
- [5] [YARA imekufa, iishi kwa muda mrefu YARA-X - Blogu ya VirusTotal](https://blog.virustotal.com/2024/05/yara-is-dead-long-live-yara-x.html)
- [6] [Amri za CLI za YARA-X](https://virustotal.github.io/yara-x/docs/cli/commands/)
- [7] [Mwongozo wa GNU ddrescue](https://www.gnu.org/software/ddrescue/manual/ddrescue_manual.html)
- [8] [extundelete](https://extundelete.sourceforge.net/)
- [9] [Mwongozo wa ext4magic](https://ext4magic.sourceforge.net/manpage_en.html)
- [10] [Hali ya mradi wa ext4magic](https://sourceforge.net/projects/ext4magic/)
{{#include ../../../banners/hacktricks-training.md}}
