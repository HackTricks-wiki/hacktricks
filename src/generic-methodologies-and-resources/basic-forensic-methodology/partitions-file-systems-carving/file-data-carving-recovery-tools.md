# File/Data Carving na Recovery Tools

{{#include ../../../banners/hacktricks-training.md}}

## Zana za Carving na Recovery

Daima fanya carving kwenye **nakala iliyothibitishwa**, si kifaa asili. Tazama [Image Acquisition & Mount](../image-acquisition-and-mount.md) kwa workflows za upatikanaji wa read-only na hashing.

Zana zaidi zinapatikana kwenye [https://github.com/Claudio-C/awesome-datarecovery](https://github.com/Claudio-C/awesome-datarecovery)

### Autopsy

Zana inayotumika zaidi katika forensics kutoa files kutoka kwenye images ni [**Autopsy**](https://www.autopsy.com/download/). Ipakue, isakinishe, kisha ifanye iingize file ili kutafuta files "zilizofichwa". Kumbuka kwamba Autopsy imeundwa kusaidia disk images na aina nyingine za images, lakini si files rahisi.

### Binwalk <a href="#binwalk" id="binwalk"></a>

**Binwalk** ni zana ya kuchanganua binary files ili kupata content iliyopachikwa. **Binwalk v3** ni rewrite ya Rust yenye extraction ya kiotomatiki (`-e`), raw carving ya objects zinazojulikana na zisizojulikana (`-c`), recursive/Matryoshka scanning (`-M`) na worker threads zinazoweza kusanidiwa. Project inapendekeza Docker build yake wakati extractors zote za nje zinahitajika; `cargo install binwalk` husakinisha Rust CLI lakini si dependencies hizo za nje.<sup>[[11]](#references)</sup>

**Useful v3 commands**:
```bash
cargo install binwalk                 # CLI only; install extractors separately
binwalk firmware.bin                  # Identify embedded content
binwalk -e firmware.bin               # Extract recognised objects
binwalk -c -d carved firmware.bin     # Carve known and unknown objects
binwalk -Me -d extracted firmware.bin # Extract and recursively scan results
binwalk -e -l results.json firmware.bin
```
Kichocheo cha legacy v2 `--dd='.*'` **si** sawa na v3 ya `-c`; kwanza angalia `binwalk --version` unapofuata amri za zamani za CTF/write-up.<sup>[[11]](#references)</sup>

⚠️  **Security note** – Versions **2.1.2b hadi 2.3.3** zimeathiriwa na vulnerability ya **Path Traversal** (CVE-2022-4510); advisory haiorodheshi pip version yoyote iliyopatiwa patch. Epuka kutoa samples zisizoaminika kwa kutumia releases zilizoathiriwa, au tenga tool hiyo kwa kutumia container/non-privileged UID.<sup>[[4]](#references)</sup>

### Foremost

Tool nyingine ya kawaida ya kutafuta files zilizofichwa ni **foremost**. Unaweza kupata configuration file ya foremost katika `/etc/foremost.conf`. Ikiwa unataka tu kutafuta files maalum, ziondoe alama ya maoni. Usipoondoa alama yoyote ya maoni, foremost itatafuta file types zake za default zilizosanidiwa.
```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
# Discovered files will appear inside the folder "output"
```
### **Scalpel**

**Scalpel** ni zana nyingine inayoweza kutumika kutafuta na kutoa **faili zilizopachikwa ndani ya faili**. Katika hali hii, utahitaji kuondoa alama ya maoni kwenye aina za faili unazotaka itoe kutoka kwenye faili ya usanidi (_/etc/scalpel/scalpel.conf_).
```bash
sudo apt-get install scalpel
scalpel file.img -o output
```
### Bulk Extractor 2.x

Zana hii huja ndani ya kali, lakini unaweza kuipata hapa: <https://github.com/simsong/bulk_extractor>

Bulk Extractor inaweza kuchanganua picha ya ushahidi na ku-carve **pcap fragments**, **network artefacts (URLs, domains, IPs, MACs, e-mails)** pamoja na vitu vingine vingi **kwa wakati mmoja kwa kutumia scanners nyingi**.

Toleo la v2.1.1 linaandika kuhusu ujenzi wa Autotools na mipangilio ya `-S jpeg_carve_mode=2` kwa ajili ya ku-carve JPEG zote zilizo contiguous.<sup>[[2]](#references)</sup>
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
Bundled `bulk_diff.py` hulinganisha runs mbili za bulk_extractor, huku `bulk_extractor_reader.py` ikisoma ripoti na faili za feature.<sup>[[3]](#references)</sup>

### PhotoRec

Unaweza kuipata kwenye <https://www.cgsecurity.org/wiki/TestDisk_Download>

Inakuja na matoleo ya GUI na CLI. Unaweza kuchagua **aina za faili** unazotaka PhotoRec itafute.

![Endesha scanners zote, carva JPEGs kwa ukali na tengeneza bodyfile - PhotoRec: Inakuja na matoleo ya GUI na CLI. Unaweza kuchagua aina za faili unazotaka itafute](<../../../images/image (242).png>)

### The Sleuth Kit `tsk_recover` (metadata-first)

Kabla ya raw signature carving, jaribu urejeshaji unaotambua filesystem wakati metadata ya volume bado inaweza kuchanganuliwa. `tsk_recover` kwa default hu-export faili zisizotengwa pekee; `-a` huchagua faili zilizotengwa na `-e` hu-export zote mbili. Kwa disk image nzima, pitisha **start sector** ya partition kutoka `mmls` kwa `-o` (usiibadilishe kuwa bytes). Ikiwa input tayari ni partition image, acha kutumia `-o`.<sup>[[12]](#references)</sup>
```bash
sudo apt install sleuthkit
mmls disk.img                         # Note the partition start sector, e.g. 2048
mkdir recovered-deleted recovered-all
tsk_recover -o 2048 disk.img recovered-deleted/
tsk_recover -e -o 2048 disk.img recovered-all/
```
Hatua hii inaweza kuhifadhi majina na njia zilizotokana na filesystem ambazo carving ya header/footer haiwezi kuhifadhi; endesha Foremost, Scalpel au PhotoRec baadaye kwa maingizo ambayo metadata yake haipo au haiwezi kutumika.<sup>[[12]](#references)</sup>

### ddrescue + ddrescueview (kutengeneza image ya drives zinazoshindwa)

Wakati drive ya kimwili haijatulia, ni mbinu bora kuunda **image yake kwanza** na kuendesha carving tools dhidi ya image hiyo pekee. `ddrescue` (mradi wa GNU) inalenga kunakili disks zenye hitilafu kwa uaminifu huku ikiweka log ya sectors zisizosomwa.
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

Ikiwa file system chanzo inategemea Linux EXT, unaweza kurejesha files zilizofutwa hivi karibuni **bila full carving**; tools hizi zinazotumia journal hufanya kazi kwenye filesystem ambayo haija-mountiwa au image ya read-only.<sup>[[8]](#references)[[9]](#references)</sup>
```bash
# Attempt journal-based undelete (metadata must still be present)
extundelete disk.img --restore-all

# Multi-stage recovery from an ext4 image
ext4magic disk.img -M -d ./recovered
```
> **Dokezo la uoanifu** – ext4magic imeachwa; ukurasa wake wa mradi unaonya kuwa filesystems za sasa haziendani nayo tena.<sup>[[10]](#references)</sup>

> 🛈 Ikiwa file system iliwekwa baada ya kufutwa, data blocks huenda tayari zimetumika tena – katika hali hiyo proper carving (Foremost/Scalpel) bado inahitajika.

### binvis

Angalia [code](https://code.google.com/archive/p/binvis/) na [web page tool](https://binvis.io/#/).

#### Vipengele vya BinVis

- **Structure viewer** ya kuona kwa macho na kwa uamilifu
- Plots nyingi kwa focus points tofauti
- Kuweka focus kwenye sehemu za sample
- **Kuona strings na resources**, kwa mfano katika PE au ELF executables
- Kupata **patterns** kwa cryptanalysis kwenye files
- **Kutambua** packer au encoder algorithms
- **Kutambua** Steganography kupitia patterns
- **Visual** binary-diffing

BinVis ni **start-point** nzuri ya kuifahamu **target isiyojulikana** katika hali ya black-boxing.

## Zana Mahususi za Data Carving

### FindAES

Hutafuta AES keys kwa kutafuta key schedules zake. Inaweza kupata keys za bits 128, 192 na 256, kama zile zinazotumiwa na TrueCrypt na BitLocker.

Pakua [hapa](https://sourceforge.net/projects/findaes/).

### YARA-X (triaging carved artefacts)

[YARA-X](https://github.com/VirusTotal/yara-x) ni Rust rewrite ya YARA iliyoanzishwa mwaka wa 2024; VirusTotal inaripoti kuwa baadhi ya regular-expression na complex-loop rules zinaweza kufanya kazi kwa kasi kubwa zaidi.<sup>[[5]](#references)</sup> CLI yake inaitwa `yr`, na command ya `scan` inasaidia recursive scans, thread count na metadata output.<sup>[[6]](#references)</sup>
```bash
# Scan every carved object produced by bulk_extractor
yr scan --recursive --threads 8 --print-meta rules/index.yar out_folder/
```
## Zana za ziada

Unaweza kutumia [**viu** ](https://github.com/atanunq/viu)kuona picha kutoka kwenye terminali.  \
Unaweza kutumia zana ya command line ya linux **pdftotext** kubadilisha pdf kuwa maandishi na kuyasoma.





## References

- [1] [Maelezo ya toleo la Autopsy 4.21](https://github.com/sleuthkit/autopsy/releases/tag/autopsy-4.21.0)
- [2] [README ya bulk_extractor v2.1.1](https://github.com/simsong/bulk_extractor/blob/v2.1.1/README.md)
- [3] [README ya zana za Python za bulk_extractor](https://raw.githubusercontent.com/simsong/bulk_extractor/v2.1.1/python/README.txt)
- [4] [Path traversal katika binwalk (CVE-2022-4510) - GitHub Advisory Database](https://github.com/advisories/GHSA-3cm8-v4mc-gppg)
- [5] [YARA imekufa, iishi kwa muda mrefu YARA-X - VirusTotal Blog](https://blog.virustotal.com/2024/05/yara-is-dead-long-live-yara-x.html)
- [6] [Amri za CLI za YARA-X](https://virustotal.github.io/yara-x/docs/cli/commands/)
- [7] [Mwongozo wa GNU ddrescue](https://www.gnu.org/software/ddrescue/manual/ddrescue_manual.html)
- [8] [extundelete](https://extundelete.sourceforge.net/)
- [9] [Mwongozo wa ext4magic](https://ext4magic.sourceforge.net/manpage_en.html)
- [10] [Hali ya mradi wa ext4magic](https://sourceforge.net/projects/ext4magic/)
- [11] [README ya Binwalk v3](https://github.com/ReFirmLabs/binwalk/blob/master/README.md)
- [12] [The Sleuth Kit: mwongozo wa tsk_recover](https://sleuthkit.org/sleuthkit/man/tsk_recover.html)
{{#include ../../../banners/hacktricks-training.md}}
