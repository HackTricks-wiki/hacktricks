# File/Data Carving & Recovery Tools

{{#include ../../../banners/hacktricks-training.md}}

## Carving & Recovery tools

[https://github.com/Claudio-C/awesome-datarecovery](https://github.com/Claudio-C/awesome-datarecovery) पर और tools

### Autopsy

Forensics में images से files extract करने के लिए सबसे सामान्य tool [**Autopsy**](https://www.autopsy.com/download/) है। इसे download और install करें, फिर इसे file ingest करने दें ताकि "hidden" files खोजी जा सकें। ध्यान दें कि Autopsy को disk images और अन्य प्रकार की images को support करने के लिए बनाया गया है, लेकिन simple files के लिए नहीं।

> **2024-2025 update** – **4.21** version (February 2025 में released) में **SleuthKit v4.13** पर आधारित rebuilt **carving module** जोड़ा गया है, जो multi-terabyte images के साथ काम करते समय noticeably quicker है और multi-core systems पर parallel extraction को support करता है। एक छोटा CLI wrapper (`autopsycli ingest <case> <image>`) भी introduce किया गया, जिससे CI/CD या large-scale lab environments के अंदर carving को script करना संभव हो गया।<sup>[[1]](#references)</sup>
```bash
# Create a case and ingest an evidence image from the CLI (Autopsy ≥4.21)
autopsycli case --create MyCase --base /cases
# ingest with the default ingest profile (includes data-carve module)
autopsycli ingest MyCase /evidence/disk01.E01 --threads 8
```
### Binwalk <a href="#binwalk" id="binwalk"></a>

**Binwalk** embedded content खोजने के लिए binary files का analysis करने वाला tool है। इसे `apt` के माध्यम से install किया जा सकता है और इसका source [GitHub](https://github.com/ReFirmLabs/binwalk) पर है।

**उपयोगी commands**:
```bash
sudo apt install binwalk         # Installation
binwalk firmware.bin             # Display embedded data
binwalk -e firmware.bin          # Extract recognised objects (safe-default)
binwalk --dd " .* " firmware.bin  # Extract *everything* (use with care)
```
⚠️  **Security note** – Versions **≤2.3.3** **Path Traversal** vulnerability से प्रभावित हैं (CVE-2022-4510)। Untrusted samples को carve करने से पहले Upgrade करें (या container/non-privileged UID के साथ isolate करें)।<sup>[[2]](#references)</sup>

### Foremost

Hidden files खोजने के लिए **foremost** एक अन्य common tool है। आप `/etc/foremost.conf` में foremost की configuration file पा सकते हैं। यदि आप केवल कुछ specific files खोजना चाहते हैं, तो उन्हें uncomment करें। यदि आप कुछ भी uncomment नहीं करते हैं, तो foremost अपने default configured file types को खोजेगा।
```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
# Discovered files will appear inside the folder "output"
```
### **Scalpel**

**Scalpel** एक अन्य tool है जिसका उपयोग **किसी file में embedded files** को खोजने और extract करने के लिए किया जा सकता है। इस स्थिति में, आपको configuration file (_/etc/scalpel/scalpel.conf_) से उन file types की comment हटानी होगी जिन्हें आप extract करना चाहते हैं।
```bash
sudo apt-get install scalpel
scalpel file.img -o output
```
### Bulk Extractor 2.x

यह tool Kali में शामिल आता है, लेकिन आप इसे यहाँ पा सकते हैं: <https://github.com/simsong/bulk_extractor>

Bulk Extractor किसी evidence image को scan कर सकता है और **pcap fragments**, **network artefacts (URLs, domains, IPs, MACs, e-mails)** तथा कई अन्य objects को **multiple scanners का उपयोग करके parallel रूप से** carve कर सकता है।
```bash
# Build from source – v2.1.1 (April 2024) requires cmake ≥3.16
git clone https://github.com/simsong/bulk_extractor.git && cd bulk_extractor
mkdir build && cd build && cmake .. && make -j$(nproc) && sudo make install

# Run every scanner, carve JPEGs aggressively and generate a bodyfile
bulk_extractor -o out_folder -S jpeg_carve_mode=2 -S write_bodyfile=y /evidence/disk.img
```
Useful post-processing scripts (`bulk_diff`, `bulk_extractor_reader.py`) दो images के बीच artefacts को de-duplicate कर सकती हैं या परिणामों को SIEM ingestion के लिए JSON में बदल सकती हैं।

### PhotoRec

आप इसे <https://www.cgsecurity.org/wiki/TestDisk_Download> पर पा सकते हैं।

यह GUI और CLI versions के साथ आता है। आप उन **file-types** को चुन सकते हैं, जिन्हें PhotoRec खोजे।

![हर scanner चलाएं, JPEGs को आक्रामक रूप से carve करें और एक bodyfile जनरेट करें - PhotoRec: यह GUI और CLI versions के साथ आता है। आप उन file-types को चुन सकते हैं, जिन्हें PhotoRec खोजे](<../../../images/image (242).png>)

### ddrescue + ddrescueview (imaging failing drives)

जब कोई physical drive unstable हो, तो best practice है कि पहले उसकी **image** बनाई जाए और carving tools को केवल image पर चलाया जाए। `ddrescue` (GNU project) unreadable sectors का log रखते हुए खराब disks को reliably copy करने पर focus करता है।
```bash
sudo apt install gddrescue ddrescueview   # On Debian-based systems
# First pass – try to get as much data as possible without retries
sudo ddrescue -f -n /dev/sdX suspect.img suspect.log
# Second pass – aggressive, 3 retries on the remaining bad areas
sudo ddrescue -d -r3 /dev/sdX suspect.img suspect.log

# Visualise the status map (green=good, red=bad)
ddrescueview suspect.log
```
Version **1.28** (दिसंबर 2024) ने **`--cluster-size`** पेश किया, जो high-capacity SSDs की imaging को तेज कर सकता है, जहां traditional sector sizes अब flash blocks के साथ align नहीं होते।

### Extundelete / Ext4magic (EXT 3/4 undelete)

यदि source file system Linux EXT-based है, तो आप **full carving** के बिना हाल ही में deleted files को recover कर सकते हैं। दोनों tools read-only image पर सीधे काम करते हैं:
```bash
# Attempt journal-based undelete (metadata must still be present)
extundelete disk.img --restore-all

# Fallback to full directory scan; supports extents and inline data
ext4magic disk.img -M -f '*.jpg' -d ./recovered
```
> 🛈 यदि deletion के बाद file system mount किया गया था, तो data blocks पहले ही reuse हो चुके हो सकते हैं – ऐसी स्थिति में proper carving (Foremost/Scalpel) अभी भी आवश्यक है।

### binvis

[code](https://code.google.com/archive/p/binvis/) और [web page tool](https://binvis.io/#/) देखें।

#### BinVis की विशेषताएँ

- Visual और active **structure viewer**
- अलग-अलग focus points के लिए multiple plots
- किसी sample के portions पर focus करना
- PE या ELF executables में, उदाहरण के लिए, **strings और resources देखना**
- Files पर cryptanalysis के लिए **patterns प्राप्त करना**
- **packer या encoder algorithms की पहचान करना**
- Patterns द्वारा **Steganography की पहचान करना**
- **Visual** binary-diffing

BinVis black-boxing scenario में **किसी अज्ञात target से परिचित होने का एक बेहतरीन start-point** है।

## Specific Data Carving Tools

### FindAES

Key schedules को search करके AES keys खोजता है। यह 128, 192 और 256 bit keys खोज सकता है, जैसे TrueCrypt और BitLocker द्वारा उपयोग की जाने वाली keys।

[यहाँ से download करें](https://sourceforge.net/projects/findaes/)।

### YARA-X (carved artefacts की triaging)

[YARA-X](https://github.com/VirusTotal/yara-x) 2024 में released YARA का Rust rewrite है। यह classic YARA से **10-30× तेज़** है और इसका उपयोग हजारों carved objects को बहुत तेज़ी से classify करने के लिए किया जा सकता है:<sup>[[3]](#references)</sup>
```bash
# Scan every carved object produced by bulk_extractor
yarax -r rules/index.yar out_folder/ --threads 8 --print-meta
```
यह speed-up बड़े पैमाने की investigations में सभी carved files को **auto-tag** करना realistic बनाता है।

## पूरक tools

आप terminal से images देखने के लिए [**viu** ](https://github.com/atanunq/viu) का उपयोग कर सकते हैं।  \
आप pdf को text में बदलने और उसे पढ़ने के लिए linux command line tool **pdftotext** का उपयोग कर सकते हैं।



## References

- [1] [Autopsy 4.21 के release notes](https://github.com/sleuthkit/autopsy/releases/tag/autopsy-4.21)
- [2] [binwalk में Path traversal (CVE-2022-4510) - GitHub Advisory Database](https://github.com/advisories/GHSA-3cm8-v4mc-gppg)
- [3] [YARA is dead, long live YARA-X - VirusTotal Blog](https://blog.virustotal.com/2024/05/yara-is-dead-long-live-yara-x.html)

{{#include ../../../banners/hacktricks-training.md}}
