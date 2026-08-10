# File/Data Carving और Recovery Tools

## Carving और Recovery tools

[https://github.com/Claudio-C/awesome-datarecovery](https://github.com/Claudio-C/awesome-datarecovery) पर और अधिक tools

### Autopsy

Forensics में images से files extract करने के लिए सबसे सामान्यतः उपयोग किया जाने वाला tool [**Autopsy**](https://www.autopsy.com/download/) है। इसे download और install करें, फिर "hidden" files खोजने के लिए इसे file ingest करने दें। ध्यान दें कि Autopsy को disk images और अन्य प्रकार की images को support करने के लिए बनाया गया है, लेकिन simple files के लिए नहीं।

### Binwalk <a href="#binwalk" id="binwalk"></a>

**Binwalk** embedded content खोजने के लिए binary files का analysis करने वाला tool है। इसे `apt` के माध्यम से install किया जा सकता है और इसका source [GitHub](https://github.com/ReFirmLabs/binwalk) पर है।

**Useful commands**:
```bash
sudo apt install binwalk         # Installation
binwalk firmware.bin             # Display embedded data
binwalk -e firmware.bin          # Extract recognised objects (safe-default)
binwalk --dd " .* " firmware.bin  # Extract *everything* (use with care)
```
⚠️  **Security note** – Versions **2.1.2b से 2.3.3** तक **Path Traversal** vulnerability (CVE-2022-4510) से प्रभावित हैं; advisory में कोई patched pip version सूचीबद्ध नहीं है। प्रभावित releases के साथ untrusted samples को extract करने से बचें, या tool को container/non-privileged UID के साथ isolate करें।<sup>[[4]](#references)</sup>

### Foremost

छिपी हुई files खोजने के लिए एक अन्य सामान्य tool **foremost** है। आप foremost की configuration file `/etc/foremost.conf` में पा सकते हैं। यदि आप केवल कुछ specific files खोजना चाहते हैं, तो उन्हें uncomment करें। यदि आप कुछ भी uncomment नहीं करते हैं, तो foremost अपने default configured file types को खोजेगा।
```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
# Discovered files will appear inside the folder "output"
```
### **Scalpel**

**Scalpel** एक अन्य tool है जिसका उपयोग **किसी file में embedded files** को खोजने और extract करने के लिए किया जा सकता है। इस मामले में, आपको configuration file (_/etc/scalpel/scalpel.conf_) में उन file types की comment हटानी होगी जिन्हें आप extract करना चाहते हैं।
```bash
sudo apt-get install scalpel
scalpel file.img -o output
```
### Bulk Extractor 2.x

यह tool Kali में आता है, लेकिन आप इसे यहाँ पा सकते हैं: <https://github.com/simsong/bulk_extractor>

Bulk Extractor किसी evidence image को scan कर सकता है और **pcap fragments**, **network artefacts (URLs, domains, IPs, MACs, e-mails)** तथा कई अन्य objects को **multiple scanners का parallel में उपयोग करके** carve कर सकता है।

v2.1.1 release में Autotools build और सभी contiguous JPEGs को carve करने के लिए `-S jpeg_carve_mode=2` setting का documentation दिया गया है।<sup>[[2]](#references)</sup>
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
Bundled `bulk_diff.py` दो bulk_extractor runs की तुलना करता है, जबकि `bulk_extractor_reader.py` report और feature files को पढ़ता है।<sup>[[3]](#references)</sup>

### PhotoRec

आप इसे <https://www.cgsecurity.org/wiki/TestDisk_Download> पर पा सकते हैं।

यह GUI और CLI versions के साथ आता है। आप उन **file-types** को select कर सकते हैं जिन्हें PhotoRec को search करना है।

![हर scanner चलाएँ, JPEGs को aggressively carve करें और एक bodyfile generate करें - PhotoRec: यह GUI और CLI versions के साथ आता है। आप उन file-types को select कर सकते हैं जिन्हें PhotoRec को search करना है](<../../../images/image (242).png>)

### ddrescue + ddrescueview (अस्थिर drives की imaging)

जब कोई physical drive अस्थिर हो, तो **पहले उसकी image बनाना** और carving tools को केवल image पर चलाना best practice है। `ddrescue` (GNU project) unreadable sectors का log रखते हुए खराब disks को reliably copy करने पर केंद्रित है।
```bash
sudo apt install gddrescue ddrescueview   # On Debian-based systems
# First pass – try to get as much data as possible without retries
sudo ddrescue -f -n /dev/sdX suspect.img suspect.log
# Second pass – aggressive, 3 retries on the remaining bad areas
sudo ddrescue -d -r3 /dev/sdX suspect.img suspect.log

# Visualise the status map (green=good, red=bad)
ddrescueview suspect.log
```
**`--cluster-size`** विकल्प एक समय में कॉपी किए जाने वाले sectors की संख्या नियंत्रित करता है; छोटे मान slow drives के लिए उपयोगी हो सकते हैं।<sup>[[7]](#references)</sup>

### Extundelete / Ext4magic (EXT 3/4 undelete)

यदि source file system Linux EXT-based है, तो आप **full carving** के बिना हाल ही में delete की गई files recover कर सकते हैं; ये journal-based tools unmounted filesystem या read-only image पर काम करते हैं।<sup>[[8]](#references)[[9]](#references)</sup>
```bash
# Attempt journal-based undelete (metadata must still be present)
extundelete disk.img --restore-all

# Multi-stage recovery from an ext4 image
ext4magic disk.img -M -d ./recovered
```
> **Compatibility note** – ext4magic abandoned है; इसके project page पर चेतावनी दी गई है कि current filesystems अब इसके साथ compatible नहीं हैं।<sup>[[10]](#references)</sup>

> 🛈 यदि deletion के बाद file system mount किया गया था, तो data blocks पहले ही reuse हो चुके हो सकते हैं – ऐसी स्थिति में proper carving (Foremost/Scalpel) अभी भी required है।

### binvis

[code](https://code.google.com/archive/p/binvis/) और [web page tool](https://binvis.io/#/) देखें।

#### Features of BinVis

- Visual और active **structure viewer**
- अलग-अलग focus points के लिए multiple plots
- किसी sample के portions पर focus करना
- PE या ELF executables में, जैसे, **strings और resources देखना**
- Files पर cryptanalysis के लिए **patterns** प्राप्त करना
- **Packer या encoder algorithms पहचानना**
- Patterns के आधार पर **Steganography की पहचान करना**
- **Visual** binary-diffing

BinVis black-boxing scenario में **किसी unknown target से परिचित होने का एक बेहतरीन start-point** है।

## Specific Data Carving Tools

### FindAES

अपने key schedules को search करके AES keys खोजता है। यह 128, 192 और 256 bit keys खोज सकता है, जैसे TrueCrypt और BitLocker द्वारा उपयोग की जाने वाली keys।

[यहाँ](https://sourceforge.net/projects/findaes/) से Download करें।

### YARA-X (triaging carved artefacts)

[YARA-X](https://github.com/VirusTotal/yara-x), YARA का Rust rewrite है, जिसे 2024 में introduce किया गया था; VirusTotal के अनुसार कुछ regular-expression और complex-loop rules काफी तेज़ी से run हो सकते हैं।<sup>[[5]](#references)</sup> इसका CLI नाम `yr` है, और `scan` command recursive scans, thread count और metadata output को support करता है।<sup>[[6]](#references)</sup>
```bash
# Scan every carved object produced by bulk_extractor
yr scan --recursive --threads 8 --print-meta rules/index.yar out_folder/
```
## पूरक tools

आप terminal से images देखने के लिए [**viu** ](https://github.com/atanunq/viu)का उपयोग कर सकते हैं।  \
आप pdf को text में बदलने और उसे पढ़ने के लिए linux command line tool **pdftotext** का उपयोग कर सकते हैं।



## References

- [1] [Autopsy 4.21 release notes](https://github.com/sleuthkit/autopsy/releases/tag/autopsy-4.21.0)
- [2] [bulk_extractor v2.1.1 README](https://github.com/simsong/bulk_extractor/blob/v2.1.1/README.md)
- [3] [bulk_extractor Python tools README](https://raw.githubusercontent.com/simsong/bulk_extractor/v2.1.1/python/README.txt)
- [4] [binwalk में Path traversal (CVE-2022-4510) - GitHub Advisory Database](https://github.com/advisories/GHSA-3cm8-v4mc-gppg)
- [5] [YARA is dead, long live YARA-X - VirusTotal Blog](https://blog.virustotal.com/2024/05/yara-is-dead-long-live-yara-x.html)
- [6] [YARA-X CLI commands](https://virustotal.github.io/yara-x/docs/cli/commands/)
- [7] [GNU ddrescue manual](https://www.gnu.org/software/ddrescue/manual/ddrescue_manual.html)
- [8] [extundelete](https://extundelete.sourceforge.net/)
- [9] [ext4magic manual](https://ext4magic.sourceforge.net/manpage_en.html)
- [10] [ext4magic project status](https://sourceforge.net/projects/ext4magic/)
{{#include ../../../banners/hacktricks-training.md}}
