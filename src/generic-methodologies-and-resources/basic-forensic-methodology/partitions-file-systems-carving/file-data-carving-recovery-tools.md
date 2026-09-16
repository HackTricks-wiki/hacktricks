# File/Data Carving & Recovery Tools

{{#include ../../../banners/hacktricks-training.md}}

## Carving & Recovery tools

हमेशा मूल device के बजाय **verified copy** पर carve करें। केवल read-only acquisition और hashing workflows के लिए [Image Acquisition & Mount](../image-acquisition-and-mount.md) देखें।

[https://github.com/Claudio-C/awesome-datarecovery](https://github.com/Claudio-C/awesome-datarecovery) में और tools उपलब्ध हैं।

### Autopsy

Images से files extract करने के लिए forensics में सबसे सामान्य रूप से उपयोग किया जाने वाला tool [**Autopsy**](https://www.autopsy.com/download/) है। इसे download और install करें, फिर "hidden" files खोजने के लिए file को ingest करें। ध्यान दें कि Autopsy disk images और अन्य प्रकार की images को support करने के लिए बनाया गया है, लेकिन simple files को नहीं।

### Binwalk <a href="#binwalk" id="binwalk"></a>

**Binwalk** embedded content खोजने के लिए binary files का analysis करने वाला tool है। **Binwalk v3** Rust में किया गया rewrite है, जिसमें automatic extraction (`-e`), known और unknown objects की raw carving (`-c`), recursive/Matryoshka scanning (`-M`) और configurable worker threads शामिल हैं। Project, सभी external extractors की आवश्यकता होने पर अपने Docker build का उपयोग करने की सलाह देता है; `cargo install binwalk` Rust CLI को install करता है, लेकिन उन external dependencies को नहीं।<sup>[[11]](#references)</sup>

**Useful v3 commands**:
```bash
cargo install binwalk                 # CLI only; install extractors separately
binwalk firmware.bin                  # Identify embedded content
binwalk -e firmware.bin               # Extract recognised objects
binwalk -c -d carved firmware.bin     # Carve known and unknown objects
binwalk -Me -d extracted firmware.bin # Extract and recursively scan results
binwalk -e -l results.json firmware.bin
```
The legacy v2 `--dd='.*'` recipe, v3 में `-c` के equivalent नहीं है; पुराने CTF/write-up commands का पालन करते समय पहले `binwalk --version` जाँचें।<sup>[[11]](#references)</sup>

⚠️  **Security note** – **2.1.2b से 2.3.3** तक के versions **Path Traversal** vulnerability (CVE-2022-4510) से प्रभावित हैं; advisory में कोई patched pip version सूचीबद्ध नहीं है। प्रभावित releases के साथ untrusted samples को extract करने से बचें, या tool को container/non-privileged UID के साथ isolate करें।<sup>[[4]](#references)</sup>

### Foremost

छिपी हुई files खोजने के लिए उपयोग किया जाने वाला एक अन्य सामान्य tool **foremost** है। आप foremost की configuration file `/etc/foremost.conf` में पा सकते हैं। यदि आप केवल कुछ specific files खोजना चाहते हैं, तो उनकी lines से comment हटाएँ। यदि आप कुछ भी uncomment नहीं करते हैं, तो foremost अपने default configured file types को खोजेगा।
```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
# Discovered files will appear inside the folder "output"
```
### **Scalpel**

**Scalpel** एक अन्य tool है जिसका उपयोग **किसी file में embedded files** को खोजने और extract करने के लिए किया जा सकता है। इस मामले में, आपको configuration file (_/etc/scalpel/scalpel.conf_) में उन file types को uncomment करना होगा जिन्हें आप extract करना चाहते हैं।
```bash
sudo apt-get install scalpel
scalpel file.img -o output
```
### Bulk Extractor 2.x

यह tool Kali में शामिल है, लेकिन आप इसे यहाँ पा सकते हैं: <https://github.com/simsong/bulk_extractor>

Bulk Extractor किसी evidence image को scan कर सकता है और **pcap fragments**, **network artefacts (URLs, domains, IPs, MACs, e-mails)** तथा कई अन्य objects को **multiple scanners का उपयोग करके parallel रूप से** carve कर सकता है।

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

यह GUI और CLI versions के साथ आता है। आप वे **file-types** चुन सकते हैं जिन्हें PhotoRec को search करना है।

![हर scanner चलाएँ, JPEGs को aggressively carve करें और एक bodyfile generate करें - PhotoRec: यह GUI और CLI versions के साथ आता है। आप वे file-types चुन सकते हैं जिन्हें PhotoRec को search करना है](<../../../images/image (242).png>)

### The Sleuth Kit `tsk_recover` (metadata-first)

Raw signature carving से पहले filesystem-aware recovery आज़माएँ, जब volume metadata अभी भी parse किया जा सकता हो। `tsk_recover` default रूप से केवल unallocated files export करता है; `-a` allocated files चुनता है और `-e` दोनों को export करता है। Whole-disk image के लिए, `mmls` से partition का **start sector** लेकर उसे `-o` में दें (इसे bytes में convert न करें)। यदि input पहले से ही partition image है, तो `-o` को छोड़ दें।<sup>[[12]](#references)</sup>
```bash
sudo apt install sleuthkit
mmls disk.img                         # Note the partition start sector, e.g. 2048
mkdir recovered-deleted recovered-all
tsk_recover -o 2048 disk.img recovered-deleted/
tsk_recover -e -o 2048 disk.img recovered-all/
```
यह pass उन filesystem-derived names और paths को सुरक्षित रख सकता है जिन्हें header/footer carving सुरक्षित नहीं रख सकता; जिन entries का metadata missing या unusable हो, उनके लिए बाद में Foremost, Scalpel या PhotoRec चलाएँ।<sup>[[12]](#references)</sup>

### ddrescue + ddrescueview (असफल हो रही drives की imaging)

जब कोई physical drive unstable हो, तो best practice है कि पहले उसकी **image बनाएँ** और carving tools केवल image पर चलाएँ। `ddrescue` (GNU project) unreadable sectors का log बनाए रखते हुए खराब disks को reliably copy करने पर केंद्रित है.
```bash
sudo apt install gddrescue ddrescueview   # On Debian-based systems
# First pass – try to get as much data as possible without retries
sudo ddrescue -f -n /dev/sdX suspect.img suspect.log
# Second pass – aggressive, 3 retries on the remaining bad areas
sudo ddrescue -d -r3 /dev/sdX suspect.img suspect.log

# Visualise the status map (green=good, red=bad)
ddrescueview suspect.log
```
**`--cluster-size`** विकल्प एक समय में कॉपी किए जाने वाले sectors की संख्या नियंत्रित करता है; छोटे मान slow drives के लिए सहायक हो सकते हैं।<sup>[[7]](#references)</sup>

### Extundelete / Ext4magic (EXT 3/4 undelete)

यदि source file system Linux EXT-based है, तो आप **full carving** के बिना हाल ही में delete की गई files recover कर सकते हैं; ये journal-based tools unmounted filesystem या read-only image पर काम करते हैं।<sup>[[8]](#references)[[9]](#references)</sup>
```bash
# Attempt journal-based undelete (metadata must still be present)
extundelete disk.img --restore-all

# Multi-stage recovery from an ext4 image
ext4magic disk.img -M -d ./recovered
```
> **Compatibility note** – ext4magic abandoned है; इसके project page पर चेतावनी दी गई है कि current filesystems अब इसके साथ compatible नहीं हैं।<sup>[[10]](#references)</sup>

> 🛈 यदि deletion के बाद file system mount किया गया था, तो data blocks पहले ही reuse हो चुके हो सकते हैं – ऐसी स्थिति में proper carving (Foremost/Scalpel) अभी भी आवश्यक है।

### binvis

[code](https://code.google.com/archive/p/binvis/) और [web page tool](https://binvis.io/#/) देखें।

#### BinVis की सुविधाएँ

- Visual और active **structure viewer**
- अलग-अलग focus points के लिए multiple plots
- किसी sample के portions पर focus करना
- PE या ELF executables में, जैसे, **strings और resources देखना**
- Files पर cryptanalysis के लिए **patterns** प्राप्त करना
- **packer या encoder algorithms पहचानना**
- Patterns द्वारा **Steganography पहचानना**
- **Visual** binary-diffing

Black-boxing scenario में **किसी unknown target से परिचित होने के लिए** BinVis एक बेहतरीन **start-point** है।

## Specific Data Carving Tools

### FindAES

यह उनके key schedules को search करके AES keys खोजता है। यह 128, 192 और 256 bit keys खोज सकता है, जैसे TrueCrypt और BitLocker द्वारा उपयोग की जाने वाली keys।

[यहाँ](https://sourceforge.net/projects/findaes/) से download करें।

### YARA-X (carved artefacts की triaging)

[YARA-X](https://github.com/VirusTotal/yara-x) YARA का Rust rewrite है, जिसे 2024 में introduce किया गया था; VirusTotal के अनुसार कुछ regular-expression और complex-loop rules काफी तेज़ी से run हो सकते हैं।<sup>[[5]](#references)</sup> इसका CLI `yr` नाम से है, और `scan` command recursive scans, thread count और metadata output को support करता है।<sup>[[6]](#references)</sup>
```bash
# Scan every carved object produced by bulk_extractor
yr scan --recursive --threads 8 --print-meta rules/index.yar out_folder/
```
## सहायक tools

आप terminal से images देखने के लिए [**viu** ](https://github.com/atanunq/viu) का उपयोग कर सकते हैं।  \
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
- [11] [Binwalk v3 README](https://github.com/ReFirmLabs/binwalk/blob/master/README.md)
- [12] [The Sleuth Kit: tsk_recover manual](https://sleuthkit.org/sleuthkit/man/tsk_recover.html)
{{#include ../../../banners/hacktricks-training.md}}
