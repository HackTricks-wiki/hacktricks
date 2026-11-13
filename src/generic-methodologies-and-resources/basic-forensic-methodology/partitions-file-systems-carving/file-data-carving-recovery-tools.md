# File/Data Carving और Recovery Tools

{{#include ../../../banners/hacktricks-training.md}}

## Carving और Recovery tools

हमेशा **verified copy** को carve करें, original device को नहीं। Read-only acquisition और hashing workflows के लिए [Image Acquisition & Mount](../image-acquisition-and-mount.md) देखें।

और tools यहाँ हैं: [https://github.com/Claudio-C/awesome-datarecovery](https://github.com/Claudio-C/awesome-datarecovery)

### Autopsy

Forensics में images से files निकालने के लिए सबसे अधिक इस्तेमाल किया जाने वाला tool [**Autopsy**](https://www.autopsy.com/download/) है। इसे download और install करें, फिर "hidden" files ढूँढ़ने के लिए इससे file ingest करवाएँ। ध्यान दें कि Autopsy को disk images और अन्य प्रकार की images के लिए बनाया गया है, लेकिन साधारण files के लिए नहीं।

### Binwalk <a href="#binwalk" id="binwalk"></a>

**Binwalk** binary files का विश्लेषण करके उनमें embedded content ढूँढ़ने वाला tool है। **Binwalk v3** इसका Rust rewrite है, जिसमें automatic extraction (`-e`), ज्ञात और अज्ञात objects की raw carving (`-c`), recursive/Matryoshka scanning (`-M`) और configurable worker threads शामिल हैं। Project सभी external extractors की ज़रूरत होने पर इसका Docker build इस्तेमाल करने की सलाह देता है; `cargo install binwalk` से Rust CLI install होता है, लेकिन वे external dependencies install नहीं होतीं।<sup>[[11]](#references)</sup>

**उपयोगी v3 commands**:

```bash
cargo install binwalk                 # CLI only; install extractors separately
binwalk firmware.bin                  # Identify embedded content
binwalk -e firmware.bin               # Extract recognised objects
binwalk -c -d carved firmware.bin     # Carve known and unknown objects
binwalk -Me -d extracted firmware.bin # Extract and recursively scan results
binwalk -e -l results.json firmware.bin
```

पुरानी v2 `--dd='.*'` recipe, v3 में `-c` के बराबर नहीं है; पुराने CTF/write-up commands का पालन करते समय पहले `binwalk --version` जाँचें।<sup>[[11]](#references)</sup>

⚠️  **सुरक्षा नोट** – **2.1.2b से 2.3.3** तक के versions **Path Traversal** vulnerability (CVE-2022-4510) से प्रभावित हैं; advisory में कोई patched pip version सूचीबद्ध नहीं है। प्रभावित releases से untrusted samples extract करने से बचें, या tool को container/non-privileged UID के साथ isolate करें।<sup>[[4]](#references)</sup>

### Foremost

छिपी हुई files खोजने का एक अन्य आम tool **foremost** है। foremost की configuration file `/etc/foremost.conf` में मिल सकती है। अगर आप केवल कुछ खास files खोजना चाहते हैं, तो उनके आगे से comment हटाएँ। अगर आप किसी के आगे से comment नहीं हटाते, तो foremost अपने default configured file types खोजेगा।

```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
# Discovered files will appear inside the folder "output"
```

### **Scalpel**

**Scalpel** एक अन्य tool है जिसका उपयोग **किसी फ़ाइल में एम्बेड की गई फ़ाइलों** को खोजने और निकालने के लिए किया जा सकता है। इस मामले में, आपको configuration file (_/etc/scalpel/scalpel.conf_) में उन file types की uncomment वाली पंक्तियाँ सक्षम करनी होंगी जिन्हें आप निकालना चाहते हैं।

```bash
sudo apt-get install scalpel
scalpel file.img -o output
```

### Scalpel3 fragmented carving

जब metadata-first recovery और contiguous carvers से split files अधूरी रह जाती हैं, तो **Scalpel3** file/block validators का उपयोग करके समर्थित formats को फिर से जोड़ सकता है। इसका codebase ऊपर दिए गए legacy `scalpel` command से अलग है। सबसे पहले carving में इस्तेमाल किए गए **समान block size** के साथ इसका आवश्यक blockmap बनाएँ; यदि ज्ञात हो, तो `fsstat` से filesystem cluster size लें, या partition image को scan करने से पहले उचित मान निर्धारित करें। इसे केवल verified copy पर चलाएँ और output को अलग volume पर रखें।<sup>[[13]](#references)[[14]](#references)[[15]](#references)</sup>

```bash
git clone https://github.com/nolaforensix/scalpel3-release.git
cd scalpel3-release && ./init_scalpel3.sh && cd src
./crblockmap -q 4096 /evidence/partition.img /analysis/partition.blockmap
./scalpel3 -Y cpu -q 4096 -w -b -o /analysis/scalpel3 \
  /evidence/partition.img /analysis/partition.blockmap
```

`4096` को चुने गए block size से बदलें। `-w` **PROMISING** candidates के साथ-साथ validated candidates को भी रखता है, और `-b` reconstructed layouts की जाँच में मदद करने के लिए blockvectors लिखता है। PROMISING में मौजूद फ़ाइल, या परिचित extension वाली फ़ाइल, पूर्ण recovery का प्रमाण नहीं है; उपयोग से पहले content validate करें।<sup>[[13]](#references)[[14]](#references)</sup> Carving से पहले deleted partitions या gaps ढूँढ़ने के लिए, [सूचीबद्ध partitions के बाहर डेटा ढूँढ़ना](./#finding-data-outside-listed-partitions) देखें।

### Bulk Extractor 2.x   

यह टूल Kali में शामिल है, लेकिन आप इसे यहाँ पा सकते हैं: <https://github.com/simsong/bulk_extractor>

Bulk Extractor किसी evidence image को scan कर सकता है और **pcap fragments**, **network artefacts (URLs, domains, IPs, MACs, e-mails)** तथा कई अन्य objects को **एक साथ कई scanners का उपयोग करके parallel में** carve कर सकता है।

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

बंडल में शामिल `bulk_diff.py` दो bulk_extractor runs की तुलना करता है, जबकि `bulk_extractor_reader.py` report और feature files को पढ़ता है।<sup>[[3]](#references)</sup>

### PhotoRec

आप इसे <https://www.cgsecurity.org/wiki/TestDisk_Download> पर पा सकते हैं।

इसके GUI और CLI versions उपलब्ध हैं। आप चुन सकते हैं कि PhotoRec किन **file-types** को खोजे।

![हर scanner चलाएँ, आक्रामक तरीके से JPEGs carve करें और bodyfile बनाएँ - PhotoRec: इसके GUI और CLI versions उपलब्ध हैं। आप चुन सकते हैं कि PhotoRec किन file-types को खोजे](<../../../images/image (242).png>)

### The Sleuth Kit `tsk_recover` (पहले metadata)

Raw signature carving से पहले, filesystem-aware recovery आज़माएँ, जब volume metadata अभी भी parse किया जा सकता हो। `tsk_recover` default रूप से केवल unallocated files export करता है; `-a` allocated files चुनता है और `-e` दोनों export करता है। पूरी disk की image के लिए, `mmls` से मिला partition का **start sector** `-o` को दें (इसे bytes में convert न करें)। अगर input पहले से ही partition image है, तो `-o` छोड़ दें।<sup>[[12]](#references)</sup>

```bash
sudo apt install sleuthkit
mmls disk.img                         # Note the partition start sector, e.g. 2048
mkdir recovered-deleted recovered-all
tsk_recover -o 2048 disk.img recovered-deleted/
tsk_recover -e -o 2048 disk.img recovered-all/
```

यह प्रक्रिया filesystem से प्राप्त नामों और paths को सुरक्षित रख सकती है, जिन्हें header/footer carving सुरक्षित नहीं रख सकती; जिन entries का metadata अनुपलब्ध या अनुपयोगी है, उनके लिए बाद में Foremost, Scalpel या PhotoRec चलाएँ।<sup>[[12]](#references)</sup>

### ddrescue + ddrescueview (विफल हो रही drives की imaging)

जब कोई physical drive अस्थिर हो, तो सबसे अच्छा तरीका है कि **पहले उसकी image बनाएँ** और carving tools केवल उस image पर चलाएँ। `ddrescue` (GNU project) unreadable sectors का log रखते हुए खराब disks को विश्वसनीय रूप से copy करने पर केंद्रित है।

```bash
sudo apt install gddrescue ddrescueview   # On Debian-based systems
# First pass – try to get as much data as possible without retries
sudo ddrescue -f -n /dev/sdX suspect.img suspect.log
# Second pass – aggressive, 3 retries on the remaining bad areas
sudo ddrescue -d -r3 /dev/sdX suspect.img suspect.log

# Visualise the status map (green=good, red=bad)
 ddrescueview suspect.log
```

**`--cluster-size`** विकल्प एक बार में कॉपी किए जाने वाले sectors की संख्या नियंत्रित करता है; छोटी values धीमी drives के लिए मददगार हो सकती हैं।<sup>[[7]](#references)</sup>

### Extundelete / Ext4magic (EXT 3/4 undelete)

अगर source file system Linux EXT-आधारित है, तो आप **पूरी carving किए बिना** हाल ही में delete की गई files recover कर सकते हैं; ये journal-आधारित tools unmounted filesystem या read-only image पर काम करते हैं।<sup>[[8]](#references)[[9]](#references)</sup>

```bash
# Attempt journal-based undelete (metadata must still be present)
extundelete disk.img --restore-all

# Multi-stage recovery from an ext4 image
ext4magic disk.img -M -d ./recovered
```

> **संगतता संबंधी नोट** – ext4magic अब अनुरक्षित नहीं है; इसका प्रोजेक्ट पेज चेतावनी देता है कि मौजूदा फ़ाइल सिस्टम अब इसके साथ संगत नहीं हैं।<sup>[[10]](#references)</sup>

> 🛈 यदि हटाने के बाद फ़ाइल सिस्टम माउंट किया गया था, तो डेटा ब्लॉक शायद पहले ही दोबारा इस्तेमाल हो चुके हों – ऐसी स्थिति में उचित carving (Foremost/Scalpel) अभी भी आवश्यक है।

### binvis

[code](https://code.google.com/archive/p/binvis/) और [web page tool](https://binvis.io/#/) देखें।

#### BinVis की विशेषताएँ

- विज़ुअल और सक्रिय **structure viewer**
- अलग-अलग focus points के लिए कई plots
- sample के हिस्सों पर focus करना
- उदाहरण के लिए, PE या ELF executables में **strings और resources देखना**
- फ़ाइलों पर cryptanalysis के लिए **patterns प्राप्त करना**
- packer या encoder algorithms **पहचानना**
- patterns के आधार पर Steganography **पहचानना**
- विज़ुअल **binary-diffing**

ब्लैक-बॉक्सिंग परिदृश्य में किसी अज्ञात target से परिचित होने के लिए BinVis एक बेहतरीन **शुरुआती बिंदु** है।

## विशिष्ट Data Carving टूल

### FindAES

AES keys को उनके key schedules खोजकर ढूँढ़ता है। यह 128, 192 और 256 bit keys खोज सकता है, जैसे कि TrueCrypt और BitLocker द्वारा इस्तेमाल की जाने वाली keys।

[यहाँ](https://sourceforge.net/projects/findaes/) डाउनलोड करें।

### YARA-X (carved artefacts की triaging)

[YARA-X](https://github.com/VirusTotal/yara-x) YARA का Rust में फिर से लिखा गया संस्करण है, जिसे 2024 में पेश किया गया था; VirusTotal के अनुसार कुछ regular-expression और complex-loop rules काफ़ी तेज़ी से चल सकते हैं।<sup>[[5]](#references)</sup> इसका CLI `yr` नाम से है, और `scan` command recursive scans, thread count और metadata output को support करता है।<sup>[[6]](#references)</sup>

```bash
# Scan every carved object produced by bulk_extractor
yr scan --recursive --threads 8 --print-meta rules/index.yar out_folder/
```

## पूरक टूल

आप टर्मिनल से इमेज देखने के लिए [**viu** ](https://github.com/atanunq/viu) का उपयोग कर सकते हैं।  \
PDF को टेक्स्ट में बदलकर पढ़ने के लिए आप Linux command line tool **pdftotext** का उपयोग कर सकते हैं।







## References

- [1] [Autopsy 4.21 रिलीज़ नोट्स](https://github.com/sleuthkit/autopsy/releases/tag/autopsy-4.21.0)
- [2] [bulk_extractor v2.1.1 README](https://github.com/simsong/bulk_extractor/blob/v2.1.1/README.md)
- [3] [bulk_extractor Python tools README](https://raw.githubusercontent.com/simsong/bulk_extractor/v2.1.1/python/README.txt)
- [4] [binwalk में Path traversal (CVE-2022-4510) - GitHub Advisory Database](https://github.com/advisories/GHSA-3cm8-v4mc-gppg)
- [5] [YARA अब नहीं रहा, YARA-X अमर रहे - VirusTotal Blog](https://blog.virustotal.com/2024/05/yara-is-dead-long-live-yara-x.html)
- [6] [YARA-X CLI कमांड](https://virustotal.github.io/yara-x/docs/cli/commands/)
- [7] [GNU ddrescue मैनुअल](https://www.gnu.org/software/ddrescue/manual/ddrescue_manual.html)
- [8] [extundelete](https://extundelete.sourceforge.net/)
- [9] [ext4magic मैनुअल](https://ext4magic.sourceforge.net/manpage_en.html)
- [10] [ext4magic प्रोजेक्ट की स्थिति](https://sourceforge.net/projects/ext4magic/)
- [11] [Binwalk v3 README](https://github.com/ReFirmLabs/binwalk/blob/master/README.md)
- [12] [The Sleuth Kit: tsk_recover मैनुअल](https://sleuthkit.org/sleuthkit/man/tsk_recover.html)
- [13] [Scalpel3 README](https://github.com/nolaforensix/scalpel3-release/blob/main/README.md)
- [14] [Scalpel3 मैनुअल](https://github.com/nolaforensix/scalpel3-release/blob/main/man/scalpel3.1)
- [15] [Scalpel3 टेस्ट वर्कफ़्लो](https://github.com/nolaforensix/scalpel3-release/blob/main/src/TESTS/cmdline.test)
{{#include ../../../banners/hacktricks-training.md}}
