# File/Data Carving & Recovery Tools

{{#include ../../../banners/hacktricks-training.md}}

## Carving & Recovery tools

More tools in [https://github.com/Claudio-C/awesome-datarecovery](https://github.com/Claudio-C/awesome-datarecovery)

### Autopsy

फोरेंसिक्स में छवियों से फ़ाइलें निकालने के लिए सबसे सामान्य उपकरण [**Autopsy**](https://www.autopsy.com/download/) है। इसे डाउनलोड करें, इंस्टॉल करें और "छिपी हुई" फ़ाइलें खोजने के लिए फ़ाइल को इनजेस्ट करें। ध्यान दें कि Autopsy डिस्क छवियों और अन्य प्रकार की छवियों का समर्थन करने के लिए बनाया गया है, लेकिन साधारण फ़ाइलों के लिए नहीं।

> **2024-2025 अपडेट** – संस्करण **4.21** (फरवरी 2025 में जारी) ने एक पुनर्निर्मित **कार्विंग मॉड्यूल जोड़ा जो SleuthKit v4.13 पर आधारित है** जो मल्टी-टेरेबाइट छवियों के साथ काम करते समय स्पष्ट रूप से तेज है और मल्टी-कोर सिस्टम पर समानांतर निष्कर्षण का समर्थन करता है।¹ एक छोटा CLI रैपर (`autopsycli ingest <case> <image>`) भी पेश किया गया, जिससे CI/CD या बड़े पैमाने पर प्रयोगशाला वातावरण के भीतर कार्विंग को स्क्रिप्ट करना संभव हो गया।
```bash
# Create a case and ingest an evidence image from the CLI (Autopsy ≥4.21)
autopsycli case --create MyCase --base /cases
# ingest with the default ingest profile (includes data-carve module)
autopsycli ingest MyCase /evidence/disk01.E01 --threads 8
```
### Binwalk <a href="#binwalk" id="binwalk"></a>

**Binwalk** एक उपकरण है जो बाइनरी फ़ाइलों का विश्लेषण करने के लिए उपयोग किया जाता है ताकि अंतर्निहित सामग्री को खोजा जा सके। इसे `apt` के माध्यम से स्थापित किया जा सकता है और इसका स्रोत [GitHub](https://github.com/ReFirmLabs/binwalk) पर है।

**उपयोगी कमांड**:
```bash
sudo apt install binwalk         # Installation
binwalk firmware.bin             # Display embedded data
binwalk -e firmware.bin          # Extract recognised objects (safe-default)
binwalk --dd " .* " firmware.bin  # Extract *everything* (use with care)
```
⚠️  **सुरक्षा नोट** – संस्करण **≤2.3.3** एक **पाथ ट्रैवर्सल** सुरक्षा दोष (CVE-2022-4510) से प्रभावित हैं। अनधिकृत नमूनों को काटने से पहले अपग्रेड करें (या कंटेनर/गैर-विशिष्ट UID के साथ अलग करें)।

### Foremost

छिपी हुई फ़ाइलों को खोजने के लिए एक और सामान्य उपकरण **foremost** है। आप foremost की कॉन्फ़िगरेशन फ़ाइल `/etc/foremost.conf` में पा सकते हैं। यदि आप कुछ विशिष्ट फ़ाइलों के लिए केवल खोज करना चाहते हैं तो उन्हें अनकमेंट करें। यदि आप कुछ भी अनकमेंट नहीं करते हैं, तो foremost अपनी डिफ़ॉल्ट कॉन्फ़िगर की गई फ़ाइल प्रकारों के लिए खोज करेगा।
```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
# Discovered files will appear inside the folder "output"
```
### **Scalpel**

**Scalpel** एक और उपकरण है जिसका उपयोग **फाइल में एम्बेडेड फाइलों** को खोजने और निकालने के लिए किया जा सकता है। इस मामले में, आपको कॉन्फ़िगरेशन फ़ाइल (_/etc/scalpel/scalpel.conf_) से उन फ़ाइल प्रकारों को अनकमेंट करना होगा जिन्हें आप निकालना चाहते हैं।
```bash
sudo apt-get install scalpel
scalpel file.img -o output
```
### Bulk Extractor 2.x

यह उपकरण काली के अंदर आता है लेकिन आप इसे यहाँ पा सकते हैं: <https://github.com/simsong/bulk_extractor>

Bulk Extractor एक साक्ष्य छवि को स्कैन कर सकता है और **pcap टुकड़े**, **नेटवर्क कलाकृतियाँ (URLs, domains, IPs, MACs, e-mails)** और कई अन्य वस्तुओं को **एक साथ कई स्कैनरों का उपयोग करके** काट सकता है।
```bash
# Build from source – v2.1.1 (April 2024) requires cmake ≥3.16
git clone https://github.com/simsong/bulk_extractor.git && cd bulk_extractor
mkdir build && cd build && cmake .. && make -j$(nproc) && sudo make install

# Run every scanner, carve JPEGs aggressively and generate a bodyfile
bulk_extractor -o out_folder -S jpeg_carve_mode=2 -S write_bodyfile=y /evidence/disk.img
```
उपयोगी पोस्ट-प्रोसेसिंग स्क्रिप्ट्स (`bulk_diff`, `bulk_extractor_reader.py`) दो इमेज के बीच आर्टिफैक्ट्स को डि-डुप्लिकेट कर सकती हैं या परिणामों को SIEM इनजेशन के लिए JSON में परिवर्तित कर सकती हैं।

### PhotoRec

आप इसे <https://www.cgsecurity.org/wiki/TestDisk_Download> पर पा सकते हैं।

यह GUI और CLI संस्करणों के साथ आता है। आप उन **फाइल-प्रकारों** का चयन कर सकते हैं जिन्हें आप PhotoRec द्वारा खोजने के लिए चाहते हैं।

![](<../../../images/image (242).png>)

### ddrescue + ddrescueview (फेलिंग ड्राइव्स की इमेजिंग)

जब एक भौतिक ड्राइव अस्थिर होता है, तो सबसे अच्छा अभ्यास है कि पहले **इसे इमेज करें** और केवल इमेज के खिलाफ कार्विंग टूल चलाएं। `ddrescue` (GNU प्रोजेक्ट) खराब डिस्क को विश्वसनीय रूप से कॉपी करने पर ध्यान केंद्रित करता है जबकि पढ़ने में असमर्थ सेक्टरों का लॉग रखता है।
```bash
sudo apt install gddrescue ddrescueview   # On Debian-based systems
# First pass – try to get as much data as possible without retries
sudo ddrescue -f -n /dev/sdX suspect.img suspect.log
# Second pass – aggressive, 3 retries on the remaining bad areas
sudo ddrescue -d -r3 /dev/sdX suspect.img suspect.log

# Visualise the status map (green=good, red=bad)
ddrescueview suspect.log
```
संस्करण **1.28** (दिसंबर 2024) ने **`--cluster-size`** पेश किया जो उच्च-क्षमता वाले SSDs की इमेजिंग को तेज कर सकता है जहाँ पारंपरिक सेक्टर आकार अब फ्लैश ब्लॉकों के साथ संरेखित नहीं होते हैं।

### Extundelete / Ext4magic (EXT 3/4 undelete)

यदि स्रोत फ़ाइल प्रणाली Linux EXT-आधारित है, तो आप हाल ही में हटाए गए फ़ाइलों को **पूर्ण कार्विंग के बिना** पुनर्प्राप्त करने में सक्षम हो सकते हैं। दोनों उपकरण सीधे एक पढ़ने-के-लिए छवि पर काम करते हैं:
```bash
# Attempt journal-based undelete (metadata must still be present)
extundelete disk.img --restore-all

# Fallback to full directory scan; supports extents and inline data
ext4magic disk.img -M -f '*.jpg' -d ./recovered
```
> 🛈 यदि फ़ाइल प्रणाली को हटाने के बाद माउंट किया गया था, तो डेटा ब्लॉक्स पहले ही पुन: उपयोग किए जा सकते हैं - इस मामले में उचित कार्विंग (Foremost/Scalpel) अभी भी आवश्यक है।

### binvis

[कोड](https://code.google.com/archive/p/binvis/) और [वेब पृष्ठ उपकरण](https://binvis.io/#/) की जांच करें।

#### BinVis की विशेषताएँ

- दृश्य और सक्रिय **संरचना दर्शक**
- विभिन्न फोकस बिंदुओं के लिए कई प्लॉट
- एक नमूने के हिस्सों पर ध्यान केंद्रित करना
- **PE या ELF निष्पादन योग्य में स्ट्रिंग और संसाधनों को देखना** जैसे
- फ़ाइलों पर क्रिप्टानालिसिस के लिए **पैटर्न** प्राप्त करना
- पैकर या एन्कोडर एल्गोरिदम को **पहचानना**
- पैटर्न द्वारा स्टेगनोग्राफी की **पहचान करना**
- **दृश्य** बाइनरी-डिफ़िंग

BinVis एक अज्ञात लक्ष्य के साथ परिचित होने के लिए एक महान **शुरुआत बिंदु** है एक ब्लैक-बॉक्सिंग परिदृश्य में।

## विशिष्ट डेटा कार्विंग उपकरण

### FindAES

AES कुंजियों के लिए उनके कुंजी शेड्यूल की खोज करके खोजता है। 128, 192, और 256 बिट कुंजियों को खोजने में सक्षम, जैसे कि TrueCrypt और BitLocker द्वारा उपयोग की जाने वाली।

[यहाँ](https://sourceforge.net/projects/findaes/) डाउनलोड करें।

### YARA-X (कार्वित कलाकृतियों का ट्रायजिंग)

[YARA-X](https://github.com/VirusTotal/yara-x) YARA का एक Rust पुनर्लेखन है जो 2024 में जारी किया गया। यह क्लासिक YARA की तुलना में **10-30× तेज** है और हजारों कार्वित वस्तुओं को बहुत तेजी से वर्गीकृत करने के लिए उपयोग किया जा सकता है:
```bash
# Scan every carved object produced by bulk_extractor
yarax -r rules/index.yar out_folder/ --threads 8 --print-meta
```
गति में वृद्धि इसे बड़े पैमाने पर जांचों में सभी काटे गए फ़ाइलों को **स्वतः-टैग** करना यथार्थवादी बनाती है।

## पूरक उपकरण

आप टर्मिनल से चित्र देखने के लिए [**viu** ](https://github.com/atanunq/viu) का उपयोग कर सकते हैं।  \
आप **pdftotext** लिनक्स कमांड लाइन उपकरण का उपयोग करके एक पीडीएफ को टेक्स्ट में बदल सकते हैं और इसे पढ़ सकते हैं।

## संदर्भ

1. Autopsy 4.21 रिलीज नोट्स – <https://github.com/sleuthkit/autopsy/releases/tag/autopsy-4.21>
{{#include ../../../banners/hacktricks-training.md}}
