# File/Data Carving & Recovery Tools

{{#include ../../../banners/hacktricks-training.md}}

## Carving & Recovery tools

More tools in [https://github.com/Claudio-C/awesome-datarecovery](https://github.com/Claudio-C/awesome-datarecovery)

### Autopsy

फोरेंसिक्स में छवियों से फ़ाइलें निकालने के लिए सबसे सामान्य उपकरण [**Autopsy**](https://www.autopsy.com/download/) है। इसे डाउनलोड करें, इंस्टॉल करें और "छिपी" फ़ाइलें खोजने के लिए इसे फ़ाइल को इनजेस्ट करने दें। ध्यान दें कि Autopsy डिस्क छवियों और अन्य प्रकार की छवियों का समर्थन करने के लिए बनाया गया है, लेकिन साधारण फ़ाइलों के लिए नहीं।

### Binwalk <a href="#binwalk" id="binwalk"></a>

**Binwalk** एक उपकरण है जो बाइनरी फ़ाइलों का विश्लेषण करने के लिए अंतर्निहित सामग्री खोजने के लिए है। इसे `apt` के माध्यम से इंस्टॉल किया जा सकता है और इसका स्रोत [GitHub](https://github.com/ReFirmLabs/binwalk) पर है।

**Useful commands**:
```bash
sudo apt install binwalk #Insllation
binwalk file #Displays the embedded data in the given file
binwalk -e file #Displays and extracts some files from the given file
binwalk --dd ".*" file #Displays and extracts all files from the given file
```
### Foremost

एक और सामान्य उपकरण जो छिपी हुई फ़ाइलों को खोजने के लिए है वह है **foremost**। आप foremost की कॉन्फ़िगरेशन फ़ाइल `/etc/foremost.conf` में पा सकते हैं। यदि आप केवल कुछ विशिष्ट फ़ाइलों के लिए खोज करना चाहते हैं, तो उन्हें अनकमेंट करें। यदि आप कुछ भी अनकमेंट नहीं करते हैं, तो foremost अपनी डिफ़ॉल्ट कॉन्फ़िगर की गई फ़ाइल प्रकारों के लिए खोज करेगा।
```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
#Discovered files will appear inside the folder "output"
```
### **Scalpel**

**Scalpel** एक और उपकरण है जिसका उपयोग **फाइल में एम्बेडेड फाइलों** को खोजने और निकालने के लिए किया जा सकता है। इस मामले में, आपको कॉन्फ़िगरेशन फ़ाइल (_/etc/scalpel/scalpel.conf_) से उन फ़ाइल प्रकारों को अनकमेंट करना होगा जिन्हें आप निकालना चाहते हैं।
```bash
sudo apt-get install scalpel
scalpel file.img -o output
```
### Bulk Extractor

यह उपकरण काली के अंदर आता है लेकिन आप इसे यहाँ पा सकते हैं: [https://github.com/simsong/bulk_extractor](https://github.com/simsong/bulk_extractor)

यह उपकरण एक इमेज को स्कैन कर सकता है और इसके अंदर **pcaps** को **निकालेगा**, **नेटवर्क जानकारी (URLs, domains, IPs, MACs, mails)** और अधिक **फाइलें**। आपको केवल यह करना है:
```
bulk_extractor memory.img -o out_folder
```
**सभी जानकारी** के माध्यम से नेविगेट करें जो उपकरण ने एकत्र की है (पासवर्ड?), **पैकेट्स** का **विश्लेषण** करें (पढ़ें[ **Pcaps analysis**](../pcap-inspection/index.html)), **अजीब डोमेन** की खोज करें (डोमेन जो **मैलवेयर** या **अवास्तविक** से संबंधित हैं)।

### PhotoRec

आप इसे [https://www.cgsecurity.org/wiki/TestDisk_Download](https://www.cgsecurity.org/wiki/TestDisk_Download) पर पा सकते हैं।

यह GUI और CLI संस्करणों के साथ आता है। आप उन **फाइल-प्रकारों** का चयन कर सकते हैं जिन्हें आप PhotoRec से खोजने के लिए चाहते हैं।

![](<../../../images/image (524).png>)

### binvis

[कोड](https://code.google.com/archive/p/binvis/) और [वेब पेज उपकरण](https://binvis.io/#/) की जांच करें।

#### BinVis की विशेषताएँ

- दृश्य और सक्रिय **संरचना दर्शक**
- विभिन्न फोकस बिंदुओं के लिए कई प्लॉट
- एक नमूने के हिस्सों पर ध्यान केंद्रित करना
- PE या ELF निष्पादन योग्य में **स्ट्रिंग्स और संसाधनों** को देखना, जैसे
- फ़ाइलों पर क्रिप्टानालिसिस के लिए **पैटर्न** प्राप्त करना
- पैकर या एन्कोडर एल्गोरिदम का **पता लगाना**
- पैटर्न द्वारा स्टीगनोग्राफी की **पहचान करना**
- **दृश्य** बाइनरी-डिफ़िंग

BinVis एक अज्ञात लक्ष्य के साथ परिचित होने के लिए एक महान **शुरुआत बिंदु** है एक ब्लैक-बॉक्सिंग परिदृश्य में।

## विशिष्ट डेटा कार्विंग उपकरण

### FindAES

AES कुंजियों की खोज उनके कुंजी शेड्यूल की खोज करके करता है। 128, 192, और 256 बिट कुंजियों को खोजने में सक्षम, जैसे कि TrueCrypt और BitLocker द्वारा उपयोग की जाने वाली।

[यहाँ डाउनलोड करें](https://sourceforge.net/projects/findaes/)।

## पूरक उपकरण

आप टर्मिनल से छवियों को देखने के लिए [**viu** ](https://github.com/atanunq/viu) का उपयोग कर सकते हैं।\
आप PDF को टेक्स्ट में बदलने और पढ़ने के लिए लिनक्स कमांड लाइन उपकरण **pdftotext** का उपयोग कर सकते हैं।

{{#include ../../../banners/hacktricks-training.md}}
