{{#include ../../../banners/hacktricks-training.md}}

# कार्विंग उपकरण

## ऑटोप्सी

फोरेंसिक्स में छवियों से फ़ाइलें निकालने के लिए सबसे सामान्य उपकरण [**ऑटोप्सी**](https://www.autopsy.com/download/) है। इसे डाउनलोड करें, इंस्टॉल करें और "छिपी" फ़ाइलें खोजने के लिए फ़ाइल को इनजेस्ट करें। ध्यान दें कि ऑटोप्सी डिस्क इमेज और अन्य प्रकार की इमेज का समर्थन करने के लिए बनाई गई है, लेकिन साधारण फ़ाइलों के लिए नहीं।

## बिनवॉक <a id="binwalk"></a>

**बिनवॉक** एक उपकरण है जो बाइनरी फ़ाइलों जैसे छवियों और ऑडियो फ़ाइलों में एम्बेडेड फ़ाइलों और डेटा की खोज के लिए है। इसे `apt` के साथ इंस्टॉल किया जा सकता है, हालाँकि [स्रोत](https://github.com/ReFirmLabs/binwalk) github पर पाया जा सकता है।  
**उपयोगी कमांड**:
```bash
sudo apt install binwalk #Insllation
binwalk file #Displays the embedded data in the given file
binwalk -e file #Displays and extracts some files from the given file
binwalk --dd ".*" file #Displays and extracts all files from the given file
```
## Foremost

एक और सामान्य उपकरण जो छिपी हुई फ़ाइलों को खोजने के लिए है वह है **foremost**। आप foremost की कॉन्फ़िगरेशन फ़ाइल `/etc/foremost.conf` में पा सकते हैं। यदि आप केवल कुछ विशिष्ट फ़ाइलों के लिए खोज करना चाहते हैं, तो उन्हें अनकमेंट करें। यदि आप कुछ भी अनकमेंट नहीं करते हैं, तो foremost अपनी डिफ़ॉल्ट कॉन्फ़िगर की गई फ़ाइल प्रकारों के लिए खोज करेगा।
```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
#Discovered files will appear inside the folder "output"
```
## **Scalpel**

**Scalpel** एक और उपकरण है जिसका उपयोग **फाइल में एम्बेडेड फाइलों** को खोजने और निकालने के लिए किया जा सकता है। इस मामले में, आपको कॉन्फ़िगरेशन फ़ाइल \(_/etc/scalpel/scalpel.conf_\) से उन फ़ाइल प्रकारों को अनकमेंट करना होगा जिन्हें आप निकालना चाहते हैं।
```bash
sudo apt-get install scalpel
scalpel file.img -o output
```
## Bulk Extractor

यह उपकरण काली के अंदर आता है लेकिन आप इसे यहाँ पा सकते हैं: [https://github.com/simsong/bulk_extractor](https://github.com/simsong/bulk_extractor)

यह उपकरण एक इमेज को स्कैन कर सकता है और इसके अंदर **pcaps** को **निकालेगा**, **नेटवर्क जानकारी\(URLs, domains, IPs, MACs, mails\)** और अधिक **फाइलें**। आपको केवल यह करना है:
```text
bulk_extractor memory.img -o out_folder
```
**सभी जानकारी** के माध्यम से नेविगेट करें जो उपकरण ने एकत्र की है \(पासवर्ड?\), **विश्लेषण** करें **पैकेट्स** का \(पढ़ें [ **Pcaps विश्लेषण**](../pcap-inspection/)\), **अजीब डोमेन** की खोज करें \(डोमेन जो **मैलवेयर** या **अवास्तविक** से संबंधित हैं\).

## PhotoRec

आप इसे [https://www.cgsecurity.org/wiki/TestDisk_Download](https://www.cgsecurity.org/wiki/TestDisk_Download) पर पा सकते हैं।

यह GUI और CLI संस्करण के साथ आता है। आप उन **फाइल-प्रकारों** का चयन कर सकते हैं जिन्हें आप PhotoRec से खोजने के लिए चाहते हैं।

![](../../../images/image%20%28524%29.png)

# विशिष्ट डेटा कार्विंग उपकरण

## FindAES

AES कुंजियों की खोज उनके कुंजी कार्यक्रमों की खोज करके करता है। 128, 192, और 256 बिट कुंजियों को खोजने में सक्षम, जैसे कि TrueCrypt और BitLocker द्वारा उपयोग की जाने वाली।

[यहाँ डाउनलोड करें](https://sourceforge.net/projects/findaes/)।

# पूरक उपकरण

आप [**viu** ](https://github.com/atanunq/viu) का उपयोग करके टर्मिनल से चित्र देख सकते हैं।
आप **pdftotext** लिनक्स कमांड लाइन उपकरण का उपयोग करके एक पीडीएफ को टेक्स्ट में बदल सकते हैं और इसे पढ़ सकते हैं।

{{#include ../../../banners/hacktricks-training.md}}
