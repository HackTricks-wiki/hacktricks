# Firmware Analysis

{{#include ../../banners/hacktricks-training.md}}

## **Introduction**

Firmware एक आवश्यक सॉफ़्टवेयर है जो उपकरणों को सही ढंग से कार्य करने में सक्षम बनाता है, हार्डवेयर घटकों और उपयोगकर्ताओं द्वारा इंटरैक्ट किए जाने वाले सॉफ़्टवेयर के बीच संचार को प्रबंधित और सुविधाजनक बनाता है। इसे स्थायी मेमोरी में संग्रहीत किया जाता है, यह सुनिश्चित करते हुए कि उपकरण को चालू होने के क्षण से महत्वपूर्ण निर्देशों तक पहुँच मिलती है, जो ऑपरेटिंग सिस्टम के लॉन्च की ओर ले जाती है। फर्मवेयर की जांच और संभावित रूप से संशोधन करना सुरक्षा कमजोरियों की पहचान में एक महत्वपूर्ण कदम है।

## **Gathering Information**

**Gathering information** एक महत्वपूर्ण प्रारंभिक कदम है एक उपकरण की संरचना और इसके द्वारा उपयोग की जाने वाली तकनीकों को समझने में। इस प्रक्रिया में डेटा एकत्र करना शामिल है:

- CPU आर्किटेक्चर और जिस ऑपरेटिंग सिस्टम पर यह चलता है
- बूटलोडर विशिष्टताएँ
- हार्डवेयर लेआउट और डेटा शीट
- कोडबेस मैट्रिक्स और स्रोत स्थान
- बाहरी पुस्तकालय और लाइसेंस प्रकार
- अपडेट इतिहास और नियामक प्रमाणन
- आर्किटेक्चरल और फ्लो डायग्राम
- सुरक्षा आकलन और पहचानी गई कमजोरियाँ

इस उद्देश्य के लिए, **open-source intelligence (OSINT)** उपकरण अमूल्य हैं, जैसे कि उपलब्ध ओपन-सोर्स सॉफ़्टवेयर घटकों का मैनुअल और स्वचालित समीक्षा प्रक्रियाओं के माध्यम से विश्लेषण। [Coverity Scan](https://scan.coverity.com) और [Semmle’s LGTM](https://lgtm.com/#explore) जैसे उपकरण संभावित मुद्दों को खोजने के लिए मुफ्त स्थैतिक विश्लेषण प्रदान करते हैं।

## **Acquiring the Firmware**

फर्मवेयर प्राप्त करने के लिए विभिन्न तरीकों का उपयोग किया जा सकता है, प्रत्येक की अपनी जटिलता का स्तर है:

- **Directly** from the source (developers, manufacturers)
- **Building** it from provided instructions
- **Downloading** from official support sites
- Utilizing **Google dork** queries for finding hosted firmware files
- Accessing **cloud storage** directly, with tools like [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Intercepting **updates** via man-in-the-middle techniques
- **Extracting** from the device through connections like **UART**, **JTAG**, or **PICit**
- **Sniffing** for update requests within device communication
- Identifying and using **hardcoded update endpoints**
- **Dumping** from the bootloader or network
- **Removing and reading** the storage chip, when all else fails, using appropriate hardware tools

## Analyzing the firmware

अब जब आपके पास **फर्मवेयर है**, तो आपको इसके बारे में जानकारी निकालने की आवश्यकता है ताकि आप जान सकें कि इसे कैसे संभालना है। इसके लिए आप विभिन्न उपकरणों का उपयोग कर सकते हैं:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
यदि आप उन उपकरणों के साथ ज्यादा कुछ नहीं पाते हैं, तो छवि की **entropy** को `binwalk -E <bin>` के साथ जांचें, यदि entropy कम है, तो यह संभावना नहीं है कि यह एन्क्रिप्टेड है। यदि entropy उच्च है, तो यह संभावना है कि यह एन्क्रिप्टेड है (या किसी न किसी तरीके से संकुचित है)।

इसके अलावा, आप इन उपकरणों का उपयोग **फर्मवेयर के अंदर एम्बेडेड फ़ाइलों** को निकालने के लिए कर सकते हैं:

{{#ref}}
../../forensics/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

या [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) का उपयोग करके फ़ाइल का निरीक्षण करें।

### फ़ाइल सिस्टम प्राप्त करना

पिछले टिप्पणी किए गए उपकरणों जैसे `binwalk -ev <bin>` के साथ, आपको **फाइल सिस्टम निकालने में सक्षम होना चाहिए**।\
Binwalk आमतौर पर इसे **फाइल सिस्टम प्रकार के नाम वाले फ़ोल्डर** के अंदर निकालता है, जो आमतौर पर निम्नलिखित में से एक होता है: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs।

#### मैनुअल फ़ाइल सिस्टम निष्कर्षण

कभी-कभी, binwalk के पास **फाइल सिस्टम के जादुई बाइट के हस्ताक्षर में नहीं होते हैं**। इन मामलों में, binwalk का उपयोग करके **फाइल सिस्टम का ऑफसेट खोजें और बाइनरी से संकुचित फाइल सिस्टम को काटें** और **इसके प्रकार के अनुसार मैन्युअल रूप से फाइल सिस्टम निकालें** नीचे दिए गए चरणों का उपयोग करके।
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
निम्नलिखित **dd कमांड** को Squashfs फ़ाइल प्रणाली को काटने के लिए चलाएँ।
```
$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs

8257536+0 records in

8257536+0 records out

8257536 bytes (8.3 MB, 7.9 MiB) copied, 12.5777 s, 657 kB/s
```
वैकल्पिक रूप से, निम्नलिखित कमांड भी चलाया जा सकता है।

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

- squashfs (उदाहरण में उपयोग किया गया)

`$ unsquashfs dir.squashfs`

फाइलें "`squashfs-root`" निर्देशिका में बाद में होंगी।

- CPIO आर्काइव फाइलें

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- jffs2 फाइल सिस्टम के लिए

`$ jefferson rootfsfile.jffs2`

- NAND फ्लैश के साथ ubifs फाइल सिस्टम के लिए

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## फर्मवेयर का विश्लेषण

एक बार फर्मवेयर प्राप्त हो जाने के बाद, इसके संरचना और संभावित कमजोरियों को समझने के लिए इसे विश्लेषित करना आवश्यक है। इस प्रक्रिया में फर्मवेयर इमेज से मूल्यवान डेटा का विश्लेषण और निकालने के लिए विभिन्न उपकरणों का उपयोग करना शामिल है।

### प्रारंभिक विश्लेषण उपकरण

बाइनरी फ़ाइल (जिसे `<bin>` कहा जाता है) के प्रारंभिक निरीक्षण के लिए एक सेट कमांड प्रदान किया गया है। ये कमांड फ़ाइल प्रकारों की पहचान करने, स्ट्रिंग्स निकालने, बाइनरी डेटा का विश्लेषण करने और विभाजन और फ़ाइल सिस्टम विवरण को समझने में मदद करते हैं:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
छवि के एन्क्रिप्शन स्थिति का आकलन करने के लिए, **entropy** को `binwalk -E <bin>` के साथ चेक किया जाता है। कम entropy एन्क्रिप्शन की कमी का सुझाव देती है, जबकि उच्च entropy संभावित एन्क्रिप्शन या संकुचन को इंगित करती है।

**Embedded files** को निकालने के लिए, **file-data-carving-recovery-tools** दस्तावेज़ और फ़ाइल निरीक्षण के लिए **binvis.io** जैसे उपकरणों और संसाधनों की सिफारिश की जाती है।

### फ़ाइल सिस्टम निकालना

`binwalk -ev <bin>` का उपयोग करके, आमतौर पर फ़ाइल सिस्टम को निकाला जा सकता है, अक्सर एक निर्देशिका में जिसका नाम फ़ाइल सिस्टम प्रकार (जैसे, squashfs, ubifs) के नाम पर होता है। हालाँकि, जब **binwalk** जादुई बाइट्स की कमी के कारण फ़ाइल सिस्टम प्रकार को पहचानने में विफल रहता है, तो मैनुअल निकासी आवश्यक होती है। इसमें फ़ाइल सिस्टम के ऑफसेट को खोजने के लिए `binwalk` का उपयोग करना शामिल है, इसके बाद फ़ाइल सिस्टम को काटने के लिए `dd` कमांड का उपयोग किया जाता है:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
इसके बाद, फ़ाइल सिस्टम प्रकार (जैसे, squashfs, cpio, jffs2, ubifs) के आधार पर, सामग्री को मैन्युअल रूप से निकालने के लिए विभिन्न कमांड का उपयोग किया जाता है।

### फ़ाइल सिस्टम विश्लेषण

फ़ाइल सिस्टम निकाले जाने के बाद, सुरक्षा खामियों की खोज शुरू होती है। असुरक्षित नेटवर्क डेमन्स, हार्डकोडेड क्रेडेंशियल्स, API एंडपॉइंट्स, अपडेट सर्वर कार्यक्षमताएँ, अनकंपाइल कोड, स्टार्टअप स्क्रिप्ट्स, और ऑफ़लाइन विश्लेषण के लिए संकलित बाइनरीज़ पर ध्यान दिया जाता है।

**मुख्य स्थान** और **आइटम** जिनकी जांच करनी है, उनमें शामिल हैं:

- **etc/shadow** और **etc/passwd** उपयोगकर्ता क्रेडेंशियल्स के लिए
- **etc/ssl** में SSL प्रमाणपत्र और कुंजी
- संभावित कमजोरियों के लिए कॉन्फ़िगरेशन और स्क्रिप्ट फ़ाइलें
- आगे के विश्लेषण के लिए एम्बेडेड बाइनरीज़
- सामान्य IoT डिवाइस वेब सर्वर और बाइनरीज़

कई उपकरण फ़ाइल सिस्टम के भीतर संवेदनशील जानकारी और कमजोरियों को उजागर करने में मदद करते हैं:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) और [**Firmwalker**](https://github.com/craigz28/firmwalker) संवेदनशील जानकारी खोजने के लिए
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) व्यापक फर्मवेयर विश्लेषण के लिए
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go), और [**EMBA**](https://github.com/e-m-b-a/emba) स्थिर और गतिशील विश्लेषण के लिए

### संकलित बाइनरीज़ पर सुरक्षा जांच

फ़ाइल सिस्टम में पाए गए स्रोत कोड और संकलित बाइनरीज़ की कमजोरियों के लिए जांच की जानी चाहिए। Unix बाइनरीज़ के लिए **checksec.sh** और Windows बाइनरीज़ के लिए **PESecurity** जैसे उपकरण असुरक्षित बाइनरीज़ की पहचान करने में मदद करते हैं।

## गतिशील विश्लेषण के लिए फर्मवेयर का अनुकरण

फर्मवेयर का अनुकरण करने की प्रक्रिया **गतिशील विश्लेषण** को सक्षम बनाती है, चाहे वह किसी डिवाइस का संचालन हो या एकल प्रोग्राम। इस दृष्टिकोण में हार्डवेयर या आर्किटेक्चर निर्भरताओं के साथ चुनौतियाँ आ सकती हैं, लेकिन रूट फ़ाइल सिस्टम या विशिष्ट बाइनरीज़ को मिलती-जुलती आर्किटेक्चर और एंडियननेस वाले डिवाइस, जैसे कि Raspberry Pi, या पूर्व-निर्मित वर्चुअल मशीन में स्थानांतरित करना आगे के परीक्षण को सुविधाजनक बना सकता है।

### व्यक्तिगत बाइनरीज़ का अनुकरण

एकल प्रोग्राम की जांच के लिए, प्रोग्राम की एंडियननेस और CPU आर्किटेक्चर की पहचान करना महत्वपूर्ण है।

#### MIPS आर्किटेक्चर के साथ उदाहरण

MIPS आर्किटेक्चर बाइनरी का अनुकरण करने के लिए, कोई निम्नलिखित कमांड का उपयोग कर सकता है:
```bash
file ./squashfs-root/bin/busybox
```
और आवश्यक अनुकरण उपकरण स्थापित करने के लिए:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
For MIPS (big-endian), `qemu-mips` का उपयोग किया जाता है, और little-endian बाइनरी के लिए, `qemu-mipsel` विकल्प होगा।

#### ARM आर्किटेक्चर अनुकरण

ARM बाइनरी के लिए, प्रक्रिया समान है, जिसमें अनुकरण के लिए `qemu-arm` अनुकरणकर्ता का उपयोग किया जाता है।

### पूर्ण प्रणाली अनुकरण

[Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) और अन्य जैसे उपकरण पूर्ण फर्मवेयर अनुकरण को सुविधाजनक बनाते हैं, प्रक्रिया को स्वचालित करते हैं और गतिशील विश्लेषण में सहायता करते हैं।

## व्याव实践 में गतिशील विश्लेषण

इस चरण में, विश्लेषण के लिए या तो एक वास्तविक या अनुकरणित डिवाइस वातावरण का उपयोग किया जाता है। OS और फ़ाइल प्रणाली तक शेल पहुंच बनाए रखना आवश्यक है। अनुकरण हार्डवेयर इंटरैक्शन को पूरी तरह से अनुकरण नहीं कर सकता, जिससे कभी-कभी अनुकरण को फिर से शुरू करने की आवश्यकता होती है। विश्लेषण को फ़ाइल प्रणाली पर फिर से जाना चाहिए, उजागर वेबपृष्ठों और नेटवर्क सेवाओं का शोषण करना चाहिए, और बूटलोडर कमजोरियों का पता लगाना चाहिए। फर्मवेयर अखंडता परीक्षण संभावित बैकडोर कमजोरियों की पहचान के लिए महत्वपूर्ण हैं।

## रनटाइम विश्लेषण तकनीकें

रनटाइम विश्लेषण एक प्रक्रिया या बाइनरी के साथ उसके संचालन वातावरण में बातचीत करने में शामिल है, जिसमें gdb-multiarch, Frida, और Ghidra जैसे उपकरणों का उपयोग करके ब्रेकपॉइंट सेट करना और फज़िंग और अन्य तकनीकों के माध्यम से कमजोरियों की पहचान करना शामिल है।

## बाइनरी शोषण और प्रमाण-का-धारणा

पहचानी गई कमजोरियों के लिए PoC विकसित करने के लिए लक्षित आर्किटेक्चर और निम्न-स्तरीय भाषाओं में प्रोग्रामिंग की गहरी समझ की आवश्यकता होती है। एम्बेडेड सिस्टम में बाइनरी रनटाइम सुरक्षा दुर्लभ होती है, लेकिन जब मौजूद होती है, तो Return Oriented Programming (ROP) जैसी तकनीकों की आवश्यकता हो सकती है।

## फर्मवेयर विश्लेषण के लिए तैयार ऑपरेटिंग सिस्टम

[AttifyOS](https://github.com/adi0x90/attifyos) और [EmbedOS](https://github.com/scriptingxss/EmbedOS) जैसे ऑपरेटिंग सिस्टम फर्मवेयर सुरक्षा परीक्षण के लिए पूर्व-कॉन्फ़िगर किए गए वातावरण प्रदान करते हैं, जिनमें आवश्यक उपकरण होते हैं।

## फर्मवेयर का विश्लेषण करने के लिए तैयार OSs

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS एक डिस्ट्रीब्यूशन है जिसका उद्देश्य आपको इंटरनेट ऑफ थिंग्स (IoT) उपकरणों की सुरक्षा मूल्यांकन और पेनटेस्टिंग करने में मदद करना है। यह आपको सभी आवश्यक उपकरणों के साथ पूर्व-कॉन्फ़िगर किए गए वातावरण प्रदान करके बहुत सारा समय बचाता है।
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): फर्मवेयर सुरक्षा परीक्षण उपकरणों के साथ प्रीलोडेड Ubuntu 18.04 पर आधारित एम्बेडेड सुरक्षा परीक्षण ऑपरेटिंग सिस्टम।

## अभ्यास के लिए कमजोर फर्मवेयर

फर्मवेयर में कमजोरियों की खोज करने का अभ्यास करने के लिए, निम्नलिखित कमजोर फर्मवेयर परियोजनाओं का उपयोग प्रारंभिक बिंदु के रूप में करें।

- OWASP IoTGoat
- [https://github.com/OWASP/IoTGoat](https://github.com/OWASP/IoTGoat)
- द डैम्न वल्नरेबल राउटर फर्मवेयर प्रोजेक्ट
- [https://github.com/praetorian-code/DVRF](https://github.com/praetorian-code/DVRF)
- डैम्न वल्नरेबल ARM राउटर (DVAR)
- [https://blog.exploitlab.net/2018/01/dvar-damn-vulnerable-arm-router.html](https://blog.exploitlab.net/2018/01/dvar-damn-vulnerable-arm-router.html)
- ARM-X
- [https://github.com/therealsaumil/armx#downloads](https://github.com/therealsaumil/armx#downloads)
- Azeria Labs VM 2.0
- [https://azeria-labs.com/lab-vm-2-0/](https://azeria-labs.com/lab-vm-2-0/)
- डैम्न वल्नरेबल IoT डिवाइस (DVID)
- [https://github.com/Vulcainreo/DVID](https://github.com/Vulcainreo/DVID)

## संदर्भ

- [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [Practical IoT Hacking: The Definitive Guide to Attacking the Internet of Things](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)

## प्रशिक्षण और प्रमाणपत्र

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

{{#include ../../banners/hacktricks-training.md}}
