# फ़र्मवेयर विश्लेषण

{{#include ../../banners/hacktricks-training.md}}

## **परिचय**

### संबंधित संसाधन


{{#ref}}
synology-encrypted-archive-decryption.md
{{#endref}}

{{#ref}}
../../network-services-pentesting/32100-udp-pentesting-pppp-cs2-p2p-cameras.md
{{#endref}}


फ़र्मवेयर एक आवश्यक सॉफ्टवेयर है जो डिवाइस को सही ढंग से काम करने में सक्षम बनाता है, हार्डवेयर घटकों और उपयोगकर्ता द्वारा इंटरैक्ट किए जाने वाले सॉफ्टवेयर के बीच संचार को प्रबंधित और सुगम बनाकर। यह स्थायी मेमोरी में संग्रहीत होता है, जिससे डिवाइस पावर ऑन होते ही आवश्यक निर्देशों तक पहुँच पाता है और ऑपरेटिंग सिस्टम लॉन्च हो जाता है। फ़र्मवेयर की जाँच और संभावित रूप से संशोधन करना सुरक्षा कमजोरियों की पहचान में एक महत्वपूर्ण कदम है।

## **जानकारी एकत्र करना**

**जानकारी एकत्र करना** किसी डिवाइस की संरचना और वह किन तकनीकों का उपयोग करता है यह समझने का एक महत्वपूर्ण आरंभिक चरण है। इस प्रक्रिया में निम्नलिखित चीजों का संग्रह शामिल होता है:

- CPU आर्किटेक्चर और जिस ऑपरेटिंग सिस्टम पर यह चलता है
- Bootloader के विवरण
- हार्डवेयर लेआउट और डेटा शीट्स
- Codebase के मेट्रिक्स और स्रोत स्थान
- बाहरी लाइब्रेरी और लाइसेंस प्रकार
- अपडेट इतिहास और नियामक प्रमाणपत्र
- वास्तुशिल्प और फ्लो डायग्राम
- सुरक्षा आकलन और पहचानी गई कमजोरियाँ

इस उद्देश्य के लिए, **open-source intelligence (OSINT)** टूल अमूल्य हैं, और किसी भी उपलब्ध ओपन-सोर्स सॉफ़्टवेयर कंपोनेंट्स का मैन्युअल और स्वचालित समीक्षा प्रक्रियाओं के माध्यम से विश्लेषण भी उतना ही महत्वपूर्ण है। टूल्स जैसे [Coverity Scan](https://scan.coverity.com) और [Semmle’s LGTM](https://lgtm.com/#explore) मुफ्त स्थैतिक विश्लेषण प्रदान करते हैं जिन्हें संभावित समस्याएँ खोजने के लिए उपयोग किया जा सकता है।

## **फ़र्मवेयर प्राप्त करना**

फ़र्मवेयर प्राप्त करने के कई तरीके हैं, जिनमें से प्रत्येक की अपनी जटिलता होती है:

- **सीधे** स्रोत से (डेवलपर्स, निर्माता)
- **निर्देशों से बनाना** (provided instructions से)
- **आधिकारिक सपोर्ट साइटों से डाउनलोड करना**
- होस्ट किए गए फ़र्मवेयर फ़ाइलें ढूँढने के लिए **Google dork** क्वेरीज का उपयोग करना
- सीधे **cloud storage** तक पहुँच, जैसे टूल [S3Scanner](https://github.com/sa7mon/S3Scanner) का उपयोग करना
- man-in-the-middle techniques के माध्यम से **updates** को इंटरसेप्ट करना
- डिवाइस से **UART**, **JTAG**, या **PICit** जैसे कनेक्शनों के माध्यम से **Extracting**
- डिवाइस कम्युनिकेशन में update requests के लिए **Sniffing**
- **hardcoded update endpoints** की पहचान करना और उनका उपयोग करना
- Bootloader या network से **Dumping**
- जब बाकी सब विफल हो तो उपयुक्त हार्डवेयर टूल्स का उपयोग करके स्टोरेज चिप को निकालना और पढ़ना

## फ़र्मवेयर का विश्लेषण

अब जब आपके पास **फ़र्मवेयर है**, तो आपको यह जानने के लिए इसके बारे में जानकारी निकालनी होगी कि इसे कैसे हैंडल करना है। इसके लिए आप निम्नलिखित विभिन्न टूल्स का उपयोग कर सकते हैं:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
यदि आपको उन tools से ज्यादा कुछ नहीं मिलता है तो इमेज का **entropy** `binwalk -E <bin>` से चेक करें — अगर entropy low है तो यह संभवतः encrypted नहीं है। अगर entropy high है, तो यह संभाविततः encrypted (या किसी तरह compressed) है।

इसके अलावा, आप इन tools का उपयोग **files embedded inside the firmware** को extract करने के लिए कर सकते हैं:

{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

या [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) का उपयोग फ़ाइल को inspect करने के लिए करें।

### Filesystem प्राप्त करना

पहले बताए गए tools जैसे `binwalk -ev <bin>` से आप **extract the filesystem** कर पाने चाहिए थे.\
Binwalk आमतौर पर इसे उस **folder named as the filesystem type** के अंदर extract कर देता है, जो आमतौर पर निम्न में से एक होता है: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Manual Filesystem Extraction

कभी-कभी, binwalk के पास **not have the magic byte of the filesystem in its signatures**. ऐसे मामलों में, binwalk का उपयोग करके **find the offset of the filesystem and carve the compressed filesystem** को binary से निकालें और नीचे दिए गए steps का उपयोग करके उसके प्रकार के अनुसार **manually extract** करें।
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
Squashfs filesystem को carve करने के लिए नीचे दिया गया **dd command** चलाएँ।
```
$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs

8257536+0 records in

8257536+0 records out

8257536 bytes (8.3 MB, 7.9 MiB) copied, 12.5777 s, 657 kB/s
```
वैकल्पिक रूप से, निम्नलिखित कमांड भी चलाया जा सकता है।

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

- For squashfs (उपरोक्त उदाहरण में उपयोग किया गया)

`$ unsquashfs dir.squashfs`

फाइलें बाद में `squashfs-root` डायरेक्टरी में होंगी।

- CPIO archive फ़ाइलें

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- jffs2 filesystems के लिए

`$ jefferson rootfsfile.jffs2`

- NAND flash वाले ubifs filesystems के लिए

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## फर्मवेयर का विश्लेषण

जब फर्मवेयर प्राप्त हो जाए, तो इसकी संरचना और संभावित कमजोरियों को समझने के लिए इसे विश्लेषित करना आवश्यक है। इस प्रक्रिया में फर्मवेयर इमेज से मूल्यवान डेटा निकालने और जांचने के लिए विभिन्न टूल्स का उपयोग होता है।

### प्रारंभिक विश्लेषण उपकरण

बाइनरी फ़ाइल (जिसे `<bin>` कहा गया है) की प्रारंभिक जाँच के लिए कुछ कमांड दिए गए हैं। ये कमांड फ़ाइल प्रकार पहचानने, strings निकालने, बाइनरी डेटा का विश्लेषण करने, और partition व filesystem विवरण समझने में मदद करते हैं:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
इमेज की encryption स्थिति का आकलन करने के लिए, **entropy** को `binwalk -E <bin>` के साथ चेक किया जाता है। कम entropy यह संकेत देता है कि encryption मौजूद नहीं है, जबकि उच्च entropy संभवतः encryption या compression का संकेत देता है।

एंबेडेड फ़ाइलें निकालने के लिए, उपकरण और संसाधन जैसे **file-data-carving-recovery-tools** दस्तावेज़ और फ़ाइल निरीक्षण के लिए **binvis.io** सुझाए जाते हैं।

### फ़ाइल सिस्टम निकालना

`binwalk -ev <bin>` का उपयोग करके, सामान्यतः फ़ाइल सिस्टम निकाला जा सकता है, अक्सर फ़ाइल सिस्टम प्रकार के नाम वाली एक डायरेक्टरी में (e.g., squashfs, ubifs)। हालाँकि, जब **binwalk** magic bytes के गायब होने के कारण फ़ाइल सिस्टम प्रकार को पहचानने में विफल होता है, तो मैनुअल extraction आवश्यक होता है। इसमें `binwalk` का उपयोग करके फ़ाइल सिस्टम का offset ढूँढना शामिल है, उसके बाद `dd` कमांड का उपयोग करके फ़ाइल सिस्टम को carve out करना:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
उसके बाद, फाइलसिस्टम के प्रकार (उदा., squashfs, cpio, jffs2, ubifs) के आधार पर, सामग्री को मैन्युअली निकालने के लिए अलग-अलग कमांड्स का उपयोग किया जाता है।

### Filesystem Analysis

Filesystem निकालने के बाद security flaws की तलाश शुरू होती है। ध्यान insecure network daemons, hardcoded credentials, API endpoints, update server functionalities, uncompiled code, startup scripts, और compiled binaries पर ऑफ़लाइन विश्लेषण के लिए दिया जाता है।

**Key locations** और **items** जिन्हें निरीक्षण करना चाहिए, में शामिल हैं:

- **etc/shadow** और **etc/passwd** — उपयोगकर्ता क्रेडेंशियल्स के लिए
- SSL certificates और keys in **etc/ssl**
- संभावित कमजोरियों के लिए कॉन्फ़िगरेशन और स्क्रिप्ट फ़ाइलें
- आगे के विश्लेषण के लिए embedded binaries
- सामान्य IoT device वेब सर्वर और बाइनरीज़

कुछ टूल्स filesystem के भीतर संवेदनशील जानकारी और कमजोरियाँ खोजने में मदद करते हैं:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) और [**Firmwalker**](https://github.com/craigz28/firmwalker) संवेदनशील जानकारी खोजने के लिए
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) विस्तृत firmware विश्लेषण के लिए
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go), और [**EMBA**](https://github.com/e-m-b-a/emba) स्थैतिक और गतिशील विश्लेषण के लिए

### Security Checks on Compiled Binaries

Filesystem में पाए गए source code और compiled binaries दोनों को कमजोरियों के लिए गहराई से जाँचना चाहिए। Tools जैसे **checksec.sh** (Unix binaries के लिए) और **PESecurity** (Windows binaries के लिए) अनप्रोटेक्टेड बाइनरीज़ की पहचान करने में मदद करते हैं जिन्हें exploit किया जा सकता है।

## Emulating Firmware for Dynamic Analysis

Firmware को emulate करने की प्रक्रिया डिवाइस के संचालन या किसी एक प्रोग्राम के लिए **dynamic analysis** की अनुमति देती है। यह तरीका hardware या architecture निर्भरताओं के साथ चुनौतियों का सामना कर सकता है, लेकिन root filesystem या विशिष्ट बाइनरीज़ को ऐसे डिवाइस पर ट्रांसफर करना जिनका architecture और endianness मेल खाता हो, जैसे Raspberry Pi, या एक pre-built virtual machine पर, आगे के परीक्षण को सुविधाजनक बना सकता है।

### Emulating Individual Binaries

एकल प्रोग्रामों की जाँच के लिए, प्रोग्राम की endianness और CPU architecture की पहचान करना महत्वपूर्ण है।

#### Example with MIPS Architecture

MIPS architecture बाइनरी को emulate करने के लिए, निम्न कमांड का इस्तेमाल किया जा सकता है:
```bash
file ./squashfs-root/bin/busybox
```
और आवश्यक emulation tools इंस्टॉल करने के लिए:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
For MIPS (big-endian), `qemu-mips` is used, and for little-endian binaries, `qemu-mipsel` would be the choice.

#### ARM Architecture Emulation

ARM बाइनरीज़ के लिए प्रक्रिया समान होती है, और इम्यूलेशन के लिए `qemu-arm` एमुलेटर का उपयोग किया जाता है।

### Full System Emulation

Tools like [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit), and others, पूर्ण फर्मवेयर इम्यूलेशन की सुविधा प्रदान करते हैं, प्रक्रिया को ऑटोमेट करते हैं और डायनामिक एनालिसिस में मदद करते हैं।

## Dynamic Analysis in Practice

इस चरण में, विश्लेषण के लिए वास्तविक या एमुलेटेड डिवाइस वातावरण का उपयोग किया जाता है। OS और फ़ाइल सिस्टम तक shell एक्सेस बनाए रखना आवश्यक है। इम्यूलेशन हार्डवेयर इंटरैक्शन की पूर्ण नकल नहीं कर सकता, इसलिए कभी-कभी इमुलेशन को पुनः आरंभ करना पड़ सकता है। विश्लेषण के दौरान फ़ाइल सिस्टम की फिर से जाँच करनी चाहिए, एक्स्पोज़्ड वेबपेजेस और नेटवर्क सेवाओं का उपयोग करना चाहिए, और bootloader कमजोरियों का अन्वेषण करना चाहिए। फर्मवेयर अखंडता परीक्षण संभावित बैकडोर कमजोरियों की पहचान के लिए महत्वपूर्ण हैं।

## Runtime Analysis Techniques

रनटाइम विश्लेषण में किसी प्रक्रिया या बाइनरी के साथ उसके ऑपरेटिंग वातावरण में इंटरैक्ट करना शामिल है, और ब्रेकपॉइंट सेट करने और कमजोरियों की पहचान के लिए gdb-multiarch, Frida, और Ghidra जैसे टूल्स का उपयोग किया जाता है, साथ ही fuzzing और अन्य तकनीकों के माध्यम से।

## Binary Exploitation and Proof-of-Concept

पहचानी गई कमजोरियों के लिए एक PoC विकसित करने के लिए लक्षित आर्किटेक्चर की गहन समझ और lower-level भाषाओं में प्रोग्रामिंग आवश्यक होती है। एम्बेडेड सिस्टम्स में बाइनरी रनटाइम प्रोटेक्शन्स दुर्लभ होते हैं, लेकिन जब मौजूद हों तो Return Oriented Programming (ROP) जैसी तकनीकों की आवश्यकता हो सकती है।

## Prepared Operating Systems for Firmware Analysis

Operating systems like [AttifyOS](https://github.com/adi0x90/attifyos) and [EmbedOS](https://github.com/scriptingxss/EmbedOS) फर्मवेयर सुरक्षा परीक्षण के लिए पूर्व-कॉन्फ़िगर किए गए वातावरण प्रदान करते हैं, जिनमें आवश्यक टूल्स शामिल होते हैं।

## Prepared OSs to analyze Firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS एक distro है जिसका उद्देश्य आपको Internet of Things (IoT) devices के security assessment और penetration testing करने में मदद करना है। यह आपको बहुत समय बचाता है क्योंकि यह सभी आवश्यक टूल्स के साथ एक pre-configured environment प्रदान करता है।
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Embedded security testing operating system जो Ubuntu 18.04 पर आधारित है और firmware security testing tools के साथ preloaded है।

## Firmware Downgrade Attacks & Insecure Update Mechanisms

यहाँ तक कि जब कोई विक्रेता फर्मवेयर इमेज के लिए cryptographic signature checks लागू करता है, तब भी **version rollback (downgrade) protection अक्सर छूट जाती है**। जब boot- या recovery-loader केवल embedded public key के साथ सिग्नेचर की जांच करता है लेकिन फ्लैश की जा रही इमेज के *version* (या एक monotonic counter) की तुलना नहीं करता, तो एक अटैकर वैध तरीके से एक **पुरानी, कमजोर फर्मवेयर जो अभी भी मान्य सिग्नेचर रखती है** इंस्टॉल कर सकता है और इस प्रकार पैच की गई कमजोरियों को फिर से वापस ला सकता है।

Typical attack workflow:

1. **Obtain an older signed image**
* इसे विक्रेता के सार्वजनिक डाउनलोड पोर्टल, CDN या सपोर्ट साइट से प्राप्त करें।
* इसे companion mobile/desktop applications से निकालें (उदा. एक Android APK के अंदर `assets/firmware/` के तहत)।
* इसे तीसरे-पक्ष रिपॉज़िटरीज़ से प्राप्त करें जैसे VirusTotal, Internet archives, forums, आदि।
2. **Upload or serve the image to the device** via any exposed update channel:
* Web UI, mobile-app API, USB, TFTP, MQTT, आदि।
* कई consumer IoT devices *unauthenticated* HTTP(S) endpoints एक्स्पोज़ करते हैं जो Base64-encoded firmware blobs स्वीकार करते हैं, उन्हें server-side पर decode करते हैं और recovery/upgrade ट्रिगर करते हैं।
3. डाउनग्रेड के बाद, उस कमजोरी का फायदा उठाएँ जिसे नए रिलीज़ में पैच किया गया था (उदा. बाद में जोड़ा गया command-injection फ़िल्टर)।
4. वैकल्पिक रूप से persistence हासिल करने के बाद detection से बचने के लिए नवीनतम इमेज को वापस फ्लैश करें या updates को डिसेबल कर दें।

### Example: Command Injection After Downgrade
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
कमजोर (downgraded) firmware में, `md5` पैरामीटर को sanitisation के बिना सीधे एक shell कमांड में जोड़ा जाता है, जिससे arbitrary कमांड्स inject करने की अनुमति मिलती है (यहाँ – SSH key-based root access सक्षम करने के लिए)। बाद की firmware versions में एक basic character filter जोड़ा गया था, लेकिन downgrade protection की अनुपस्थिति के कारण यह फिक्स बेअसर हो जाता है।

### मोबाइल ऐप्स से Firmware निकालना

कई विक्रेता अपने companion मोबाइल एप्लिकेशन के अंदर पूरा firmware image बंडल करते हैं ताकि ऐप डिवाइस को Bluetooth/Wi‑Fi के जरिए अपडेट कर सके। ये पैकेज आमतौर पर बिना एन्क्रिप्शन के APK/APEX में `assets/fw/` या `res/raw/` जैसे पाथ के अंतर्गत स्टोर होते हैं। `apktool`, `ghidra`, या साधारण `unzip` जैसे tools आपको फिजिकल हार्डवेयर को छुए बिना signed images निकालने की अनुमति देते हैं।
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### अपडेट लॉजिक का आकलन करने की चेकलिस्ट

* क्या *update endpoint* का transport/authentication पर्याप्त रूप से सुरक्षित है (TLS + authentication)?
* क्या डिवाइस flashing से पहले **version numbers** या एक **monotonic anti-rollback counter** की तुलना करता है?
* क्या image को secure boot chain के भीतर verify किया जाता है (उदा. signatures को ROM code द्वारा चेक किया जाता है)?
* क्या userland code अतिरिक्त sanity checks करता है (उदा. allowed partition map, model number)?
* क्या *partial* या *backup* update flows वही validation logic पुनः उपयोग कर रहे हैं?

> 💡  यदि ऊपर में से कोई भी तत्व अनुपस्थित है, तो प्लेटफ़ॉर्म संभवतः rollback attacks के प्रति संवेदनशील है।

## अभ्यास के लिए कमजोर फ़र्मवेयर

फ़र्मवेयर में कमजोरियों की खोज का अभ्यास करने के लिए, निम्नलिखित vulnerable firmware परियोजनाओं को प्रारंभिक बिंदु के रूप में उपयोग करें।

- OWASP IoTGoat
- [https://github.com/OWASP/IoTGoat](https://github.com/OWASP/IoTGoat)
- The Damn Vulnerable Router Firmware Project
- [https://github.com/praetorian-code/DVRF](https://github.com/praetorian-code/DVRF)
- Damn Vulnerable ARM Router (DVAR)
- [https://blog.exploitlab.net/2018/01/dvar-damn-vulnerable-arm-router.html](https://blog.exploitlab.net/2018/01/dvar-damn-vulnerable-arm-router.html)
- ARM-X
- [https://github.com/therealsaumil/armx#downloads](https://github.com/therealsaumil/armx#downloads)
- Azeria Labs VM 2.0
- [https://azeria-labs.com/lab-vm-2-0/](https://azeria-labs.com/lab-vm-2-0/)
- Damn Vulnerable IoT Device (DVID)
- [https://github.com/Vulcainreo/DVID](https://github.com/Vulcainreo/DVID)

## संदर्भ

- [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [Practical IoT Hacking: The Definitive Guide to Attacking the Internet of Things](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [Exploiting zero days in abandoned hardware – Trail of Bits blog](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)

## ट्रेनिंग और प्रमाणपत्र

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

{{#include ../../banners/hacktricks-training.md}}
